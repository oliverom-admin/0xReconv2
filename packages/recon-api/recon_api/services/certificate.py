"""
CertificateService — internal PKI provisioning and management.

Three-tier hierarchy:
  Internal CA (root, one per deployment)
    └── Project CA (one per project)
          └── Collector certs (mTLS, 30-day, issued on registration)

Vault key naming (immutable — names are embedded in reports):
  Internal CA:      "internal-ca-key"
  Project CA:       "project-ca-key-{project_id[:8_no_hyphens]}"
  Report signing:   "report-signing-key-{8char}"
  Report viewer:    "report-viewer-key-{user_id}-{type}-{id}"

All sync crypto operations run in asyncio.to_thread().
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import asyncpg
import structlog
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import secrets

from recon_api.services.vault import VaultService

logger = structlog.get_logger("recon.certificate")

KEY_SIZE = 4096
HASH = hashes.SHA256()
INTERNAL_CA_DAYS = 3650
ENGAGEMENT_CA_DAYS = 1825
COLLECTOR_DAYS = 30


def _id_suffix(project_id: str) -> str:
    return project_id.replace("-", "").lower()[:8]


class CertificateService:
    def __init__(self, db: asyncpg.Connection, vault: VaultService) -> None:
        self._db = db
        self._vault = vault

    async def ensure_internal_ca(self) -> str:
        row = await self._db.fetchrow(
            "SELECT certificate_pem FROM internal_ca WHERE status='active' LIMIT 1"
        )
        if row:
            logger.info("internal_ca_exists")
            return row["certificate_pem"]

        logger.info("internal_ca_generating")
        cert_pem, key_pem = await asyncio.to_thread(_gen_self_signed_ca)
        await self._vault.set_key("internal-ca-key", key_pem)

        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        await self._db.execute(
            """
            INSERT INTO internal_ca
              (certificate_pem, certificate_serial, subject,
               private_key_ref, issued_at, expires_at, status)
            VALUES ($1,$2,$3,'internal-ca-key',$4,$5,'active')
            """,
            cert_pem,
            format(cert.serial_number, "X"),
            cert.subject.rfc4514_string(),
            cert.not_valid_before_utc,
            cert.not_valid_after_utc,
        )
        logger.info("internal_ca_provisioned", serial=format(cert.serial_number, "X")[:16])
        return cert_pem

    async def get_internal_ca_cert(self) -> str | None:
        row = await self._db.fetchrow(
            "SELECT certificate_pem FROM internal_ca WHERE status='active' LIMIT 1"
        )
        return row["certificate_pem"] if row else None

    async def ensure_project_ca(self, project_id: str) -> str:
        row = await self._db.fetchrow(
            "SELECT certificate_pem FROM project_cas "
            "WHERE project_id=$1 AND status='active' LIMIT 1",
            project_id,
        )
        if row:
            return row["certificate_pem"]

        internal_ca_pem = await self.get_internal_ca_cert()
        if not internal_ca_pem:
            raise RuntimeError("Internal CA not provisioned")
        internal_ca_key = await self._vault.get_key("internal-ca-key")
        if not internal_ca_key:
            raise RuntimeError("Internal CA private key not found in vault")

        suffix = _id_suffix(project_id)
        vault_key = f"project-ca-key-{suffix}"

        logger.info("project_ca_generating", project_id=project_id, vault_key=vault_key)
        cert_pem, key_pem = await asyncio.to_thread(
            _gen_signed_ca, project_id, internal_ca_pem, internal_ca_key
        )
        await self._vault.set_key(vault_key, key_pem)

        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        await self._db.execute(
            """
            INSERT INTO project_cas
              (project_id, certificate_pem, certificate_serial, subject,
               issuer, public_key_pem, private_key_ref, issued_at, expires_at, status)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'active')
            """,
            project_id, cert_pem, format(cert.serial_number, "X"),
            cert.subject.rfc4514_string(), cert.issuer.rfc4514_string(),
            cert.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
            vault_key, cert.not_valid_before_utc, cert.not_valid_after_utc,
        )
        logger.info("project_ca_provisioned", project_id=project_id)

        # Auto-provision signing cert for this project
        try:
            await self.provision_project_signing_cert(project_id)
        except (ValueError, RuntimeError) as exc:
            logger.warning("signing_cert_provision_failed",
                           project_id=project_id, error=str(exc))

        return cert_pem

    @staticmethod
    async def load_project_ca(
        project_id: str, conn: asyncpg.Connection, vault: VaultService,
    ) -> tuple:
        """Load project CA cert and private key for signing CSRs."""
        row = await conn.fetchrow(
            "SELECT certificate_pem, private_key_ref FROM project_cas "
            "WHERE project_id=$1 AND status='active' LIMIT 1",
            project_id,
        )
        if not row:
            raise ValueError(f"No active CA for project {project_id}")
        ca_key_pem = await vault.get_key(row["private_key_ref"])
        if not ca_key_pem:
            raise ValueError(f"Project CA private key not found in vault")
        ca_cert = x509.load_pem_x509_certificate(
            row["certificate_pem"].encode(), default_backend()
        )
        ca_key = serialization.load_pem_private_key(
            ca_key_pem.encode(), password=None, backend=default_backend()
        )
        return ca_cert, ca_key

    async def issue_collector_cert(
        self, project_id: str, collector_id: str
    ) -> tuple[str, str]:
        suffix = _id_suffix(project_id)
        ca_key = await self._vault.get_key(f"project-ca-key-{suffix}")
        if not ca_key:
            await self.ensure_project_ca(project_id)
            ca_key = await self._vault.get_key(f"project-ca-key-{suffix}")
        ca_row = await self._db.fetchrow(
            "SELECT certificate_pem FROM project_cas "
            "WHERE project_id=$1 AND status='active' LIMIT 1",
            project_id,
        )
        if not ca_row or not ca_key:
            raise RuntimeError(f"Project CA not available for {project_id}")

        cert_pem, key_pem = await asyncio.to_thread(
            _gen_collector_cert, collector_id, project_id,
            ca_row["certificate_pem"], ca_key,
        )
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        await self._db.execute(
            """
            INSERT INTO collector_certificates
              (project_id, collector_id, certificate_pem,
               certificate_serial, subject, issued_at, expires_at, status)
            VALUES ($1,$2,$3,$4,$5,$6,$7,'active')
            """,
            project_id, collector_id, cert_pem,
            format(cert.serial_number, "X"),
            cert.subject.rfc4514_string(),
            cert.not_valid_before_utc, cert.not_valid_after_utc,
        )
        return cert_pem, key_pem

    # ── Report viewer cert issuance ───────────────────────────

    async def issue_report_viewer_cert(
        self, project_id: str, user_id: str,
        report_type: str, report_id: str, report_name: str,
        validity_days: int = 30,
    ) -> dict:
        """Issue a short-lived report viewer certificate signed by project CA."""
        report_ref = f"{report_type}:{report_id}"

        # Idempotency: return existing if not revoked
        existing = await self._db.fetchrow(
            """SELECT * FROM user_digital_identities
               WHERE user_id=$1 AND project_id=$2
                 AND cert_purpose='report_viewer' AND report_ref=$3
                 AND status != 'revoked'""",
            user_id, project_id, report_ref,
        )
        if existing:
            return dict(existing)

        # Get username
        user_row = await self._db.fetchrow(
            "SELECT username FROM users WHERE id=$1", user_id,
        )
        username = user_row["username"] if user_row else "unknown"

        # Load project CA
        ca_cert, ca_key = await self.load_project_ca(
            project_id, self._db, self._vault,
        )

        # Generate viewer cert
        cn = f"viewer:{username}:report:{report_name}"
        cert_pem, key_pem, cert_obj = await asyncio.to_thread(
            _gen_viewer_cert, cn, ca_cert, ca_key, validity_days,
        )
        serial = format(cert_obj.serial_number, "X")
        pub_pem = cert_obj.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        # Store private key in vault
        vault_key = f"report-viewer-key-{user_id}-{report_type}-{report_id}"
        await self._vault.set_key(vault_key, key_pem)

        # Insert record
        await self._db.execute(
            """INSERT INTO user_digital_identities
               (user_id, project_id, cert_purpose, report_ref, validity_days,
                certificate_pem, certificate_serial, public_key_pem,
                private_key_ref, expires_at)
               VALUES ($1,$2,'report_viewer',$3,$4,$5,$6,$7,$8,$9)""",
            user_id, project_id, report_ref, validity_days,
            cert_pem, serial, pub_pem, vault_key,
            cert_obj.not_valid_after_utc,
        )

        logger.info("viewer_cert_issued", user_id=user_id,
                     project_id=project_id, serial=serial[:16])

        return {
            "certificate_pem": cert_pem,
            "certificate_serial": serial,
            "public_key_pem": pub_pem,
            "private_key_ref": vault_key,
            "issued_at": cert_obj.not_valid_before_utc.isoformat(),
            "expires_at": cert_obj.not_valid_after_utc.isoformat(),
            "username": username,
        }

    # ── P12 generation ────────────────────────────────────────

    async def generate_p12(
        self, user_id: str, project_id: str,
    ) -> dict:
        """Generate PKCS#12 for the most recent active viewer cert."""
        row = await self._db.fetchrow(
            """SELECT * FROM user_digital_identities
               WHERE user_id=$1 AND project_id=$2
                 AND cert_purpose='report_viewer'
                 AND status IN ('pending_p12_creation', 'active')
               ORDER BY issued_at DESC LIMIT 1""",
            user_id, project_id,
        )
        if not row:
            raise ValueError("No viewer certificate found for this user/project")

        cert_pem = row["certificate_pem"]
        key_pem = await self._vault.get_key(row["private_key_ref"])
        if not key_pem:
            raise ValueError("Viewer cert private key not found in vault")

        # Get username
        user_row = await self._db.fetchrow(
            "SELECT username FROM users WHERE id=$1", user_id,
        )
        username = user_row["username"] if user_row else "unknown"

        # Generate P12 using pyOpenSSL
        p12_password = secrets.token_urlsafe(20)
        p12_bytes = await asyncio.to_thread(
            _build_p12, cert_pem, key_pem, p12_password,
        )

        # Update record
        await self._db.execute(
            """UPDATE user_digital_identities
               SET p12_generated_at=NOW(), status='active', updated_at=NOW()
               WHERE id=$1""",
            row["id"],
        )

        logger.info("p12_generated", user_id=user_id, project_id=project_id)

        return {
            "username": username,
            "p12_bytes": p12_bytes,
            "p12_password": p12_password,
            "expires_at": row["expires_at"].isoformat() if row["expires_at"] else None,
        }

    # ── Project signing cert provisioning ─────────────────────

    async def provision_project_signing_cert(
        self, project_id: str,
    ) -> dict:
        """Create a 2-year report signing cert signed by the project CA."""
        # Idempotent
        existing = await self._db.fetchrow(
            """SELECT * FROM project_signing_certs
               WHERE project_id=$1 AND status='active'""",
            project_id,
        )
        if existing:
            return dict(existing)

        ca_cert, ca_key = await self.load_project_ca(
            project_id, self._db, self._vault,
        )

        cn = f"0xRecon Report Signing - {project_id[:8]}"
        cert_pem, key_pem, cert_obj = await asyncio.to_thread(
            _gen_signing_cert, cn, ca_cert, ca_key,
        )
        serial = format(cert_obj.serial_number, "X")
        pub_pem = cert_obj.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        vault_key = f"report-signing-key-{project_id}"
        await self._vault.set_key(vault_key, key_pem)

        await self._db.execute(
            """INSERT INTO project_signing_certs
               (project_id, certificate_pem, certificate_serial, subject,
                issuer, public_key_pem, private_key_ref, expires_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8)""",
            project_id, cert_pem, serial,
            cert_obj.subject.rfc4514_string(),
            cert_obj.issuer.rfc4514_string(),
            pub_pem, vault_key, cert_obj.not_valid_after_utc,
        )

        logger.info("signing_cert_provisioned", project_id=project_id,
                     serial=serial[:16])

        row = await self._db.fetchrow(
            "SELECT * FROM project_signing_certs WHERE certificate_serial=$1",
            serial,
        )
        return dict(row) if row else {"certificate_serial": serial}

    # ── Load signing cert ─────────────────────────────────────

    async def load_project_signing_cert(
        self, project_id: str,
    ) -> tuple:
        """Load active signing cert + private key for report signing."""
        row = await self._db.fetchrow(
            """SELECT certificate_pem, private_key_ref, certificate_serial
               FROM project_signing_certs
               WHERE project_id=$1 AND status='active'""",
            project_id,
        )
        if not row:
            raise ValueError(f"No active signing cert for project {project_id}")

        key_pem = await self._vault.get_key(row["private_key_ref"])
        if not key_pem:
            raise ValueError("Signing cert private key not found in vault")

        return row["certificate_pem"], key_pem, row["certificate_serial"]


def _gen_viewer_cert(
    cn: str, ca_cert, ca_key, validity_days: int,
) -> tuple[str, str, object]:
    """Generate a viewer certificate (runs in thread)."""
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=KEY_SIZE, backend=default_backend()
    )
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "0xRecon"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=True,
            content_commitment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH,
        ]), critical=False)
        .sign(ca_key, HASH, default_backend())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem, cert


def _gen_signing_cert(
    cn: str, ca_cert, ca_key,
) -> tuple[str, str, object]:
    """Generate a 2-year report signing certificate (runs in thread)."""
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=KEY_SIZE, backend=default_backend()
    )
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "0xRecon"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=730))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=True,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(ca_key, HASH, default_backend())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem, cert


def _build_p12(cert_pem: str, key_pem: str, password: str) -> bytes:
    """Build PKCS#12 file using pyOpenSSL (runs in thread)."""
    from OpenSSL import crypto
    cert_obj = crypto.X509.from_cryptography(
        x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    )
    key_obj = crypto.PKey.from_cryptography_key(
        serialization.load_pem_private_key(
            key_pem.encode(), password=None, backend=default_backend()
        )
    )
    p12 = crypto.PKCS12()
    p12.set_certificate(cert_obj)
    p12.set_privatekey(key_obj)
    return p12.export(password.encode())


def _gen_self_signed_ca() -> tuple[str, str]:
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=KEY_SIZE, backend=default_backend()
    )
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "0xRecon"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Internal Infrastructure"),
        x509.NameAttribute(NameOID.COMMON_NAME, "0xRecon Internal CA"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=INTERNAL_CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(key, HASH, default_backend())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(serialization.Encoding.PEM,
                          serialization.PrivateFormat.TraditionalOpenSSL,
                          serialization.NoEncryption()).decode(),
    )


def _gen_signed_ca(
    project_id: str, issuer_cert_pem: str, issuer_key_pem: str
) -> tuple[str, str]:
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=KEY_SIZE, backend=default_backend()
    )
    issuer_cert = x509.load_pem_x509_certificate(issuer_cert_pem.encode(), default_backend())
    issuer_key = serialization.load_pem_private_key(
        issuer_key_pem.encode(), password=None, backend=default_backend()
    )
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "0xRecon"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"0xRecon Project CA - {project_id[:8]}"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=ENGAGEMENT_CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(issuer_key, HASH, default_backend())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(serialization.Encoding.PEM,
                          serialization.PrivateFormat.TraditionalOpenSSL,
                          serialization.NoEncryption()).decode(),
    )


def _gen_collector_cert(
    collector_id: str, project_id: str, ca_cert_pem: str, ca_key_pem: str,
) -> tuple[str, str]:
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=KEY_SIZE, backend=default_backend()
    )
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode(), default_backend())
    ca_key = serialization.load_pem_private_key(
        ca_key_pem.encode(), password=None, backend=default_backend()
    )
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, collector_id),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, project_id),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "0xRecon"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=COLLECTOR_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=False,
            content_commitment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(ca_key, HASH, default_backend())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(serialization.Encoding.PEM,
                          serialization.PrivateFormat.TraditionalOpenSSL,
                          serialization.NoEncryption()).decode(),
    )
