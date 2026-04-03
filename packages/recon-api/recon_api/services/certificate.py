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
