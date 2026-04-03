"""
CertificateLifecycleService — CSR workflow, revocation, and renewal queue.

Separate from CertificateService (issuance) to keep concerns clean.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

import asyncpg
import structlog
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

logger = structlog.get_logger("recon.certificate_lifecycle")

VALID_PURPOSES = ("collector", "report_viewer", "report_signing")
PURPOSE_VALIDITY_DAYS = {
    "collector": 30,
    "report_viewer": 90,
    "report_signing": 730,
}


class CertificateLifecycleService:
    def __init__(self, db: asyncpg.Connection) -> None:
        self._db = db

    # ── CSR Workflow ──────────────────────────────────────────

    async def submit_csr(
        self, project_id: str, requester_id: str,
        csr_pem: str, requested_purpose: str,
        collector_id: str | None = None,
    ) -> dict[str, Any]:
        """Validate and store a CSR."""
        if requested_purpose not in VALID_PURPOSES:
            raise ValueError(
                f"Invalid purpose: {requested_purpose}. "
                f"Must be one of: {', '.join(VALID_PURPOSES)}"
            )

        # Parse and validate CSR
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid CSR PEM: {exc}")

        # Extract subject CN
        try:
            cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            subject_cn = cn_attrs[0].value if cn_attrs else ""
        except (IndexError, AttributeError):
            subject_cn = ""

        if not subject_cn:
            raise ValueError("CSR subject CN must not be empty")

        # For collector purpose, validate CN format
        if requested_purpose == "collector" and collector_id:
            expected_cn = f"collector_{collector_id}"
            if subject_cn != expected_cn and subject_cn != collector_id:
                logger.warning("csr_cn_mismatch",
                               expected=expected_cn, got=subject_cn)

        csr_id = await self._db.fetchval(
            """INSERT INTO certificate_signing_reqs
               (project_id, requester_id, collector_id, csr_pem,
                subject_cn, requested_purpose)
               VALUES ($1, $2, $3, $4, $5, $6)
               RETURNING id""",
            project_id, requester_id, collector_id, csr_pem,
            subject_cn, requested_purpose,
        )
        row = await self._db.fetchrow(
            "SELECT * FROM certificate_signing_reqs WHERE id = $1", csr_id,
        )
        return dict(row) if row else {"id": csr_id}

    async def get_csr(
        self, csr_id: str, project_id: str,
    ) -> dict[str, Any] | None:
        row = await self._db.fetchrow(
            """SELECT * FROM certificate_signing_reqs
               WHERE id = $1 AND project_id = $2""",
            csr_id, project_id,
        )
        return dict(row) if row else None

    async def list_csrs(
        self, project_id: str, status: str | None = None,
        requested_purpose: str | None = None,
        limit: int = 50, offset: int = 0,
    ) -> list[dict]:
        conditions = ["project_id = $1"]
        params: list[Any] = [project_id]
        idx = 2
        if status:
            conditions.append(f"status = ${idx}")
            params.append(status)
            idx += 1
        if requested_purpose:
            conditions.append(f"requested_purpose = ${idx}")
            params.append(requested_purpose)
            idx += 1
        where = " AND ".join(conditions)
        rows = await self._db.fetch(
            f"""SELECT * FROM certificate_signing_reqs
                WHERE {where}
                ORDER BY created_at DESC LIMIT {limit} OFFSET {offset}""",
            *params,
        )
        return [dict(r) for r in rows]

    async def approve_csr(
        self, csr_id: str, project_id: str,
        approved_by: str, vault: Any,
    ) -> dict[str, Any]:
        """Approve a pending CSR and issue the certificate."""
        rec = await self.get_csr(csr_id, project_id)
        if not rec:
            raise ValueError("CSR not found")
        if rec["status"] != "pending":
            raise ValueError(f"CSR is not pending (status={rec['status']})")

        # Load project CA
        from recon_api.services.certificate import CertificateService
        ca_cert, ca_key = await CertificateService.load_project_ca(
            project_id, self._db, vault,
        )

        # Parse the CSR
        csr = x509.load_pem_x509_csr(rec["csr_pem"].encode(), default_backend())

        # Issue certificate
        validity_days = PURPOSE_VALIDITY_DAYS.get(rec["requested_purpose"], 30)
        now = datetime.now(timezone.utc)
        cert = await asyncio.to_thread(
            _sign_csr, csr, ca_cert, ca_key, validity_days,
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        serial = format(cert.serial_number, "X")

        # Store in collector_certificates if purpose is collector
        if rec["requested_purpose"] == "collector":
            await self._db.execute(
                """INSERT INTO collector_certificates
                   (project_id, collector_id, certificate_pem,
                    certificate_serial, subject, issued_at, expires_at, status)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, 'active')
                   ON CONFLICT DO NOTHING""",
                project_id, rec.get("collector_id"),
                cert_pem, serial, cert.subject.rfc4514_string(),
                cert.not_valid_before_utc, cert.not_valid_after_utc,
            )

        # Update CSR record
        await self._db.execute(
            """UPDATE certificate_signing_reqs
               SET status = 'issued', approved_by = $2, approved_at = NOW(),
                   issued_cert_serial = $3, updated_at = NOW()
               WHERE id = $1""",
            csr_id, approved_by, serial,
        )

        updated = await self.get_csr(csr_id, project_id)
        return {
            "csr": updated,
            "certificate_pem": cert_pem,
            "serial_number": serial,
        }

    async def reject_csr(
        self, csr_id: str, project_id: str,
        rejected_by: str, rejection_reason: str,
    ) -> dict[str, Any]:
        rec = await self.get_csr(csr_id, project_id)
        if not rec:
            raise ValueError("CSR not found")
        if rec["status"] != "pending":
            raise ValueError(f"CSR is not pending (status={rec['status']})")
        await self._db.execute(
            """UPDATE certificate_signing_reqs
               SET status = 'rejected', rejection_reason = $2, updated_at = NOW()
               WHERE id = $1""",
            csr_id, rejection_reason,
        )
        return await self.get_csr(csr_id, project_id) or {}

    # ── Revocation ────────────────────────────────────────────

    async def revoke_certificate(
        self, project_id: str, serial_number: str,
        revoked_by: str, revocation_reason: str = "unspecified",
    ) -> dict[str, Any]:
        """Revoke a certificate by serial number."""
        # Check if already revoked (idempotent)
        existing = await self._db.fetchrow(
            """SELECT * FROM revocation_list
               WHERE project_id = $1 AND serial_number = $2""",
            project_id, serial_number,
        )
        if existing:
            return dict(existing)

        # Insert revocation record
        rev_id = await self._db.fetchval(
            """INSERT INTO revocation_list
               (project_id, serial_number, revocation_reason, revoked_by)
               VALUES ($1, $2, $3, $4) RETURNING id""",
            project_id, serial_number, revocation_reason, revoked_by,
        )

        # Update collector_certificates if found
        await self._db.execute(
            """UPDATE collector_certificates
               SET status = 'revoked', revoked_at = NOW()
               WHERE project_id = $1 AND certificate_serial = $2""",
            project_id, serial_number,
        )

        row = await self._db.fetchrow(
            "SELECT * FROM revocation_list WHERE id = $1", rev_id,
        )
        logger.info("certificate_revoked",
                     project_id=project_id, serial=serial_number)
        return dict(row) if row else {"id": rev_id}

    async def is_revoked(self, project_id: str, serial_number: str) -> bool:
        count = await self._db.fetchval(
            """SELECT count(*) FROM revocation_list
               WHERE project_id = $1 AND serial_number = $2""",
            project_id, serial_number,
        )
        return (count or 0) > 0

    async def get_revocation_list(self, project_id: str) -> list[dict]:
        rows = await self._db.fetch(
            """SELECT * FROM revocation_list
               WHERE project_id = $1 ORDER BY revoked_at DESC""",
            project_id,
        )
        return [dict(r) for r in rows]

    async def get_certificate_status(
        self, project_id: str, serial_number: str,
    ) -> dict[str, Any] | None:
        cert_row = await self._db.fetchrow(
            """SELECT * FROM collector_certificates
               WHERE project_id = $1 AND certificate_serial = $2""",
            project_id, serial_number,
        )
        revoked = await self.is_revoked(project_id, serial_number)
        if not cert_row and not revoked:
            return None
        result: dict[str, Any] = {}
        if cert_row:
            result = dict(cert_row)
        result["is_revoked"] = revoked
        return result

    # ── Renewal Queue ─────────────────────────────────────────

    async def get_renewal_queue(
        self, project_id: str, threshold_days: int = 30,
    ) -> dict[str, Any]:
        rows = await self._db.fetch(
            """SELECT * FROM collector_certificates
               WHERE project_id = $1 AND status = 'active'
                 AND expires_at <= NOW() + make_interval(days => $2)
               ORDER BY expires_at ASC""",
            project_id, threshold_days,
        )
        now = datetime.now(timezone.utc)
        expired, critical, warning = [], [], []
        for r in rows:
            d = dict(r)
            exp = r.get("expires_at")
            if exp and exp < now:
                expired.append(d)
            elif exp and exp < now + timedelta(days=7):
                critical.append(d)
            else:
                warning.append(d)

        return {
            "expired": expired,
            "critical": critical,
            "warning": warning,
            "total": len(rows),
            "threshold_days": threshold_days,
        }

    async def renew_collector_cert(
        self, project_id: str, collector_id: str,
        renewed_by: str, vault: Any,
    ) -> dict[str, Any]:
        """Issue a fresh collector certificate."""
        from recon_api.services.certificate import CertificateService
        cert_svc = CertificateService(self._db, vault)
        cert_pem, key_pem = await cert_svc.issue_collector_cert(
            project_id, collector_id,
        )
        logger.info("collector_cert_renewed",
                     project_id=project_id, collector_id=collector_id,
                     renewed_by=renewed_by)
        return {
            "certificate_pem": cert_pem,
            "collector_id": collector_id,
            "renewed_by": renewed_by,
        }


def _sign_csr(
    csr: x509.CertificateSigningRequest,
    ca_cert: x509.Certificate,
    ca_key: Any,
    validity_days: int,
) -> x509.Certificate:
    """Sign a CSR with the CA key (runs in thread)."""
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
    )
    return builder.sign(ca_key, hashes.SHA256(), default_backend())
