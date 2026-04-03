"""
InventoryService — sync scan results into persistent inventory with change detection.

Lifecycle: scan completes → sync_from_scan() → upsert certs/keys → change journal
Identity: certificates by fingerprint_sha256, keys by key_identifier
Change types: added | updated | removed | reappeared
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

import asyncpg
import structlog

logger = structlog.get_logger("recon.inventory")


@dataclass
class SyncResult:
    """Result of an inventory sync operation."""
    project_id: str
    scan_id: str
    success: bool
    started_at: str
    completed_at: str
    duration_seconds: float
    certificates_total: int = 0
    certificates_added: int = 0
    certificates_updated: int = 0
    certificates_removed: int = 0
    certificates_reappeared: int = 0
    keys_total: int = 0
    keys_added: int = 0
    keys_updated: int = 0
    keys_removed: int = 0
    keys_reappeared: int = 0
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class InventoryService:
    def __init__(self, db: asyncpg.Connection) -> None:
        self._db = db

    # ── Primary sync method ───────────────────────────────────

    async def sync_from_scan(
        self, scan_id: str, project_id: str,
        scan_results_json: dict[str, Any],
    ) -> SyncResult:
        """Sync scan results into persistent inventory with change detection."""
        started = datetime.now(timezone.utc)
        result = SyncResult(
            project_id=project_id,
            scan_id=scan_id,
            success=False,
            started_at=started.isoformat(),
            completed_at="",
            duration_seconds=0.0,
        )

        try:
            # Extract certificates and keys from scan results
            certs = scan_results_json.get("certificates", [])
            keys = scan_results_json.get("keys", [])

            # Get or create a "promoted" integration for scan-sourced data
            integration_id = await self._ensure_promoted_integration()

            # Upsert certificates
            cert_stats = await self._upsert_certificates(
                certs, project_id, integration_id, scan_id,
            )
            result.certificates_total = len(certs)
            result.certificates_added = cert_stats["added"]
            result.certificates_updated = cert_stats["updated"]
            result.certificates_removed = cert_stats["removed"]
            result.certificates_reappeared = cert_stats["reappeared"]

            # Upsert keys
            key_stats = await self._upsert_keys(
                keys, project_id, integration_id, scan_id,
            )
            result.keys_total = len(keys)
            result.keys_added = key_stats["added"]
            result.keys_updated = key_stats["updated"]
            result.keys_removed = key_stats["removed"]
            result.keys_reappeared = key_stats["reappeared"]

            result.success = True

        except Exception as exc:
            result.error_message = str(exc)
            logger.error("inventory_sync_failed",
                         scan_id=scan_id, error=str(exc))

        completed = datetime.now(timezone.utc)
        result.completed_at = completed.isoformat()
        result.duration_seconds = (completed - started).total_seconds()

        logger.info("inventory_sync_complete",
                    scan_id=scan_id,
                    certs_added=result.certificates_added,
                    keys_added=result.keys_added,
                    success=result.success)
        return result

    # ── Promotion ─────────────────────────────────────────────

    async def promote_from_scan(
        self, scan_id: str, project_id: str,
    ) -> dict[str, int]:
        """Mark inventory records sourced from a scan as promoted."""
        cert_count = await self._db.fetchval(
            """UPDATE certificates_inventory
               SET is_promoted=true, promoted_from_scan_id=$1, promoted_at=NOW()
               WHERE project_id=$2 AND is_promoted=false
                 AND id IN (
                   SELECT ci.id FROM certificates_inventory ci
                   JOIN inventory_changes ic ON ic.entity_id=ci.fingerprint_sha256
                     AND ic.project_id=ci.project_id
                   WHERE ci.project_id=$2
                 )
               RETURNING id""",
            scan_id, project_id,
        )
        # Simpler: promote all active non-promoted in project
        cert_result = await self._db.fetchval(
            """UPDATE certificates_inventory
               SET is_promoted=true, promoted_from_scan_id=$1, promoted_at=NOW()
               WHERE project_id=$2 AND is_active=true AND is_promoted=false
               RETURNING count(*)""",
            scan_id, project_id,
        )
        # fetchval with RETURNING count(*) doesn't work as expected, use execute
        cert_tag = await self._db.execute(
            """UPDATE certificates_inventory
               SET is_promoted=true, promoted_from_scan_id=$1, promoted_at=NOW()
               WHERE project_id=$2 AND is_active=true AND is_promoted=false""",
            scan_id, project_id,
        )
        cert_count = int(cert_tag.split()[-1]) if cert_tag else 0

        key_tag = await self._db.execute(
            """UPDATE keys_inventory
               SET is_promoted=true, promoted_from_scan_id=$1, promoted_at=NOW()
               WHERE project_id=$2 AND is_active=true AND is_promoted=false""",
            scan_id, project_id,
        )
        key_count = int(key_tag.split()[-1]) if key_tag else 0

        return {"promoted_certificates": cert_count, "promoted_keys": key_count}

    # ── Query methods ─────────────────────────────────────────

    async def get_certificates(
        self, project_id: str, filters: dict[str, Any] | None = None,
    ) -> list[dict]:
        """Return active certificates for a project with optional filters."""
        filters = filters or {}
        conditions = ["project_id = $1"]
        params: list[Any] = [project_id]
        idx = 2

        if not filters.get("include_inactive"):
            conditions.append("is_active = true")

        if filters.get("source_type"):
            conditions.append(f"source_type = ${idx}")
            params.append(filters["source_type"])
            idx += 1

        if filters.get("expiring_within_days") is not None:
            conditions.append(
                f"days_until_expiry IS NOT NULL AND days_until_expiry <= ${idx}"
            )
            params.append(int(filters["expiring_within_days"]))
            idx += 1

        if filters.get("is_promoted") is not None:
            conditions.append(f"is_promoted = ${idx}")
            params.append(bool(filters["is_promoted"]))
            idx += 1

        if filters.get("integration_id"):
            conditions.append(f"integration_id = ${idx}")
            params.append(filters["integration_id"])
            idx += 1

        where = " AND ".join(conditions)
        limit = min(int(filters.get("limit", 50)), 500)
        offset = int(filters.get("offset", 0))

        query = f"""
            SELECT * FROM certificates_inventory
            WHERE {where}
            ORDER BY not_after ASC NULLS LAST
            LIMIT {limit} OFFSET {offset}
        """
        rows = await self._db.fetch(query, *params)
        return [dict(r) for r in rows]

    async def count_certificates(
        self, project_id: str, filters: dict[str, Any] | None = None,
    ) -> int:
        """Count certificates matching filters."""
        filters = filters or {}
        conditions = ["project_id = $1"]
        params: list[Any] = [project_id]
        idx = 2

        if not filters.get("include_inactive"):
            conditions.append("is_active = true")

        if filters.get("source_type"):
            conditions.append(f"source_type = ${idx}")
            params.append(filters["source_type"])
            idx += 1

        where = " AND ".join(conditions)
        return await self._db.fetchval(
            f"SELECT count(*) FROM certificates_inventory WHERE {where}",
            *params,
        ) or 0

    async def get_keys(
        self, project_id: str, filters: dict[str, Any] | None = None,
    ) -> list[dict]:
        """Return active keys for a project with optional filters."""
        filters = filters or {}
        conditions = ["project_id = $1"]
        params: list[Any] = [project_id]
        idx = 2

        if not filters.get("include_inactive"):
            conditions.append("is_active = true")

        if filters.get("source_type"):
            conditions.append(f"source_type = ${idx}")
            params.append(filters["source_type"])
            idx += 1

        if filters.get("is_hsm_backed") is not None:
            conditions.append(f"is_hsm_backed = ${idx}")
            params.append(bool(filters["is_hsm_backed"]))
            idx += 1

        where = " AND ".join(conditions)
        limit = min(int(filters.get("limit", 50)), 500)
        offset = int(filters.get("offset", 0))

        query = f"""
            SELECT * FROM keys_inventory
            WHERE {where}
            ORDER BY key_name ASC NULLS LAST
            LIMIT {limit} OFFSET {offset}
        """
        rows = await self._db.fetch(query, *params)
        return [dict(r) for r in rows]

    async def get_lifecycle_queue(
        self, project_id: str, threshold_days: int = 90,
    ) -> dict[str, Any]:
        """Return certificates expiring within threshold, grouped by urgency."""
        rows = await self._db.fetch(
            """SELECT * FROM certificates_inventory
               WHERE project_id = $1 AND is_active = true
                 AND days_until_expiry IS NOT NULL
                 AND days_until_expiry <= $2
               ORDER BY days_until_expiry ASC""",
            project_id, threshold_days,
        )

        critical, warning, upcoming = [], [], []
        for r in rows:
            d = dict(r)
            days = d.get("days_until_expiry") or 0
            if days <= 30:
                critical.append(d)
            elif days <= 90:
                warning.append(d)
            else:
                upcoming.append(d)

        return {
            "critical": critical,
            "warning": warning,
            "upcoming": upcoming,
            "total": len(rows),
        }

    async def get_inventory_summary(self, project_id: str) -> dict[str, Any]:
        """Return summary counts for a project's inventory."""
        row = await self._db.fetchrow(
            """SELECT
                 count(*) FILTER (WHERE true) AS total_certificates,
                 count(*) FILTER (WHERE is_active) AS active_certificates,
                 count(*) FILTER (WHERE is_active AND days_until_expiry IS NOT NULL
                                    AND days_until_expiry <= 30) AS expiring_30_days,
                 count(*) FILTER (WHERE is_active AND days_until_expiry IS NOT NULL
                                    AND days_until_expiry <= 90) AS expiring_90_days,
                 count(*) FILTER (WHERE is_promoted) AS promoted_certificates
               FROM certificates_inventory WHERE project_id = $1""",
            project_id,
        )
        cert = dict(row) if row else {}

        key_row = await self._db.fetchrow(
            """SELECT
                 count(*) FILTER (WHERE true) AS total_keys,
                 count(*) FILTER (WHERE is_active) AS active_keys,
                 count(*) FILTER (WHERE is_promoted) AS promoted_keys
               FROM keys_inventory WHERE project_id = $1""",
            project_id,
        )
        key = dict(key_row) if key_row else {}

        return {
            "total_certificates": cert.get("total_certificates", 0),
            "active_certificates": cert.get("active_certificates", 0),
            "expiring_30_days": cert.get("expiring_30_days", 0),
            "expiring_90_days": cert.get("expiring_90_days", 0),
            "promoted_certificates": cert.get("promoted_certificates", 0),
            "total_keys": key.get("total_keys", 0),
            "active_keys": key.get("active_keys", 0),
            "promoted_keys": key.get("promoted_keys", 0),
        }

    async def get_sync_status(
        self, project_id: str | None = None,
    ) -> list[dict]:
        """Return connector sync status, optionally filtered."""
        rows = await self._db.fetch(
            """SELECT css.*, ci.name AS integration_name, ci.type AS integration_type
               FROM connector_sync_status css
               JOIN clm_integrations ci ON ci.id = css.integration_id
               ORDER BY css.last_sync_completed DESC NULLS LAST"""
        )
        return [dict(r) for r in rows]

    async def get_recent_changes(
        self, project_id: str,
        since: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Return recent inventory changes for a project."""
        if since:
            rows = await self._db.fetch(
                """SELECT * FROM inventory_changes
                   WHERE project_id = $1 AND detected_at >= $2::timestamptz
                   ORDER BY detected_at DESC LIMIT $3""",
                project_id, since, limit,
            )
        else:
            rows = await self._db.fetch(
                """SELECT * FROM inventory_changes
                   WHERE project_id = $1
                   ORDER BY detected_at DESC LIMIT $2""",
                project_id, limit,
            )
        return [dict(r) for r in rows]

    # ── Internal: certificate upsert with change detection ────

    async def _upsert_certificates(
        self, certs: list[dict], project_id: str,
        integration_id: str | None, scan_id: str,
    ) -> dict[str, int]:
        stats = {"added": 0, "updated": 0, "removed": 0, "reappeared": 0}
        if not certs:
            return stats

        # Load existing records for this project + integration
        existing_rows = await self._db.fetch(
            """SELECT id, fingerprint_sha256, is_active, normalised_data
               FROM certificates_inventory
               WHERE project_id = $1 AND integration_id IS NOT DISTINCT FROM $2""",
            project_id, integration_id,
        )
        existing = {r["fingerprint_sha256"]: dict(r) for r in existing_rows}
        seen_fps: set[str] = set()

        for cert in certs:
            fp = self._extract_fingerprint(cert)
            if not fp:
                continue
            fp = fp.lower().replace(":", "")
            seen_fps.add(fp)

            subject_cn = self._extract_cn(cert, "subject")
            issuer_cn = self._extract_cn(cert, "issuer")
            not_after = self._parse_dt(cert.get("not_after") or cert.get("not_valid_after"))
            days_exp = self._compute_days_expiry(not_after)
            source_type = self._detect_cert_source(cert)

            if fp in existing:
                rec = existing[fp]
                if not rec["is_active"]:
                    # Reappeared
                    await self._db.execute(
                        """UPDATE certificates_inventory
                           SET is_active=true, last_seen_at=NOW(),
                               normalised_data=$2::jsonb, subject_cn=$3,
                               issuer_cn=$4, not_after=$5,
                               days_until_expiry=$6, key_algorithm=$7,
                               key_size=$8, source_type=$9
                           WHERE id=$1""",
                        rec["id"], json.dumps(cert), subject_cn, issuer_cn,
                        not_after, days_exp,
                        cert.get("public_key_algorithm") or cert.get("key_algorithm"),
                        cert.get("public_key_size") or cert.get("key_size"),
                        source_type,
                    )
                    await self._record_change(
                        "certificate", fp, integration_id, project_id, "reappeared",
                    )
                    stats["reappeared"] += 1
                else:
                    # Update last_seen and expiry
                    await self._db.execute(
                        """UPDATE certificates_inventory
                           SET last_seen_at=NOW(), normalised_data=$2::jsonb,
                               days_until_expiry=$3, subject_cn=$4, issuer_cn=$5,
                               not_after=$6
                           WHERE id=$1""",
                        rec["id"], json.dumps(cert), days_exp,
                        subject_cn, issuer_cn, not_after,
                    )
                    stats["updated"] += 1
            else:
                # New certificate
                await self._db.execute(
                    """INSERT INTO certificates_inventory
                       (project_id, fingerprint_sha256, integration_id,
                        normalised_data, subject_cn, issuer_cn, not_after,
                        days_until_expiry, key_algorithm, key_size,
                        source_type, integration_name)
                       VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,$10,$11,$12)""",
                    project_id, fp, integration_id,
                    json.dumps(cert), subject_cn, issuer_cn, not_after,
                    days_exp,
                    cert.get("public_key_algorithm") or cert.get("key_algorithm"),
                    cert.get("public_key_size") or cert.get("key_size"),
                    source_type, "Promoted Scans",
                )
                await self._record_change(
                    "certificate", fp, integration_id, project_id, "added",
                )
                stats["added"] += 1

        # Mark unseen active records as removed
        for fp_key, rec in existing.items():
            if fp_key not in seen_fps and rec["is_active"]:
                await self._db.execute(
                    "UPDATE certificates_inventory SET is_active=false WHERE id=$1",
                    rec["id"],
                )
                await self._record_change(
                    "certificate", fp_key, integration_id, project_id, "removed",
                )
                stats["removed"] += 1

        return stats

    # ── Internal: key upsert with change detection ────────────

    async def _upsert_keys(
        self, keys: list[dict], project_id: str,
        integration_id: str | None, scan_id: str,
    ) -> dict[str, int]:
        stats = {"added": 0, "updated": 0, "removed": 0, "reappeared": 0}
        if not keys:
            return stats

        existing_rows = await self._db.fetch(
            """SELECT id, key_identifier, is_active, normalised_data
               FROM keys_inventory
               WHERE project_id = $1 AND integration_id IS NOT DISTINCT FROM $2""",
            project_id, integration_id,
        )
        existing = {r["key_identifier"]: dict(r) for r in existing_rows}
        seen_ids: set[str] = set()

        for key in keys:
            kid = key.get("key_id") or key.get("name") or key.get("label") or ""
            if not kid:
                continue
            seen_ids.add(kid)

            key_name = key.get("name") or key.get("label") or kid
            key_type = key.get("key_type") or key.get("kty") or ""
            key_size = key.get("key_size")
            source_type = key.get("source_type") or "generic"
            expires_on = self._parse_dt(key.get("expires_on"))
            days_exp = self._compute_days_expiry(expires_on)
            is_hsm = bool(key.get("is_hardware_protected") or key.get("hsm_backed"))

            if kid in existing:
                rec = existing[kid]
                if not rec["is_active"]:
                    await self._db.execute(
                        """UPDATE keys_inventory
                           SET is_active=true, last_seen_at=NOW(),
                               normalised_data=$2::jsonb, key_name=$3,
                               key_type=$4, key_size=$5, source_type=$6,
                               expires_on=$7, days_until_expiry=$8,
                               is_hsm_backed=$9
                           WHERE id=$1""",
                        rec["id"], json.dumps(key), key_name, key_type,
                        key_size, source_type, expires_on, days_exp, is_hsm,
                    )
                    await self._record_change(
                        "key", kid, integration_id, project_id, "reappeared",
                    )
                    stats["reappeared"] += 1
                else:
                    await self._db.execute(
                        """UPDATE keys_inventory
                           SET last_seen_at=NOW(), normalised_data=$2::jsonb,
                               days_until_expiry=$3
                           WHERE id=$1""",
                        rec["id"], json.dumps(key), days_exp,
                    )
                    stats["updated"] += 1
            else:
                await self._db.execute(
                    """INSERT INTO keys_inventory
                       (project_id, key_identifier, integration_id,
                        normalised_data, key_name, key_type, key_size,
                        source_type, integration_name, expires_on,
                        days_until_expiry, is_hsm_backed)
                       VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,$10,$11,$12)""",
                    project_id, kid, integration_id,
                    json.dumps(key), key_name, key_type, key_size,
                    source_type, "Promoted Scans", expires_on,
                    days_exp, is_hsm,
                )
                await self._record_change(
                    "key", kid, integration_id, project_id, "added",
                )
                stats["added"] += 1

        for kid_key, rec in existing.items():
            if kid_key not in seen_ids and rec["is_active"]:
                await self._db.execute(
                    "UPDATE keys_inventory SET is_active=false WHERE id=$1",
                    rec["id"],
                )
                await self._record_change(
                    "key", kid_key, integration_id, project_id, "removed",
                )
                stats["removed"] += 1

        return stats

    # ── Internal helpers ──────────────────────────────────────

    async def _ensure_promoted_integration(self) -> str:
        """Get or create the 'Promoted Scans' CLM integration."""
        row = await self._db.fetchrow(
            "SELECT id FROM clm_integrations WHERE name = 'Promoted Scans'"
        )
        if row:
            return row["id"]
        return await self._db.fetchval(
            """INSERT INTO clm_integrations (name, type)
               VALUES ('Promoted Scans', 'promoted')
               RETURNING id"""
        )

    async def _record_change(
        self, entity_type: str, entity_id: str,
        integration_id: str | None, project_id: str,
        change_type: str, change_details: dict | None = None,
    ) -> None:
        await self._db.execute(
            """INSERT INTO inventory_changes
               (entity_type, entity_id, integration_id, project_id,
                change_type, change_details)
               VALUES ($1, $2, $3, $4, $5, $6::jsonb)""",
            entity_type, entity_id, integration_id, project_id,
            change_type, json.dumps(change_details or {}),
        )

    @staticmethod
    def _extract_fingerprint(cert: dict) -> str | None:
        return (cert.get("fingerprint_sha256")
                or cert.get("fingerprint")
                or cert.get("thumbprint"))

    @staticmethod
    def _extract_cn(cert: dict, field: str) -> str | None:
        """Extract CN from subject or issuer dict/string."""
        val = cert.get(f"{field}_cn")
        if val:
            return val
        subj = cert.get(field)
        if isinstance(subj, dict):
            return subj.get("commonName") or subj.get("CN")
        if isinstance(subj, str) and "CN=" in subj:
            for part in subj.split(","):
                part = part.strip()
                if part.startswith("CN="):
                    return part[3:]
        return None

    @staticmethod
    def _detect_cert_source(cert: dict) -> str:
        source = (cert.get("source") or cert.get("source_type") or "").lower()
        if "luna" in source or "hsm" in source:
            return "luna_hsm"
        if "azure" in source:
            return "azure_keyvault"
        if "ejbca" in source:
            return "ejbca"
        if "tls" in source:
            return "tls"
        if "crl" in source:
            return "crl"
        if "file" in source:
            return "file_share"
        return "promoted"

    @staticmethod
    def _compute_days_expiry(dt: datetime | None) -> int | None:
        if dt is None:
            return None
        now = datetime.now(timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (dt - now).days

    @staticmethod
    def _parse_dt(val: Any) -> datetime | None:
        if val is None:
            return None
        if isinstance(val, datetime):
            return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
        if isinstance(val, str):
            try:
                dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except ValueError:
                return None
        return None
