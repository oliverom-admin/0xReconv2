"""
RelationshipService — asset relationship graph management.

Manages asset_relationships table: cert-to-key, cert-to-cert chains,
issuer relationships with confidence scoring.
"""
from __future__ import annotations

import json
from typing import Any

import asyncpg
import structlog

logger = structlog.get_logger("recon.relationships")


class RelationshipService:
    def __init__(self, db: asyncpg.Connection) -> None:
        self._db = db

    async def create_relationship(
        self, project_id: str,
        source_id: str, source_type: str,
        target_id: str, target_type: str,
        relationship_type: str,
        confidence: float = 1.0,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Upsert a relationship between two assets."""
        row = await self._db.fetchrow(
            """INSERT INTO asset_relationships
               (project_id, source_id, source_type, target_id, target_type,
                relationship_type, confidence, evidence)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
               ON CONFLICT (project_id, source_id, target_id, relationship_type)
               DO UPDATE SET confidence = $7, evidence = $8::jsonb
               RETURNING *""",
            project_id, source_id, source_type,
            target_id, target_type, relationship_type,
            confidence, json.dumps(evidence or {}),
        )
        return dict(row)

    async def get_relationships(
        self, project_id: str,
        asset_id: str | None = None,
        relationship_type: str | None = None,
    ) -> list[dict]:
        """Fetch relationships for a project with optional filters."""
        conditions = ["project_id = $1"]
        params: list[Any] = [project_id]
        idx = 2

        if asset_id:
            conditions.append(f"(source_id = ${idx} OR target_id = ${idx})")
            params.append(asset_id)
            idx += 1

        if relationship_type:
            conditions.append(f"relationship_type = ${idx}")
            params.append(relationship_type)
            idx += 1

        where = " AND ".join(conditions)
        rows = await self._db.fetch(
            f"""SELECT * FROM asset_relationships
                WHERE {where}
                ORDER BY created_at DESC""",
            *params,
        )
        return [dict(r) for r in rows]

    async def calculate_dependency_level(
        self, project_id: str, asset_id: str,
    ) -> str:
        """Count relationships where this asset is a target and map to level."""
        count = await self._db.fetchval(
            """SELECT count(*) FROM asset_relationships
               WHERE project_id = $1 AND target_id = $2""",
            project_id, asset_id,
        ) or 0

        if count == 0:
            return "None"
        if count <= 2:
            return "Low (1-2)"
        if count <= 5:
            return "Medium (3-5)"
        return "High (6+)"

    async def infer_relationships_from_scan(
        self, project_id: str, scan_results_json: dict[str, Any],
    ) -> int:
        """Auto-detect relationships from scan results and existing inventory."""
        created = 0
        certs = scan_results_json.get("certificates", [])

        # Build lookup of subject_cn -> fingerprint from current inventory
        inv_rows = await self._db.fetch(
            """SELECT fingerprint_sha256, subject_cn, issuer_cn
               FROM certificates_inventory
               WHERE project_id = $1 AND is_active = true""",
            project_id,
        )
        cn_to_fp: dict[str, str] = {}
        for r in inv_rows:
            if r["subject_cn"]:
                cn_to_fp[r["subject_cn"]] = r["fingerprint_sha256"]

        # Check each cert's issuer_cn against inventory subject_cn
        for cert in certs:
            fp = cert.get("fingerprint_sha256", "")
            if isinstance(fp, str):
                fp = fp.lower().replace(":", "")
            issuer_cn = None
            issuer = cert.get("issuer")
            if isinstance(issuer, dict):
                issuer_cn = issuer.get("commonName") or issuer.get("CN")
            elif isinstance(issuer, str):
                issuer_cn = cert.get("issuer_cn", issuer)
            else:
                issuer_cn = cert.get("issuer_cn")

            if issuer_cn and issuer_cn in cn_to_fp:
                target_fp = cn_to_fp[issuer_cn]
                if target_fp != fp:  # Don't self-reference
                    await self.create_relationship(
                        project_id=project_id,
                        source_id=fp,
                        source_type="certificate",
                        target_id=target_fp,
                        target_type="certificate",
                        relationship_type="chains_to",
                        confidence=0.9,
                        evidence={"method": "issuer_cn_match",
                                  "issuer_cn": issuer_cn},
                    )
                    created += 1

        logger.info("relationships_inferred",
                    project_id=project_id, created=created)
        return created
