"""
AssetContextService — business context enrichment per asset.

Manages asset_context and asset_context_history tables.
Supports manual and auto-discovered context with confidence-based merge.
"""
from __future__ import annotations

import json
from typing import Any

import asyncpg
import structlog

logger = structlog.get_logger("recon.asset_context")

# Fields that can be set via upsert
CONTEXT_FIELDS = (
    "asset_name", "source", "business_unit", "business_function",
    "data_classification", "dependencies", "compliance_scope",
    "migration_path", "owner", "notes", "environment_type",
    "service_name", "application_name", "discovery_method",
    "discovery_confidence", "override_enabled", "override_score",
    "override_reason", "changed_by",
)


class AssetContextService:
    def __init__(self, db: asyncpg.Connection) -> None:
        self._db = db

    async def upsert_context(
        self, project_id: str, asset_id: str, asset_type: str,
        **fields: Any,
    ) -> dict[str, Any]:
        """Insert or update asset context. Writes history on update."""
        existing = await self.get_context(project_id, asset_id)

        if existing:
            # Record previous values in history before updating
            previous = {
                k: existing.get(k) for k in CONTEXT_FIELDS
                if k in fields and existing.get(k) != fields.get(k)
            }
            if previous:
                await self._db.execute(
                    """INSERT INTO asset_context_history
                       (context_id, project_id, asset_id, asset_type,
                        change_type, changed_by, previous_values)
                       VALUES ($1, $2, $3, $4, 'updated', $5, $6::jsonb)""",
                    existing["id"], project_id, asset_id, asset_type,
                    fields.get("changed_by"), json.dumps(previous),
                )

            # Build UPDATE SET clause for provided fields only
            sets = ["updated_at = NOW()"]
            params: list[Any] = []
            idx = 1
            for f in CONTEXT_FIELDS:
                if f in fields:
                    sets.append(f"{f} = ${idx}")
                    params.append(fields[f])
                    idx += 1
            params.append(existing["id"])

            await self._db.execute(
                f"UPDATE asset_context SET {', '.join(sets)} WHERE id = ${idx}",
                *params,
            )
            return await self.get_context(project_id, asset_id) or {}
        else:
            # Insert new context
            cols = ["project_id", "asset_id", "asset_type"]
            vals = [project_id, asset_id, asset_type]
            for f in CONTEXT_FIELDS:
                if f in fields and fields[f] is not None:
                    cols.append(f)
                    vals.append(fields[f])

            placeholders = ", ".join(f"${i+1}" for i in range(len(vals)))
            col_str = ", ".join(cols)
            ctx_id = await self._db.fetchval(
                f"""INSERT INTO asset_context ({col_str})
                    VALUES ({placeholders}) RETURNING id""",
                *vals,
            )

            # Record creation in history
            await self._db.execute(
                """INSERT INTO asset_context_history
                   (context_id, project_id, asset_id, asset_type,
                    change_type, changed_by)
                   VALUES ($1, $2, $3, $4, 'created', $5)""",
                ctx_id, project_id, asset_id, asset_type,
                fields.get("changed_by"),
            )

            return await self.get_context(project_id, asset_id) or {}

    async def get_context(
        self, project_id: str, asset_id: str,
    ) -> dict[str, Any] | None:
        """Fetch context for a single asset."""
        row = await self._db.fetchrow(
            """SELECT * FROM asset_context
               WHERE project_id = $1 AND asset_id = $2""",
            project_id, asset_id,
        )
        return dict(row) if row else None

    async def get_project_context(
        self, project_id: str, asset_type: str | None = None,
    ) -> list[dict]:
        """Fetch all context records for a project."""
        if asset_type:
            rows = await self._db.fetch(
                """SELECT * FROM asset_context
                   WHERE project_id = $1 AND asset_type = $2
                   ORDER BY asset_type, asset_name NULLS LAST""",
                project_id, asset_type,
            )
        else:
            rows = await self._db.fetch(
                """SELECT * FROM asset_context
                   WHERE project_id = $1
                   ORDER BY asset_type, asset_name NULLS LAST""",
                project_id,
            )
        return [dict(r) for r in rows]

    async def merge_auto_discovered(
        self, project_id: str, asset_id: str, asset_type: str,
        auto_metadata: dict[str, Any],
    ) -> bool:
        """
        Merge auto-discovered metadata into context.

        Confidence-based merge logic (ported from legacy):
        - Manual context (discovery_method='manual') is never overwritten
        - Auto-discovery only updates if new confidence > existing confidence
        - If no context exists, create it with auto-discovered data
        Returns True if context was created or updated.
        """
        existing = await self.get_context(project_id, asset_id)
        auto_confidence = auto_metadata.get("discovery_confidence", 0.5)

        if existing is None:
            # No context exists — create from auto-discovered data
            await self.upsert_context(
                project_id, asset_id, asset_type,
                environment_type=auto_metadata.get("environment_type"),
                service_name=auto_metadata.get("service_name"),
                application_name=auto_metadata.get("application_name"),
                discovery_method=auto_metadata.get("discovery_method", "auto"),
                discovery_confidence=auto_confidence,
                changed_by="auto-discovery",
            )
            return True

        # Manual context is never overwritten by auto-discovery
        if existing.get("discovery_method") == "manual":
            return False

        existing_confidence = existing.get("discovery_confidence") or 0.0

        # Only update if auto confidence is higher
        if auto_confidence <= existing_confidence:
            return False

        updates: dict[str, Any] = {}
        merge_fields = ["environment_type", "service_name", "application_name"]
        for field in merge_fields:
            auto_val = auto_metadata.get(field)
            existing_val = existing.get(field)
            if auto_val and (not existing_val or auto_confidence > existing_confidence):
                updates[field] = auto_val

        if not updates:
            return False

        updates["discovery_confidence"] = auto_confidence
        updates["discovery_method"] = auto_metadata.get("discovery_method", "auto")
        updates["changed_by"] = "auto-discovery"

        await self.upsert_context(project_id, asset_id, asset_type, **updates)
        return True

    async def get_context_statistics(self, project_id: str) -> dict[str, Any]:
        """Return enrichment statistics for a project."""
        total = await self._db.fetchval(
            "SELECT count(*) FROM asset_context WHERE project_id = $1",
            project_id,
        ) or 0

        env_rows = await self._db.fetch(
            """SELECT environment_type, count(*) AS cnt
               FROM asset_context WHERE project_id = $1
               GROUP BY environment_type""",
            project_id,
        )
        by_environment = {r["environment_type"] or "unknown": r["cnt"]
                          for r in env_rows}

        # Count total inventory items for coverage calculation
        cert_count = await self._db.fetchval(
            """SELECT count(*) FROM certificates_inventory
               WHERE project_id = $1 AND is_active = true""",
            project_id,
        ) or 0
        key_count = await self._db.fetchval(
            """SELECT count(*) FROM keys_inventory
               WHERE project_id = $1 AND is_active = true""",
            project_id,
        ) or 0
        total_inventory = cert_count + key_count
        coverage = (total / total_inventory * 100) if total_inventory > 0 else 0.0

        return {
            "total_with_context": total,
            "total_inventory_items": total_inventory,
            "coverage_percent": round(coverage, 1),
            "by_environment": by_environment,
        }

    async def delete_context(
        self, project_id: str, asset_id: str, changed_by: str,
    ) -> dict[str, bool]:
        """Delete context with audit trail."""
        existing = await self.get_context(project_id, asset_id)
        if not existing:
            return {"deleted": False}

        # Write deletion to history
        await self._db.execute(
            """INSERT INTO asset_context_history
               (context_id, project_id, asset_id, asset_type,
                change_type, changed_by, previous_values)
               VALUES ($1, $2, $3, $4, 'deleted', $5, $6::jsonb)""",
            existing["id"], project_id, asset_id,
            existing.get("asset_type", "unknown"),
            changed_by, json.dumps({k: existing.get(k) for k in CONTEXT_FIELDS}),
        )

        await self._db.execute(
            "DELETE FROM asset_context WHERE id = $1", existing["id"],
        )
        return {"deleted": True}
