"""
ReportService — report record CRUD and file management.
"""
from __future__ import annotations

import json
from typing import Any

import asyncpg
import structlog

logger = structlog.get_logger("recon.report")


class ReportService:
    def __init__(self, db: asyncpg.Connection) -> None:
        self._db = db

    async def create_report(
        self, project_id: str, name: str, report_type: str,
        scan_id: str | None = None, created_by: str | None = None,
        format: str | None = None,
    ) -> dict[str, Any]:
        """Create a report record with status='pending'."""
        report_id = await self._db.fetchval(
            """INSERT INTO reports
               (project_id, scan_id, name, report_type, format, created_by)
               VALUES ($1, $2, $3, $4, $5, $6) RETURNING id""",
            project_id, scan_id, name, report_type, format, created_by,
        )
        # Create project_reports join
        await self._db.execute(
            """INSERT INTO project_reports (project_id, report_id)
               VALUES ($1, $2) ON CONFLICT DO NOTHING""",
            project_id, report_id,
        )
        row = await self._db.fetchrow(
            "SELECT * FROM reports WHERE id = $1", report_id,
        )
        return dict(row) if row else {"id": report_id}

    async def get_report(
        self, report_id: str, project_id: str,
    ) -> dict[str, Any] | None:
        row = await self._db.fetchrow(
            "SELECT * FROM reports WHERE id = $1 AND project_id = $2",
            report_id, project_id,
        )
        return dict(row) if row else None

    async def list_reports(
        self, project_id: str, report_type: str | None = None,
        status: str | None = None, limit: int = 50, offset: int = 0,
    ) -> list[dict]:
        conditions = ["project_id = $1"]
        params: list[Any] = [project_id]
        idx = 2

        if report_type:
            conditions.append(f"report_type = ${idx}")
            params.append(report_type)
            idx += 1
        if status:
            conditions.append(f"status = ${idx}")
            params.append(status)
            idx += 1

        where = " AND ".join(conditions)
        rows = await self._db.fetch(
            f"""SELECT * FROM reports WHERE {where}
                ORDER BY created_at DESC LIMIT {limit} OFFSET {offset}""",
            *params,
        )
        return [dict(r) for r in rows]

    async def update_report_status(
        self, report_id: str, status: str,
        error_message: str | None = None,
        file_path: str | None = None,
        file_size_bytes: int | None = None,
        generation_metadata: dict | None = None,
    ) -> dict[str, Any]:
        completed_clause = ""
        if status in ("complete", "failed"):
            completed_clause = ", completed_at = NOW()"

        await self._db.execute(
            f"""UPDATE reports
                SET status = $2, error_message = $3, file_path = $4,
                    file_size_bytes = $5,
                    generation_metadata = COALESCE($6::jsonb, generation_metadata),
                    updated_at = NOW(){completed_clause}
                WHERE id = $1""",
            report_id, status, error_message, file_path,
            file_size_bytes,
            json.dumps(generation_metadata) if generation_metadata else None,
        )
        row = await self._db.fetchrow(
            "SELECT * FROM reports WHERE id = $1", report_id,
        )
        return dict(row) if row else {}

    async def delete_report(
        self, report_id: str, project_id: str,
    ) -> bool:
        tag = await self._db.execute(
            """UPDATE reports SET status = 'deleted', updated_at = NOW()
               WHERE id = $1 AND project_id = $2 AND status != 'deleted'""",
            report_id, project_id,
        )
        return tag and tag.endswith("1")

    async def get_report_file_path(
        self, report_id: str, project_id: str,
    ) -> str | None:
        return await self._db.fetchval(
            """SELECT file_path FROM reports
               WHERE id = $1 AND project_id = $2 AND status = 'complete'""",
            report_id, project_id,
        )
