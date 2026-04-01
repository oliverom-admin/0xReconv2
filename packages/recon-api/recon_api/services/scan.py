"""
ScanService — scan lifecycle, job dispatch, status management.

Scan lifecycle:
  created → never_run → pending (on run) → running (worker) → complete | failed
"""
from __future__ import annotations

import json
from typing import Any

import asyncpg
import structlog

logger = structlog.get_logger("recon.scan")


class ScanService:
    def __init__(self, db: asyncpg.Connection) -> None:
        self._db = db

    async def create_scan(
        self, project_id: str, name: str, config_id: str | None,
        policy_id: str | None, assessment_type: str, created_by: str,
        description: str | None = None,
    ) -> dict[str, Any]:
        row = await self._db.fetchrow(
            """
            INSERT INTO scans
              (project_id, name, description, config_id, policy_id,
               assessment_type, created_by)
            VALUES ($1,$2,$3,$4,$5,$6,$7)
            RETURNING id, name, status, assessment_type, created_at
            """,
            project_id, name, description, config_id,
            policy_id, assessment_type, created_by,
        )
        return dict(row)

    async def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        row = await self._db.fetchrow("SELECT * FROM scans WHERE id = $1", scan_id)
        return dict(row) if row else None

    async def list_scans(self, project_id: str) -> list[dict]:
        rows = await self._db.fetch(
            "SELECT * FROM scans WHERE project_id = $1 ORDER BY created_at DESC",
            project_id,
        )
        return [dict(r) for r in rows]

    async def update_scan_status(self, scan_id: str, status: str) -> None:
        await self._db.execute(
            "UPDATE scans SET status=$2, updated_at=NOW() WHERE id=$1",
            scan_id, status,
        )

    async def delete_scan(self, scan_id: str) -> None:
        await self._db.execute("DELETE FROM scans WHERE id=$1", scan_id)

    async def dispatch_scan(self, scan_id: str, dispatched_by: str) -> str:
        scan = await self.get_scan(scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        config_payload: dict = {}
        policy_payload: dict = {}

        if scan["config_id"]:
            cfg_row = await self._db.fetchrow(
                "SELECT config FROM scan_configurations WHERE id=$1",
                scan["config_id"],
            )
            if cfg_row:
                val = cfg_row["config"]
                config_payload = val if isinstance(val, dict) else json.loads(val) if isinstance(val, str) else {}

        if scan["policy_id"]:
            pol_row = await self._db.fetchrow(
                "SELECT rules, schema_version FROM policies WHERE id=$1",
                scan["policy_id"],
            )
            if pol_row:
                policy_payload = {
                    "rules": list(pol_row["rules"]),
                    "schema_version": pol_row["schema_version"],
                }

        run_number = (scan.get("last_run_number") or 0) + 1

        job_payload = {
            "scan_id": scan_id,
            "scan_name": scan["name"],
            "project_id": scan["project_id"],
            "assessment_type": scan["assessment_type"],
            "config": config_payload,
            "policy": policy_payload,
            "run_number": run_number,
        }

        job_id = await self._db.fetchval(
            """
            INSERT INTO job_queue
              (job_type, status, project_id, payload, created_by, priority)
            VALUES ('scan_execute','pending',$1,$2::jsonb,$3,5)
            RETURNING id
            """,
            scan["project_id"],
            json.dumps(job_payload),
            dispatched_by,
        )

        await self._db.execute(
            "UPDATE scans SET status='pending', updated_at=NOW() WHERE id=$1",
            scan_id,
        )

        logger.info("scan_dispatched", scan_id=scan_id, job_id=job_id, run_number=run_number)
        return str(job_id)

    async def write_scan_results(
        self, scan_id: str, run_number: int, scan_results_json: dict,
        findings: list[dict], collector_stats: dict, job_id: str | None = None,
    ) -> None:
        cert_count = len(scan_results_json.get("certificates", []))
        key_count = len(scan_results_json.get("keys", []))

        await self._db.execute(
            """
            INSERT INTO scan_runs
              (scan_id, run_number, status, job_id, completed_at,
               certificates_found, keys_found, findings_count, collector_stats)
            VALUES ($1,$2,'complete',$3,NOW(),$4,$5,$6,$7::jsonb)
            """,
            scan_id, run_number, job_id, cert_count, key_count,
            len(findings), json.dumps(collector_stats),
        )

        for ctype, stats in collector_stats.items():
            await self._db.execute(
                """
                INSERT INTO scan_results
                  (scan_id, run_number, collector_type, result_blob,
                   certificates_count, keys_count)
                VALUES ($1,$2,$3,$4::jsonb,$5,$6)
                """,
                scan_id, run_number, ctype, json.dumps(stats),
                stats.get("total_certificates", 0), stats.get("total_keys", 0),
            )

        for f in findings:
            await self._db.execute(
                """
                INSERT INTO findings
                  (scan_id, run_number, rule_id, rule_name, severity,
                   risk_score, title, description, remediation, evidence,
                   compliance_impact, category, affected_asset_id, affected_asset_type)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13,$14)
                """,
                scan_id, run_number,
                f.get("rule_id", ""), f.get("rule_name", ""),
                f.get("severity", "info"), float(f.get("risk_score", 0.0)),
                f.get("title", ""), f.get("description"),
                f.get("remediation"), json.dumps(f.get("evidence", {})),
                f.get("compliance_impact"), f.get("category"),
                f.get("affected_asset_id"), f.get("affected_asset_type"),
            )

        await self._db.execute(
            """
            UPDATE scans SET status='complete', last_run_at=NOW(),
                last_run_number=$2, collector_results=$3::jsonb, updated_at=NOW()
            WHERE id=$1
            """,
            scan_id, run_number, json.dumps(collector_stats),
        )
        logger.info("scan_results_written", scan_id=scan_id,
                    certs=cert_count, keys=key_count, findings=len(findings))

    async def fail_scan(
        self, scan_id: str, run_number: int, error: str, job_id: str | None
    ) -> None:
        await self._db.execute(
            """
            INSERT INTO scan_runs
              (scan_id, run_number, status, job_id, completed_at, error_message)
            VALUES ($1,$2,'failed',$3,NOW(),$4)
            """,
            scan_id, run_number, job_id, error,
        )
        await self._db.execute(
            "UPDATE scans SET status='failed', updated_at=NOW() WHERE id=$1", scan_id,
        )

    async def list_findings(self, scan_id: str, run_number: int | None = None) -> list[dict]:
        if run_number:
            rows = await self._db.fetch(
                "SELECT * FROM findings WHERE scan_id=$1 AND run_number=$2 ORDER BY risk_score DESC",
                scan_id, run_number,
            )
        else:
            rows = await self._db.fetch(
                "SELECT * FROM findings WHERE scan_id=$1 ORDER BY risk_score DESC", scan_id,
            )
        return [dict(r) for r in rows]

    async def get_scan_logs(self, scan_id: str) -> list[dict]:
        rows = await self._db.fetch(
            "SELECT * FROM scan_logs WHERE scan_id=$1 ORDER BY created_at", scan_id,
        )
        return [dict(r) for r in rows]

    async def append_scan_log(
        self, scan_id: str, run_number: int, message: str, level: str = "info"
    ) -> None:
        await self._db.execute(
            "INSERT INTO scan_logs (scan_id, run_number, level, message) VALUES ($1,$2,$3,$4)",
            scan_id, run_number, level, message,
        )
