"""
ReassessmentService — re-run historical scan results through a different policy.

No collector execution — just re-evaluation of existing data with a new policy.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import asyncpg
import structlog

logger = structlog.get_logger("recon.reassessment")


class ReassessmentService:
    def __init__(self, db: asyncpg.Connection) -> None:
        self._db = db

    async def create_reassessment(
        self, project_id: str, name: str,
        original_scan_id: str, policy_id: str,
        created_by: str | None = None,
    ) -> dict[str, Any]:
        """Create a reassessment record and dispatch a worker job."""
        # Validate scan belongs to project and is complete
        scan = await self._db.fetchrow(
            "SELECT id, project_id, name, status FROM scans WHERE id = $1",
            original_scan_id,
        )
        if not scan:
            raise ValueError("Scan not found")
        if scan["project_id"] != project_id:
            raise ValueError("Scan does not belong to this project")
        if scan["status"] != "complete":
            raise ValueError("Scan is not complete — cannot reassess")

        # Validate policy exists
        policy = await self._db.fetchrow(
            "SELECT id, name FROM policies WHERE id = $1", policy_id,
        )
        if not policy:
            raise ValueError("Policy not found")

        # Create report record
        report_id = await self._db.fetchval(
            """INSERT INTO reports
               (project_id, scan_id, name, report_type, format, created_by)
               VALUES ($1, $2, $3, 'reassessment', 'json', $4)
               RETURNING id""",
            project_id, original_scan_id, name, created_by,
        )
        await self._db.execute(
            """INSERT INTO project_reports (project_id, report_id)
               VALUES ($1, $2) ON CONFLICT DO NOTHING""",
            project_id, report_id,
        )

        # Create reassessment record
        reassessment_id = await self._db.fetchval(
            """INSERT INTO report_reassessments
               (project_id, name, original_scan_id, policy_id,
                output_report_id, created_by)
               VALUES ($1, $2, $3, $4, $5, $6)
               RETURNING id""",
            project_id, name, original_scan_id, policy_id,
            report_id, created_by,
        )

        # Dispatch worker job
        await self._db.execute(
            """INSERT INTO job_queue
               (job_type, status, project_id, payload, created_by, priority)
               VALUES ('reassessment_execute', 'pending', $1, $2::jsonb, $3, 5)""",
            project_id,
            json.dumps({"reassessment_id": reassessment_id, "project_id": project_id}),
            created_by,
        )

        row = await self._db.fetchrow(
            "SELECT * FROM report_reassessments WHERE id = $1",
            reassessment_id,
        )
        return dict(row) if row else {"id": reassessment_id}

    async def get_reassessment(
        self, reassessment_id: str, project_id: str,
    ) -> dict[str, Any] | None:
        row = await self._db.fetchrow(
            """SELECT * FROM report_reassessments
               WHERE id = $1 AND project_id = $2""",
            reassessment_id, project_id,
        )
        return dict(row) if row else None

    async def list_reassessments(
        self, project_id: str, status: str | None = None,
        limit: int = 50, offset: int = 0,
    ) -> list[dict]:
        if status:
            rows = await self._db.fetch(
                """SELECT * FROM report_reassessments
                   WHERE project_id = $1 AND status = $2
                   ORDER BY created_at DESC LIMIT $3 OFFSET $4""",
                project_id, status, limit, offset,
            )
        else:
            rows = await self._db.fetch(
                """SELECT * FROM report_reassessments
                   WHERE project_id = $1
                   ORDER BY created_at DESC LIMIT $2 OFFSET $3""",
                project_id, limit, offset,
            )
        return [dict(r) for r in rows]

    async def execute_reassessment(self, reassessment_id: str) -> dict[str, Any]:
        """Execute a reassessment — called by the worker."""
        rec = await self._db.fetchrow(
            "SELECT * FROM report_reassessments WHERE id = $1",
            reassessment_id,
        )
        if not rec:
            return {"error": f"Reassessment {reassessment_id} not found"}

        try:
            # Set running
            await self._db.execute(
                """UPDATE report_reassessments
                   SET status = 'running', updated_at = NOW() WHERE id = $1""",
                reassessment_id,
            )

            # Load original scan results
            scan_rows = await self._db.fetch(
                "SELECT collector_type, result_blob FROM scan_results WHERE scan_id = $1",
                rec["original_scan_id"],
            )
            certificates: list[dict] = []
            keys: list[dict] = []
            for sr in scan_rows:
                blob = sr["result_blob"]
                if isinstance(blob, str):
                    blob = json.loads(blob)
                if isinstance(blob, dict):
                    certificates.extend(blob.get("certificates", []))
                    keys.extend(blob.get("keys", []))

            # If no scan_results, try scan_runs collector_stats
            if not certificates and not keys:
                run_row = await self._db.fetchrow(
                    """SELECT collector_stats FROM scan_runs
                       WHERE scan_id = $1 ORDER BY run_number DESC LIMIT 1""",
                    rec["original_scan_id"],
                )
                if run_row and run_row["collector_stats"]:
                    stats = run_row["collector_stats"]
                    if isinstance(stats, str):
                        stats = json.loads(stats)
                    for cdata in stats.values():
                        if isinstance(cdata, dict):
                            certificates.extend(cdata.get("certificates", []))
                            keys.extend(cdata.get("keys", []))

            # Load target policy
            policy_row = await self._db.fetchrow(
                "SELECT id, name, rules, schema_version FROM policies WHERE id = $1",
                rec["policy_id"],
            )
            policy_name = policy_row["name"] if policy_row else "Unknown"
            policy_data = {}
            if policy_row:
                rules = policy_row["rules"]
                if isinstance(rules, str):
                    rules = json.loads(rules)
                policy_data = {
                    "rules": list(rules) if rules else [],
                    "schema_version": policy_row.get("schema_version"),
                }

            # Capture enrichment snapshot
            enrichment: dict[str, Any] = {}
            for cert in certificates:
                fp = (cert.get("fingerprint_sha256") or "").lower().replace(":", "")
                if fp:
                    ctx = await self._db.fetchrow(
                        """SELECT * FROM asset_context
                           WHERE project_id = $1 AND asset_id = $2""",
                        rec["project_id"], fp,
                    )
                    if ctx:
                        enrichment[fp] = dict(ctx)

            await self._db.execute(
                """UPDATE report_reassessments
                   SET enrichment_snapshot = $2::jsonb WHERE id = $1""",
                reassessment_id, json.dumps(enrichment),
            )

            # Run UnifiedAssessor
            from recon_api.services.policy import UnifiedAssessor
            assessor = UnifiedAssessor()
            findings: list[dict] = []
            if assessor.load_policy(policy_data):
                for cert in certificates:
                    for r in assessor.assess_certificate(cert):
                        if r.triggered:
                            findings.append(r.to_dict())
                for key in keys:
                    for r in assessor.assess_key(key):
                        if r.triggered:
                            findings.append(r.to_dict())

            # Score
            from recon_core.scoring import ScoringEngine, AggregationEngine
            scored = []
            for f in findings:
                scored.append(ScoringEngine.score_finding(
                    finding_id=f.get("rule_id", ""),
                    severity=f.get("severity", "info"),
                    title=f.get("title", ""),
                ))
            total_assets = len(certificates) + len(keys)
            agg = AggregationEngine.aggregate(scored, total_assets=total_assets)

            # Get original scan name
            scan_name_row = await self._db.fetchrow(
                "SELECT name FROM scans WHERE id = $1", rec["original_scan_id"],
            )

            # Build result summary
            findings_by_severity: dict[str, int] = {}
            for f in findings:
                sev = (f.get("severity") or "info").lower()
                findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1

            result_summary = {
                "total_certificates": len(certificates),
                "total_keys": len(keys),
                "total_findings": len(findings),
                "findings_by_severity": findings_by_severity,
                "health_score": agg.health_index,
                "grade": agg.grade,
                "policy_name": policy_name,
                "policy_version": policy_data.get("schema_version"),
                "original_scan_name": scan_name_row["name"] if scan_name_row else None,
            }

            # Update records
            await self._db.execute(
                """UPDATE report_reassessments
                   SET status = 'complete', result_summary = $2::jsonb,
                       completed_at = NOW(), updated_at = NOW()
                   WHERE id = $1""",
                reassessment_id, json.dumps(result_summary),
            )
            if rec.get("output_report_id"):
                await self._db.execute(
                    """UPDATE reports SET status = 'complete',
                       completed_at = NOW(), updated_at = NOW(),
                       generation_metadata = $2::jsonb
                       WHERE id = $1""",
                    rec["output_report_id"], json.dumps(result_summary),
                )

            logger.info("reassessment_complete",
                        reassessment_id=reassessment_id,
                        findings=len(findings), grade=agg.grade)
            return result_summary

        except Exception as exc:
            error_msg = str(exc)
            logger.error("reassessment_failed",
                         reassessment_id=reassessment_id, error=error_msg)
            await self._db.execute(
                """UPDATE report_reassessments
                   SET status = 'failed', error_message = $2,
                       completed_at = NOW(), updated_at = NOW()
                   WHERE id = $1""",
                reassessment_id, error_msg,
            )
            if rec.get("output_report_id"):
                await self._db.execute(
                    """UPDATE reports SET status = 'failed',
                       error_message = $2, completed_at = NOW()
                       WHERE id = $1""",
                    rec["output_report_id"], error_msg,
                )
            return {"error": error_msg}

    async def get_reassessment_result(
        self, reassessment_id: str, project_id: str,
    ) -> dict[str, Any] | None:
        row = await self._db.fetchrow(
            """SELECT * FROM report_reassessments
               WHERE id = $1 AND project_id = $2 AND status = 'complete'""",
            reassessment_id, project_id,
        )
        return dict(row) if row else None
