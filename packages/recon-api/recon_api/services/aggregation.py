"""
AggregationService — merge multiple scan results into a combined view.

Merge strategies: union | intersection | weighted
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import asyncpg
import structlog

logger = structlog.get_logger("recon.aggregation")

VALID_STRATEGIES = ("union", "intersection", "weighted")


class AggregationService:
    def __init__(self, db: asyncpg.Connection) -> None:
        self._db = db

    async def create_aggregation(
        self, project_id: str, name: str,
        source_scan_ids: list[str],
        merge_strategy: str = "union",
        created_by: str | None = None,
    ) -> dict[str, Any]:
        """Create an aggregation record and dispatch a worker job."""
        if len(source_scan_ids) < 2:
            raise ValueError("At least 2 scan IDs are required for aggregation")
        if merge_strategy not in VALID_STRATEGIES:
            raise ValueError(
                f"Invalid merge strategy: {merge_strategy}. "
                f"Must be one of: {', '.join(VALID_STRATEGIES)}"
            )

        # Validate all scans
        for sid in source_scan_ids:
            scan = await self._db.fetchrow(
                "SELECT id, project_id, status FROM scans WHERE id = $1", sid,
            )
            if not scan:
                raise ValueError(f"Scan {sid} not found")
            if scan["project_id"] != project_id:
                raise ValueError(f"Scan {sid} does not belong to this project")
            if scan["status"] != "complete":
                raise ValueError(f"Scan {sid} is not complete")

        # Create report record
        report_id = await self._db.fetchval(
            """INSERT INTO reports
               (project_id, name, report_type, format, created_by)
               VALUES ($1, $2, 'aggregation', 'json', $3)
               RETURNING id""",
            project_id, name, created_by,
        )
        await self._db.execute(
            """INSERT INTO project_reports (project_id, report_id)
               VALUES ($1, $2) ON CONFLICT DO NOTHING""",
            project_id, report_id,
        )

        # Create aggregation record
        agg_id = await self._db.fetchval(
            """INSERT INTO report_aggregations
               (project_id, name, merge_strategy, source_scan_ids,
                output_report_id, created_by)
               VALUES ($1, $2, $3, $4::jsonb, $5, $6)
               RETURNING id""",
            project_id, name, merge_strategy,
            json.dumps(source_scan_ids), report_id, created_by,
        )

        # Dispatch worker job
        await self._db.execute(
            """INSERT INTO job_queue
               (job_type, status, project_id, payload, created_by, priority)
               VALUES ('aggregation_execute', 'pending', $1, $2::jsonb, $3, 5)""",
            project_id,
            json.dumps({"aggregation_id": agg_id, "project_id": project_id}),
            created_by,
        )

        row = await self._db.fetchrow(
            "SELECT * FROM report_aggregations WHERE id = $1", agg_id,
        )
        return dict(row) if row else {"id": agg_id}

    async def get_aggregation(
        self, aggregation_id: str, project_id: str,
    ) -> dict[str, Any] | None:
        row = await self._db.fetchrow(
            """SELECT * FROM report_aggregations
               WHERE id = $1 AND project_id = $2""",
            aggregation_id, project_id,
        )
        return dict(row) if row else None

    async def list_aggregations(
        self, project_id: str, status: str | None = None,
        limit: int = 50, offset: int = 0,
    ) -> list[dict]:
        if status:
            rows = await self._db.fetch(
                """SELECT * FROM report_aggregations
                   WHERE project_id = $1 AND status = $2
                   ORDER BY created_at DESC LIMIT $3 OFFSET $4""",
                project_id, status, limit, offset,
            )
        else:
            rows = await self._db.fetch(
                """SELECT * FROM report_aggregations
                   WHERE project_id = $1
                   ORDER BY created_at DESC LIMIT $2 OFFSET $3""",
                project_id, limit, offset,
            )
        return [dict(r) for r in rows]

    async def execute_aggregation(self, aggregation_id: str) -> dict[str, Any]:
        """Execute an aggregation — called by the worker."""
        rec = await self._db.fetchrow(
            "SELECT * FROM report_aggregations WHERE id = $1",
            aggregation_id,
        )
        if not rec:
            return {"error": f"Aggregation {aggregation_id} not found"}

        try:
            await self._db.execute(
                """UPDATE report_aggregations
                   SET status = 'running', updated_at = NOW() WHERE id = $1""",
                aggregation_id,
            )

            scan_ids = rec["source_scan_ids"]
            if isinstance(scan_ids, str):
                scan_ids = json.loads(scan_ids)
            strategy = rec["merge_strategy"]

            # Load all scan results
            scan_results_list: list[dict] = []
            scan_names: list[str] = []
            for sid in scan_ids:
                certs, keys = await self._load_scan_data(sid)
                scan_results_list.append({"certificates": certs, "keys": keys})
                name_row = await self._db.fetchrow(
                    "SELECT name FROM scans WHERE id = $1", sid,
                )
                scan_names.append(name_row["name"] if name_row else sid)

            # Merge per strategy
            if strategy == "intersection":
                merged_certs, merged_keys = self._merge_intersection(scan_results_list)
            elif strategy == "weighted":
                merged_certs, merged_keys = self._merge_weighted(scan_results_list)
            else:
                merged_certs, merged_keys = self._merge_union(scan_results_list)

            # Load project policy (if any)
            policy_row = await self._db.fetchrow(
                """SELECT rules, schema_version FROM policies
                   WHERE project_id = $1 ORDER BY created_at DESC LIMIT 1""",
                rec["project_id"],
            )
            policy_data: dict = {}
            if policy_row and policy_row["rules"]:
                rules = policy_row["rules"]
                if isinstance(rules, str):
                    rules = json.loads(rules)
                policy_data = {"rules": list(rules)}

            # Assess
            from recon_api.services.policy import UnifiedAssessor
            findings: list[dict] = []
            assessor = UnifiedAssessor()
            if policy_data.get("rules") and assessor.load_policy(policy_data):
                for cert in merged_certs:
                    for r in assessor.assess_certificate(cert):
                        if r.triggered:
                            findings.append(r.to_dict())
                for key in merged_keys:
                    for r in assessor.assess_key(key):
                        if r.triggered:
                            findings.append(r.to_dict())

            # Score
            from recon_core.scoring import ScoringEngine, AggregationEngine
            scored = [
                ScoringEngine.score_finding(
                    finding_id=f.get("rule_id", ""),
                    severity=f.get("severity", "info"),
                    title=f.get("title", ""),
                )
                for f in findings
            ]
            total_assets = len(merged_certs) + len(merged_keys)
            agg_score = AggregationEngine.aggregate(scored, total_assets=total_assets)

            findings_by_severity: dict[str, int] = {}
            for f in findings:
                sev = (f.get("severity") or "info").lower()
                findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1

            # Count unique
            unique_certs = len({
                (c.get("fingerprint_sha256") or "").lower().replace(":", "")
                for c in merged_certs
                if c.get("fingerprint_sha256")
            })
            unique_keys = len({
                c.get("key_id") or c.get("name") or ""
                for c in merged_keys
                if c.get("key_id") or c.get("name")
            })

            result_summary = {
                "total_certificates": len(merged_certs),
                "total_keys": len(merged_keys),
                "unique_certificates": unique_certs,
                "unique_keys": unique_keys,
                "source_scan_count": len(scan_ids),
                "merge_strategy": strategy,
                "total_findings": len(findings),
                "findings_by_severity": findings_by_severity,
                "health_score": agg_score.health_index,
                "grade": agg_score.grade,
                "source_scan_names": scan_names,
            }

            await self._db.execute(
                """UPDATE report_aggregations
                   SET status = 'complete', result_summary = $2::jsonb,
                       completed_at = NOW(), updated_at = NOW()
                   WHERE id = $1""",
                aggregation_id, json.dumps(result_summary),
            )
            if rec.get("output_report_id"):
                await self._db.execute(
                    """UPDATE reports SET status = 'complete',
                       completed_at = NOW(), updated_at = NOW(),
                       generation_metadata = $2::jsonb
                       WHERE id = $1""",
                    rec["output_report_id"], json.dumps(result_summary),
                )

            logger.info("aggregation_complete",
                        aggregation_id=aggregation_id,
                        strategy=strategy, certs=len(merged_certs))
            return result_summary

        except Exception as exc:
            error_msg = str(exc)
            logger.error("aggregation_failed",
                         aggregation_id=aggregation_id, error=error_msg)
            await self._db.execute(
                """UPDATE report_aggregations
                   SET status = 'failed', error_message = $2,
                       completed_at = NOW(), updated_at = NOW()
                   WHERE id = $1""",
                aggregation_id, error_msg,
            )
            if rec.get("output_report_id"):
                await self._db.execute(
                    """UPDATE reports SET status = 'failed',
                       error_message = $2, completed_at = NOW()
                       WHERE id = $1""",
                    rec["output_report_id"], error_msg,
                )
            return {"error": error_msg}

    async def get_aggregation_result(
        self, aggregation_id: str, project_id: str,
    ) -> dict[str, Any] | None:
        row = await self._db.fetchrow(
            """SELECT * FROM report_aggregations
               WHERE id = $1 AND project_id = $2 AND status = 'complete'""",
            aggregation_id, project_id,
        )
        return dict(row) if row else None

    # ── Merge strategies ──────────────────────────────────────

    @staticmethod
    def _merge_union(
        scan_results_list: list[dict],
    ) -> tuple[list[dict], list[dict]]:
        """All unique certs/keys across all scans."""
        cert_map: dict[str, dict] = {}
        key_map: dict[str, dict] = {}
        for sr in scan_results_list:
            for c in sr.get("certificates", []):
                fp = (c.get("fingerprint_sha256") or "").lower().replace(":", "")
                if fp and fp not in cert_map:
                    cert_map[fp] = c
            for k in sr.get("keys", []):
                kid = k.get("key_id") or k.get("name") or ""
                if kid and kid not in key_map:
                    key_map[kid] = k
        return list(cert_map.values()), list(key_map.values())

    @staticmethod
    def _merge_intersection(
        scan_results_list: list[dict],
    ) -> tuple[list[dict], list[dict]]:
        """Only certs/keys present in ALL scans."""
        if not scan_results_list:
            return [], []

        # Build fingerprint sets per scan
        cert_sets: list[set[str]] = []
        key_sets: list[set[str]] = []
        cert_data: dict[str, dict] = {}
        key_data: dict[str, dict] = {}

        for sr in scan_results_list:
            fps = set()
            for c in sr.get("certificates", []):
                fp = (c.get("fingerprint_sha256") or "").lower().replace(":", "")
                if fp:
                    fps.add(fp)
                    cert_data[fp] = c
            cert_sets.append(fps)

            kids = set()
            for k in sr.get("keys", []):
                kid = k.get("key_id") or k.get("name") or ""
                if kid:
                    kids.add(kid)
                    key_data[kid] = k
            key_sets.append(kids)

        common_certs = cert_sets[0]
        for s in cert_sets[1:]:
            common_certs = common_certs & s

        common_keys = key_sets[0]
        for s in key_sets[1:]:
            common_keys = common_keys & s

        return (
            [cert_data[fp] for fp in common_certs if fp in cert_data],
            [key_data[kid] for kid in common_keys if kid in key_data],
        )

    @staticmethod
    def _merge_weighted(
        scan_results_list: list[dict],
    ) -> tuple[list[dict], list[dict]]:
        """Union with occurrence count annotation."""
        cert_counts: dict[str, int] = {}
        key_counts: dict[str, int] = {}
        cert_data: dict[str, dict] = {}
        key_data: dict[str, dict] = {}
        total_scans = len(scan_results_list)

        for sr in scan_results_list:
            for c in sr.get("certificates", []):
                fp = (c.get("fingerprint_sha256") or "").lower().replace(":", "")
                if fp:
                    cert_counts[fp] = cert_counts.get(fp, 0) + 1
                    cert_data[fp] = c
            for k in sr.get("keys", []):
                kid = k.get("key_id") or k.get("name") or ""
                if kid:
                    key_counts[kid] = key_counts.get(kid, 0) + 1
                    key_data[kid] = k

        certs = []
        for fp, data in cert_data.items():
            data["scan_occurrence_count"] = cert_counts.get(fp, 0)
            data["scan_occurrence_pct"] = round(
                cert_counts.get(fp, 0) / max(total_scans, 1) * 100, 1
            )
            certs.append(data)

        keys_out = []
        for kid, data in key_data.items():
            data["scan_occurrence_count"] = key_counts.get(kid, 0)
            data["scan_occurrence_pct"] = round(
                key_counts.get(kid, 0) / max(total_scans, 1) * 100, 1
            )
            keys_out.append(data)

        return certs, keys_out

    # ── Helpers ───────────────────────────────────────────────

    async def _load_scan_data(
        self, scan_id: str,
    ) -> tuple[list[dict], list[dict]]:
        """Load certificates and keys from scan_results for a scan."""
        rows = await self._db.fetch(
            "SELECT result_blob FROM scan_results WHERE scan_id = $1",
            scan_id,
        )
        certificates: list[dict] = []
        keys: list[dict] = []
        for row in rows:
            blob = row["result_blob"]
            if isinstance(blob, str):
                blob = json.loads(blob)
            if isinstance(blob, dict):
                certificates.extend(blob.get("certificates", []))
                keys.extend(blob.get("keys", []))

        # Fallback to scan_runs collector_stats
        if not certificates and not keys:
            run_row = await self._db.fetchrow(
                """SELECT collector_stats FROM scan_runs
                   WHERE scan_id = $1 ORDER BY run_number DESC LIMIT 1""",
                scan_id,
            )
            if run_row and run_row["collector_stats"]:
                stats = run_row["collector_stats"]
                if isinstance(stats, str):
                    stats = json.loads(stats)
                for cdata in stats.values():
                    if isinstance(cdata, dict):
                        certificates.extend(cdata.get("certificates", []))
                        keys.extend(cdata.get("keys", []))

        return certificates, keys
