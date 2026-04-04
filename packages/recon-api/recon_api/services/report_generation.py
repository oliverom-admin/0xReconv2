"""
ReportGenerationService — full encrypted HTML report pipeline.

Steps: load scan data → assess → score → encrypt → sign → render template → write file
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import asyncpg
import jinja2
import structlog

logger = structlog.get_logger("recon.report_generation")


class ReportGenerationService:
    def __init__(self, db: asyncpg.Connection) -> None:
        self._db = db

    async def generate_html_report(
        self,
        report_id: str,
        project_id: str,
        scan_id: str,
        report_type: str,
        recipient_user_ids: list[str],
        signed_by_user_id: str | None = None,
    ) -> dict[str, Any]:
        """Generate a full encrypted HTML report."""
        from recon_api.services.certificate import CertificateService
        from recon_api.services.report import ReportService
        from recon_api.services.report_crypto import ReportCryptoService
        from recon_api.services.vault import VaultService

        vault = VaultService(
            os.environ.get("RECON_VAULT_PATH", "/app/data/vault.enc"),
            os.environ.get("RECON_VAULT_MASTER_PASSWORD", ""),
        )
        await vault.initialize()

        report_svc = ReportService(self._db)
        cert_svc = CertificateService(self._db, vault)
        crypto_svc = ReportCryptoService(self._db)

        try:
            # Update report status to generating
            await report_svc.update_report_status(report_id, "generating")

            # Load scan metadata
            scan = await self._db.fetchrow(
                "SELECT * FROM scans WHERE id = $1", scan_id,
            )
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            project = await self._db.fetchrow(
                "SELECT name FROM projects WHERE id = $1", project_id,
            )
            report_name = scan.get("name") or f"Scan {scan_id[:8]}"

            # Build report data
            report_data = await self._build_report_data(scan_id, project_id)
            report_data["metadata"]["report_name"] = report_name
            report_data["metadata"]["report_type"] = report_type

            # Financial analysis
            from recon_api.services.financial import ReportFinancialCalculator
            try:
                calc = ReportFinancialCalculator({
                    "certificates": report_data.get("certificates", []),
                    "keys": report_data.get("keys", []),
                    "findings": report_data.get("findings", []),
                })
                report_data["financial"] = calc.get_financial_summary()
            except Exception as fin_exc:
                logger.warning("financial_calc_failed", error=str(fin_exc))
                report_data["financial"] = None

            # Issue viewer certs and generate P12s for recipients
            p12_results: dict[str, dict] = {}
            for uid in recipient_user_ids:
                try:
                    await cert_svc.issue_report_viewer_cert(
                        project_id=project_id,
                        user_id=uid,
                        report_type=report_type,
                        report_id=report_id,
                        report_name=report_name,
                    )
                    p12 = await cert_svc.generate_p12(uid, project_id)
                    p12_results[p12["username"]] = {
                        "p12_password": p12["p12_password"],
                        "expires_at": p12["expires_at"],
                    }
                except (ValueError, RuntimeError) as exc:
                    logger.warning("viewer_cert_failed",
                                   user_id=uid, error=str(exc))

            # Encrypt report data
            encrypted_blobs = None
            signing_result = None
            encryption_metadata = None

            if recipient_user_ids:
                encrypted_blobs = await crypto_svc.encrypt_report_data(
                    report_data=report_data,
                    recipient_user_ids=recipient_user_ids,
                    project_id=project_id,
                )
                signing_result = await crypto_svc.sign_encrypted_blob(
                    encrypted_blobs=encrypted_blobs,
                    project_id=project_id,
                    report_id=report_id,
                    report_type=report_type,
                    signed_by_user_id=signed_by_user_id or "",
                )
                encryption_metadata = {
                    "encryption_algorithm": "AES-256-GCM",
                    "key_wrapping_algorithm": "RSA-OAEP-SHA256",
                    "signing_algorithm": "RSA-PSS-SHA256",
                    "recipients": list(encrypted_blobs.keys()),
                    "report_id": report_id,
                    "report_type": report_type,
                    "encrypted_at": datetime.now(timezone.utc).isoformat(),
                }

            # Load forge.js
            forge_js = self._load_forge_js()

            # Determine template
            template_name = "pki_report.html"
            if report_type == "pqc_html":
                template_name = "pqc_report.html"

            # Build template context
            report_data_json = None
            if not recipient_user_ids:
                report_data_json = json.dumps(report_data)

            context = {
                "report_data": report_data_json,
                "encrypted_blobs": (
                    json.dumps(encrypted_blobs) if encrypted_blobs else None
                ),
                "encryption_metadata": (
                    json.dumps(encryption_metadata) if encryption_metadata else None
                ),
                "signing_result": signing_result,
                "forge_js_content": forge_js,
                "product_name": os.environ.get("PRODUCT_NAME", "0xRecon"),
            }

            # Render template
            html = self._render_template(template_name, context)

            # Write to file
            report_dir = Path(f"/app/reports/{project_id}")
            report_dir.mkdir(parents=True, exist_ok=True)
            file_path = str(report_dir / f"{report_id}.html")
            Path(file_path).write_text(html, encoding="utf-8")
            file_size = Path(file_path).stat().st_size

            # Update report record
            gen_metadata = {
                "recipients": list(p12_results.keys()),
                "encrypted": bool(encrypted_blobs),
                "signed": bool(signing_result),
                "template": template_name,
                "file_size_bytes": file_size,
            }
            await report_svc.update_report_status(
                report_id, "complete",
                file_path=file_path,
                file_size_bytes=file_size,
                generation_metadata=gen_metadata,
            )
            # Mark encrypted and signed
            if encrypted_blobs:
                await self._db.execute(
                    """UPDATE reports SET is_encrypted=true, is_signed=true
                       WHERE id=$1""",
                    report_id,
                )

            logger.info("report_generated",
                        report_id=report_id, size=file_size,
                        recipients=len(p12_results))

            return {
                "report_id": report_id,
                "file_path": file_path,
                "file_size_bytes": file_size,
                "p12_credentials": p12_results,
                "status": "complete",
            }

        except Exception as exc:
            logger.error("report_generation_failed",
                         report_id=report_id, error=str(exc))
            await report_svc.update_report_status(
                report_id, "failed", error_message=str(exc),
            )
            raise

    async def _build_report_data(
        self, scan_id: str, project_id: str,
    ) -> dict[str, Any]:
        """
        Build the report_data dict read by the JavaScript dashboard.

        Key naming must match exactly what the JS reads — see pki_report.html
        and pqc_report.html for the exact field names accessed.
        """
        from recon_core.scoring import ScoringEngine, AggregationEngine

        # ── 1. Load scan record ───────────────────────────────
        scan = await self._db.fetchrow(
            """SELECT s.id, s.name, s.project_id, s.assessment_type,
                      s.last_run_at, s.policy_id, s.collector_results,
                      p.name as project_name
               FROM scans s
               JOIN projects p ON p.id = s.project_id
               WHERE s.id = $1 AND s.project_id = $2""",
            scan_id, project_id,
        )
        if not scan:
            raise ValueError(f"Scan {scan_id} not found in project {project_id}")

        # ── 2. Load scan_results blobs ────────────────────────
        result_rows = await self._db.fetch(
            """SELECT collector_type, result_blob, certificates_count, keys_count
               FROM scan_results WHERE scan_id = $1""",
            scan_id,
        )

        certificates: list[dict] = []
        keys: list[dict] = []
        azure_keys: list[dict] = []
        tls_results: list[dict] = []
        file_scan: list[dict] = []
        collector_summaries: dict[str, Any] = {}

        for row in result_rows:
            blob = row["result_blob"]
            if isinstance(blob, str):
                blob = json.loads(blob)

            ctype = row["collector_type"]

            if isinstance(blob, dict):
                certificates.extend(blob.get("certificates", []))
                keys.extend(blob.get("keys", []))
                azure_keys.extend(blob.get("azure_keys", []))
                tls_results.extend(blob.get("tls_results", []))
                file_scan.extend(blob.get("file_scan_results", []))

                if "summary" in blob:
                    collector_summaries[ctype] = blob["summary"]
                elif "collector_stats" in blob:
                    collector_summaries[ctype] = blob["collector_stats"]
                else:
                    collector_summaries[ctype] = {
                        "enabled": True,
                        "certificates_discovered": row.get("certificates_count") or 0,
                        "keys_discovered": row.get("keys_count") or 0,
                    }

        # Also pull collector_results from scan record
        scan_collector_results = scan.get("collector_results")
        if isinstance(scan_collector_results, str):
            scan_collector_results = json.loads(scan_collector_results)
        if isinstance(scan_collector_results, dict):
            for ctype, stats in scan_collector_results.items():
                if ctype not in collector_summaries:
                    collector_summaries[ctype] = stats

        # Fallback: scan_runs collector_stats
        if not certificates and not keys:
            run_row = await self._db.fetchrow(
                """SELECT collector_stats FROM scan_runs
                   WHERE scan_id=$1 ORDER BY run_number DESC LIMIT 1""",
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

        total_crls = sum(
            s.get("crls_checked", s.get("crl_count", 0))
            for s in collector_summaries.values()
            if isinstance(s, dict)
        )

        # ── 3. Load findings ──────────────────────────────────
        finding_rows = await self._db.fetch(
            """SELECT * FROM findings
               WHERE scan_id = $1 ORDER BY risk_score DESC""",
            scan_id,
        )
        findings = [dict(r) for r in finding_rows]

        # ── 4. Scoring ────────────────────────────────────────
        scoring_block: dict[str, Any]
        if findings:
            try:
                total_assets = len(certificates) + len(keys) + len(azure_keys)
                scored = []
                for f in findings:
                    evidence = f.get("evidence") or {}
                    if isinstance(evidence, str):
                        evidence = json.loads(evidence)
                    sf = ScoringEngine.score_finding(
                        finding_id=f.get("rule_id", "unknown"),
                        severity=f.get("severity", "medium"),
                        title=f.get("title", ""),
                        details={
                            "rule_name": f.get("rule_name"),
                            "asset_id": f.get("affected_asset_id"),
                            "evidence": evidence,
                            "effort_estimate": f.get("effort_estimate", "-"),
                        },
                    )
                    scored.append(sf)

                assessment = AggregationEngine.aggregate(
                    scored, total_assets=total_assets,
                )
                assets_at_risk = assessment.critical_count + assessment.high_count
                assets_at_risk_pct = round(
                    assets_at_risk / max(total_assets, 1) * 100, 1,
                )

                scoring_block = {
                    "enabled": True,
                    "health_index": assessment.health_index,
                    "grade": assessment.grade,
                    "grade_description": _grade_description(assessment.grade),
                    "total_findings": assessment.total_findings,
                    "assets_at_risk": assets_at_risk,
                    "assets_at_risk_percent": assets_at_risk_pct,
                    "risk_exposure_percent": round(
                        100 - assessment.health_index, 1,
                    ),
                    "severity_breakdown": {
                        "critical": assessment.critical_count,
                        "high": assessment.high_count,
                        "medium": assessment.medium_count,
                        "low": assessment.low_count,
                        "info": assessment.info_count,
                    },
                    "priority_queue": [
                        {
                            "finding_id": sf.finding_id,
                            "title": sf.title,
                            "severity": sf.severity,
                            "weighted_score": round(sf.weighted_score, 2),
                            "priority_score": round(sf.priority_score, 2),
                            "effort_estimate": sf.details.get("effort_estimate", "-"),
                            "asset_id": sf.details.get("asset_id"),
                            "rule_name": sf.details.get("rule_name"),
                            "evidence": sf.details.get("evidence", {}),
                        }
                        for sf in assessment.priority_queue
                    ],
                }

                # Annotate findings with scored values
                scored_by_id = {sf.finding_id: sf for sf in scored}
                for f in findings:
                    sf = scored_by_id.get(f.get("rule_id", ""))
                    if sf:
                        f["weighted_score"] = round(sf.weighted_score, 2)
                        f["priority_score"] = round(sf.priority_score, 2)

            except Exception as exc:
                logger.warning("scoring_failed", scan_id=scan_id, error=str(exc))
                scoring_block = {"enabled": False, "reason": str(exc)}
        else:
            scoring_block = {"enabled": False, "reason": "No findings"}

        # ── 5. Load policy ────────────────────────────────────
        policy_block = None
        if scan.get("policy_id"):
            policy_row = await self._db.fetchrow(
                """SELECT name, schema_version, description, rules
                   FROM policies WHERE id = $1""",
                scan["policy_id"],
            )
            if policy_row:
                rules = policy_row["rules"]
                if isinstance(rules, str):
                    rules = json.loads(rules)
                policy_block = {
                    "metadata": {
                        "name": policy_row["name"],
                        "version": policy_row["schema_version"] or "2.0",
                        "category": "PKI Assessment",
                        "description": policy_row["description"] or "",
                    },
                    "rules": rules if isinstance(rules, list) else [],
                }

        # ── 6. Assemble ──────────────────────────────────────
        scan_timestamp = (
            scan["last_run_at"].isoformat()
            if scan.get("last_run_at")
            else datetime.now(timezone.utc).isoformat()
        )

        return {
            "metadata": {
                "scan_timestamp": scan_timestamp,
                "report_name": None,
                "project_name": scan["project_name"],
                "scan_id": scan_id,
                "scan_name": scan["name"],
                "assessment_type": scan["assessment_type"],
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_certificates": len(certificates),
                "total_keys": len(keys) + len(azure_keys),
                "total_crls_checked": total_crls,
            },
            "certificates": certificates,
            "keys": keys,
            "azure_keys": azure_keys,
            "tls_results": tls_results,
            "file_scan": file_scan,
            "findings": findings,
            "scoring": scoring_block,
            "policy": policy_block,
            "integration_summary": {
                "scan_timestamp": scan_timestamp,
                "collector_summaries": collector_summaries,
            },
            "financial": None,
        }

    def _load_forge_js(self) -> str:
        forge_path = Path(__file__).parent / "static" / "forge.min.js"
        if not forge_path.exists():
            raise FileNotFoundError(
                f"forge.min.js not found at {forge_path}. "
                "Run: curl -fsSL https://cdnjs.cloudflare.com/ajax/libs/forge/1.3.1/forge.min.js "
                f"-o {forge_path}"
            )
        return forge_path.read_text(encoding="utf-8")

    def _render_template(self, template_name: str, context: dict) -> str:
        templates_dir = Path(__file__).parent / "templates" / "reports"
        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(templates_dir)),
            autoescape=False,
        )
        template = env.get_template(template_name)
        return template.render(**context)


def _grade_description(grade: str) -> str:
    """Human-readable description for each grade — matches legacy text."""
    return {
        "A+": "Excellent cryptographic posture",
        "A": "Strong cryptographic posture",
        "B": "Good cryptographic posture with minor issues",
        "C": "Fair posture — remediation recommended",
        "D": "Poor posture — remediation required",
        "F": "Critical issues — immediate action required",
    }.get(grade, "Assessment complete")
