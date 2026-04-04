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
            report_data["metadata"] = {
                "report_name": report_name,
                "project_name": project["name"] if project else "Unknown",
                "scan_id": scan_id,
                "scan_name": scan.get("name") or "",
                "scan_time": (
                    scan.get("last_run_at") or scan.get("created_at") or
                    datetime.now(timezone.utc)
                ).isoformat(),
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "report_type": report_type,
                "assessment_type": scan.get("assessment_type") or "pki",
            }

            # Financial analysis
            from recon_api.services.financial import ReportFinancialCalculator
            calc = ReportFinancialCalculator({
                "certificates": report_data.get("certificates", []),
                "keys": report_data.get("keys", []),
                "findings": report_data.get("findings", []),
            })
            report_data["financial"] = calc.get_financial_summary()

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
        """Load and structure scan data for report templates."""
        # Load scan results
        rows = await self._db.fetch(
            "SELECT collector_type, result_blob FROM scan_results WHERE scan_id=$1",
            scan_id,
        )
        certificates: list[dict] = []
        keys: list[dict] = []
        azure_keys: list[dict] = []
        tls_results: list[dict] = []

        for row in rows:
            blob = row["result_blob"]
            if isinstance(blob, str):
                blob = json.loads(blob)
            if isinstance(blob, dict):
                certificates.extend(blob.get("certificates", []))
                keys.extend(blob.get("keys", []))
                azure_keys.extend(blob.get("azure_keys", []))
                tls_results.extend(blob.get("tls_results", []))

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

        # Load findings
        findings_rows = await self._db.fetch(
            "SELECT * FROM findings WHERE scan_id=$1 ORDER BY risk_score DESC",
            scan_id,
        )
        findings = [dict(r) for r in findings_rows]

        # Load policy
        policy_data = None
        scan_row = await self._db.fetchrow(
            "SELECT policy_id FROM scans WHERE id=$1", scan_id,
        )
        if scan_row and scan_row.get("policy_id"):
            pol = await self._db.fetchrow(
                "SELECT name, rules, schema_version FROM policies WHERE id=$1",
                scan_row["policy_id"],
            )
            if pol:
                rules = pol["rules"]
                if isinstance(rules, str):
                    rules = json.loads(rules)
                policy_data = {
                    "metadata": {
                        "name": pol["name"],
                        "version": pol.get("schema_version") or "2.0",
                        "category": "pki",
                    },
                    "rules": list(rules) if rules else [],
                }

        # Scoring
        scoring_data = None
        if findings:
            try:
                from recon_core.scoring import ScoringEngine, AggregationEngine
                scored = [
                    ScoringEngine.score_finding(
                        finding_id=f.get("rule_id") or f.get("id") or "",
                        severity=f.get("severity") or "info",
                        title=f.get("title") or "",
                    )
                    for f in findings
                ]
                total_assets = len(certificates) + len(keys)
                agg = AggregationEngine.aggregate(scored, total_assets=total_assets)
                scoring_data = {
                    "health_score": agg.health_index,
                    "grade": agg.grade,
                    "total_assets": total_assets,
                    "weighted_findings": [
                        {**f, "weighted_score": s.weighted_score,
                         "priority_score": s.priority_score}
                        for f, s in zip(findings, scored)
                    ],
                    "priority_queue": [
                        {
                            "finding_id": s.finding_id,
                            "severity": s.severity,
                            "title": s.title,
                            "weighted_score": s.weighted_score,
                            "priority_score": s.priority_score,
                        }
                        for s in agg.priority_queue
                    ],
                }
            except ImportError:
                logger.warning("scoring_unavailable")

        return {
            "certificates": certificates,
            "keys": keys,
            "azure_keys": azure_keys,
            "tls_results": tls_results,
            "findings": findings,
            "policy": policy_data,
            "scoring": scoring_data,
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
