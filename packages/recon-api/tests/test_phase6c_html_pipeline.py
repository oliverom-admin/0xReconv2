"""Tests for Phase 6C — HTML templates, ReportGenerationService, embed route."""
from __future__ import annotations

import inspect
import os
from pathlib import Path

import pytest

TEMPLATES_DIR = Path(__file__).parent.parent / "recon_api" / "templates" / "reports"
STATIC_DIR = Path(__file__).parent.parent / "recon_api" / "static"


class TestTemplateFiles:
    def test_pki_template_exists(self):
        assert (TEMPLATES_DIR / "pki_report.html").exists()

    def test_pqc_template_exists(self):
        assert (TEMPLATES_DIR / "pqc_report.html").exists()

    def test_pki_template_is_full(self):
        lines = (TEMPLATES_DIR / "pki_report.html").read_text().splitlines()
        assert len(lines) > 2000, f"Expected >2000 lines, got {len(lines)}"

    def test_pqc_template_is_full(self):
        lines = (TEMPLATES_DIR / "pqc_report.html").read_text().splitlines()
        assert len(lines) > 2000, f"Expected >2000 lines, got {len(lines)}"

    def test_caip_branding_removed_pki(self):
        import re
        content = (TEMPLATES_DIR / "pki_report.html").read_text()
        matches = re.findall(r"sidebar-logo-text[^<]*CAIP", content)
        assert not matches, f"CAIP still in sidebar-logo-text"

    def test_product_name_variable_pki(self):
        content = (TEMPLATES_DIR / "pki_report.html").read_text()
        assert "product_name" in content

    def test_all_dom_ids_preserved_pki(self):
        content = (TEMPLATES_DIR / "pki_report.html").read_text()
        for dom_id in ["pkiReportDataJson", "caip-encrypted-blobs",
                        "caip-encryption-metadata", "caip-signing-result"]:
            assert dom_id in content, f"Missing DOM ID: {dom_id}"

    def test_pqc_data_element(self):
        content = (TEMPLATES_DIR / "pqc_report.html").read_text()
        assert "pqcReportDataJson" in content

    def test_signature_verification_pki(self):
        content = (TEMPLATES_DIR / "pki_report.html").read_text()
        assert "saltLength: 32" in content
        assert "BLOCK DECRYPTION" in content

    def test_signature_verification_pqc(self):
        content = (TEMPLATES_DIR / "pqc_report.html").read_text()
        assert "saltLength: 32" in content

    def test_cert_expiry_warning(self):
        content = (TEMPLATES_DIR / "pki_report.html").read_text()
        assert "certNotAfter" in content

    def test_promote_trailing_slash(self):
        content = (TEMPLATES_DIR / "pki_report.html").read_text()
        assert "/promote/'," in content or "/promote/`," in content

    def test_context_import_backward_compat_pqc(self):
        content = (TEMPLATES_DIR / "pqc_report.html").read_text()
        assert "recon_context_enrichment" in content
        assert "caip_context_enrichment" in content

    def test_forge_js_exists(self):
        forge_path = STATIC_DIR / "forge.min.js"
        assert forge_path.exists()
        assert forge_path.stat().st_size > 100_000


class TestReportGenerationService:
    def test_imports(self):
        from recon_api.services.report_generation import ReportGenerationService
        assert ReportGenerationService is not None

    def test_no_bare_except(self):
        from recon_api.services import report_generation
        src = inspect.getsource(report_generation)
        for i, line in enumerate(src.split("\n"), 1):
            if line.strip() == "except:" or line.strip() == "except :":
                pytest.fail(f"Bare except at line {i}")

    def test_forge_js_loaded_from_static(self):
        from recon_api.services.report_generation import ReportGenerationService
        src = inspect.getsource(ReportGenerationService._load_forge_js)
        assert "forge.min.js" in src
        assert "__file__" in src

    def test_jinja2_autoescape_disabled(self):
        from recon_api.services.report_generation import ReportGenerationService
        src = inspect.getsource(ReportGenerationService._render_template)
        assert "autoescape=False" in src


class TestReportDataStructure:
    """Validates _build_report_data() produces the keys the JS expects."""

    def test_metadata_uses_scan_timestamp_not_scan_time(self):
        from recon_api.services.report_generation import ReportGenerationService
        src = inspect.getsource(ReportGenerationService._build_report_data)
        assert '"scan_timestamp"' in src
        assert '"scan_time"' not in src

    def test_scoring_uses_health_index_not_health_score(self):
        from recon_api.services.report_generation import ReportGenerationService
        src = inspect.getsource(ReportGenerationService._build_report_data)
        assert '"health_index"' in src
        assert '"health_score"' not in src

    def test_scoring_has_enabled_flag(self):
        from recon_api.services.report_generation import ReportGenerationService
        src = inspect.getsource(ReportGenerationService._build_report_data)
        assert '"enabled"' in src

    def test_scoring_has_grade_description(self):
        from recon_api.services.report_generation import ReportGenerationService
        src = inspect.getsource(ReportGenerationService._build_report_data)
        assert '"grade_description"' in src

    def test_scoring_has_risk_exposure_percent(self):
        from recon_api.services.report_generation import ReportGenerationService
        src = inspect.getsource(ReportGenerationService._build_report_data)
        assert '"risk_exposure_percent"' in src

    def test_priority_queue_has_required_fields(self):
        from recon_api.services.report_generation import ReportGenerationService
        src = inspect.getsource(ReportGenerationService._build_report_data)
        for field in ["weighted_score", "priority_score",
                       "effort_estimate", "evidence"]:
            assert f'"{field}"' in src, f"Missing {field} in priority_queue"

    def test_integration_summary_present(self):
        from recon_api.services.report_generation import ReportGenerationService
        src = inspect.getsource(ReportGenerationService._build_report_data)
        assert '"integration_summary"' in src
        assert '"collector_summaries"' in src

    def test_file_scan_present(self):
        from recon_api.services.report_generation import ReportGenerationService
        src = inspect.getsource(ReportGenerationService._build_report_data)
        assert '"file_scan"' in src

    def test_policy_block_present(self):
        from recon_api.services.report_generation import ReportGenerationService
        src = inspect.getsource(ReportGenerationService._build_report_data)
        assert '"policy"' in src
        assert "policy_id" in src

    def test_metadata_has_total_certificates(self):
        from recon_api.services.report_generation import ReportGenerationService
        src = inspect.getsource(ReportGenerationService._build_report_data)
        assert '"total_certificates"' in src

    def test_grade_description_helper(self):
        from recon_api.services.report_generation import _grade_description
        assert _grade_description("A+") == "Excellent cryptographic posture"
        assert _grade_description("F") == "Critical issues — immediate action required"
        assert _grade_description("B") != ""


class TestWorkerHandler:
    def test_report_generate_handler_registered(self):
        from recon_api.services.scheduler import SchedulerService
        src = inspect.getsource(SchedulerService._dispatch)
        assert "report_generate" in src


class TestEmbedRoute:
    async def test_embed_requires_auth(self, async_client):
        r = await async_client.post(
            "/api/v1/reports/embed/",
            json={
                "project_id": "fake",
                "scan_id": "fake",
                "report_name": "test",
            },
        )
        assert r.status_code in (401, 403)

    async def test_embed_invalid_type(self, async_client):
        # Without auth this will be 401/403 — that's fine for route existence check
        r = await async_client.post(
            "/api/v1/reports/embed/",
            json={
                "project_id": "fake",
                "scan_id": "fake",
                "report_name": "test",
                "report_type": "invalid",
            },
        )
        assert r.status_code in (401, 403, 422)
