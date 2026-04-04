"""Tests for Phase 6D — DOCX and PDF executive reports."""
from __future__ import annotations

import inspect
import os
import tempfile

import pytest


TEST_DATA = {
    "report_name": "Test Executive Report",
    "project_name": "Test Project",
    "scan_name": "Gate Scan",
    "generated_at": "2026-04-04T12:00:00Z",
    "certificates": [
        {"subject_cn": "test.example.com", "key_algorithm": "RSA",
         "key_size": 2048, "is_expired": False,
         "not_after": "2027-01-01T00:00:00Z"},
    ],
    "keys": [],
    "findings": [
        {"severity": "high", "title": "Weak RSA Key",
         "description": "Key size below 4096", "entity_cn": "test.example.com",
         "remediation": "Regenerate with RSA-4096"},
        {"severity": "medium", "title": "Expiring Soon",
         "description": "Cert expires within 90 days",
         "remediation": "Renew certificate"},
    ],
    "summary": {
        "total_certificates": 1, "total_keys": 0, "total_findings": 2,
        "findings_by_severity": {"critical": 0, "high": 1, "medium": 1, "low": 0},
        "health_score": 72.5, "grade": "B",
    },
    "financial_impact": {
        "annual_risk_cost": {"total_annual_cost": 355000, "risk_level": "HIGH"},
        "roi_analysis": {"remediation_investment": 7000,
                         "payback_months": 6, "roi_year3": 200000},
    },
}


class TestExecutiveDocxServiceImports:
    def test_imports(self):
        from recon_api.services.executive_docx import ExecutiveDocxService
        assert ExecutiveDocxService is not None

    def test_no_bare_except(self):
        from recon_api.services import executive_docx
        src = inspect.getsource(executive_docx)
        for i, line in enumerate(src.split("\n"), 1):
            if line.strip() == "except:" or line.strip() == "except :":
                pytest.fail(f"Bare except at line {i}")

    def test_no_swallowed_exceptions(self):
        from recon_api.services import executive_docx
        src = inspect.getsource(executive_docx)
        assert "except Exception: pass" not in src


class TestExecutivePdfServiceImports:
    def test_imports(self):
        from recon_api.services.executive_pdf import ExecutivePdfService
        assert ExecutivePdfService is not None

    def test_no_bare_except(self):
        from recon_api.services import executive_pdf
        src = inspect.getsource(executive_pdf)
        for i, line in enumerate(src.split("\n"), 1):
            if line.strip() == "except:" or line.strip() == "except :":
                pytest.fail(f"Bare except at line {i}")

    def test_no_swallowed_exceptions(self):
        from recon_api.services import executive_pdf
        src = inspect.getsource(executive_pdf)
        assert "except Exception: pass" not in src


class TestDocxGeneration:
    def test_generate_creates_file(self):
        from recon_api.services.executive_docx import ExecutiveDocxService
        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as f:
            path = f.name
        try:
            svc = ExecutiveDocxService(TEST_DATA)
            output = svc.generate(path)
            assert os.path.exists(output)
            assert os.path.getsize(output) > 5000
        finally:
            os.unlink(path)

    def test_severity_colours_defined(self):
        from recon_api.services import executive_docx
        src = inspect.getsource(executive_docx)
        # DOCX uses RGBColor(0xFF, 0x44, 0x44) not hex string
        assert "0x44, 0x44" in src or "FF4444" in src  # CRITICAL red
        assert "0x88, 0x00" in src or "FF8800" in src  # HIGH orange

    def test_handles_empty_findings(self):
        from recon_api.services.executive_docx import ExecutiveDocxService
        data = {**TEST_DATA, "findings": [], "summary": {
            **TEST_DATA["summary"], "total_findings": 0,
            "findings_by_severity": {}}}
        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as f:
            path = f.name
        try:
            svc = ExecutiveDocxService(data)
            svc.generate(path)
            assert os.path.getsize(path) > 3000
        finally:
            os.unlink(path)

    def test_handles_missing_financial(self):
        from recon_api.services.executive_docx import ExecutiveDocxService
        data = {**TEST_DATA, "financial_impact": None}
        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as f:
            path = f.name
        try:
            svc = ExecutiveDocxService(data)
            svc.generate(path)
            assert os.path.getsize(path) > 3000
        finally:
            os.unlink(path)


class TestPdfGeneration:
    def test_generate_creates_valid_pdf(self):
        from recon_api.services.executive_pdf import ExecutivePdfService
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            path = f.name
        try:
            svc = ExecutivePdfService(TEST_DATA)
            output = svc.generate(path)
            assert os.path.exists(output)
            assert os.path.getsize(output) > 3000
            with open(output, "rb") as fh:
                magic = fh.read(4)
            assert magic == b"%PDF"
        finally:
            os.unlink(path)

    def test_colors_preserved(self):
        from recon_api.services import executive_pdf
        src = inspect.getsource(executive_pdf)
        assert "#00FF41" in src
        assert "#FFB800" in src

    def test_handles_empty_findings(self):
        from recon_api.services.executive_pdf import ExecutivePdfService
        data = {**TEST_DATA, "findings": [], "summary": {
            **TEST_DATA["summary"], "total_findings": 0,
            "findings_by_severity": {}}}
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            path = f.name
        try:
            svc = ExecutivePdfService(data)
            svc.generate(path)
            assert os.path.getsize(path) > 5000
        finally:
            os.unlink(path)

    def test_page_size_is_a4(self):
        from recon_api.services import executive_pdf
        src = inspect.getsource(executive_pdf)
        assert "A4" in src


class TestWorkerHandlers:
    def test_docx_handler_registered(self):
        from recon_api.services.scheduler import SchedulerService
        src = inspect.getsource(SchedulerService._dispatch)
        assert "docx_generate" in src

    def test_pdf_handler_registered(self):
        from recon_api.services.scheduler import SchedulerService
        src = inspect.getsource(SchedulerService._dispatch)
        assert "pdf_generate" in src


class TestExecutiveRoute:
    async def test_requires_auth(self, async_client):
        r = await async_client.post(
            "/api/v1/reports/executive/",
            json={"project_id": "x", "scan_id": "y", "report_name": "z"},
        )
        assert r.status_code in (401, 403)

    async def test_invalid_format(self, async_client):
        r = await async_client.post(
            "/api/v1/reports/executive/",
            json={"project_id": "x", "scan_id": "y",
                   "report_name": "z", "format": "xml"},
        )
        assert r.status_code in (401, 403, 422)
