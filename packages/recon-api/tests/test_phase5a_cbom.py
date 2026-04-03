"""Tests for Phase 5A — CBOMExportService, ReportFinancialCalculator, routes."""
from __future__ import annotations

import pytest


# ── CBOMExportService tests ───────────────────────────────────

class TestCBOMExportServiceImports:
    def test_imports(self):
        from recon_api.services.cbom import CBOMExportService
        assert CBOMExportService is not None

    def test_spec_version_is_1_6(self):
        from recon_api.services.cbom import CBOMExportService
        assert CBOMExportService.SPEC_VERSION == "1.6"

    def test_bom_format_is_cyclonedx(self):
        from recon_api.services.cbom import CBOMExportService
        assert CBOMExportService.BOM_FORMAT == "CycloneDX"

    def test_sig_oid_table_has_sha256_rsa(self):
        from recon_api.services.cbom import CBOMExportService
        assert "sha256WithRSAEncryption" in CBOMExportService.SIGNATURE_ALGORITHM_OIDS
        assert CBOMExportService.SIGNATURE_ALGORITHM_OIDS[
            "sha256WithRSAEncryption"
        ] == "1.2.840.113549.1.1.11"

    def test_sig_oid_table_has_pqc(self):
        from recon_api.services.cbom import CBOMExportService
        assert "ML-DSA-65" in CBOMExportService.SIGNATURE_ALGORITHM_OIDS

    def test_key_oid_table_has_ml_kem(self):
        from recon_api.services.cbom import CBOMExportService
        assert "ML-KEM-512" in CBOMExportService.KEY_ALGORITHM_OIDS
        assert "ML-KEM-768" in CBOMExportService.KEY_ALGORITHM_OIDS
        assert "ML-KEM-1024" in CBOMExportService.KEY_ALGORITHM_OIDS

    def test_sig_oid_count(self):
        from recon_api.services.cbom import CBOMExportService
        assert len(CBOMExportService.SIGNATURE_ALGORITHM_OIDS) >= 15

    def test_key_oid_count(self):
        from recon_api.services.cbom import CBOMExportService
        assert len(CBOMExportService.KEY_ALGORITHM_OIDS) >= 15

    def test_tls_protocol_info_has_deprecated_flag(self):
        from recon_api.services.cbom import CBOMExportService
        assert CBOMExportService.TLS_PROTOCOL_INFO["TLSv1.0"]["deprecated"] is True
        assert CBOMExportService.TLS_PROTOCOL_INFO["TLSv1.3"]["deprecated"] is False


class TestExportScanResults:
    def test_empty_input_returns_valid_structure(self):
        from recon_api.services.cbom import CBOMExportService
        result = CBOMExportService.export_scan_results([], [])
        assert result["bomFormat"] == "CycloneDX"
        assert result["specVersion"] == "1.6"
        assert result["serialNumber"].startswith("urn:uuid:")
        assert result["version"] == 1
        assert "metadata" in result
        assert "components" in result
        assert isinstance(result["components"], list)

    def test_single_cert_produces_components(self):
        from recon_api.services.cbom import CBOMExportService
        result = CBOMExportService.export_scan_results(
            certificates=[{
                "fingerprint_sha256": "abc123def456" * 3,
                "subject": {"CN": "test.example.com"},
                "issuer": {"CN": "Test CA"},
                "signature_algorithm": "sha256WithRSAEncryption",
                "public_key_algorithm": "RSA",
                "public_key_size": 2048,
            }],
        )
        assert len(result["components"]) >= 2  # cert + at least 1 algo

    def test_algorithm_deduplication(self):
        from recon_api.services.cbom import CBOMExportService
        certs = [
            {
                "fingerprint_sha256": f"abc{i}" * 8,
                "subject": {"CN": f"cert{i}.example.com"},
                "issuer": {"CN": "Test CA"},
                "signature_algorithm": "sha256WithRSAEncryption",
                "public_key_algorithm": "RSA",
            }
            for i in range(3)
        ]
        result = CBOMExportService.export_scan_results(certificates=certs)
        algo_comps = [
            c for c in result["components"]
            if c.get("cryptoProperties", {}).get("assetType") == "algorithm"
        ]
        sig_algos = [
            c for c in algo_comps
            if "sha256" in c.get("bom-ref", "").lower()
        ]
        assert len(sig_algos) == 1

    def test_cert_bom_ref_format(self):
        from recon_api.services.cbom import CBOMExportService
        result = CBOMExportService.export_scan_results(
            certificates=[{
                "fingerprint_sha256": "aabbccdd" * 4,
                "subject": {"CN": "test"},
                "signature_algorithm": "sha256WithRSAEncryption",
            }],
        )
        cert_comps = [
            c for c in result["components"]
            if c.get("cryptoProperties", {}).get("assetType") == "certificate"
        ]
        assert cert_comps
        assert cert_comps[0]["bom-ref"].startswith("cert-")

    def test_dependencies_populated(self):
        from recon_api.services.cbom import CBOMExportService
        result = CBOMExportService.export_scan_results(
            certificates=[{
                "fingerprint_sha256": "aabb" * 8,
                "subject": {"CN": "test"},
                "signature_algorithm": "sha256WithRSAEncryption",
            }],
        )
        assert len(result["dependencies"]) >= 1
        dep = result["dependencies"][0]
        assert "ref" in dep
        assert "dependsOn" in dep
        assert len(dep["dependsOn"]) >= 1

    def test_serial_number_is_urn_uuid(self):
        from recon_api.services.cbom import CBOMExportService
        result = CBOMExportService.export_scan_results([])
        assert result["serialNumber"].startswith("urn:uuid:")

    def test_metadata_contains_timestamp(self):
        from recon_api.services.cbom import CBOMExportService
        result = CBOMExportService.export_scan_results([])
        assert "timestamp" in result["metadata"]

    def test_tls_version_produces_protocol(self):
        from recon_api.services.cbom import CBOMExportService
        result = CBOMExportService.export_scan_results(
            certificates=[{
                "fingerprint_sha256": "aabb" * 8,
                "subject": {"CN": "test"},
                "tls_version": "TLSv1.2",
                "signature_algorithm": "sha256WithRSAEncryption",
            }],
        )
        proto_comps = [
            c for c in result["components"]
            if c.get("cryptoProperties", {}).get("assetType") == "protocol"
        ]
        assert len(proto_comps) >= 1

    def test_hsm_key_has_secured_by(self):
        from recon_api.services.cbom import CBOMExportService
        result = CBOMExportService.export_scan_results(
            certificates=[],
            keys=[{
                "key_id": "hsm-key-1",
                "name": "HSM Key",
                "key_type": "RSA",
                "key_size": 4096,
                "is_hardware_protected": True,
            }],
        )
        key_comps = [
            c for c in result["components"]
            if c.get("cryptoProperties", {}).get("assetType") == "related-crypto-material"
        ]
        assert key_comps
        props = key_comps[0]["cryptoProperties"]["relatedCryptoMaterialProperties"]
        assert "securedBy" in props


class TestFormatDN:
    def test_dict_dn(self):
        from recon_api.services.cbom import CBOMExportService
        result = CBOMExportService._format_dn(
            {"CN": "test.example.com", "O": "Test Corp"}
        )
        assert "CN=test.example.com" in result
        assert "O=Test Corp" in result

    def test_string_dn(self):
        from recon_api.services.cbom import CBOMExportService
        assert CBOMExportService._format_dn("CN=test") == "CN=test"

    def test_none_returns_empty(self):
        from recon_api.services.cbom import CBOMExportService
        assert CBOMExportService._format_dn(None) == ""


class TestNoBareCBOM:
    def test_no_bare_except(self):
        import inspect
        from recon_api.services import cbom
        src = inspect.getsource(cbom)
        for i, line in enumerate(src.split("\n"), 1):
            if line.strip() == "except:" or line.strip() == "except :":
                pytest.fail(f"Bare except at line {i}")

    def test_no_caip_references(self):
        import inspect
        from recon_api.services import cbom
        src = inspect.getsource(cbom)
        assert "caip_" not in src
        assert "engagement_name" not in src


# ── ReportFinancialCalculator tests ───────────────────────────

class TestReportFinancialCalculator:
    def test_imports(self):
        from recon_api.services.financial import ReportFinancialCalculator
        assert ReportFinancialCalculator is not None

    def test_constants_preserved(self):
        from recon_api.services.financial import ReportFinancialCalculator
        assert ReportFinancialCalculator.AVG_DATA_BREACH_COST == 3_555_000
        assert ReportFinancialCalculator.AVG_COST_PER_RECORD == 152
        assert ReportFinancialCalculator.AVG_DETECTION_DAYS == 207
        assert ReportFinancialCalculator.COMPLIANCE_FINE_MIN == 21_000
        assert ReportFinancialCalculator.RISK_MULTIPLIERS["CRITICAL"] == 0.35
        assert ReportFinancialCalculator.RISK_MULTIPLIERS["HIGH"] == 0.20
        assert ReportFinancialCalculator.RISK_MULTIPLIERS["MEDIUM"] == 0.10
        assert ReportFinancialCalculator.RISK_MULTIPLIERS["LOW"] == 0.03

    def test_risk_level_hierarchy(self):
        from recon_api.services.financial import ReportFinancialCalculator
        calc = ReportFinancialCalculator(
            {"certificates": [], "keys": [], "findings": []}
        )
        assert calc._determine_risk_level([]) == "LOW"
        assert calc._determine_risk_level(
            [{"severity": "medium"}]
        ) == "MEDIUM"
        assert calc._determine_risk_level(
            [{"severity": "high"}]
        ) == "HIGH"
        assert calc._determine_risk_level(
            [{"severity": "high"}, {"severity": "critical"}]
        ) == "CRITICAL"

    def test_get_financial_summary_structure(self):
        from recon_api.services.financial import ReportFinancialCalculator
        calc = ReportFinancialCalculator({
            "certificates": [{"is_expired": True}],
            "keys": [],
            "findings": [{"severity": "high"}, {"severity": "medium"}],
        })
        summary = calc.get_financial_summary()
        assert "annual_risk_cost" in summary
        assert "remediation_costs" in summary
        assert "roi_analysis" in summary
        assert "generated_at" in summary
        assert "model_version" in summary
        assert "disclaimer" in summary

    def test_annual_risk_cost_fields(self):
        from recon_api.services.financial import ReportFinancialCalculator
        calc = ReportFinancialCalculator({
            "certificates": [], "keys": [],
            "findings": [{"severity": "high"}],
        })
        arc = calc.calculate_annual_risk_cost()
        assert "total_annual_cost" in arc
        assert "risk_level" in arc
        assert "multiplier" in arc
        assert "breakdown" in arc
        assert arc["risk_level"] == "HIGH"

    def test_high_findings_increase_cost(self):
        from recon_api.services.financial import ReportFinancialCalculator
        no_findings = ReportFinancialCalculator({
            "certificates": [], "keys": [], "findings": [],
        }).calculate_annual_risk_cost()
        high_findings = ReportFinancialCalculator({
            "certificates": [], "keys": [],
            "findings": [{"severity": "high"}],
        }).calculate_annual_risk_cost()
        assert high_findings["total_annual_cost"] > no_findings["total_annual_cost"]

    def test_no_bare_except(self):
        import inspect
        from recon_api.services import financial
        src = inspect.getsource(financial)
        for i, line in enumerate(src.split("\n"), 1):
            if line.strip() == "except:" or line.strip() == "except :":
                pytest.fail(f"Bare except at line {i}")


# ── ReportService tests ──────────────────────────────────────

class TestReportServiceImports:
    def test_imports(self):
        from recon_api.services.report import ReportService
        assert ReportService is not None

    def test_no_bare_except(self):
        import inspect
        from recon_api.services import report
        src = inspect.getsource(report)
        for i, line in enumerate(src.split("\n"), 1):
            if line.strip() == "except:" or line.strip() == "except :":
                pytest.fail(f"Bare except at line {i}")


# ── Route tests ───────────────────────────────────────────────

class TestCBOMRoutes:
    async def test_cbom_requires_auth(self, async_client):
        r = await async_client.get("/api/v1/cbom/scans/fake-id/")
        assert r.status_code in (401, 403)

    async def test_report_list_requires_auth(self, async_client):
        r = await async_client.get("/api/v1/reports/fake-id/")
        assert r.status_code in (401, 403)

    async def test_report_delete_requires_auth(self, async_client):
        r = await async_client.delete("/api/v1/reports/fake-id/fake-rid/")
        assert r.status_code in (401, 403)
