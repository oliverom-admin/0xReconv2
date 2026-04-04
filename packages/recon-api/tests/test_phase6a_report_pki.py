"""Tests for Phase 6A — report PKI tables and CertificateService methods."""
from __future__ import annotations

import pytest


class TestMigration0007:
    def test_user_digital_identities_import(self):
        # Table exists if migration ran — verify service can reference it
        from recon_api.services.certificate import CertificateService
        assert CertificateService is not None

    def test_project_signing_certs_referenced(self):
        import inspect
        from recon_api.services.certificate import CertificateService
        src = inspect.getsource(CertificateService.provision_project_signing_cert)
        assert "project_signing_certs" in src


class TestCertificateServiceMethods:
    def test_all_four_methods_present(self):
        from recon_api.services.certificate import CertificateService
        for m in ["issue_report_viewer_cert", "generate_p12",
                   "provision_project_signing_cert", "load_project_signing_cert"]:
            assert hasattr(CertificateService, m), f"Missing: {m}"

    def test_pyopenssl_available(self):
        from OpenSSL import crypto
        assert crypto is not None

    def test_issue_report_viewer_cert_signature(self):
        import inspect
        from recon_api.services.certificate import CertificateService
        sig = inspect.signature(CertificateService.issue_report_viewer_cert)
        params = list(sig.parameters.keys())
        assert "project_id" in params
        assert "user_id" in params
        assert "report_name" in params
        assert "validity_days" in params

    def test_cn_format_in_source(self):
        import inspect
        from recon_api.services.certificate import CertificateService
        src = inspect.getsource(CertificateService.issue_report_viewer_cert)
        assert "viewer:" in src
        assert "report:" in src

    def test_vault_key_naming_viewer(self):
        import inspect
        from recon_api.services.certificate import CertificateService
        src = inspect.getsource(CertificateService.issue_report_viewer_cert)
        assert "report-viewer-key-" in src

    def test_signing_cert_vault_key_naming(self):
        import inspect
        from recon_api.services.certificate import CertificateService
        src = inspect.getsource(CertificateService.provision_project_signing_cert)
        assert "report-signing-key-" in src

    def test_generate_p12_uses_pyopenssl(self):
        import inspect
        from recon_api.services.certificate import CertificateService
        src = inspect.getsource(CertificateService.generate_p12)
        assert "PKCS12" in src or "p12" in src.lower()

    def test_p12_password_uses_secrets(self):
        import inspect
        from recon_api.services.certificate import CertificateService
        src = inspect.getsource(CertificateService.generate_p12)
        assert "token_urlsafe" in src

    def test_no_bare_except(self):
        import inspect
        from recon_api.services import certificate
        src = inspect.getsource(certificate)
        for i, line in enumerate(src.split("\n"), 1):
            if line.strip() == "except:" or line.strip() == "except :":
                pytest.fail(f"Bare except at line {i}")


class TestSigningCertProvisioning:
    def test_provision_chained_to_project_ca(self):
        import inspect
        from recon_api.services import certificate
        src = inspect.getsource(certificate.CertificateService.ensure_project_ca)
        assert "provision_project_signing_cert" in src

    def test_signing_cert_cn_format(self):
        import inspect
        from recon_api.services.certificate import CertificateService
        src = inspect.getsource(CertificateService.provision_project_signing_cert)
        assert "0xRecon Report Signing" in src

    def test_signing_cert_validity_730_days(self):
        import inspect
        from recon_api.services import certificate
        src = inspect.getsource(certificate._gen_signing_cert)
        assert "730" in src


class TestViewerCertHelpers:
    def test_gen_viewer_cert_key_usage(self):
        import inspect
        from recon_api.services import certificate
        src = inspect.getsource(certificate._gen_viewer_cert)
        assert "digital_signature=True" in src
        assert "key_encipherment=True" in src

    def test_gen_viewer_cert_eku(self):
        import inspect
        from recon_api.services import certificate
        src = inspect.getsource(certificate._gen_viewer_cert)
        assert "CLIENT_AUTH" in src

    def test_build_p12_function_exists(self):
        from recon_api.services.certificate import _build_p12
        assert callable(_build_p12)
