"""Tests for Phase 6B — ReportCryptoService crypto parameters and round-trip."""
from __future__ import annotations

import base64
import inspect
import json
import os

import pytest


class TestReportCryptoServiceImports:
    def test_imports(self):
        from recon_api.services.report_crypto import ReportCryptoService
        assert ReportCryptoService is not None

    def test_all_methods_present(self):
        from recon_api.services.report_crypto import ReportCryptoService
        for m in ["encrypt_report_data", "sign_encrypted_blob",
                   "verify_signature", "decrypt_report_for_testing"]:
            assert hasattr(ReportCryptoService, m), f"Missing: {m}"

    def test_no_bare_except(self):
        from recon_api.services import report_crypto
        src = inspect.getsource(report_crypto)
        for i, line in enumerate(src.split("\n"), 1):
            if line.strip() == "except:" or line.strip() == "except :":
                pytest.fail(f"Bare except at line {i}")


class TestEncryptionParameters:
    def test_uses_aesgcm(self):
        from recon_api.services.report_crypto import ReportCryptoService
        src = inspect.getsource(ReportCryptoService.encrypt_report_data)
        assert "AESGCM" in src

    def test_aes_key_is_32_bytes(self):
        from recon_api.services.report_crypto import ReportCryptoService
        src = inspect.getsource(ReportCryptoService.encrypt_report_data)
        assert "urandom(32)" in src

    def test_nonce_is_12_bytes(self):
        from recon_api.services.report_crypto import ReportCryptoService
        src = inspect.getsource(ReportCryptoService.encrypt_report_data)
        assert "urandom(12)" in src

    def test_oaep_label_is_none(self):
        from recon_api.services.report_crypto import ReportCryptoService
        src = inspect.getsource(ReportCryptoService.encrypt_report_data)
        assert "label=None" in src

    def test_tag_field_is_string_literal(self):
        from recon_api.services.report_crypto import ReportCryptoService
        src = inspect.getsource(ReportCryptoService.encrypt_report_data)
        assert "'aes-256-gcm'" in src or '"aes-256-gcm"' in src

    def test_oaep_uses_sha256(self):
        from recon_api.services.report_crypto import ReportCryptoService
        src = inspect.getsource(ReportCryptoService.encrypt_report_data)
        assert "SHA256()" in src


class TestSigningParameters:
    def test_pss_salt_length_is_32(self):
        from recon_api.services.report_crypto import ReportCryptoService
        src = inspect.getsource(ReportCryptoService.sign_encrypted_blob)
        assert "salt_length=32" in src

    def test_signature_algorithm_string(self):
        from recon_api.services.report_crypto import ReportCryptoService
        src = inspect.getsource(ReportCryptoService.sign_encrypted_blob)
        assert "RSA-PSS-SHA256" in src

    def test_metadata_has_salt_length(self):
        from recon_api.services.report_crypto import ReportCryptoService
        src = inspect.getsource(ReportCryptoService.sign_encrypted_blob)
        assert "salt_length_bytes" in src

    def test_signing_result_fields_in_source(self):
        from recon_api.services.report_crypto import ReportCryptoService
        src = inspect.getsource(ReportCryptoService.sign_encrypted_blob)
        for field in ["signature", "signature_algorithm", "certificate_pem",
                       "certificate_serial", "signed_timestamp", "metadata"]:
            assert field in src, f"Missing field: {field}"


class TestSignatureVerification:
    def test_verify_is_static_method(self):
        from recon_api.services.report_crypto import ReportCryptoService
        assert isinstance(
            inspect.getattr_static(ReportCryptoService, "verify_signature"),
            staticmethod,
        )

    def test_verify_pss_salt_length_is_32(self):
        from recon_api.services.report_crypto import ReportCryptoService
        src = inspect.getsource(ReportCryptoService.verify_signature)
        assert "salt_length=32" in src

    def test_verify_returns_false_on_tampered(self):
        """Build a real signature, tamper with data, verify fails."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.backends import default_backend
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from datetime import datetime, timedelta, timezone
        from recon_api.services.report_crypto import ReportCryptoService

        # Generate a signing key pair and self-signed cert
        key = rsa.generate_private_key(65537, 4096, default_backend())
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "Test Signing"),
            ]))
            .issuer_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "Test Signing"),
            ]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .sign(key, hashes.SHA256(), default_backend())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

        # Sign some data
        original_blobs = {"user1": {"data": "test"}}
        blobs_json = json.dumps(original_blobs)
        blobs_b64 = base64.b64encode(blobs_json.encode()).decode()
        signed_bytes = base64.b64decode(blobs_b64.encode())

        signature = key.sign(
            signed_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        signing_result = {
            "signature": base64.b64encode(signature).decode(),
            "certificate_pem": cert_pem,
        }

        # Valid signature should verify
        assert ReportCryptoService.verify_signature(
            original_blobs, signing_result
        ) is True

        # Tampered data should fail
        tampered_blobs = {"user1": {"data": "TAMPERED"}}
        assert ReportCryptoService.verify_signature(
            tampered_blobs, signing_result
        ) is False


class TestRoundTrip:
    def test_encrypt_decrypt_round_trip(self):
        """Full encrypt/decrypt round-trip using real RSA-4096 keys."""
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.backends import default_backend
        from recon_api.services.report_crypto import ReportCryptoService

        # Generate recipient key pair
        recipient_key = rsa.generate_private_key(
            65537, 4096, default_backend()
        )
        pub_pem = recipient_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        priv_pem = recipient_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode()

        # Encrypt manually (simulating what encrypt_report_data does)
        test_data = {"test": True, "value": 42, "nested": {"key": "val"}}
        report_json = json.dumps(test_data, sort_keys=True).encode("utf-8")
        aes_key = os.urandom(32)
        aes_iv = os.urandom(12)
        cipher = AESGCM(aes_key)
        encrypted_report = cipher.encrypt(aes_iv, report_json, None)

        public_key = serialization.load_pem_public_key(pub_pem.encode())
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        blobs = {
            "testuser": {
                "encrypted_aes_key": base64.b64encode(
                    encrypted_aes_key
                ).decode(),
                "encrypted_report": base64.b64encode(
                    encrypted_report
                ).decode(),
                "iv": base64.b64encode(aes_iv).decode(),
                "tag": "aes-256-gcm",
            }
        }

        # Decrypt using the service's test helper
        decrypted = ReportCryptoService.decrypt_report_for_testing(
            blobs, "testuser", priv_pem,
        )
        assert decrypted == test_data

    def test_decrypt_helper_is_static(self):
        from recon_api.services.report_crypto import ReportCryptoService
        assert isinstance(
            inspect.getattr_static(
                ReportCryptoService, "decrypt_report_for_testing"
            ),
            staticmethod,
        )
