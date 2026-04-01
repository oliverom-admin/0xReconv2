"""PQCService unit tests."""
from __future__ import annotations
import pytest
from recon_core.pqc import PQCService, VULNERABLE_OIDS, SAFE_OIDS


class TestPQCOID:
    def test_rsa_is_vulnerable(self):
        r = PQCService.classify_oid("1.2.840.113549.1.1.1")
        assert r.status == "vulnerable"
        assert r.algorithm_name == "RSA"

    def test_ecdsa_sha256_is_vulnerable(self):
        assert PQCService.classify_oid("1.2.840.10045.4.3.2").status == "vulnerable"

    def test_ml_kem_512_is_safe(self):
        r = PQCService.classify_oid("2.16.840.1.101.3.4.4.1")
        assert r.status == "safe"
        assert "ML-KEM" in r.algorithm_name

    def test_x25519_is_safe(self):
        assert PQCService.classify_oid("1.3.101.110").status == "safe"

    def test_unknown_oid(self):
        assert PQCService.classify_oid("9.9.9.9").status == "unknown"

    def test_all_vulnerable_oids_classified(self):
        for oid in VULNERABLE_OIDS:
            assert PQCService.classify_oid(oid).status == "vulnerable", f"OID {oid}"

    def test_all_safe_oids_classified(self):
        for oid in SAFE_OIDS:
            assert PQCService.classify_oid(oid).status == "safe", f"OID {oid}"


class TestPQCName:
    def test_rsa_name_vulnerable(self):
        assert PQCService.classify_name("RSA-2048").status == "vulnerable"

    def test_kyber_name_safe(self):
        assert PQCService.classify_name("Kyber-768").status == "safe"

    def test_hybrid_transitioning(self):
        assert PQCService.classify_name("RSA-Kyber-Hybrid").status == "transitioning"


class TestPQCCombined:
    def test_oid_takes_priority_over_name(self):
        r = PQCService.classify("1.2.840.113549.1.1.1", "kyber")
        assert r.status == "vulnerable"

    def test_falls_back_to_name(self):
        r = PQCService.classify("9.9.9.9", "kyber-768")
        assert r.status == "safe"

    def test_is_vulnerable_helper(self):
        assert PQCService.is_vulnerable("1.2.840.113549.1.1.1", None) is True
        assert PQCService.is_vulnerable("2.16.840.1.101.3.4.4.1", None) is False
