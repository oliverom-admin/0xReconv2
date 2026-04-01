"""CertificateService unit tests (no DB — smoke tests only)."""
from __future__ import annotations
import pytest
from recon_api.services.certificate import _id_suffix, KEY_SIZE


class TestCertHelpers:
    def test_id_suffix_strips_hyphens(self):
        pid = "550e8400-e29b-41d4-a716-446655440000"
        suffix = _id_suffix(pid)
        assert "-" not in suffix
        assert len(suffix) == 8
        assert suffix == "550e8400"

    def test_id_suffix_lowercase(self):
        assert _id_suffix("ABCDEF12-rest") == "abcdef12"

    def test_key_size_is_4096(self):
        assert KEY_SIZE == 4096
