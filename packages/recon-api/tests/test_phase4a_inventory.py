"""Tests for Phase 4A — InventoryService, SyncResult, inventory routes."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest


# ── Schema / import tests ─────────────────────────────────────

class TestSyncResult:
    def test_instantiates_with_defaults(self):
        from recon_api.services.inventory import SyncResult
        r = SyncResult(
            project_id="p1", scan_id="s1", success=True,
            started_at=datetime.now(timezone.utc).isoformat(),
            completed_at=datetime.now(timezone.utc).isoformat(),
            duration_seconds=1.0,
        )
        assert r.certificates_total == 0
        assert r.keys_total == 0
        assert r.certificates_added == 0
        assert r.keys_removed == 0

    def test_to_dict_returns_dict(self):
        from recon_api.services.inventory import SyncResult
        r = SyncResult(
            project_id="p1", scan_id="s1", success=True,
            started_at="2026-04-03", completed_at="2026-04-03",
            duration_seconds=0.5,
        )
        d = r.to_dict()
        assert isinstance(d, dict)
        assert d["project_id"] == "p1"
        assert d["success"] is True

    def test_error_state(self):
        from recon_api.services.inventory import SyncResult
        r = SyncResult(
            project_id="p1", scan_id="s1", success=False,
            started_at="2026-04-03", completed_at="2026-04-03",
            duration_seconds=0.0,
            error_message="connection timeout",
        )
        assert r.success is False
        assert r.error_message == "connection timeout"


class TestInventoryServiceImports:
    def test_imports(self):
        from recon_api.services.inventory import InventoryService, SyncResult
        assert InventoryService is not None
        assert SyncResult is not None

    def test_no_flask_imports(self):
        import inspect
        from recon_api.services import inventory
        src = inspect.getsource(inventory)
        assert "from flask" not in src
        assert "import flask" not in src
        assert "import requests" not in src
        assert "caip_" not in src

    def test_no_bare_except(self):
        import inspect
        from recon_api.services import inventory
        src = inspect.getsource(inventory)
        lines = src.split("\n")
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped == "except:" or stripped == "except :":
                pytest.fail(f"Bare except at line {i}: {line}")


class TestInventoryHelpers:
    def test_extract_fingerprint(self):
        from recon_api.services.inventory import InventoryService
        assert InventoryService._extract_fingerprint(
            {"fingerprint_sha256": "abc123"}
        ) == "abc123"
        assert InventoryService._extract_fingerprint(
            {"thumbprint": "def456"}
        ) == "def456"
        assert InventoryService._extract_fingerprint({}) is None

    def test_extract_cn_from_dict(self):
        from recon_api.services.inventory import InventoryService
        assert InventoryService._extract_cn(
            {"subject": {"commonName": "test.example.com"}}, "subject"
        ) == "test.example.com"

    def test_extract_cn_from_string(self):
        from recon_api.services.inventory import InventoryService
        assert InventoryService._extract_cn(
            {"issuer": "CN=Root CA,O=Test"}, "issuer"
        ) == "Root CA"

    def test_detect_cert_source(self):
        from recon_api.services.inventory import InventoryService
        assert InventoryService._detect_cert_source(
            {"source_type": "tls"}
        ) == "tls"
        assert InventoryService._detect_cert_source(
            {"source": "Luna HSM: prod"}
        ) == "luna_hsm"
        assert InventoryService._detect_cert_source(
            {"source": "Azure Key Vault"}
        ) == "azure_keyvault"

    def test_compute_days_expiry(self):
        from recon_api.services.inventory import InventoryService
        from datetime import timedelta
        future = datetime.now(timezone.utc) + timedelta(days=30)
        days = InventoryService._compute_days_expiry(future)
        assert 28 <= days <= 32

        past = datetime.now(timezone.utc) - timedelta(days=10)
        days = InventoryService._compute_days_expiry(past)
        assert days < 0

        assert InventoryService._compute_days_expiry(None) is None

    def test_parse_dt_iso(self):
        from recon_api.services.inventory import InventoryService
        dt = InventoryService._parse_dt("2026-04-03T12:00:00+00:00")
        assert dt is not None
        assert dt.tzinfo is not None

    def test_parse_dt_none(self):
        from recon_api.services.inventory import InventoryService
        assert InventoryService._parse_dt(None) is None
        assert InventoryService._parse_dt("not-a-date") is None


# ── Route tests ───────────────────────────────────────────────

class TestInventoryRoutes:
    async def test_requires_auth(self, async_client):
        r = await async_client.get("/api/v1/inventory/")
        assert r.status_code in (401, 403)

    async def test_project_summary_requires_auth(self, async_client):
        r = await async_client.get("/api/v1/inventory/fake-id/")
        assert r.status_code in (401, 403)

    async def test_certificates_requires_auth(self, async_client):
        r = await async_client.get("/api/v1/inventory/fake-id/certificates/")
        assert r.status_code in (401, 403)

    async def test_lifecycle_requires_auth(self, async_client):
        r = await async_client.get("/api/v1/inventory/fake-id/lifecycle/")
        assert r.status_code in (401, 403)

    async def test_promote_requires_auth(self, async_client):
        r = await async_client.post("/api/v1/inventory/fake-id/scans/s1/promote/")
        assert r.status_code in (401, 403)


class TestInventorySummaryStructure:
    def test_summary_keys(self):
        """get_inventory_summary should return dict with expected keys."""
        expected_keys = {
            "total_certificates", "active_certificates",
            "expiring_30_days", "expiring_90_days",
            "promoted_certificates",
            "total_keys", "active_keys", "promoted_keys",
        }
        # Verify the method exists and would return these keys
        from recon_api.services.inventory import InventoryService
        import inspect
        src = inspect.getsource(InventoryService.get_inventory_summary)
        for key in expected_keys:
            assert key in src, f"Missing key in summary: {key}"
