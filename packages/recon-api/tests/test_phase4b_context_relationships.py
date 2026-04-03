"""Tests for Phase 4B — AssetContextService, RelationshipService, EnvironmentInference, routes."""
from __future__ import annotations

import pytest


# ── AssetContextService tests ─────────────────────────────────

class TestAssetContextServiceImports:
    def test_imports(self):
        from recon_api.services.asset_context import AssetContextService
        assert AssetContextService is not None

    def test_no_bare_except(self):
        import inspect
        from recon_api.services import asset_context
        src = inspect.getsource(asset_context)
        for i, line in enumerate(src.split("\n"), 1):
            stripped = line.strip()
            if stripped == "except:" or stripped == "except :":
                pytest.fail(f"Bare except at line {i}")

    def test_merge_confidence_logic_present(self):
        import inspect
        from recon_api.services.asset_context import AssetContextService
        src = inspect.getsource(AssetContextService.merge_auto_discovered)
        assert "discovery_confidence" in src
        assert "manual" in src


# ── RelationshipService tests ─────────────────────────────────

class TestRelationshipServiceImports:
    def test_imports(self):
        from recon_api.services.relationships import RelationshipService
        assert RelationshipService is not None

    def test_no_bare_except(self):
        import inspect
        from recon_api.services import relationships
        src = inspect.getsource(relationships)
        for i, line in enumerate(src.split("\n"), 1):
            stripped = line.strip()
            if stripped == "except:" or stripped == "except :":
                pytest.fail(f"Bare except at line {i}")


# ── EnvironmentInferenceService tests ─────────────────────────

class TestEnvironmentInferenceImports:
    def test_imports(self):
        from recon_api.services.environment_inference import (
            EnvironmentInferenceService,
        )
        assert EnvironmentInferenceService is not None


class TestInferFromHostname:
    def test_production_patterns(self):
        from recon_api.services.environment_inference import (
            EnvironmentInferenceService as EIS,
        )
        for h in ["prod-api.example.com", "production.corp.com", "www.example.com"]:
            sig = EIS.infer_from_hostname(h)
            assert sig is not None, f"No signal for {h}"
            assert sig["environment_type"] == "production"
            assert sig["confidence"] == 0.7

    def test_dev_patterns(self):
        from recon_api.services.environment_inference import (
            EnvironmentInferenceService as EIS,
        )
        for h in ["dev-api.example.com", "development.corp.com", "localhost"]:
            sig = EIS.infer_from_hostname(h)
            assert sig is not None
            assert sig["environment_type"] == "development"

    def test_staging_patterns(self):
        from recon_api.services.environment_inference import (
            EnvironmentInferenceService as EIS,
        )
        for h in ["staging.corp.com", "uat-api.example.com", "stg.corp.com"]:
            sig = EIS.infer_from_hostname(h)
            assert sig is not None
            assert sig["environment_type"] == "staging"

    def test_testing_patterns(self):
        from recon_api.services.environment_inference import (
            EnvironmentInferenceService as EIS,
        )
        for h in ["test-api.corp.com", "qa.example.com"]:
            sig = EIS.infer_from_hostname(h)
            assert sig is not None
            assert sig["environment_type"] == "testing"

    def test_no_keyword_port_443(self):
        from recon_api.services.environment_inference import (
            EnvironmentInferenceService as EIS,
        )
        sig = EIS.infer_from_hostname("api.example.com", port=443)
        assert sig is not None
        assert sig["environment_type"] == "production"
        assert sig["confidence"] == 0.5

    def test_no_signal_returns_none(self):
        from recon_api.services.environment_inference import (
            EnvironmentInferenceService as EIS,
        )
        sig = EIS.infer_from_hostname("api.example.com")
        assert sig is None

    def test_empty_hostname_returns_none(self):
        from recon_api.services.environment_inference import (
            EnvironmentInferenceService as EIS,
        )
        assert EIS.infer_from_hostname("") is None
        assert EIS.infer_from_hostname(None) is None


class TestInferFromInfrastructureTier:
    def test_standard_ports(self):
        from recon_api.services.environment_inference import (
            EnvironmentInferenceService as EIS,
        )
        sig = EIS.infer_from_infrastructure_tier("api.example.com", 443)
        assert sig is not None
        assert sig["environment_type"] == "production"

    def test_high_port_dev(self):
        from recon_api.services.environment_inference import (
            EnvironmentInferenceService as EIS,
        )
        sig = EIS.infer_from_infrastructure_tier("api.example.com", 8000)
        assert sig is not None
        assert sig["environment_type"] == "development"

    def test_private_ip(self):
        from recon_api.services.environment_inference import (
            EnvironmentInferenceService as EIS,
        )
        sig = EIS.infer_from_infrastructure_tier(
            "api.internal", 8080, ip="192.168.1.10"
        )
        assert sig is not None
        assert sig["environment_type"] == "development"


class TestFuseSignals:
    def test_highest_confidence_wins(self):
        from recon_api.services.environment_inference import (
            EnvironmentInferenceService as EIS,
        )
        signals = [
            {"signal_type": "hostname", "environment_type": "development",
             "confidence": 0.5},
            {"signal_type": "infrastructure_tier", "environment_type": "production",
             "confidence": 0.7},
        ]
        result = EIS.fuse_signals(signals)
        assert result is not None
        assert result["environment_type"] == "production"
        assert result["confidence"] == 0.7

    def test_empty_returns_none(self):
        from recon_api.services.environment_inference import (
            EnvironmentInferenceService as EIS,
        )
        assert EIS.fuse_signals([]) is None

    def test_none_signals_filtered(self):
        from recon_api.services.environment_inference import (
            EnvironmentInferenceService as EIS,
        )
        assert EIS.fuse_signals([None, None]) is None


class TestInferConvenience:
    def test_prod_hostname_and_port(self):
        from recon_api.services.environment_inference import (
            EnvironmentInferenceService as EIS,
        )
        result = EIS.infer(hostname="prod-api.example.com", port=443)
        assert result is not None
        assert result["environment_type"] == "production"

    def test_no_input_returns_none(self):
        from recon_api.services.environment_inference import (
            EnvironmentInferenceService as EIS,
        )
        assert EIS.infer() is None


# ── Route tests ───────────────────────────────────────────────

class TestContextRoutes:
    async def test_context_list_requires_auth(self, async_client):
        r = await async_client.get("/api/v1/assets/fake-id/context/")
        assert r.status_code in (401, 403)

    async def test_context_statistics_requires_auth(self, async_client):
        r = await async_client.get("/api/v1/assets/fake-id/context/statistics/")
        assert r.status_code in (401, 403)

    async def test_context_post_requires_auth(self, async_client):
        r = await async_client.post(
            "/api/v1/assets/fake-id/context/",
            json={"asset_id": "x", "asset_type": "certificate"},
        )
        assert r.status_code in (401, 403)

    async def test_context_delete_requires_auth(self, async_client):
        r = await async_client.delete("/api/v1/assets/fake-id/context/x/")
        assert r.status_code in (401, 403)


class TestRelationshipRoutes:
    async def test_relationships_list_requires_auth(self, async_client):
        r = await async_client.get("/api/v1/assets/fake-id/relationships/")
        assert r.status_code in (401, 403)

    async def test_relationships_post_requires_auth(self, async_client):
        r = await async_client.post(
            "/api/v1/assets/fake-id/relationships/",
            json={
                "source_id": "a", "source_type": "certificate",
                "target_id": "b", "target_type": "certificate",
                "relationship_type": "chains_to",
            },
        )
        assert r.status_code in (401, 403)

    async def test_infer_requires_auth(self, async_client):
        r = await async_client.post("/api/v1/assets/fake-id/relationships/infer/")
        assert r.status_code in (401, 403)
