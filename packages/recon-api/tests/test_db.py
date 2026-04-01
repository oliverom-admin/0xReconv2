"""
Database pool and health endpoint tests.

Marked integration tests require a running database container.
Unit tests run without any external dependencies.
"""
from __future__ import annotations

import pytest


class TestHealthEndpoint:
    """Health endpoint tests — use the existing async_client fixture."""

    async def test_health_returns_200(self, async_client):
        r = await async_client.get("/api/v1/health/")
        assert r.status_code == 200

    async def test_health_has_required_fields(self, async_client):
        data = (await async_client.get("/api/v1/health/")).json()
        assert "status" in data
        assert "version" in data
        assert "db_connected" in data

    async def test_health_db_connected_is_bool(self, async_client):
        data = (await async_client.get("/api/v1/health/")).json()
        assert isinstance(data["db_connected"], bool)

    async def test_health_status_valid_values(self, async_client):
        data = (await async_client.get("/api/v1/health/")).json()
        assert data["status"] in ("ok", "degraded")

    async def test_health_no_auth_required(self, async_client):
        r = await async_client.get("/api/v1/health/")
        assert r.status_code not in (401, 403)

    async def test_product_config_still_works(self, async_client):
        """Phase 1 product config endpoint must continue to work."""
        r = await async_client.get("/api/v1/product/config/")
        assert r.status_code == 200
        data = r.json()
        assert "product_id" in data
