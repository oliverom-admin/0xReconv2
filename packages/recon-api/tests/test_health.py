"""Tests for GET /api/v1/health/"""
from __future__ import annotations
import pytest


class TestHealth:

    async def test_returns_200(self, async_client):
        response = await async_client.get("/api/v1/health/")
        assert response.status_code == 200

    async def test_response_shape(self, async_client):
        data = (await async_client.get("/api/v1/health/")).json()
        assert "status" in data
        assert "version" in data
        assert "db_connected" in data

    async def test_db_connected_is_bool(self, async_client):
        data = (await async_client.get("/api/v1/health/")).json()
        assert isinstance(data["db_connected"], bool)

    async def test_phase1_db_not_connected(self, async_client):
        data = (await async_client.get("/api/v1/health/")).json()
        assert data["db_connected"] is False
        assert data["status"] == "degraded"

    async def test_no_auth_required(self, async_client):
        response = await async_client.get("/api/v1/health/")
        assert response.status_code not in (401, 403)
