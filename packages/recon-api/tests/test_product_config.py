"""Tests for GET /api/v1/product/config/"""
from __future__ import annotations
import pytest


class TestProductConfig:

    async def test_returns_200(self, async_client):
        response = await async_client.get("/api/v1/product/config/")
        assert response.status_code == 200

    async def test_response_shape(self, async_client):
        data = (await async_client.get("/api/v1/product/config/")).json()
        for field in (
            "product_id", "product_name", "product_short_name",
            "logo_url", "favicon_url", "accent_colour",
            "terminology", "feature_flags",
        ):
            assert field in data, f"Missing: {field}"

    async def test_terminology_keys(self, async_client):
        data = (await async_client.get("/api/v1/product/config/")).json()
        for key in ("engagement", "collector", "finding", "scan", "assessment"):
            assert key in data["terminology"], f"Missing terminology key: {key}"

    async def test_feature_flags_are_booleans(self, async_client):
        data = (await async_client.get("/api/v1/product/config/")).json()
        for k, v in data["feature_flags"].items():
            assert isinstance(v, bool), f"Flag '{k}' must be bool"

    async def test_reads_from_env(self, async_client, monkeypatch):
        from recon_api.config import get_product_config
        monkeypatch.setenv("PRODUCT_ID", "testbrand")
        monkeypatch.setenv("PRODUCT_NAME", "TestBrand")
        get_product_config.cache_clear()

        data = (await async_client.get("/api/v1/product/config/")).json()
        assert data["product_id"] == "testbrand"
        assert data["product_name"] == "TestBrand"

        get_product_config.cache_clear()

    async def test_accent_colour_is_hex(self, async_client):
        data = (await async_client.get("/api/v1/product/config/")).json()
        colour = data["accent_colour"]
        assert colour.startswith("#")
        assert len(colour) in (4, 7)

    async def test_no_auth_required(self, async_client):
        response = await async_client.get("/api/v1/product/config/")
        assert response.status_code not in (401, 403)
