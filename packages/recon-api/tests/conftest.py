"""Shared test fixtures."""
from __future__ import annotations

import os

import pytest
from httpx import ASGITransport, AsyncClient

# Set environment before importing the app
os.environ.setdefault("RECON_ENV", "development")
os.environ.setdefault("RECON_DEBUG", "true")
os.environ.setdefault("RECON_SECRET_KEY", "test_secret_key_for_tests_only")
os.environ.setdefault("RECON_DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("RECON_DATABASE_URL_SYNC", "postgresql+psycopg2://test:test@localhost/test")
os.environ.setdefault("RECON_VAULT_MASTER_PASSWORD", "test_vault_password_minimum_32_chars")
os.environ.setdefault("PRODUCT_ID", "0xrecon")
os.environ.setdefault("PRODUCT_NAME", "0xRecon")
os.environ.setdefault("PRODUCT_SHORT_NAME", "0xRecon")


@pytest.fixture
async def async_client():
    """AsyncClient connected to FastAPI test app. No real DB required."""
    from recon_api.config import get_settings, get_product_config
    from recon_api.main import create_app

    get_settings.cache_clear()
    get_product_config.cache_clear()

    app = create_app()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client

    get_settings.cache_clear()
    get_product_config.cache_clear()
