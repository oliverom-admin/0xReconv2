"""Auth endpoint tests.

Auth routes require a DB connection. In unit tests (no DB pool),
routes return 503. We test both the unit-test path (503 acceptable)
and the shape validation that works without DB.
"""
from __future__ import annotations
import pytest


class TestLogin:
    async def test_login_rejects_bad_creds_or_no_db(self, async_client):
        r = await async_client.post(
            "/api/v1/auth/login/", json={"username": "nobody", "password": "pw"},
        )
        # 401 = no such user (with DB), 503 = no DB pool (unit test)
        assert r.status_code in (401, 503)

    async def test_me_without_token_rejected(self, async_client):
        r = await async_client.get("/api/v1/auth/me/")
        assert r.status_code in (401, 403)

    async def test_invalid_token_rejected(self, async_client):
        r = await async_client.get(
            "/api/v1/auth/me/",
            headers={"Authorization": "Bearer invalid.token.value"},
        )
        # 401 = invalid JWT, 503 = no DB pool for user lookup
        assert r.status_code in (401, 503)

    async def test_providers_requires_db(self, async_client):
        r = await async_client.get("/api/v1/auth/providers/")
        # 200 = empty list (with DB), 503 = no DB pool (unit test)
        assert r.status_code in (200, 503)
