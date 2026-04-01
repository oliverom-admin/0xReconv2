"""
AuthService — JWT creation/validation and local credential authentication.

JWT algorithm: RS256 in production, HS256 fallback in development.
Token lifetime: RECON_JWT_EXPIRY_HOURS (default 8).
bcrypt cost factor: 12 (matches legacy system).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import asyncpg
import bcrypt
import structlog
from jose import JWTError, jwt

from recon_api.config import get_settings

logger = structlog.get_logger("recon.auth")

_HS256_SECRET: str | None = None


def _get_hs256_secret() -> str:
    global _HS256_SECRET
    if _HS256_SECRET is None:
        _HS256_SECRET = get_settings().secret_key
    return _HS256_SECRET


def _load_private_key() -> str | None:
    path = get_settings().jwt_private_key_path
    if path and Path(path).exists():
        return Path(path).read_text()
    return None


def _load_public_key() -> str | None:
    path = get_settings().jwt_public_key_path
    if path and Path(path).exists():
        return Path(path).read_text()
    return None


def create_access_token(
    user_id: str, username: str, is_system_admin: bool
) -> str:
    """Create and sign a JWT access token."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": user_id,
        "username": username,
        "is_system_admin": is_system_admin,
        "iat": now,
        "exp": now + timedelta(hours=settings.jwt_expiry_hours),
        "jti": str(uuid.uuid4()),
    }
    private_key = _load_private_key()
    if private_key:
        return jwt.encode(payload, private_key, algorithm="RS256")
    logger.warning("jwt_hs256_fallback",
                   reason="RS256 key not configured, using HS256 dev fallback")
    return jwt.encode(payload, _get_hs256_secret(), algorithm="HS256")


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT. Raises jose.JWTError on failure."""
    public_key = _load_public_key()
    if public_key:
        return jwt.decode(token, public_key, algorithms=["RS256"])
    return jwt.decode(token, _get_hs256_secret(), algorithms=["HS256"])


def hash_password(plaintext: str) -> str:
    """Return a bcrypt hash of the plaintext password. Cost factor: 12."""
    return bcrypt.hashpw(
        plaintext.encode(), bcrypt.gensalt(rounds=12)
    ).decode()


def verify_password(plaintext: str, hashed: str) -> bool:
    """Return True if plaintext matches the bcrypt hash."""
    try:
        return bcrypt.checkpw(plaintext.encode(), hashed.encode())
    except Exception:
        return False


class AuthService:
    """Handles user authentication and OAuth provider management."""

    def __init__(self, db: asyncpg.Connection) -> None:
        self._db = db

    async def authenticate_local(
        self, username: str, password: str
    ) -> dict[str, Any] | None:
        row = await self._db.fetchrow(
            "SELECT id, username, password_hash, is_active, is_system_admin "
            "FROM users WHERE username = $1",
            username,
        )
        if not row:
            logger.info("auth_user_not_found", username=username)
            return None
        if not row["is_active"]:
            logger.info("auth_user_inactive", username=username)
            return None
        if not row["password_hash"]:
            logger.info("auth_no_local_password", username=username)
            return None
        if not verify_password(password, row["password_hash"]):
            logger.info("auth_wrong_password", username=username)
            return None

        await self._db.execute(
            "UPDATE users SET last_login_at = NOW() WHERE id = $1",
            row["id"],
        )
        logger.info("auth_login_success", username=username)
        return dict(row)

    async def get_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        row = await self._db.fetchrow(
            "SELECT id, username, email, is_active, is_system_admin, "
            "last_login_at, created_at FROM users WHERE id = $1",
            user_id,
        )
        return dict(row) if row else None

    async def list_auth_providers(self) -> list[dict]:
        rows = await self._db.fetch(
            "SELECT id, name, provider_type, is_enabled, auto_provision "
            "FROM auth_providers WHERE is_enabled = true ORDER BY name"
        )
        return [dict(r) for r in rows]

    async def get_oauth_login_url(
        self, provider_id: str, redirect_uri: str
    ) -> str | None:
        row = await self._db.fetchrow(
            "SELECT id, name, provider_type FROM auth_providers "
            "WHERE id = $1 AND is_enabled = true",
            provider_id,
        )
        if not row:
            return None
        logger.warning("oauth_login_url_stub", provider_id=provider_id)
        return None
