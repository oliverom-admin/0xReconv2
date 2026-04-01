"""
JWT authentication FastAPI dependencies.

get_current_user: Validates Bearer token, returns user dict. HTTP 401/403 on failure.
require_system_admin: Wraps get_current_user, requires is_system_admin=True.
"""
from __future__ import annotations

from typing import Any

import asyncpg
import structlog
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError

from recon_api.dependencies.db import get_db_conn
from recon_api.services.auth import AuthService, decode_access_token

logger = structlog.get_logger("recon.auth.dep")

_bearer = HTTPBearer(auto_error=True)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict[str, Any]:
    """Validate Bearer JWT and return authenticated user dict."""
    try:
        payload = decode_access_token(credentials.credentials)
    except JWTError as exc:
        logger.info("jwt_invalid", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id: str | None = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject claim",
        )

    svc = AuthService(conn)
    user = await svc.get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account inactive",
        )
    return user


async def require_system_admin(
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    """Require is_system_admin = True. Raises HTTP 403 otherwise."""
    if not user.get("is_system_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="System administrator access required",
        )
    return user
