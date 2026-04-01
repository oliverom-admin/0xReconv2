"""
Authentication routes.

Public:  POST /api/v1/auth/login/, GET /api/v1/auth/providers/, GET /api/v1/auth/oauth/login/
Protected: GET /api/v1/auth/me/, POST /api/v1/auth/logout/
"""
from __future__ import annotations

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from recon_api.dependencies.auth import get_current_user
from recon_api.dependencies.db import get_db_conn
from recon_api.models.common import SuccessResponse
from recon_api.services.auth import AuthService, create_access_token

logger = structlog.get_logger("recon.auth.router")
router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login/", response_model=SuccessResponse)
async def login(
    body: LoginRequest,
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    svc = AuthService(conn)
    user = await svc.authenticate_local(body.username, body.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    token = create_access_token(
        user_id=user["id"],
        username=user["username"],
        is_system_admin=user["is_system_admin"],
    )
    return {
        "data": {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": 8 * 3600,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "is_system_admin": user["is_system_admin"],
            },
        },
        "meta": {},
    }


@router.get("/me/", response_model=SuccessResponse)
async def me(user: dict = Depends(get_current_user)) -> dict:
    return {
        "data": {
            "id": user["id"],
            "username": user["username"],
            "email": user.get("email"),
            "is_system_admin": user["is_system_admin"],
            "last_login_at": str(user.get("last_login_at") or ""),
        },
        "meta": {},
    }


@router.post("/logout/", response_model=SuccessResponse)
async def logout(user: dict = Depends(get_current_user)) -> dict:
    logger.info("auth_logout", username=user["username"])
    return {"data": {"message": "Logged out"}, "meta": {}}


@router.get("/providers/", response_model=SuccessResponse)
async def list_providers(
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    svc = AuthService(conn)
    providers = await svc.list_auth_providers()
    return {"data": providers, "meta": {"total": len(providers)}}


@router.get("/oauth/login/", response_model=SuccessResponse)
async def oauth_login(
    provider_id: str = Query(...),
    redirect_uri: str = Query(...),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    svc = AuthService(conn)
    url = await svc.get_oauth_login_url(provider_id, redirect_uri)
    if not url:
        raise HTTPException(status_code=404, detail="Provider not found or OAuth not configured")
    return {"data": {"authorization_url": url}, "meta": {}}
