"""
User management routes.

POST   /api/v1/users/bootstrap/   — seed first admin (no auth, idempotent)
GET    /api/v1/users/             — list users (system-admin)
POST   /api/v1/users/             — create user (system-admin)
GET    /api/v1/users/{id}/        — get user (self or system-admin)
PUT    /api/v1/users/{id}/        — update user (self or system-admin)
DELETE /api/v1/users/{id}/        — deactivate user (system-admin)
"""
from __future__ import annotations

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from recon_api.dependencies.auth import get_current_user, require_system_admin
from recon_api.dependencies.db import get_db_conn
from recon_api.models.common import SuccessResponse
from recon_api.services.auth import hash_password

logger = structlog.get_logger("recon.users.router")
router = APIRouter(prefix="/users", tags=["users"])


class BootstrapRequest(BaseModel):
    username: str
    password: str
    email: str | None = None


class CreateUserRequest(BaseModel):
    username: str
    password: str | None = None
    email: str | None = None
    is_system_admin: bool = False


class UpdateUserRequest(BaseModel):
    email: str | None = None
    is_active: bool | None = None
    is_system_admin: bool | None = None
    password: str | None = None


@router.post("/bootstrap/", response_model=SuccessResponse, status_code=201)
async def bootstrap_admin(
    body: BootstrapRequest,
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    existing = await conn.fetchrow(
        "SELECT id FROM users WHERE is_system_admin = true LIMIT 1"
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A system administrator already exists. Bootstrap not needed.",
        )
    if len(body.password) < 8:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must be at least 8 characters",
        )
    user_id = await conn.fetchval(
        """
        INSERT INTO users (username, email, password_hash, is_system_admin)
        VALUES ($1, $2, $3, true) RETURNING id
        """,
        body.username,
        body.email,
        hash_password(body.password),
    )
    logger.info("admin_bootstrap_complete", username=body.username)
    return {
        "data": {"id": user_id, "username": body.username, "is_system_admin": True},
        "meta": {},
    }


@router.get("/", response_model=SuccessResponse)
async def list_users(
    _admin: dict = Depends(require_system_admin),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    rows = await conn.fetch(
        "SELECT id, username, email, is_active, is_system_admin, "
        "last_login_at, created_at FROM users ORDER BY username"
    )
    return {"data": [dict(r) for r in rows], "meta": {"total": len(rows)}}


@router.post("/", response_model=SuccessResponse, status_code=201)
async def create_user(
    body: CreateUserRequest,
    _admin: dict = Depends(require_system_admin),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    existing = await conn.fetchrow(
        "SELECT id FROM users WHERE username=$1", body.username
    )
    if existing:
        raise HTTPException(status_code=409, detail="Username already taken")
    pw = hash_password(body.password) if body.password else None
    uid = await conn.fetchval(
        "INSERT INTO users (username, email, password_hash, is_system_admin) "
        "VALUES ($1,$2,$3,$4) RETURNING id",
        body.username, body.email, pw, body.is_system_admin,
    )
    return {"data": {"id": uid, "username": body.username}, "meta": {}}


@router.get("/{user_id}/", response_model=SuccessResponse)
async def get_user(
    user_id: str,
    current: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    if not current["is_system_admin"] and current["id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    row = await conn.fetchrow(
        "SELECT id, username, email, is_active, is_system_admin, "
        "last_login_at, created_at FROM users WHERE id=$1",
        user_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return {"data": dict(row), "meta": {}}


@router.put("/{user_id}/", response_model=SuccessResponse)
async def update_user(
    user_id: str,
    body: UpdateUserRequest,
    current: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    if not current["is_system_admin"] and current["id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    updates: dict = {}
    if body.email is not None:
        updates["email"] = body.email
    if body.password is not None:
        updates["password_hash"] = hash_password(body.password)
    if current["is_system_admin"]:
        if body.is_active is not None:
            updates["is_active"] = body.is_active
        if body.is_system_admin is not None:
            updates["is_system_admin"] = body.is_system_admin
    if not updates:
        raise HTTPException(status_code=422, detail="No updateable fields provided")
    set_clause = ", ".join(f"{k} = ${i + 2}" for i, k in enumerate(updates))
    await conn.execute(
        f"UPDATE users SET {set_clause}, updated_at = NOW() WHERE id = $1",
        user_id, *updates.values(),
    )
    return {"data": {"id": user_id, "updated": list(updates)}, "meta": {}}


@router.delete("/{user_id}/", response_model=SuccessResponse)
async def deactivate_user(
    user_id: str,
    _admin: dict = Depends(require_system_admin),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await conn.execute(
        "UPDATE users SET is_active=false, updated_at=NOW() WHERE id=$1",
        user_id,
    )
    return {"data": {"id": user_id, "is_active": False}, "meta": {}}
