"""
RBAC management routes.

GET    /api/v1/rbac/roles/                          — list all roles
GET    /api/v1/rbac/roles/{id}/permissions/         — permissions for role
GET    /api/v1/rbac/users/{id}/permissions/         — effective permissions
POST   /api/v1/rbac/users/{id}/roles/               — assign role
DELETE /api/v1/rbac/users/{id}/roles/{role_name}/   — remove role
"""
from __future__ import annotations

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from recon_api.dependencies.auth import get_current_user, require_system_admin
from recon_api.dependencies.db import get_db_conn
from recon_api.models.common import SuccessResponse
from recon_api.services.rbac import RBACService

logger = structlog.get_logger("recon.rbac.router")
router = APIRouter(prefix="/rbac", tags=["rbac"])


class AssignRoleRequest(BaseModel):
    role_name: str
    project_id: str | None = None


@router.get("/roles/", response_model=SuccessResponse)
async def list_roles(
    _user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    svc = RBACService(conn)
    roles = await svc.list_roles()
    return {"data": roles, "meta": {"total": len(roles)}}


@router.get("/roles/{role_id}/permissions/", response_model=SuccessResponse)
async def role_permissions(
    role_id: str,
    _user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    svc = RBACService(conn)
    perms = await svc.list_role_permissions(role_id)
    return {"data": perms, "meta": {"total": len(perms)}}


@router.get("/users/{user_id}/permissions/", response_model=SuccessResponse)
async def user_permissions(
    user_id: str,
    project_id: str | None = Query(None),
    current: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    if not current["is_system_admin"] and current["id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    svc = RBACService(conn)
    perms = await svc.get_user_permissions(user_id, project_id)
    return {"data": sorted(perms), "meta": {"total": len(perms)}}


@router.post("/users/{user_id}/roles/", response_model=SuccessResponse, status_code=201)
async def assign_role(
    user_id: str,
    body: AssignRoleRequest,
    admin: dict = Depends(require_system_admin),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    svc = RBACService(conn)
    await svc.assign_role(user_id, body.role_name, body.project_id, admin["id"])
    return {
        "data": {"user_id": user_id, "role": body.role_name, "project_id": body.project_id},
        "meta": {},
    }


@router.delete("/users/{user_id}/roles/{role_name}/", response_model=SuccessResponse)
async def remove_role(
    user_id: str,
    role_name: str,
    project_id: str | None = Query(None),
    _admin: dict = Depends(require_system_admin),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    svc = RBACService(conn)
    await svc.remove_role(user_id, role_name, project_id)
    return {"data": {"removed": True}, "meta": {}}
