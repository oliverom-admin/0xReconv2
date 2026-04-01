"""
Project management routes.

GET    /api/v1/projects/                       — list (scoped to user)
POST   /api/v1/projects/                       — create (provisions CA)
GET    /api/v1/projects/{id}/                  — get detail
PUT    /api/v1/projects/{id}/                  — update
DELETE /api/v1/projects/{id}/                  — archive (soft delete)
POST   /api/v1/projects/{id}/users/            — assign user
DELETE /api/v1/projects/{id}/users/{user_id}/  — remove user
"""
from __future__ import annotations

from typing import Any

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from recon_api.dependencies.auth import get_current_user
from recon_api.dependencies.db import get_db_conn
from recon_api.models.common import SuccessResponse
from recon_api.services.certificate import CertificateService
from recon_api.services.rbac import RBACService

logger = structlog.get_logger("recon.projects.router")
router = APIRouter(prefix="/projects", tags=["projects"])


class CreateProjectRequest(BaseModel):
    name: str
    client_name: str | None = None
    description: str | None = None


class UpdateProjectRequest(BaseModel):
    name: str | None = None
    client_name: str | None = None
    description: str | None = None
    status: str | None = None


class AssignUserRequest(BaseModel):
    user_id: str
    role: str = "analyst"


async def _check_permission(
    project_id: str, permission: str, user: dict[str, Any], conn: asyncpg.Connection,
) -> None:
    if user["is_system_admin"]:
        return
    ok = await RBACService(conn).has_permission(
        user["id"], permission, project_id=project_id
    )
    if not ok:
        raise HTTPException(status_code=403, detail="Insufficient permissions")


@router.get("/", response_model=SuccessResponse)
async def list_projects(
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    if user["is_system_admin"]:
        rows = await conn.fetch(
            "SELECT id, name, client_name, description, status, "
            "is_active, created_at, updated_at FROM projects ORDER BY name"
        )
    else:
        rows = await conn.fetch(
            """
            SELECT p.id, p.name, p.client_name, p.description,
                   p.status, p.is_active, p.created_at, p.updated_at
            FROM projects p
            JOIN project_users pu ON pu.project_id = p.id
            WHERE pu.user_id = $1 AND p.is_active = true
            ORDER BY p.name
            """,
            user["id"],
        )
    return {"data": [dict(r) for r in rows], "meta": {"total": len(rows)}}


@router.post("/", response_model=SuccessResponse, status_code=201)
async def create_project(
    body: CreateProjectRequest,
    request: Request,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    if not user["is_system_admin"]:
        ok = await RBACService(conn).has_permission(user["id"], "projects:create")
        if not ok:
            raise HTTPException(status_code=403, detail="Insufficient permissions")

    pid = await conn.fetchval(
        """
        INSERT INTO projects (name, client_name, description, created_by)
        VALUES ($1, $2, $3, $4) RETURNING id
        """,
        body.name, body.client_name, body.description, user["id"],
    )

    await RBACService(conn).assign_role(user["id"], "project-admin", pid, user["id"])

    try:
        vault = request.app.state.vault
        cert_svc = CertificateService(conn, vault)
        await cert_svc.ensure_project_ca(pid)
        logger.info("project_ca_provisioned", project_id=pid)
    except Exception as exc:
        logger.error("project_ca_provision_failed", project_id=pid, error=str(exc))

    return {"data": {"id": pid, "name": body.name}, "meta": {}}


@router.get("/{pid}/", response_model=SuccessResponse)
async def get_project(
    pid: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_permission(pid, "projects:read", user, conn)
    row = await conn.fetchrow(
        "SELECT id, name, client_name, description, status, "
        "is_active, created_at, updated_at FROM projects WHERE id=$1",
        pid,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Project not found")
    return {"data": dict(row), "meta": {}}


@router.put("/{pid}/", response_model=SuccessResponse)
async def update_project(
    pid: str,
    body: UpdateProjectRequest,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_permission(pid, "projects:update", user, conn)
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update")
    set_clause = ", ".join(f"{k}=${i+2}" for i, k in enumerate(updates))
    await conn.execute(
        f"UPDATE projects SET {set_clause}, updated_at=NOW() WHERE id=$1",
        pid, *updates.values(),
    )
    return {"data": {"id": pid, "updated": list(updates)}, "meta": {}}


@router.delete("/{pid}/", response_model=SuccessResponse)
async def archive_project(
    pid: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_permission(pid, "projects:delete", user, conn)
    await conn.execute(
        "UPDATE projects SET is_active=false, archived_at=NOW(), updated_at=NOW() WHERE id=$1",
        pid,
    )
    return {"data": {"id": pid, "archived": True}, "meta": {}}


@router.post("/{pid}/users/", response_model=SuccessResponse, status_code=201)
async def assign_user(
    pid: str,
    body: AssignUserRequest,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_permission(pid, "projects:assign_users", user, conn)
    await conn.execute(
        """
        INSERT INTO project_users (project_id, user_id, role, assigned_by)
        VALUES ($1,$2,$3,$4)
        ON CONFLICT (project_id, user_id) DO UPDATE SET role=$3
        """,
        pid, body.user_id, body.role, user["id"],
    )
    return {"data": {"project_id": pid, "user_id": body.user_id, "role": body.role}, "meta": {}}


@router.delete("/{pid}/users/{target_uid}/", response_model=SuccessResponse)
async def remove_user(
    pid: str,
    target_uid: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_permission(pid, "projects:assign_users", user, conn)
    await conn.execute(
        "DELETE FROM project_users WHERE project_id=$1 AND user_id=$2",
        pid, target_uid,
    )
    return {"data": {"removed": True}, "meta": {}}
