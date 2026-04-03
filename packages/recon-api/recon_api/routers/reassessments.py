"""
Reassessment routes.

POST   /api/v1/reassessments/{project_id}/
GET    /api/v1/reassessments/{project_id}/
GET    /api/v1/reassessments/{project_id}/{id}/
GET    /api/v1/reassessments/{project_id}/{id}/result/
DELETE /api/v1/reassessments/{project_id}/{id}/
"""
from __future__ import annotations

from typing import Any

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from recon_api.dependencies.auth import get_current_user
from recon_api.dependencies.db import get_db_conn
from recon_api.models.common import SuccessResponse
from recon_api.services.reassessment import ReassessmentService
from recon_api.services.rbac import RBACService

logger = structlog.get_logger("recon.reassessments.router")
router = APIRouter(prefix="/reassessments", tags=["reassessments"])


async def _check_project_access(
    project_id: str, user: dict[str, Any], conn: asyncpg.Connection,
) -> None:
    if user["is_system_admin"]:
        return
    ok = await RBACService(conn).has_permission(
        user["id"], "projects:read", project_id=project_id
    )
    if not ok:
        raise HTTPException(status_code=403, detail="Insufficient permissions")


class CreateReassessmentRequest(BaseModel):
    name: str
    original_scan_id: str
    policy_id: str


@router.post("/{project_id}/", response_model=SuccessResponse, status_code=202)
async def create_reassessment(
    project_id: str,
    body: CreateReassessmentRequest,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = ReassessmentService(conn)
    try:
        result = await svc.create_reassessment(
            project_id=project_id,
            name=body.name,
            original_scan_id=body.original_scan_id,
            policy_id=body.policy_id,
            created_by=user.get("id"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"data": result, "meta": {}}


@router.get("/{project_id}/", response_model=SuccessResponse)
async def list_reassessments(
    project_id: str,
    status: str | None = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = ReassessmentService(conn)
    items = await svc.list_reassessments(project_id, status, limit, offset)
    return {"data": items, "meta": {"total": len(items)}}


@router.get("/{project_id}/{reassessment_id}/", response_model=SuccessResponse)
async def get_reassessment(
    project_id: str,
    reassessment_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = ReassessmentService(conn)
    rec = await svc.get_reassessment(reassessment_id, project_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Reassessment not found")
    return {"data": rec, "meta": {}}


@router.get("/{project_id}/{reassessment_id}/result/", response_model=SuccessResponse)
async def get_reassessment_result(
    project_id: str,
    reassessment_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = ReassessmentService(conn)
    rec = await svc.get_reassessment_result(reassessment_id, project_id)
    if not rec:
        raise HTTPException(
            status_code=404,
            detail="Reassessment result not available — job may still be running",
        )
    return {"data": rec, "meta": {}}


@router.delete("/{project_id}/{reassessment_id}/", response_model=SuccessResponse)
async def delete_reassessment(
    project_id: str,
    reassessment_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    tag = await conn.execute(
        """UPDATE report_reassessments SET status = 'deleted', updated_at = NOW()
           WHERE id = $1 AND project_id = $2 AND status != 'deleted'""",
        reassessment_id, project_id,
    )
    if not tag or not tag.endswith("1"):
        raise HTTPException(status_code=404, detail="Reassessment not found")
    return {"data": {"deleted": True}, "meta": {}}
