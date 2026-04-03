"""
Aggregation routes.

POST   /api/v1/aggregations/{project_id}/
GET    /api/v1/aggregations/{project_id}/
GET    /api/v1/aggregations/{project_id}/{id}/
GET    /api/v1/aggregations/{project_id}/{id}/result/
DELETE /api/v1/aggregations/{project_id}/{id}/
"""
from __future__ import annotations

from typing import Any

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from recon_api.dependencies.auth import get_current_user
from recon_api.dependencies.db import get_db_conn
from recon_api.models.common import SuccessResponse
from recon_api.services.aggregation import AggregationService
from recon_api.services.rbac import RBACService

logger = structlog.get_logger("recon.aggregations.router")
router = APIRouter(prefix="/aggregations", tags=["aggregations"])


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


class CreateAggregationRequest(BaseModel):
    name: str
    source_scan_ids: list[str]
    merge_strategy: str = "union"


@router.post("/{project_id}/", response_model=SuccessResponse, status_code=202)
async def create_aggregation(
    project_id: str,
    body: CreateAggregationRequest,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = AggregationService(conn)
    try:
        result = await svc.create_aggregation(
            project_id=project_id,
            name=body.name,
            source_scan_ids=body.source_scan_ids,
            merge_strategy=body.merge_strategy,
            created_by=user.get("id"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"data": result, "meta": {}}


@router.get("/{project_id}/", response_model=SuccessResponse)
async def list_aggregations(
    project_id: str,
    status: str | None = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = AggregationService(conn)
    items = await svc.list_aggregations(project_id, status, limit, offset)
    return {"data": items, "meta": {"total": len(items)}}


@router.get("/{project_id}/{aggregation_id}/", response_model=SuccessResponse)
async def get_aggregation(
    project_id: str,
    aggregation_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = AggregationService(conn)
    rec = await svc.get_aggregation(aggregation_id, project_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Aggregation not found")
    return {"data": rec, "meta": {}}


@router.get("/{project_id}/{aggregation_id}/result/", response_model=SuccessResponse)
async def get_aggregation_result(
    project_id: str,
    aggregation_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = AggregationService(conn)
    rec = await svc.get_aggregation_result(aggregation_id, project_id)
    if not rec:
        raise HTTPException(
            status_code=404,
            detail="Aggregation result not available — job may still be running",
        )
    return {"data": rec, "meta": {}}


@router.delete("/{project_id}/{aggregation_id}/", response_model=SuccessResponse)
async def delete_aggregation(
    project_id: str,
    aggregation_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    tag = await conn.execute(
        """UPDATE report_aggregations SET status = 'deleted', updated_at = NOW()
           WHERE id = $1 AND project_id = $2 AND status != 'deleted'""",
        aggregation_id, project_id,
    )
    if not tag or not tag.endswith("1"):
        raise HTTPException(status_code=404, detail="Aggregation not found")
    return {"data": {"deleted": True}, "meta": {}}
