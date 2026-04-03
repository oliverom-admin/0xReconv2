"""
Asset context routes — business enrichment per asset.

GET    /api/v1/assets/{project_id}/context/
POST   /api/v1/assets/{project_id}/context/
GET    /api/v1/assets/{project_id}/context/{asset_id}/
PUT    /api/v1/assets/{project_id}/context/{asset_id}/
DELETE /api/v1/assets/{project_id}/context/{asset_id}/
GET    /api/v1/assets/{project_id}/context/statistics/
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
from recon_api.services.asset_context import AssetContextService
from recon_api.services.rbac import RBACService

logger = structlog.get_logger("recon.asset_context.router")
router = APIRouter(prefix="/assets", tags=["assets"])


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


class ContextCreateRequest(BaseModel):
    asset_id: str
    asset_type: str
    asset_name: str | None = None
    business_unit: str | None = None
    business_function: str | None = None
    data_classification: str | None = None
    dependencies: str | None = None
    compliance_scope: str | None = None
    migration_path: str | None = None
    owner: str | None = None
    notes: str | None = None
    environment_type: str | None = None
    service_name: str | None = None
    application_name: str | None = None
    override_enabled: bool | None = None
    override_score: int | None = None
    override_reason: str | None = None


class ContextUpdateRequest(BaseModel):
    asset_name: str | None = None
    business_unit: str | None = None
    business_function: str | None = None
    data_classification: str | None = None
    dependencies: str | None = None
    compliance_scope: str | None = None
    migration_path: str | None = None
    owner: str | None = None
    notes: str | None = None
    environment_type: str | None = None
    service_name: str | None = None
    application_name: str | None = None
    override_enabled: bool | None = None
    override_score: int | None = None
    override_reason: str | None = None


@router.get("/{project_id}/context/", response_model=SuccessResponse)
async def list_context(
    project_id: str,
    asset_type: str | None = Query(None),
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = AssetContextService(conn)
    items = await svc.get_project_context(project_id, asset_type)
    return {"data": items, "meta": {"total": len(items)}}


@router.post("/{project_id}/context/", response_model=SuccessResponse)
async def create_context(
    project_id: str,
    body: ContextCreateRequest,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = AssetContextService(conn)
    fields = body.model_dump(exclude_none=True)
    asset_id = fields.pop("asset_id")
    asset_type = fields.pop("asset_type")
    fields["changed_by"] = user["username"]
    result = await svc.upsert_context(project_id, asset_id, asset_type, **fields)
    return {"data": result, "meta": {}}


@router.get("/{project_id}/context/statistics/", response_model=SuccessResponse)
async def context_statistics(
    project_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = AssetContextService(conn)
    stats = await svc.get_context_statistics(project_id)
    return {"data": stats, "meta": {}}


@router.get("/{project_id}/context/{asset_id}/", response_model=SuccessResponse)
async def get_context(
    project_id: str,
    asset_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = AssetContextService(conn)
    ctx = await svc.get_context(project_id, asset_id)
    if not ctx:
        raise HTTPException(status_code=404, detail="Asset context not found")
    return {"data": ctx, "meta": {}}


@router.put("/{project_id}/context/{asset_id}/", response_model=SuccessResponse)
async def update_context(
    project_id: str,
    asset_id: str,
    body: ContextUpdateRequest,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = AssetContextService(conn)
    existing = await svc.get_context(project_id, asset_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Asset context not found")
    fields = body.model_dump(exclude_none=True)
    fields["changed_by"] = user["username"]
    result = await svc.upsert_context(
        project_id, asset_id, existing["asset_type"], **fields
    )
    return {"data": result, "meta": {}}


@router.delete("/{project_id}/context/{asset_id}/", response_model=SuccessResponse)
async def delete_context(
    project_id: str,
    asset_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = AssetContextService(conn)
    result = await svc.delete_context(project_id, asset_id, user["username"])
    return {"data": result, "meta": {}}
