"""
Asset relationship routes.

GET  /api/v1/assets/{project_id}/relationships/
POST /api/v1/assets/{project_id}/relationships/
GET  /api/v1/assets/{project_id}/relationships/{asset_id}/
POST /api/v1/assets/{project_id}/relationships/infer/
"""
from __future__ import annotations

from typing import Any

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from recon_api.dependencies.auth import get_current_user
from recon_api.dependencies.db import get_db_conn
from recon_api.models.common import SuccessResponse
from recon_api.services.relationships import RelationshipService
from recon_api.services.rbac import RBACService

logger = structlog.get_logger("recon.relationships.router")
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


class CreateRelationshipRequest(BaseModel):
    source_id: str
    source_type: str
    target_id: str
    target_type: str
    relationship_type: str
    confidence: float = 1.0
    evidence: dict[str, Any] | None = None


@router.get("/{project_id}/relationships/", response_model=SuccessResponse)
async def list_relationships(
    project_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = RelationshipService(conn)
    rels = await svc.get_relationships(project_id)
    return {"data": rels, "meta": {"total": len(rels)}}


@router.post("/{project_id}/relationships/", response_model=SuccessResponse)
async def create_relationship(
    project_id: str,
    body: CreateRelationshipRequest,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = RelationshipService(conn)
    result = await svc.create_relationship(
        project_id=project_id,
        source_id=body.source_id,
        source_type=body.source_type,
        target_id=body.target_id,
        target_type=body.target_type,
        relationship_type=body.relationship_type,
        confidence=body.confidence,
        evidence=body.evidence,
    )
    return {"data": result, "meta": {}}


@router.get("/{project_id}/relationships/{asset_id}/", response_model=SuccessResponse)
async def get_asset_relationships(
    project_id: str,
    asset_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = RelationshipService(conn)
    rels = await svc.get_relationships(project_id, asset_id=asset_id)
    return {"data": rels, "meta": {"total": len(rels)}}


@router.post("/{project_id}/relationships/infer/", response_model=SuccessResponse)
async def infer_relationships(
    project_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = RelationshipService(conn)
    # Use empty scan_results_json — infer from existing inventory
    count = await svc.infer_relationships_from_scan(project_id, {})
    return {"data": {"inferred_count": count}, "meta": {}}
