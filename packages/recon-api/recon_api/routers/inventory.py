"""
Inventory routes — CLM inventory queries, lifecycle, promotion.

GET  /api/v1/inventory/                             — admin summary
GET  /api/v1/inventory/{project_id}/                — project summary
GET  /api/v1/inventory/{project_id}/certificates/   — list certificates
GET  /api/v1/inventory/{project_id}/certificates/{id}/ — single cert
GET  /api/v1/inventory/{project_id}/keys/           — list keys
GET  /api/v1/inventory/{project_id}/keys/{id}/      — single key
GET  /api/v1/inventory/{project_id}/lifecycle/       — lifecycle queue
GET  /api/v1/inventory/{project_id}/changes/         — change journal
GET  /api/v1/inventory/{project_id}/sync-status/     — sync health
POST /api/v1/inventory/{project_id}/scans/{scan_id}/promote/ — promote scan
"""
from __future__ import annotations

from typing import Any

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query

from recon_api.dependencies.auth import get_current_user
from recon_api.dependencies.db import get_db_conn
from recon_api.models.common import SuccessResponse
from recon_api.services.inventory import InventoryService
from recon_api.services.rbac import RBACService

logger = structlog.get_logger("recon.inventory.router")
router = APIRouter(prefix="/inventory", tags=["inventory"])


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


# ── Admin summary ─────────────────────────────────────────────

@router.get("/", response_model=SuccessResponse)
async def inventory_admin_summary(
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    """Admin-level inventory summary across all projects."""
    if not user["is_system_admin"]:
        raise HTTPException(status_code=403, detail="System admin required")
    svc = InventoryService(conn)
    # Aggregate across all projects
    row = await conn.fetchrow(
        """SELECT
             count(*) FILTER (WHERE is_active) AS total_certificates
           FROM certificates_inventory"""
    )
    key_row = await conn.fetchrow(
        "SELECT count(*) FILTER (WHERE is_active) AS total_keys FROM keys_inventory"
    )
    return {
        "data": {
            "total_certificates": (row["total_certificates"] if row else 0),
            "total_keys": (key_row["total_keys"] if key_row else 0),
        },
        "meta": {},
    }


# ── Project summary ──────────────────────────────────────────

@router.get("/{project_id}/", response_model=SuccessResponse)
async def inventory_project_summary(
    project_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = InventoryService(conn)
    summary = await svc.get_inventory_summary(project_id)
    return {"data": summary, "meta": {}}


# ── Certificates ──────────────────────────────────────────────

@router.get("/{project_id}/certificates/", response_model=SuccessResponse)
async def list_certificates(
    project_id: str,
    source_type: str | None = Query(None),
    expiring_within_days: int | None = Query(None),
    is_promoted: str | None = Query(None),
    is_active: str | None = Query("true"),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = InventoryService(conn)
    filters: dict[str, Any] = {"limit": limit, "offset": offset}
    if source_type:
        filters["source_type"] = source_type
    if expiring_within_days is not None:
        filters["expiring_within_days"] = expiring_within_days
    if is_promoted and is_promoted.lower() == "true":
        filters["is_promoted"] = True
    if is_active and is_active.lower() == "false":
        filters["include_inactive"] = True

    certs = await svc.get_certificates(project_id, filters)
    total = await svc.count_certificates(project_id, filters)
    return {"data": certs, "meta": {"total": total, "limit": limit, "offset": offset}}


@router.get("/{project_id}/certificates/{cert_id}/", response_model=SuccessResponse)
async def get_certificate(
    project_id: str,
    cert_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    row = await conn.fetchrow(
        "SELECT * FROM certificates_inventory WHERE id=$1 AND project_id=$2",
        cert_id, project_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return {"data": dict(row), "meta": {}}


# ── Keys ──────────────────────────────────────────────────────

@router.get("/{project_id}/keys/", response_model=SuccessResponse)
async def list_keys(
    project_id: str,
    source_type: str | None = Query(None),
    is_active: str | None = Query("true"),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = InventoryService(conn)
    filters: dict[str, Any] = {"limit": limit, "offset": offset}
    if source_type:
        filters["source_type"] = source_type
    if is_active and is_active.lower() == "false":
        filters["include_inactive"] = True

    keys = await svc.get_keys(project_id, filters)
    return {"data": keys, "meta": {"total": len(keys), "limit": limit, "offset": offset}}


@router.get("/{project_id}/keys/{key_id}/", response_model=SuccessResponse)
async def get_key(
    project_id: str,
    key_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    row = await conn.fetchrow(
        "SELECT * FROM keys_inventory WHERE id=$1 AND project_id=$2",
        key_id, project_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"data": dict(row), "meta": {}}


# ── Lifecycle ─────────────────────────────────────────────────

@router.get("/{project_id}/lifecycle/", response_model=SuccessResponse)
async def lifecycle_queue(
    project_id: str,
    threshold_days: int = Query(90),
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = InventoryService(conn)
    queue = await svc.get_lifecycle_queue(project_id, threshold_days)
    return {"data": queue, "meta": {"total": queue["total"]}}


# ── Changes ───────────────────────────────────────────────────

@router.get("/{project_id}/changes/", response_model=SuccessResponse)
async def list_changes(
    project_id: str,
    since: str | None = Query(None),
    limit: int = Query(100),
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = InventoryService(conn)
    changes = await svc.get_recent_changes(project_id, since=since, limit=limit)
    return {"data": changes, "meta": {"total": len(changes)}}


# ── Sync status ───────────────────────────────────────────────

@router.get("/{project_id}/sync-status/", response_model=SuccessResponse)
async def sync_status(
    project_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = InventoryService(conn)
    status = await svc.get_sync_status(project_id)
    return {"data": status, "meta": {"total": len(status)}}


# ── Promote scan ──────────────────────────────────────────────

@router.post("/{project_id}/scans/{scan_id}/promote/", response_model=SuccessResponse)
async def promote_scan(
    project_id: str,
    scan_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = InventoryService(conn)
    result = await svc.promote_from_scan(scan_id, project_id)
    return {"data": result, "meta": {}}
