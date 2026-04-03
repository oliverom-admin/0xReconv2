"""
PKI certificate lifecycle routes — CSR workflow, revocation, renewal.

POST   /api/v1/certificates/{project_id}/csrs/
GET    /api/v1/certificates/{project_id}/csrs/
GET    /api/v1/certificates/{project_id}/csrs/{csr_id}/
POST   /api/v1/certificates/{project_id}/csrs/{csr_id}/approve/
POST   /api/v1/certificates/{project_id}/csrs/{csr_id}/reject/
POST   /api/v1/certificates/{project_id}/revoke/
GET    /api/v1/certificates/{project_id}/revocation-list/
GET    /api/v1/certificates/{project_id}/certs/{serial}/status/
GET    /api/v1/certificates/{project_id}/renewal-queue/
POST   /api/v1/certificates/{project_id}/collectors/{collector_id}/renew/
"""
from __future__ import annotations

from typing import Any

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from recon_api.dependencies.auth import get_current_user
from recon_api.dependencies.db import get_db_conn
from recon_api.models.common import SuccessResponse
from recon_api.services.certificate_lifecycle import CertificateLifecycleService
from recon_api.services.rbac import RBACService

logger = structlog.get_logger("recon.certificates.router")
router = APIRouter(prefix="/certificates", tags=["certificates"])


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


async def _check_admin_access(
    project_id: str, user: dict[str, Any], conn: asyncpg.Connection,
) -> None:
    """Require system-admin or project-admin."""
    if user["is_system_admin"]:
        return
    ok = await RBACService(conn).has_permission(
        user["id"], "projects:update", project_id=project_id
    )
    if not ok:
        raise HTTPException(status_code=403, detail="Admin privileges required")


# ── Request models ────────────────────────────────────────────

class SubmitCSRRequest(BaseModel):
    csr_pem: str
    requested_purpose: str
    collector_id: str | None = None


class RejectCSRRequest(BaseModel):
    rejection_reason: str


class RevokeRequest(BaseModel):
    serial_number: str
    revocation_reason: str = "unspecified"


# ── CSR routes ────────────────────────────────────────────────

@router.post("/{project_id}/csrs/", response_model=SuccessResponse)
async def submit_csr(
    project_id: str,
    body: SubmitCSRRequest,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = CertificateLifecycleService(conn)
    try:
        result = await svc.submit_csr(
            project_id=project_id,
            requester_id=user["id"],
            csr_pem=body.csr_pem,
            requested_purpose=body.requested_purpose,
            collector_id=body.collector_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"data": result, "meta": {}}


@router.get("/{project_id}/csrs/", response_model=SuccessResponse)
async def list_csrs(
    project_id: str,
    status: str | None = Query(None),
    requested_purpose: str | None = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = CertificateLifecycleService(conn)
    items = await svc.list_csrs(project_id, status, requested_purpose, limit, offset)
    return {"data": items, "meta": {"total": len(items)}}


@router.get("/{project_id}/csrs/{csr_id}/", response_model=SuccessResponse)
async def get_csr(
    project_id: str,
    csr_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = CertificateLifecycleService(conn)
    rec = await svc.get_csr(csr_id, project_id)
    if not rec:
        raise HTTPException(status_code=404, detail="CSR not found")
    return {"data": rec, "meta": {}}


@router.post("/{project_id}/csrs/{csr_id}/approve/", response_model=SuccessResponse)
async def approve_csr(
    project_id: str,
    csr_id: str,
    request: Request,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_admin_access(project_id, user, conn)
    vault = request.app.state.vault
    svc = CertificateLifecycleService(conn)
    try:
        result = await svc.approve_csr(csr_id, project_id, user["id"], vault)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"data": result, "meta": {}}


@router.post("/{project_id}/csrs/{csr_id}/reject/", response_model=SuccessResponse)
async def reject_csr(
    project_id: str,
    csr_id: str,
    body: RejectCSRRequest,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_admin_access(project_id, user, conn)
    svc = CertificateLifecycleService(conn)
    try:
        result = await svc.reject_csr(csr_id, project_id, user["id"], body.rejection_reason)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"data": result, "meta": {}}


# ── Revocation routes ─────────────────────────────────────────

@router.post("/{project_id}/revoke/", response_model=SuccessResponse)
async def revoke_certificate(
    project_id: str,
    body: RevokeRequest,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_admin_access(project_id, user, conn)
    svc = CertificateLifecycleService(conn)
    result = await svc.revoke_certificate(
        project_id, body.serial_number, user["id"], body.revocation_reason,
    )
    return {"data": result, "meta": {}}


@router.get("/{project_id}/revocation-list/", response_model=SuccessResponse)
async def get_revocation_list(
    project_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = CertificateLifecycleService(conn)
    items = await svc.get_revocation_list(project_id)
    return {"data": items, "meta": {"total": len(items)}}


@router.get("/{project_id}/certs/{serial}/status/", response_model=SuccessResponse)
async def get_cert_status(
    project_id: str,
    serial: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = CertificateLifecycleService(conn)
    result = await svc.get_certificate_status(project_id, serial)
    if not result:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return {"data": result, "meta": {}}


# ── Renewal routes ────────────────────────────────────────────

@router.get("/{project_id}/renewal-queue/", response_model=SuccessResponse)
async def renewal_queue(
    project_id: str,
    threshold_days: int = Query(30),
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = CertificateLifecycleService(conn)
    queue = await svc.get_renewal_queue(project_id, threshold_days)
    return {"data": queue, "meta": {"total": queue["total"]}}


@router.post("/{project_id}/collectors/{collector_id}/renew/",
             response_model=SuccessResponse)
async def renew_collector_cert(
    project_id: str,
    collector_id: str,
    request: Request,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_admin_access(project_id, user, conn)
    vault = request.app.state.vault
    svc = CertificateLifecycleService(conn)
    try:
        result = await svc.renew_collector_cert(
            project_id, collector_id, user["id"], vault,
        )
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"data": result, "meta": {}}
