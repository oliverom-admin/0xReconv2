"""Scan management routes — /api/v1/scans/"""
from __future__ import annotations

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from recon_api.dependencies.auth import get_current_user
from recon_api.dependencies.db import get_db_conn
from recon_api.models.common import SuccessResponse
from recon_api.services.scan import ScanService

logger = structlog.get_logger("recon.scans.router")
router = APIRouter(prefix="/scans", tags=["scans"])


class CreateScanRequest(BaseModel):
    name: str
    project_id: str
    config_id: str | None = None
    policy_id: str | None = None
    assessment_type: str = "pki_assessment"
    description: str | None = None


@router.get("/", response_model=SuccessResponse)
async def list_scans(
    project_id: str = Query(...),
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    scans = await ScanService(conn).list_scans(project_id)
    return {"data": scans, "meta": {"total": len(scans)}}


@router.post("/", response_model=SuccessResponse, status_code=201)
async def create_scan(
    body: CreateScanRequest,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    scan = await ScanService(conn).create_scan(
        project_id=body.project_id, name=body.name,
        config_id=body.config_id, policy_id=body.policy_id,
        assessment_type=body.assessment_type, created_by=user["id"],
        description=body.description,
    )
    return {"data": scan, "meta": {}}


@router.get("/{scan_id}/", response_model=SuccessResponse)
async def get_scan(
    scan_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    scan = await ScanService(conn).get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"data": scan, "meta": {}}


@router.delete("/{scan_id}/", response_model=SuccessResponse)
async def delete_scan(
    scan_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await ScanService(conn).delete_scan(scan_id)
    return {"data": {"deleted": True}, "meta": {}}


@router.post("/{scan_id}/run/", response_model=SuccessResponse,
             status_code=status.HTTP_202_ACCEPTED)
async def run_scan(
    scan_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    svc = ScanService(conn)
    scan = await svc.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["status"] in ("pending", "running"):
        raise HTTPException(status_code=409, detail=f"Scan already {scan['status']}")
    try:
        job_id = await svc.dispatch_scan(scan_id, dispatched_by=user["id"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"data": {"job_id": job_id, "scan_id": scan_id, "status": "pending"}, "meta": {}}


@router.get("/{scan_id}/findings/", response_model=SuccessResponse)
async def list_findings(
    scan_id: str,
    run_number: int | None = Query(None),
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    findings = await ScanService(conn).list_findings(scan_id, run_number)
    return {"data": findings, "meta": {"total": len(findings)}}


@router.get("/{scan_id}/logs/", response_model=SuccessResponse)
async def get_logs(
    scan_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    logs = await ScanService(conn).get_scan_logs(scan_id)
    return {"data": logs, "meta": {"total": len(logs)}}


@router.get("/{scan_id}/runs/", response_model=SuccessResponse)
async def get_runs(
    scan_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    rows = await conn.fetch(
        "SELECT * FROM scan_runs WHERE scan_id=$1 ORDER BY run_number DESC", scan_id,
    )
    return {"data": [dict(r) for r in rows], "meta": {"total": len(rows)}}
