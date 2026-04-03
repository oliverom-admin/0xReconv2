"""
Report and CBOM routes.

GET  /api/v1/cbom/scans/{scan_id}/              — CBOM from scan results
GET  /api/v1/cbom/scans/{scan_id}/inventory/     — CBOM from promoted inventory
GET  /api/v1/reports/{project_id}/               — list reports
GET  /api/v1/reports/{project_id}/{report_id}/   — get report
DELETE /api/v1/reports/{project_id}/{report_id}/ — delete report
GET  /api/v1/reports/{project_id}/{report_id}/download/ — download file
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import asyncpg
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse

from recon_api.dependencies.auth import get_current_user
from recon_api.dependencies.db import get_db_conn
from recon_api.models.common import SuccessResponse
from recon_api.services.cbom import CBOMExportService
from recon_api.services.financial import ReportFinancialCalculator
from recon_api.services.report import ReportService
from recon_api.services.rbac import RBACService

logger = structlog.get_logger("recon.reports.router")

cbom_router = APIRouter(prefix="/cbom", tags=["cbom"])
report_router = APIRouter(prefix="/reports", tags=["reports"])


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


# ── CBOM routes ───────────────────────────────────────────────

@cbom_router.get("/scans/{scan_id}/", response_model=None)
async def cbom_from_scan(
    scan_id: str,
    financial: bool = Query(False),
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    """Export scan results as CycloneDX 1.6 CBOM."""
    # Verify scan exists and get project_id
    scan = await conn.fetchrow(
        "SELECT id, project_id, name, status FROM scans WHERE id = $1",
        scan_id,
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    await _check_project_access(scan["project_id"], user, conn)

    # Extract certificates and keys from scan_results
    certificates, keys = await _extract_scan_data(conn, scan_id)

    # Also extract from scan_runs collector_stats if scan_results is empty
    if not certificates and not keys:
        run_row = await conn.fetchrow(
            """SELECT collector_stats FROM scan_runs
               WHERE scan_id = $1 ORDER BY run_number DESC LIMIT 1""",
            scan_id,
        )
        if run_row and run_row["collector_stats"]:
            stats = run_row["collector_stats"]
            if isinstance(stats, str):
                stats = json.loads(stats)
            for ctype, cdata in stats.items():
                if isinstance(cdata, dict):
                    certificates.extend(cdata.get("certificates", []))
                    keys.extend(cdata.get("keys", []))

    # Generate CBOM
    cbom = CBOMExportService.export_scan_results(
        certificates=certificates,
        keys=keys,
        metadata={
            "project_name": scan["name"] or "Scan",
            "scan_id": scan_id,
        },
    )

    # Financial impact extension
    if financial:
        findings_rows = await conn.fetch(
            "SELECT * FROM findings WHERE scan_id = $1", scan_id,
        )
        findings = [dict(r) for r in findings_rows]
        calc = ReportFinancialCalculator({
            "certificates": certificates,
            "keys": keys,
            "findings": findings,
        })
        cbom["financial_impact"] = calc.get_financial_summary()

    # Record report generation
    try:
        rpt_svc = ReportService(conn)
        report = await rpt_svc.create_report(
            project_id=scan["project_id"],
            scan_id=scan_id,
            name=f"CBOM — {scan['name'] or scan_id}",
            report_type="cbom",
            format="json",
            created_by=user.get("id"),
        )
        await rpt_svc.update_report_status(
            report["id"], "complete",
            generation_metadata={"components_count": len(cbom.get("components", []))},
        )
    except Exception as exc:
        logger.warning("cbom_report_record_failed", error=str(exc))

    return cbom


@cbom_router.get("/scans/{scan_id}/inventory/", response_model=None)
async def cbom_from_inventory(
    scan_id: str,
    financial: bool = Query(False),
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    """Export CBOM from promoted inventory records."""
    scan = await conn.fetchrow(
        "SELECT id, project_id, name FROM scans WHERE id = $1", scan_id,
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    await _check_project_access(scan["project_id"], user, conn)

    # Get promoted certs and keys from inventory
    cert_rows = await conn.fetch(
        """SELECT normalised_data FROM certificates_inventory
           WHERE project_id = $1 AND is_promoted = true AND is_active = true""",
        scan["project_id"],
    )
    key_rows = await conn.fetch(
        """SELECT normalised_data FROM keys_inventory
           WHERE project_id = $1 AND is_promoted = true AND is_active = true""",
        scan["project_id"],
    )

    certificates = [r["normalised_data"] for r in cert_rows
                     if isinstance(r["normalised_data"], dict)]
    keys = [r["normalised_data"] for r in key_rows
            if isinstance(r["normalised_data"], dict)]

    cbom = CBOMExportService.export_scan_results(
        certificates=certificates,
        keys=keys,
        metadata={"project_name": scan["name"] or "Inventory", "scan_id": scan_id},
    )

    if financial:
        findings_rows = await conn.fetch(
            "SELECT * FROM findings WHERE scan_id = $1", scan_id,
        )
        calc = ReportFinancialCalculator({
            "certificates": certificates,
            "keys": keys,
            "findings": [dict(r) for r in findings_rows],
        })
        cbom["financial_impact"] = calc.get_financial_summary()

    return cbom


async def _extract_scan_data(
    conn: asyncpg.Connection, scan_id: str,
) -> tuple[list[dict], list[dict]]:
    """Extract certificates and keys from scan_results table."""
    rows = await conn.fetch(
        "SELECT collector_type, result_blob FROM scan_results WHERE scan_id = $1",
        scan_id,
    )
    certificates: list[dict] = []
    keys: list[dict] = []
    for row in rows:
        blob = row["result_blob"]
        if isinstance(blob, str):
            blob = json.loads(blob)
        if isinstance(blob, dict):
            certificates.extend(blob.get("certificates", []))
            keys.extend(blob.get("keys", []))
            keys.extend(blob.get("azure_keys", []))
    return certificates, keys


# ── Report CRUD routes ────────────────────────────────────────

@report_router.get("/{project_id}/", response_model=SuccessResponse)
async def list_reports(
    project_id: str,
    report_type: str | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = ReportService(conn)
    reports = await svc.list_reports(project_id, report_type, status, limit, offset)
    return {"data": reports, "meta": {"total": len(reports), "limit": limit, "offset": offset}}


@report_router.get("/{project_id}/{report_id}/", response_model=SuccessResponse)
async def get_report(
    project_id: str,
    report_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = ReportService(conn)
    report = await svc.get_report(report_id, project_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"data": report, "meta": {}}


@report_router.delete("/{project_id}/{report_id}/", response_model=SuccessResponse)
async def delete_report(
    project_id: str,
    report_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await _check_project_access(project_id, user, conn)
    svc = ReportService(conn)
    deleted = await svc.delete_report(report_id, project_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"data": {"deleted": True}, "meta": {}}


@report_router.get("/{project_id}/{report_id}/download/")
async def download_report(
    project_id: str,
    report_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> FileResponse:
    await _check_project_access(project_id, user, conn)
    svc = ReportService(conn)
    file_path = await svc.get_report_file_path(report_id, project_id)
    if not file_path or not Path(file_path).exists():
        raise HTTPException(status_code=404, detail="Report file not found")
    return FileResponse(path=file_path, filename=Path(file_path).name)
