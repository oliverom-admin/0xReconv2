"""Scan configuration routes — /api/v1/configurations/"""
from __future__ import annotations
import json
import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from recon_api.dependencies.auth import get_current_user
from recon_api.dependencies.db import get_db_conn
from recon_api.models.common import SuccessResponse

router = APIRouter(prefix="/configurations", tags=["configurations"])


class CreateConfigRequest(BaseModel):
    name: str
    project_id: str
    config: dict
    description: str | None = None


@router.post("/", response_model=SuccessResponse, status_code=201)
async def create_config(
    body: CreateConfigRequest,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    row = await conn.fetchrow(
        """
        INSERT INTO scan_configurations
          (project_id, name, description, config, created_by)
        VALUES ($1,$2,$3,$4::jsonb,$5) RETURNING id, name
        """,
        body.project_id, body.name, body.description,
        json.dumps(body.config), user["id"],
    )
    return {"data": dict(row), "meta": {}}


@router.get("/", response_model=SuccessResponse)
async def list_configs(
    project_id: str = Query(...),
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    rows = await conn.fetch(
        "SELECT id,name,description,is_active,created_at "
        "FROM scan_configurations WHERE project_id=$1 ORDER BY name", project_id,
    )
    return {"data": [dict(r) for r in rows], "meta": {"total": len(rows)}}


@router.get("/{cfg_id}/", response_model=SuccessResponse)
async def get_config(
    cfg_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    row = await conn.fetchrow("SELECT * FROM scan_configurations WHERE id=$1", cfg_id)
    if not row:
        raise HTTPException(status_code=404, detail="Configuration not found")
    return {"data": dict(row), "meta": {}}


@router.delete("/{cfg_id}/", response_model=SuccessResponse)
async def delete_config(
    cfg_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await conn.execute("UPDATE scan_configurations SET is_active=false WHERE id=$1", cfg_id)
    return {"data": {"deleted": True}, "meta": {}}
