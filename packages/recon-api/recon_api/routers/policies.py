"""Policy management routes — /api/v1/policies/"""
from __future__ import annotations
import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from recon_api.dependencies.auth import get_current_user
from recon_api.dependencies.db import get_db_conn
from recon_api.models.common import SuccessResponse
from recon_api.services.policy import PolicyService

router = APIRouter(prefix="/policies", tags=["policies"])


class CreatePolicyRequest(BaseModel):
    name: str
    project_id: str
    rules: list
    description: str | None = None
    assessment_type_id: str | None = None


@router.post("/", response_model=SuccessResponse, status_code=201)
async def create_policy(
    body: CreatePolicyRequest,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    policy = await PolicyService(conn).create_policy(
        project_id=body.project_id, name=body.name, rules=body.rules,
        assessment_type_id=body.assessment_type_id, created_by=user["id"],
        description=body.description,
    )
    return {"data": policy, "meta": {}}


@router.get("/", response_model=SuccessResponse)
async def list_policies(
    project_id: str = Query(...),
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    policies = await PolicyService(conn).list_policies(project_id)
    return {"data": policies, "meta": {"total": len(policies)}}


@router.get("/{policy_id}/", response_model=SuccessResponse)
async def get_policy(
    policy_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    policy = await PolicyService(conn).get_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return {"data": policy, "meta": {}}


@router.delete("/{policy_id}/", response_model=SuccessResponse)
async def delete_policy(
    policy_id: str,
    user: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_db_conn),
) -> dict:
    await PolicyService(conn).delete_policy(policy_id)
    return {"data": {"deleted": True}, "meta": {}}
