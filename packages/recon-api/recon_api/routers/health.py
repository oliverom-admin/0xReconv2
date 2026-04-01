"""
Health check endpoint. No authentication required.
Used by nginx, Docker healthcheck, and Phase gate commands.

Phase 1: db_connected always False — no DB pool yet.
Phase 2: Replace stub with real asyncpg pool ping.
"""
from __future__ import annotations

import structlog
from fastapi import APIRouter

logger = structlog.get_logger("recon.health")
router = APIRouter(tags=["health"])


@router.get("/health/")
async def health_check() -> dict:
    # Phase 2: db_connected = await db_pool.ping()
    db_connected = False
    status = "ok" if db_connected else "degraded"
    logger.debug("health_check", db_connected=db_connected, status=status)
    return {
        "status": status,
        "version": "1.0.0",
        "db_connected": db_connected,
    }
