"""
Health check endpoint. No authentication required.
Phase 1: db_connected always False (stub).
Phase 2A: Real asyncpg pool ping.
"""
from __future__ import annotations

import structlog
from fastapi import APIRouter

from recon_api.db.pool import ping_pool

logger = structlog.get_logger("recon.health")
router = APIRouter(tags=["health"])


@router.get("/health/")
async def health_check() -> dict:
    """Returns API liveness and database connectivity status."""
    db_connected = await ping_pool()
    status = "ok" if db_connected else "degraded"
    logger.debug("health_check", db_connected=db_connected, status=status)
    return {
        "status": status,
        "version": "1.0.0",
        "db_connected": db_connected,
    }
