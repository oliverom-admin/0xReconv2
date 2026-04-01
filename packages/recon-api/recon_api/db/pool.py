"""
Asyncpg connection pool lifecycle.

The pool is created once at application startup in the lifespan
context manager and stored on app.state. Routes access it via
the get_db_conn dependency (dependencies/db.py).

Never expose the pool directly to routers.
"""
from __future__ import annotations

import asyncpg
import structlog

logger = structlog.get_logger("recon.db.pool")

_pool: asyncpg.Pool | None = None


async def init_pool(
    database_url: str, min_size: int = 2, max_size: int = 10
) -> asyncpg.Pool:
    """Create and store the global asyncpg connection pool."""
    global _pool
    # Strip SQLAlchemy driver prefix — asyncpg uses plain postgresql://
    url = database_url.replace("postgresql+asyncpg://", "postgresql://")
    _pool = await asyncpg.create_pool(
        url,
        min_size=min_size,
        max_size=max_size,
        command_timeout=60,
    )
    logger.info("db_pool_created", min_size=min_size, max_size=max_size)
    return _pool


async def close_pool() -> None:
    """Close the pool at application shutdown."""
    global _pool
    if _pool:
        await _pool.close()
        _pool = None
        logger.info("db_pool_closed")


async def ping_pool() -> bool:
    """
    Perform a lightweight DB liveness check.
    Returns True if the pool is healthy, False otherwise.
    Used by the /health/ endpoint.
    """
    global _pool
    if not _pool:
        return False
    try:
        async with _pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return True
    except Exception as exc:
        logger.warning("db_ping_failed", error=str(exc))
        return False


def get_pool() -> asyncpg.Pool | None:
    """Return the pool instance. None before startup completes."""
    return _pool
