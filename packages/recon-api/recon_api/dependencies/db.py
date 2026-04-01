"""
Database connection dependency.

Usage in routes:
    from recon_api.dependencies.db import get_db_conn

    @router.get("/things/")
    async def list_things(conn: asyncpg.Connection = Depends(get_db_conn)):
        rows = await conn.fetch("SELECT * FROM things")
        ...
"""
from __future__ import annotations

from typing import AsyncGenerator

import asyncpg
from fastapi import HTTPException

from recon_api.db.pool import get_pool


async def get_db_conn() -> AsyncGenerator[asyncpg.Connection, None]:
    """
    Acquire a connection from the pool, yield it to the route handler,
    and release it back to the pool when the request completes.
    Raises HTTP 503 if the pool is not yet initialised.
    """
    pool = get_pool()
    if pool is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    async with pool.acquire() as conn:
        yield conn
