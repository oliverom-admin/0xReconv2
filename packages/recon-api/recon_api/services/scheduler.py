"""
SchedulerService — job_queue polling and dispatch.

Job lifecycle: pending → running → complete | failed
Poll interval: 10 seconds.
FOR UPDATE SKIP LOCKED for safe multi-worker concurrency.
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import traceback
import uuid
from typing import Any

import asyncpg
import structlog

logger = structlog.get_logger("recon.scheduler")

POLL_INTERVAL = 10
WORKER_ID = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"


class SchedulerService:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def run(self, shutdown_event: asyncio.Event) -> None:
        logger.info("scheduler_loop_start", worker_id=WORKER_ID, poll_interval=POLL_INTERVAL)
        polls = 0
        while not shutdown_event.is_set():
            polls += 1
            try:
                await self._poll_once()
            except Exception as exc:
                logger.error("scheduler_poll_error", error=str(exc),
                             traceback=traceback.format_exc())
            try:
                await asyncio.wait_for(shutdown_event.wait(), timeout=POLL_INTERVAL)
            except asyncio.TimeoutError:
                pass
        logger.info("scheduler_loop_stopped", polls=polls)

    async def _poll_once(self) -> None:
        async with self._pool.acquire() as conn:
            job = await self._claim_next(conn)
            if job is None:
                return
            logger.info("job_claimed", job_id=job["id"], job_type=job["job_type"])
            try:
                result = await self._dispatch(job)
                await self._complete(conn, job["id"], result)
                logger.info("job_complete", job_id=job["id"])
            except Exception as exc:
                await self._fail(conn, job["id"], str(exc))
                logger.error("job_failed", job_id=job["id"], error=str(exc))

    async def _claim_next(self, conn: asyncpg.Connection) -> dict[str, Any] | None:
        row = await conn.fetchrow(
            """
            UPDATE job_queue
            SET status='running', claimed_by=$1, started_at=NOW(),
                attempts=attempts+1, updated_at=NOW()
            WHERE id = (
                SELECT id FROM job_queue
                WHERE status='pending'
                  AND (scheduled_for IS NULL OR scheduled_for <= NOW())
                ORDER BY priority DESC, created_at ASC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING id, job_type, payload, project_id, attempts, max_attempts
            """,
            WORKER_ID,
        )
        return dict(row) if row else None

    async def _complete(self, conn: asyncpg.Connection, job_id: str, result: Any) -> None:
        await conn.execute(
            """
            UPDATE job_queue SET status='complete', result=$2::jsonb,
                   completed_at=NOW(), updated_at=NOW()
            WHERE id=$1
            """,
            job_id, json.dumps(result) if result is not None else "{}",
        )

    async def _fail(self, conn: asyncpg.Connection, job_id: str, error: str) -> None:
        await conn.execute(
            """
            UPDATE job_queue
            SET status = CASE WHEN attempts < max_attempts THEN 'pending' ELSE 'failed' END,
                error_message = $2,
                completed_at = CASE WHEN attempts >= max_attempts THEN NOW() ELSE NULL END,
                updated_at = NOW()
            WHERE id = $1
            """,
            job_id, error,
        )

    async def _dispatch(self, job: dict[str, Any]) -> dict[str, Any]:
        handlers: dict = {}
        handler = handlers.get(job["job_type"])
        if handler:
            return await handler(job)
        raise ValueError(f"Unknown job type: {job['job_type']}")
