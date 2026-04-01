"""
Worker entrypoint.
Phase 2B: real SchedulerService with job_queue polling.
"""
from __future__ import annotations

import asyncio
import signal

import structlog

from recon_api.config import get_settings
from recon_api.db.pool import close_pool, init_pool
from recon_api.logging_config import configure_logging
from recon_api.services.scheduler import SchedulerService

logger = structlog.get_logger("recon.worker")


async def main() -> None:
    settings = get_settings()
    configure_logging(debug=settings.debug)
    logger.info("recon_worker_starting", version="1.0.0", env=settings.env)

    pool = await init_pool(
        settings.database_url,
        min_size=settings.database_pool_min,
        max_size=settings.database_pool_max,
    )
    logger.info("recon_worker_db_pool_ready")

    shutdown_event = asyncio.Event()

    def _sig(sig: int, frame: object) -> None:
        logger.info("recon_worker_shutdown_signal", signal=sig)
        shutdown_event.set()

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    scheduler = SchedulerService(pool)
    try:
        await scheduler.run(shutdown_event)
    finally:
        await close_pool()
        logger.info("recon_worker_stopped")


if __name__ == "__main__":
    asyncio.run(main())
