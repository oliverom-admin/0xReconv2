"""
Worker entrypoint — SchedulerService polling loop.

Phase 1: Stub that confirms the worker starts and loops cleanly.
Phase 2: Replace loop body with SchedulerService.run(shutdown_event).
"""
from __future__ import annotations

import asyncio
import signal

import structlog

from recon_api.config import get_settings
from recon_api.logging_config import configure_logging

logger = structlog.get_logger("recon.worker")


async def main() -> None:
    settings = get_settings()
    configure_logging(debug=settings.debug)
    logger.info("recon_worker_starting", version="1.0.0", env=settings.env)

    shutdown_event = asyncio.Event()

    def _handle_signal(sig: int, frame: object) -> None:
        logger.info("recon_worker_shutdown_signal", signal=sig)
        shutdown_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    logger.info("recon_worker_polling_loop_start")
    poll_count = 0
    while not shutdown_event.is_set():
        poll_count += 1
        logger.debug("recon_worker_poll", poll_count=poll_count)
        # Phase 2: job = await job_queue.next_pending()
        # Phase 2: if job: await executor.execute(job)
        await asyncio.sleep(60)

    logger.info("recon_worker_stopped")


if __name__ == "__main__":
    asyncio.run(main())
