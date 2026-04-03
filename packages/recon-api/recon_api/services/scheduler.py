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
        handlers: dict = {
            "scan_execute": self._handle_scan_execute,
        }
        handler = handlers.get(job["job_type"])
        if handler:
            return await handler(job)
        raise ValueError(f"Unknown job type: {job['job_type']}")

    async def _handle_scan_execute(self, job: dict) -> dict:
        """Execute a scan job dispatched by ScanService.dispatch_scan()."""
        import json as _json
        from recon_collectors.orchestrator import CollectorOrchestrator
        from recon_api.services.scan import ScanService
        from recon_api.services.policy import UnifiedAssessor

        payload = job.get("payload", {})
        if isinstance(payload, str):
            payload = _json.loads(payload)

        scan_id = payload.get("scan_id")
        run_number = payload.get("run_number", 1)
        config = payload.get("config", {})
        policy_data = payload.get("policy", {})
        job_id = job.get("id")

        async with self._pool.acquire() as conn:
            scan_svc = ScanService(conn)
            await scan_svc.update_scan_status(scan_id, "running")
            await scan_svc.append_scan_log(
                scan_id, run_number,
                f"Scan job {job_id} started (run #{run_number})"
            )

            try:
                orch = CollectorOrchestrator()
                scan_results = await orch.run(config)

                await scan_svc.append_scan_log(
                    scan_id, run_number,
                    f"Collection complete: {len(scan_results.certificates)} certs, "
                    f"{len(scan_results.keys)} keys, "
                    f"{len(scan_results.tls_results)} TLS results"
                )

                findings: list[dict] = []
                if policy_data.get("rules"):
                    assessor = UnifiedAssessor()
                    if assessor.load_policy(policy_data):
                        for cert in scan_results.certificates:
                            cd = vars(cert) if hasattr(cert, '__dict__') else cert
                            for r in assessor.assess_certificate(cd):
                                if r.triggered:
                                    findings.append(r.to_dict())
                        for key in scan_results.keys:
                            kd = vars(key) if hasattr(key, '__dict__') else key
                            for r in assessor.assess_key(kd):
                                if r.triggered:
                                    findings.append(r.to_dict())
                        for tls in scan_results.tls_results:
                            td = vars(tls) if hasattr(tls, '__dict__') else tls
                            for r in assessor.assess_tls(td):
                                if r.triggered:
                                    findings.append(r.to_dict())

                    await scan_svc.append_scan_log(
                        scan_id, run_number,
                        f"Policy assessment complete: {len(findings)} findings"
                    )

                # Build scan results JSON for storage and inventory sync
                scan_results_json = {
                    "certificates": [
                        vars(c) if hasattr(c, '__dict__') else c
                        for c in scan_results.certificates
                    ],
                    "keys": [
                        vars(k) if hasattr(k, '__dict__') else k
                        for k in scan_results.keys
                    ],
                }

                await scan_svc.write_scan_results(
                    scan_id=scan_id, run_number=run_number,
                    scan_results_json=scan_results_json, findings=findings,
                    collector_stats=scan_results.collector_stats,
                    job_id=job_id,
                )

                # Sync scan results into persistent inventory
                try:
                    from recon_api.services.inventory import InventoryService
                    inv_svc = InventoryService(conn)
                    sync_result = await inv_svc.sync_from_scan(
                        scan_id=scan_id,
                        project_id=payload.get("project_id"),
                        scan_results_json=scan_results_json,
                    )
                    await scan_svc.append_scan_log(
                        scan_id, run_number,
                        f"Inventory sync complete: {sync_result.certificates_total} certs, "
                        f"{sync_result.keys_total} keys "
                        f"(+{sync_result.certificates_added} added, "
                        f"+{sync_result.keys_added} key added)"
                    )
                except Exception as exc:
                    logger.warning("inventory_sync_failed",
                                   scan_id=scan_id, error=str(exc))

                logger.info("scan_execute_complete", scan_id=scan_id,
                            findings=len(findings))
                return {
                    "scan_id": scan_id,
                    "certificates": len(scan_results.certificates),
                    "keys": len(scan_results.keys),
                    "findings": len(findings),
                }

            except Exception as exc:
                logger.error("scan_execute_failed", scan_id=scan_id, error=str(exc))
                await scan_svc.fail_scan(scan_id, run_number, str(exc), job_id)
                raise
