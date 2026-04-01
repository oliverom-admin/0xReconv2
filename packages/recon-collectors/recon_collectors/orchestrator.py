"""CollectorOrchestrator — multi-collector coordination."""

from __future__ import annotations

import asyncio
import time
from dataclasses import fields
from typing import Any

import structlog

from recon_collectors.models import ScanResults

log = structlog.get_logger("recon.collectors.orchestrator")

# Maps config key → (module path relative to recon_collectors.collectors, class name)
_COLLECTOR_REGISTRY: dict[str, tuple[str, str]] = {
    "tls_scan": ("recon_collectors.collectors.tls", "TLSScanner"),
    "crl": ("recon_collectors.collectors.crl", "CRLCollector"),
    "file_scan": ("recon_collectors.collectors.file", "FileShareScanner"),
    "luna_hsm": ("recon_collectors.collectors.luna_hsm", "LunaHSMCollector"),
    "azure": ("recon_collectors.collectors.azure_keyvault", "AzureKeyVaultCollector"),
    "ejbca": ("recon_collectors.collectors.ejbca", "EJBCACollector"),
}


class CollectorOrchestrator:
    """Coordinate multiple collectors and merge their results."""

    def __init__(self, timeout_per_collector: int = 300) -> None:
        self._timeout = timeout_per_collector

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self, config: dict) -> ScanResults:
        """Run all enabled collectors concurrently and merge results.

        Args:
            config: Top-level scan configuration. Each key matching a
                registered collector name should contain a dict with at
                least ``{"enabled": true}``.

        Returns:
            Merged :class:`ScanResults` containing data from every
            collector that completed successfully.
        """
        collectors = self._build_collectors(config)
        if not collectors:
            log.warning("orchestrator.no_collectors_enabled")
            return ScanResults()

        tasks: dict[asyncio.Task, str] = {}
        for name, (collector, section_config) in collectors.items():
            task = asyncio.create_task(
                self._run_single(name, collector, section_config),
                name=f"collector-{name}",
            )
            tasks[task] = name

        done, _ = await asyncio.wait(tasks.keys())

        merged = ScanResults()
        for task in done:
            name = tasks[task]
            try:
                result: ScanResults = task.result()
                self._merge(merged, result)
                log.info("orchestrator.collector_merged", collector=name)
            except Exception as exc:  # noqa: BLE001
                error_msg = f"{name}: {exc}"
                merged.errors.append(error_msg)
                log.error(
                    "orchestrator.collector_failed",
                    collector=name,
                    error=str(exc),
                )

        return merged

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_collectors(
        self, config: dict
    ) -> dict[str, tuple[Any, dict]]:
        """Instantiate enabled collectors from *config*.

        Collectors whose dependencies are not installed are silently
        skipped (ImportError is caught and logged).
        """
        result: dict[str, tuple[Any, dict]] = {}

        for config_key, (module_path, class_name) in _COLLECTOR_REGISTRY.items():
            section = config.get(config_key)
            if not isinstance(section, dict) or not section.get("enabled"):
                continue

            try:
                mod = _lazy_import(module_path)
                cls = getattr(mod, class_name)
            except (ImportError, AttributeError) as exc:
                log.warning(
                    "orchestrator.import_skipped",
                    collector=config_key,
                    error=str(exc),
                )
                continue

            result[config_key] = (cls(), section)
            log.debug("orchestrator.collector_loaded", collector=config_key)

        return result

    async def _run_single(
        self, name: str, collector: Any, config: dict
    ) -> ScanResults:
        """Execute a single collector with a timeout guard."""
        log.info("orchestrator.collector_start", collector=name)
        start = time.monotonic()

        try:
            result = await asyncio.wait_for(
                collector.collect(config),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError:
            elapsed = time.monotonic() - start
            log.error(
                "orchestrator.collector_timeout",
                collector=name,
                elapsed_s=round(elapsed, 2),
                timeout_s=self._timeout,
            )
            error_result = ScanResults()
            error_result.errors.append(
                f"{name}: timed out after {self._timeout}s"
            )
            error_result.collector_stats[name] = {
                "status": "timeout",
                "elapsed_s": round(elapsed, 2),
            }
            return error_result

        elapsed = time.monotonic() - start
        if result.collector_stats is None:
            result.collector_stats = {}
        result.collector_stats[name] = {
            "status": "ok",
            "elapsed_s": round(elapsed, 2),
        }
        log.info(
            "orchestrator.collector_done",
            collector=name,
            elapsed_s=round(elapsed, 2),
        )
        return result

    @staticmethod
    def _merge(target: ScanResults, source: ScanResults) -> None:
        """Merge *source* into *target* in place."""
        for f in fields(ScanResults):
            src_val = getattr(source, f.name)
            tgt_val = getattr(target, f.name)

            if isinstance(tgt_val, list) and isinstance(src_val, list):
                tgt_val.extend(src_val)
            elif isinstance(tgt_val, dict) and isinstance(src_val, dict):
                tgt_val.update(src_val)


def _lazy_import(module_path: str) -> Any:
    """Import a module by dotted path at runtime."""
    import importlib

    return importlib.import_module(module_path)
