"""CRL collector using httpx.AsyncClient."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import httpx
import structlog
from cryptography import x509
from cryptography.x509 import CertificateRevocationList

from recon_collectors.collectors.base import BaseCollector
from recon_collectors.models import CRLInfo, ScanResults

logger = structlog.get_logger("recon.collectors.crl")


class CRLCollector(BaseCollector):
    """Fetches and parses Certificate Revocation Lists from HTTP URLs."""

    @property
    def collector_type(self) -> str:
        return "crl"

    @staticmethod
    def _parse_crl(raw: bytes) -> CertificateRevocationList:
        """Attempt to parse raw bytes as DER, then as PEM CRL."""
        try:
            return x509.load_der_x509_crl(raw)
        except Exception:
            return x509.load_pem_x509_crl(raw)

    @staticmethod
    def _dn_string(name: x509.Name) -> str:
        """Convert an x509.Name to a single-line string."""
        parts: list[str] = []
        for attr in name:
            friendly = attr.oid._name if hasattr(attr.oid, "_name") else attr.oid.dotted_string
            parts.append(f"{friendly}={attr.value}")
        return ", ".join(parts)

    @staticmethod
    def _extract_crl_number(crl: CertificateRevocationList) -> Optional[int]:
        """Extract the CRL number extension if present."""
        try:
            ext = crl.extensions.get_extension_for_class(x509.CRLNumber)
            return ext.value.crl_number
        except x509.ExtensionNotFound:
            return None

    def _build_crl_info(
        self,
        crl: CertificateRevocationList,
        url: str,
    ) -> CRLInfo:
        """Build a CRLInfo from a parsed CRL object."""
        now = datetime.now(tz=timezone.utc)

        next_update = (
            crl.next_update_utc
            if hasattr(crl, "next_update_utc")
            else crl.next_update
        )
        this_update = (
            crl.last_update_utc
            if hasattr(crl, "last_update_utc")
            else crl.last_update
        )

        # Normalise to timezone-aware
        if this_update and this_update.tzinfo is None:
            this_update = this_update.replace(tzinfo=timezone.utc)
        if next_update and next_update.tzinfo is None:
            next_update = next_update.replace(tzinfo=timezone.utc)

        is_stale = next_update < now if next_update else False

        revoked_certs = list(crl)
        sig_algo = (
            crl.signature_algorithm_oid._name
            if hasattr(crl.signature_algorithm_oid, "_name")
            else crl.signature_algorithm_oid.dotted_string
        )

        return CRLInfo(
            source_url=url,
            issuer=self._dn_string(crl.issuer),
            this_update=this_update,
            next_update=next_update,
            total_revoked=len(revoked_certs),
            signature_algorithm=sig_algo,
            crl_number=self._extract_crl_number(crl),
            is_stale=is_stale,
        )

    async def collect(self, config: dict) -> ScanResults:
        """Fetch and parse CRLs from the configured URLs."""
        urls: list[str] = config.get("urls", [])
        timeout = config.get("timeout", 30)
        results = ScanResults()
        start = datetime.now(tz=timezone.utc)

        async with httpx.AsyncClient(timeout=float(timeout), follow_redirects=True) as client:
            for url in urls:
                try:
                    resp = await client.get(url)
                    resp.raise_for_status()
                    crl = self._parse_crl(resp.content)
                    info = self._build_crl_info(crl, url)
                    results.crls[url] = info
                    logger.info(
                        "crl.fetched",
                        url=url,
                        revoked=info.total_revoked,
                        is_stale=info.is_stale,
                    )
                except Exception as exc:
                    error_info = CRLInfo(source_url=url, error=str(exc))
                    results.crls[url] = error_info
                    results.errors.append(f"CRL fetch/parse failed for {url}: {exc}")
                    logger.warning("crl.fetch_failed", url=url, error=str(exc))

        elapsed = (datetime.now(tz=timezone.utc) - start).total_seconds()
        successful = sum(1 for v in results.crls.values() if isinstance(v, CRLInfo) and v.error is None)
        results.collector_stats = {
            "collector_type": self.collector_type,
            "urls_attempted": len(urls),
            "urls_successful": successful,
            "errors": len(results.errors),
            "elapsed_seconds": round(elapsed, 3),
        }
        logger.info(
            "crl.collect_complete",
            attempted=len(urls),
            successful=successful,
            elapsed=round(elapsed, 3),
        )
        return results

    async def health_check(self) -> dict:
        """Verify httpx and cryptography are importable."""
        try:
            import httpx as _h  # noqa: F401
            from cryptography import x509 as _x  # noqa: F401

            return {"status": "ok", "details": {"dependencies": "available"}}
        except ImportError as exc:
            return {"status": "error", "details": {"error": str(exc)}}
