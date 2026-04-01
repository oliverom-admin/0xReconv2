"""Abstract base class for all collectors."""

from __future__ import annotations

from abc import ABC, abstractmethod

from recon_collectors.models import ScanResults


class BaseCollector(ABC):
    """Base class that every collector must inherit from."""

    @property
    @abstractmethod
    def collector_type(self) -> str:
        """Return the collector type identifier.

        Must be one of: luna_hsm, azure_keyvault, ejbca, tls, crl, file.
        """
        ...

    @abstractmethod
    async def collect(self, config: dict) -> ScanResults:
        """Run the collection process and return scan results.

        Args:
            config: Collector-specific configuration dictionary.

        Returns:
            ScanResults populated with discovered assets and findings.
        """
        ...

    @abstractmethod
    async def health_check(self) -> dict:
        """Check connectivity and readiness of the collector target.

        Returns:
            Dictionary with at least ``status`` (ok | error) and
            optional ``details`` key.
        """
        ...
