"""
SecretResolutionService — multi-backend secret resolution.

Resolution priority (first non-None result wins):
  1. memory   — in-process dict (tests and bootstrap)
  2. vault    — local AES-256-GCM file vault (primary for production)
  3. azure_kv — Azure Key Vault (stubbed until Phase 3 connector)

Secrets are identified by a string key name.
PKI private keys use resolve_key() which reads from the vault pki_keys section.
"""
from __future__ import annotations

import structlog

from recon_api.services.vault import VaultService

logger = structlog.get_logger("recon.secret_resolution")


class SecretResolutionService:
    """
    Resolves secrets from a prioritised chain of backends.

    Instantiate with at minimum a VaultService.
    Azure KV URL is optional — if absent, Azure backend is skipped.
    Memory store is for tests and bootstrap-time overrides.
    """

    def __init__(
        self,
        vault: VaultService,
        azure_vault_url: str | None = None,
        memory_store: dict[str, str] | None = None,
    ) -> None:
        self._vault = vault
        self._azure_vault_url = azure_vault_url
        self._memory: dict[str, str] = memory_store or {}

    async def resolve(self, secret_id: str) -> str | None:
        """
        Resolve a secret by ID. Returns the value or None if not found
        in any backend.
        """
        # 1. In-memory (test/bootstrap overrides)
        if secret_id in self._memory:
            logger.debug("secret_resolved_memory", secret_id=secret_id)
            return self._memory[secret_id]

        # 2. Vault file
        value = await self._vault.get_secret(secret_id)
        if value is not None:
            logger.debug("secret_resolved_vault", secret_id=secret_id)
            return value

        # 3. Azure Key Vault (Phase 3 connector adds full async implementation)
        if self._azure_vault_url:
            value = await self._resolve_azure(secret_id)
            if value is not None:
                logger.debug("secret_resolved_azure_kv", secret_id=secret_id)
                return value

        logger.warning("secret_not_found", secret_id=secret_id)
        return None

    async def resolve_key(self, key_name: str) -> str | None:
        """
        Resolve a PEM private key by vault key name.
        Returns the PEM string or None.
        """
        pem = await self._vault.get_key(key_name)
        if pem:
            logger.debug("key_resolved_vault", key_name=key_name)
        else:
            logger.warning("key_not_found", key_name=key_name)
        return pem

    def set_memory_secret(self, key: str, value: str) -> None:
        """Register an in-memory secret override. Useful in tests."""
        self._memory[key] = value

    async def _resolve_azure(self, secret_id: str) -> str | None:
        """
        Azure Key Vault resolution stub.
        Phase 3+: replace with real azure-keyvault-secrets async client.
        """
        return None
