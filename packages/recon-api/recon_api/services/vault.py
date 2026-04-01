"""
VaultService — AES-256-GCM encrypted file vault.

IMMUTABLE CRYPTO CONSTANTS — DO NOT CHANGE:
  ITERATIONS = 600_000   (PBKDF2-SHA256)
  SALT_LENGTH = 16
  KEY_LENGTH = 32
  NONCE_LENGTH = 12

IMMUTABLE VAULT KEY NAMES — DO NOT CHANGE:
  "internal-ca-key"
  "engagement-ca-key-{8char}"
  "report-signing-key-{8char}"
  "report-viewer-key-{user_id}-{type}-{id}"

Changing iterations or key names breaks existing vault files
and report decryption. These values match the legacy system exactly.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = structlog.get_logger("recon.vault")


class VaultError(Exception):
    """Base vault error."""


class VaultNotInitializedError(VaultError):
    """Vault used before initialize() was called."""


class VaultDecryptionError(VaultError):
    """Wrong password or corrupted vault file."""


class VaultService:
    """AES-256-GCM encrypted file vault with PBKDF2 key derivation."""

    # — Immutable crypto constants ————————————————————————————————————————
    ITERATIONS = 600_000   # Must not change — existing vault files use this value
    KEY_LENGTH = 32        # 256-bit AES key
    SALT_LENGTH = 16       # 128-bit salt
    NONCE_LENGTH = 12      # 96-bit GCM nonce (standard)
    # —————————————————————————————————————————————————————————————————————

    def __init__(self, vault_path: str, master_password: str) -> None:
        self.vault_path = Path(vault_path)
        self._master_password = master_password
        self._master_key: bytes | None = None
        self._vault_data: dict[str, Any] | None = None
        self._initialized = False

    # — Public async API —————————————————————————————————————————————————

    async def initialize(self) -> None:
        """Load existing vault or create a new one. Call once at startup."""
        await asyncio.to_thread(self._init_sync)
        logger.info("vault_initialized", path=str(self.vault_path),
                    exists=self.vault_path.exists())

    async def get_secret(self, key: str) -> str | None:
        """Return a secret value by key name, or None if not found."""
        self._require_initialized()
        await asyncio.to_thread(self._reload_sync)
        return self._vault_data.get("secrets", {}).get(key)  # type: ignore[union-attr]

    async def set_secret(self, key: str, value: str) -> None:
        """Store or overwrite a secret. Persists to disk immediately."""
        self._require_initialized()
        await asyncio.to_thread(self._reload_sync)
        self._vault_data["secrets"][key] = value  # type: ignore[index]
        await asyncio.to_thread(self._save_sync)
        logger.info("vault_secret_set", key=key)

    async def get_key(self, key_name: str) -> str | None:
        """Return a PEM private key by vault key name, or None."""
        self._require_initialized()
        await asyncio.to_thread(self._reload_sync)
        return self._vault_data.get("pki_keys", {}).get(key_name)  # type: ignore[union-attr]

    async def set_key(self, key_name: str, pem: str) -> None:
        """Store or overwrite a PEM private key. Persists immediately."""
        self._require_initialized()
        await asyncio.to_thread(self._reload_sync)
        self._vault_data["pki_keys"][key_name] = pem  # type: ignore[index]
        await asyncio.to_thread(self._save_sync)
        logger.info("vault_key_set", key_name=key_name)

    async def delete_key(self, key_name: str) -> None:
        """Remove a PEM private key from the vault."""
        self._require_initialized()
        await asyncio.to_thread(self._reload_sync)
        self._vault_data["pki_keys"].pop(key_name, None)  # type: ignore[union-attr]
        await asyncio.to_thread(self._save_sync)

    async def health(self) -> dict:
        """Return vault health summary. Never exposes key material."""
        if not self._initialized:
            return {"status": "uninitialized", "path": str(self.vault_path)}
        d = self._vault_data or {}
        return {
            "status": "ok",
            "path": str(self.vault_path),
            "secrets_count": len(d.get("secrets", {})),
            "keys_count": len(d.get("pki_keys", {})),
        }

    # — Private sync helpers (all run in asyncio.to_thread) ———————————————

    def _require_initialized(self) -> None:
        if not self._initialized or self._vault_data is None:
            raise VaultNotInitializedError(
                "VaultService not initialized — call await initialize() first"
            )

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=VaultService.KEY_LENGTH,
            salt=salt,
            iterations=VaultService.ITERATIONS,
            backend=default_backend(),
        )
        return kdf.derive(password.encode("utf-8"))

    @staticmethod
    def _encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
        """
        Encrypt with AES-256-GCM.
        Returns (ciphertext_without_tag, nonce, tag).
        The last 16 bytes of AESGCM output are the authentication tag.
        """
        cipher = AESGCM(key)
        nonce = secrets.token_bytes(VaultService.NONCE_LENGTH)
        ct_with_tag = cipher.encrypt(nonce, plaintext, None)
        return ct_with_tag[:-16], nonce, ct_with_tag[-16:]

    @staticmethod
    def _decrypt(ciphertext: bytes, nonce: bytes, tag: bytes, key: bytes) -> bytes:
        cipher = AESGCM(key)
        return cipher.decrypt(nonce, ciphertext + tag, None)

    def _init_sync(self) -> None:
        if self.vault_path.exists():
            self._load_sync()
        else:
            self._create_sync()
        self._initialized = True

    def _create_sync(self) -> None:
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        salt = secrets.token_bytes(self.SALT_LENGTH)
        self._master_key = self._derive_key(self._master_password, salt)
        self._vault_data = {
            "metadata": {
                "vault_version": "1.0",
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
            "secrets": {},
            "pki_keys": {},
        }
        self._save_sync(salt=salt)
        logger.info("vault_created", path=str(self.vault_path))

    def _load_sync(self) -> None:
        try:
            with open(self.vault_path, "r", encoding="utf-8") as fh:
                container = json.load(fh)
        except Exception as exc:
            raise VaultDecryptionError(
                f"Cannot read vault file: {exc}"
            ) from exc

        try:
            salt = base64.b64decode(container["salt"])
            nonce = base64.b64decode(container["nonce"])
            tag = base64.b64decode(container["tag"])
            ciphertext = base64.b64decode(container["encrypted_blob"])
        except (KeyError, Exception) as exc:
            raise VaultDecryptionError(
                f"Malformed vault container: {exc}"
            ) from exc

        self._master_key = self._derive_key(self._master_password, salt)

        try:
            plaintext = self._decrypt(ciphertext, nonce, tag, self._master_key)
        except Exception as exc:
            raise VaultDecryptionError(
                "Vault decryption failed — wrong master password or corrupted file"
            ) from exc

        self._vault_data = json.loads(plaintext.decode("utf-8"))

    def _reload_sync(self) -> None:
        """Re-read from disk. Keeps in-memory state consistent with file."""
        if self.vault_path.exists():
            self._load_sync()

    def _save_sync(self, salt: bytes | None = None) -> None:
        if self._master_key is None or self._vault_data is None:
            raise VaultError("Vault not initialised — cannot save")

        if salt is None:
            if self.vault_path.exists():
                with open(self.vault_path, "r", encoding="utf-8") as fh:
                    existing = json.load(fh)
                salt = base64.b64decode(existing["salt"])
                self._master_key = self._derive_key(self._master_password, salt)
            else:
                salt = secrets.token_bytes(self.SALT_LENGTH)
                self._master_key = self._derive_key(self._master_password, salt)

        plaintext = json.dumps(self._vault_data, indent=2).encode("utf-8")
        checksum = hashlib.sha256(plaintext).hexdigest()
        ciphertext, nonce, tag = self._encrypt(plaintext, self._master_key)

        container = {
            "version": "1.0",
            "algorithm": "AES-256-GCM",
            "key_derivation": "PBKDF2-SHA256",
            "iterations": self.ITERATIONS,
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "encrypted_blob": base64.b64encode(ciphertext).decode(),
            "checksum": checksum,
        }

        tmp = self.vault_path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(container, fh, indent=2)
        os.replace(tmp, self.vault_path)
