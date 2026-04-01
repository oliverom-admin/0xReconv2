# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: caip_service_layer/unified_vault_service.py
# Copied: 2026-04-01
# Used in: Phase 18 — Secret Store Management
#
# When porting logic from this file:
#   - Rewrite using the new stack (FastAPI, asyncpg, python-pkcs11, httpx)
#   - Remove all Flask/SQLite/PyKCS11/requests dependencies
#   - Remove all caip_* naming conventions
#   - Fix any bare except: or except Exception: pass blocks
#   - Add proper async/await patterns
#   - Do not copy — port deliberately
# =============================================================================

"""
Unified Vault Service for CAIP

Single encrypted vault containing:
- Application secrets (/app_secrets/)
- PKI keys (/pki_keys/)
- Vault metadata (/metadata/)

Uses AES-256-GCM encryption with PBKDF2 key derivation.
Single master password for entire vault.
"""

import json
import os
import base64
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import secrets

logger = logging.getLogger('caip.operational')


class UnifiedVaultError(Exception):
    """Base exception for unified vault operations"""
    pass


class VaultInitializationError(UnifiedVaultError):
    """Raised when vault initialization fails"""
    pass


class VaultEncryptionError(UnifiedVaultError):
    """Raised when encryption/decryption fails"""
    pass


class VaultCorruptionError(UnifiedVaultError):
    """Raised when vault file appears corrupted"""
    pass


class UnifiedVaultService:
    """
    Manages a single encrypted vault containing all CAIP secrets and PKI keys.

    File Format (system_vault.enc):
    {
        "version": "1.0",
        "algorithm": "AES-256-GCM",
        "key_derivation": "PBKDF2-SHA256",
        "created_at": "2024-03-01T00:00:00Z",
        "last_updated": "2024-03-01T14:30:00Z",
        "vault_id": "system_vault",
        "salt": "base64-encoded-salt",
        "nonce": "base64-encoded-nonce",
        "tag": "base64-encoded-auth-tag",
        "encrypted_blob": "base64-encoded-ciphertext",
        "checksum": "sha256-hash-of-plaintext"
    }

    Plaintext content (when decrypted):
    {
        "metadata": {
            "vault_version": "1.0",
            "encryption_algorithm": "AES-256-GCM",
            "created_at": "2024-03-01T00:00:00Z"
        },
        "app_secrets": {
            "flask_secret_key": "...",
            "azure_sp_client_secret": "...",
            "database_connection_string": "..."
        },
        "pki_keys": {
            "internal_ca_private_key": "-----BEGIN PRIVATE KEY-----\n...",
            "engagement_ca_keys": {
                "12": "-----BEGIN PRIVATE KEY-----\n...",
                "13": "-----BEGIN PRIVATE KEY-----\n..."
            },
            "report_signing_keys": {
                "12": "-----BEGIN PRIVATE KEY-----\n...",
                "13": "-----BEGIN PRIVATE KEY-----\n..."
            }
        }
    }
    """

    # Encryption parameters
    ALGORITHM = "AES-256-GCM"
    KEY_DERIVATION = "PBKDF2-SHA256"
    ITERATIONS = 600000
    KEY_LENGTH = 32  # 256 bits
    SALT_LENGTH = 16
    NONCE_LENGTH = 12  # Standard for GCM

    def __init__(self, vault_file_path: str, master_password: str):
        """
        Initialize unified vault service.

        Args:
            vault_file_path: Path to system_vault.enc file
            master_password: Master password for encryption
        """
        self.vault_file_path = vault_file_path
        self.master_password = master_password
        self._vault_data: Optional[Dict[str, Any]] = None
        self._master_key: Optional[bytes] = None
        self._initialized = False

    def initialize(self) -> None:
        """
        Load and decrypt vault at application startup.

        Raises:
            VaultInitializationError: If vault file not found or decryption fails
            VaultCorruptionError: If vault appears corrupted
        """
        try:
            if not os.path.exists(self.vault_file_path):
                raise VaultInitializationError(
                    f"Vault file not found: {self.vault_file_path}"
                )

            # Load vault file
            with open(self.vault_file_path, 'r', encoding='utf-8') as f:
                vault_container = json.load(f)

            # Validate structure
            required_fields = ['version', 'algorithm', 'salt', 'nonce', 'tag', 'encrypted_blob']
            missing = [f for f in required_fields if f not in vault_container]
            if missing:
                raise VaultCorruptionError(f"Missing vault fields: {missing}")

            # Derive master key from password and stored salt
            salt = base64.b64decode(vault_container['salt'])
            self._master_key = self._derive_key(self.master_password, salt)

            # Decrypt vault
            encrypted_blob = base64.b64decode(vault_container['encrypted_blob'])
            nonce = base64.b64decode(vault_container['nonce'])
            tag = base64.b64decode(vault_container['tag'])

            plaintext = self._decrypt_aes_gcm(encrypted_blob, nonce, tag, self._master_key)

            # Parse decrypted content
            self._vault_data = json.loads(plaintext)

            # Verify checksum
            expected_checksum = vault_container.get('checksum')
            if expected_checksum:
                import hashlib
                actual_checksum = hashlib.sha256(plaintext).hexdigest()
                if actual_checksum != expected_checksum:
                    raise VaultCorruptionError("Vault checksum mismatch - file may be corrupted")

            self._initialized = True
            logger.info(f"Unified vault initialized: {self.vault_file_path}")

        except json.JSONDecodeError as e:
            raise VaultCorruptionError(f"Vault file JSON invalid: {e}")
        except Exception as e:
            raise VaultInitializationError(f"Failed to initialize vault: {e}")

    def create_new_vault(self) -> None:
        """
        Create a new empty vault file.

        This is used during first-run initialization.
        """
        try:
            # Generate salt and master key
            salt = secrets.token_bytes(self.SALT_LENGTH)
            self._master_key = self._derive_key(self.master_password, salt)

            # Initialize empty vault structure
            self._vault_data = {
                "metadata": {
                    "vault_version": "1.0",
                    "encryption_algorithm": self.ALGORITHM,
                    "created_at": datetime.utcnow().isoformat() + "Z"
                },
                "app_secrets": {},
                "pki_keys": {
                    "internal_ca_private_key": None,
                    "engagement_ca_keys": {},
                    "report_signing_keys": {}
                }
            }

            # Save encrypted vault
            self._save_vault(salt)

            self._initialized = True
            logger.info(f"Created new vault: {self.vault_file_path}")

        except Exception as e:
            raise VaultInitializationError(f"Failed to create new vault: {e}")

    def get_secret(self, path: str) -> Optional[str]:
        """
        Retrieve a secret by path.

        Args:
            path: Secret path (e.g., "app_secrets/flask_secret_key" or "pki_keys/internal_ca_private_key")

        Returns:
            Secret value or None if not found

        Raises:
            UnifiedVaultError: If vault not initialized
        """
        if not self._initialized or self._vault_data is None:
            raise UnifiedVaultError("Vault not initialized - call initialize() first")

        try:
            # Reload vault from disk before reading to handle multi-worker scenarios
            self._reload_vault()

            parts = path.split('/')
            current = self._vault_data

            for part in parts:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    return None

            return current if isinstance(current, str) else None

        except Exception as e:
            logger.error(f"Failed to get secret at path {path}: {e}")
            raise UnifiedVaultError(f"Failed to retrieve secret: {e}")

    def set_secret(self, path: str, value: str) -> None:
        """
        Store or update a secret by path.

        Args:
            path: Secret path (e.g., "app_secrets/flask_secret_key")
            value: Secret value to store

        Raises:
            UnifiedVaultError: If vault not initialized or operation fails

        Flow: Load from disk → Update in memory → Save to disk → Reload from disk
        """
        if not self._initialized or self._vault_data is None:
            raise UnifiedVaultError("Vault not initialized - call initialize() first")

        try:
            # Step 1: Reload from disk to ensure latest data
            self._reload_vault()

            # Step 2: Update in-memory copy
            parts = path.split('/')
            current = self._vault_data

            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]

            current[parts[-1]] = value

            # Step 3: Save to disk (which also reloads)
            self._save_vault()

            logger.info(f"Stored secret at path: {path}")

        except Exception as e:
            logger.error(f"Failed to set secret at path {path}: {e}")
            raise UnifiedVaultError(f"Failed to store secret: {e}")

    # =========================================================================
    # PKI KEY MANAGEMENT (Specialized for private keys with metadata)
    # =========================================================================

    def set_key(self, key_name: str, key_pem: str, key_type: str = "rsa-4096",
                metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Store a PKI private key with metadata.

        Args:
            key_name: Key identifier (e.g., "internal_ca_private_key", "report-signing-key-ENG-2026-001")
            key_pem: Private key in PEM format
            key_type: Algorithm info (e.g., "rsa-4096", "rsa-2048")
            metadata: Optional dict with rotation_count, created_at, algorithm, etc.

        Raises:
            UnifiedVaultError: If vault not initialized or operation fails

        Flow: Load from disk → Update in memory → Save to disk → Reload from disk
        Single source of truth is always the disk file.
        """
        if not self._initialized or self._vault_data is None:
            raise UnifiedVaultError("Vault not initialized - call initialize() first")

        try:
            # Reload from disk to ensure we're working with latest data
            self._reload_vault()

            # Update in-memory copy with new key
            if 'pki_keys' not in self._vault_data:
                self._vault_data['pki_keys'] = {}

            key_object = {
                "pem": key_pem,
                "key_type": key_type,
                "created_at": datetime.utcnow().isoformat() + "Z"
            }

            if metadata:
                key_object.update(metadata)

            self._vault_data['pki_keys'][key_name] = key_object

            # Write to disk (reload happens automatically in _save_vault)
            self._save_vault()

            logger.info(f"Stored PKI key in vault: {key_name} (type: {key_type})")

        except Exception as e:
            logger.error(f"Failed to store PKI key {key_name}: {e}")
            raise UnifiedVaultError(f"Failed to store key: {e}")

    def get_key(self, key_name: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a PKI private key with metadata from vault.

        Args:
            key_name: Key identifier

        Returns:
            Dict with 'pem' (the private key), 'key_type', 'created_at', and other metadata
            or None if not found

        Raises:
            UnifiedVaultError: If vault not initialized
        """
        if not self._initialized or self._vault_data is None:
            raise UnifiedVaultError("Vault not initialized - call initialize() first")

        try:
            # Reload vault from disk before reading to ensure consistency in multi-worker environments
            self._reload_vault()

            pki_keys = self._vault_data.get('pki_keys', {})
            key_object = pki_keys.get(key_name)

            if not key_object:
                logger.debug(f"[VAULT GET_KEY] Key not found: {key_name}")
                return None

            # DIAGNOSTIC LOGGING
            logger.info(f"[VAULT GET_KEY] Found key in vault: {key_name}")
            logger.info(f"[VAULT GET_KEY] Key object type: {type(key_object).__name__}")

            # Return key object (dict with pem, key_type, metadata)
            if isinstance(key_object, dict):
                logger.info(f"[VAULT GET_KEY] Key is dict format with keys: {list(key_object.keys())}")
                pem_value = key_object.get('pem', '')
                logger.info(f"[VAULT GET_KEY] PEM field length: {len(pem_value)} chars")
                logger.info(f"[VAULT GET_KEY] PEM field type: {type(pem_value).__name__}")
                logger.info(f"[VAULT GET_KEY] PEM first 80 chars: {repr(pem_value[:80])}")
                logger.info(f"[VAULT GET_KEY] PEM last 80 chars: {repr(pem_value[-80:])}")
                logger.info(f"[VAULT GET_KEY] Actual newlines in PEM: {pem_value.count(chr(10))}")
                logger.info(f"[VAULT GET_KEY] String '\\\\n' sequences in PEM: {pem_value.count(r'\\n')}")
                return key_object
            elif isinstance(key_object, str):
                # Backward compatibility: old format stored just the PEM string
                logger.debug(f"Key {key_name} in old string format, converting to dict")
                return {"pem": key_object, "key_type": "unknown"}

            return None

        except Exception as e:
            logger.error(f"Failed to retrieve PKI key {key_name}: {e}")
            raise UnifiedVaultError(f"Failed to retrieve key: {e}")

    def get_key_pem(self, key_name: str) -> Optional[str]:
        """
        Convenience method: retrieve just the PEM portion of a key from vault.

        Args:
            key_name: Key identifier

        Returns:
            Private key in PEM format or None if not found
        """
        key_obj = self.get_key(key_name)
        return key_obj['pem'] if key_obj else None

    def delete_key(self, key_name: str) -> bool:
        """
        Delete a PKI key from vault (e.g., on rotation or revocation).

        Args:
            key_name: Key identifier

        Returns:
            True if deleted, False if not found

        Raises:
            UnifiedVaultError: If vault not initialized
        """
        if not self._initialized or self._vault_data is None:
            raise UnifiedVaultError("Vault not initialized - call initialize() first")

        try:
            pki_keys = self._vault_data.get('pki_keys', {})
            if key_name in pki_keys:
                del pki_keys[key_name]
                self._save_vault()
                logger.info(f"Deleted PKI key from vault: {key_name}")
                return True
            return False

        except Exception as e:
            logger.error(f"Failed to delete PKI key {key_name}: {e}")
            raise UnifiedVaultError(f"Failed to delete key: {e}")

    def delete_secret(self, path: str) -> bool:
        """
        Delete a secret by path.

        Args:
            path: Secret path

        Returns:
            True if deleted, False if not found

        Raises:
            UnifiedVaultError: If vault not initialized
        """
        if not self._initialized or self._vault_data is None:
            raise UnifiedVaultError("Vault not initialized - call initialize() first")

        try:
            # Step 1: Reload from disk to ensure latest data
            self._reload_vault()

            # Step 2: Delete from in-memory copy
            parts = path.split('/')
            current = self._vault_data

            for part in parts[:-1]:
                if part not in current:
                    return False
                current = current[part]

            # Delete final key
            if parts[-1] in current:
                del current[parts[-1]]
                # Step 3: Save to disk (which also reloads)
                self._save_vault()
                logger.info(f"Deleted secret at path: {path}")
                return True

            return False

        except Exception as e:
            logger.error(f"Failed to delete secret at path {path}: {e}")
            raise UnifiedVaultError(f"Failed to delete secret: {e}")

    def list_secrets(self, path_prefix: str = "") -> List[str]:
        """
        List all secret paths in vault (not values).

        Args:
            path_prefix: Optional prefix to filter (e.g., "app_secrets/")

        Returns:
            List of secret paths
        """
        if not self._initialized or self._vault_data is None:
            return []

        try:
            # Reload vault from disk before reading to handle multi-worker scenarios
            self._reload_vault()

            paths = []

            def traverse(obj: Any, current_path: str = ""):
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        new_path = f"{current_path}/{key}" if current_path else key

                        if isinstance(value, dict):
                            traverse(value, new_path)
                        elif isinstance(value, str) and value:
                            if not path_prefix or new_path.startswith(path_prefix):
                                paths.append(new_path)

            traverse(self._vault_data)
            return sorted(paths)

        except Exception as e:
            logger.error(f"Failed to list secrets: {e}")
            return []

    def get_vault_status(self) -> Dict[str, Any]:
        """
        Get vault status and metadata.

        Returns:
            Dict with vault health and statistics
        """
        if not self._initialized:
            return {
                "status": "uninitialized",
                "file_path": self.vault_file_path,
                "exists": os.path.exists(self.vault_file_path)
            }

        try:
            file_size = os.path.getsize(self.vault_file_path) if os.path.exists(self.vault_file_path) else 0

            app_secrets = self._vault_data.get('app_secrets', {})
            pki_keys = self._vault_data.get('pki_keys', {})

            internal_ca_key = pki_keys.get('internal_ca_private_key')
            engagement_ca_count = len(pki_keys.get('engagement_ca_keys', {}))
            report_signing_count = len(pki_keys.get('report_signing_keys', {}))

            return {
                "status": "initialized",
                "file_path": self.vault_file_path,
                "file_size_bytes": file_size,
                "created_at": self._vault_data.get('metadata', {}).get('created_at'),
                "app_secrets_count": len(app_secrets),
                "pki_keys": {
                    "internal_ca": "present" if internal_ca_key else "missing",
                    "engagement_ca_count": engagement_ca_count,
                    "report_signing_count": report_signing_count,
                    "total_pki_keys": 1 + engagement_ca_count + report_signing_count if internal_ca_key else engagement_ca_count + report_signing_count
                }
            }

        except Exception as e:
            logger.error(f"Failed to get vault status: {e}")
            return {"status": "error", "error": str(e)}

    # Private Methods

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=UnifiedVaultService.KEY_LENGTH,
            salt=salt,
            iterations=UnifiedVaultService.ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))

    @staticmethod
    def _encrypt_aes_gcm(plaintext: bytes, key: bytes) -> tuple:
        """
        Encrypt plaintext using AES-256-GCM.

        Returns:
            (ciphertext, nonce, tag)
        """
        cipher = AESGCM(key)
        nonce = secrets.token_bytes(UnifiedVaultService.NONCE_LENGTH)
        ciphertext = cipher.encrypt(nonce, plaintext, None)

        # GCM mode includes authentication tag in the ciphertext
        # Split into ciphertext and tag
        return ciphertext[:-16], nonce, ciphertext[-16:]

    @staticmethod
    def _decrypt_aes_gcm(ciphertext: bytes, nonce: bytes, tag: bytes, key: bytes) -> bytes:
        """Decrypt ciphertext using AES-256-GCM with authentication tag."""
        cipher = AESGCM(key)
        combined = ciphertext + tag  # GCM expects ciphertext + tag combined
        plaintext = cipher.decrypt(nonce, combined, None)
        return plaintext

    def _save_vault(self, salt: Optional[bytes] = None) -> None:
        """
        Encrypt and save vault to file.

        Args:
            salt: Optional salt to use (if None, reload from existing vault file)
        """
        try:
            # Use existing salt if not provided
            if salt is None:
                with open(self.vault_file_path, 'r', encoding='utf-8') as f:
                    existing = json.load(f)
                    salt = base64.b64decode(existing.get('salt', ''))

            # Serialize vault data
            plaintext = json.dumps(self._vault_data, indent=2)
            plaintext_bytes = plaintext.encode('utf-8')

            # Calculate checksum
            import hashlib
            checksum = hashlib.sha256(plaintext_bytes).hexdigest()

            # Encrypt
            ciphertext, nonce, tag = self._encrypt_aes_gcm(plaintext_bytes, self._master_key)

            # Create vault container
            vault_container = {
                "version": "1.0",
                "algorithm": self.ALGORITHM,
                "key_derivation": self.KEY_DERIVATION,
                "iterations": self.ITERATIONS,
                "created_at": self._vault_data.get('metadata', {}).get('created_at'),
                "last_updated": datetime.utcnow().isoformat() + "Z",
                "vault_id": "system_vault",
                "salt": base64.b64encode(salt).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "tag": base64.b64encode(tag).decode(),
                "encrypted_blob": base64.b64encode(ciphertext).decode(),
                "checksum": checksum
            }

            # Write to file
            with open(self.vault_file_path, 'w', encoding='utf-8') as f:
                json.dump(vault_container, f, indent=2)

            logger.info(f"Vault saved: {self.vault_file_path} ({len(plaintext_bytes)} bytes encrypted)")

            # Reload vault from disk to keep in-memory cache in sync
            self._reload_vault()

        except Exception as e:
            logger.error(f"Failed to save vault: {e}")
            raise VaultEncryptionError(f"Failed to encrypt and save vault: {e}")

    def _reload_vault(self) -> None:
        """
        Reload vault from disk into memory.

        Called after modifications to ensure in-memory cache stays in sync with file.
        Implements disk-first architecture where the encrypted file is the single source of truth.
        """
        try:
            if not os.path.exists(self.vault_file_path):
                logger.warning(f"Vault file not found during reload: {self.vault_file_path}")
                return

            # Load vault file
            with open(self.vault_file_path, 'r', encoding='utf-8') as f:
                vault_container = json.load(f)

            # Decrypt vault
            encrypted_blob = base64.b64decode(vault_container['encrypted_blob'])
            nonce = base64.b64decode(vault_container['nonce'])
            tag = base64.b64decode(vault_container['tag'])
            plaintext = self._decrypt_aes_gcm(encrypted_blob, nonce, tag, self._master_key)

            # Parse and update in-memory data
            self._vault_data = json.loads(plaintext)
            logger.debug(f"Vault reloaded from disk: {self.vault_file_path}")

        except Exception as e:
            # Log error but don't raise - reload is best-effort sync
            logger.error(f"Failed to reload vault: {e}")

    def export_for_backup(self) -> bytes:
        """
        Export encrypted vault file as bytes (for backup/download).

        Returns:
            Encrypted vault file contents
        """
        try:
            with open(self.vault_file_path, 'rb') as f:
                return f.read()
        except Exception as e:
            raise UnifiedVaultError(f"Failed to export vault: {e}")

    def restore_from_backup(self, backup_data: bytes) -> None:
        """
        Restore vault from backup data.

        Args:
            backup_data: Encrypted vault file contents

        Raises:
            UnifiedVaultError: If restore fails
        """
        try:
            # Write backup data to file
            with open(self.vault_file_path, 'wb') as f:
                f.write(backup_data)

            # Re-initialize to verify integrity
            self._vault_data = None
            self._initialized = False
            self.initialize()

            logger.info(f"Vault restored from backup: {self.vault_file_path}")

        except Exception as e:
            raise UnifiedVaultError(f"Failed to restore vault from backup: {e}")


# Global instance (initialized at app startup)
_unified_vault_service: Optional[UnifiedVaultService] = None


def init_unified_vault_service(vault_file_path: str, master_password: str) -> UnifiedVaultService:
    """
    Initialize global unified vault service.

    Args:
        vault_file_path: Path to system_vault.enc
        master_password: Master password for vault

    Returns:
        Initialized UnifiedVaultService instance

    Raises:
        VaultInitializationError: If initialization fails
    """
    global _unified_vault_service

    _unified_vault_service = UnifiedVaultService(vault_file_path, master_password)

    # If vault file doesn't exist, create it
    if not os.path.exists(vault_file_path):
        logger.info(f"Vault file not found - creating new vault: {vault_file_path}")
        _unified_vault_service.create_new_vault()
    else:
        # Load existing vault
        _unified_vault_service.initialize()

    return _unified_vault_service


def get_unified_vault_service() -> Optional[UnifiedVaultService]:
    """Get the global unified vault service instance."""
    return _unified_vault_service
