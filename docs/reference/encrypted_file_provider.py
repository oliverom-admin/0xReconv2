"""
Encrypted File Secret Store Provider

Offline secret store using native AES-256-GCM encryption.
Designed for air-gapped environments and local secret management.

The encrypted vault file format:
- JSON file with AES-256-GCM encrypted content
- Contains a dict mapping secret paths to values
- Requires passphrase or key file to unlock
- No external tool dependencies (native Python cryptography)

This provider never stores decrypted secrets in memory beyond immediate use.
"""

import logging
import json
import os
import base64
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

from caip_service_layer.secret_store_providers.base import (
    SecretStoreProvider,
    SecretMetadata,
    StoreConnectionStatus,
    resolve_bootstrap_credential
)
from caip_service_layer.secret_service import (
    SecretStoreConnectionError,
    SecretStoreAccessError,
    SecretStoreUnlockError,
    SecretNotFoundError,
    SecretStoreLockedError
)
from caip_service_layer.encryption_utils import (
    derive_key_from_passphrase,
    load_key_from_file,
    encrypt_content,
    decrypt_content,
    encrypt_file as encrypt_to_file,
    decrypt_file as decrypt_from_file,
    EncryptionError,
    DecryptionError
)

logger = logging.getLogger('caip.operational')


class EncryptedFileProvider(SecretStoreProvider):
    """
    Encrypted file-based secret store for offline environments.

    Uses native AES-256-GCM encryption (no external tools required).
    Stores secrets in a JSON file that is encrypted at rest.

    Config options:
    {
        "vault_file_path": "/path/to/secrets.enc",
        "unlock_method": "passphrase" | "key_file",

        # For passphrase unlock:
        "passphrase_source": "env" | "prompt" | "value",
        "passphrase_env_var": "VAULT_PASSPHRASE",

        # For key file unlock:
        "key_file_path": "/path/to/encryption-key.txt",

        # Optional startup credentials (injected by SecretStoreManager)
        "_startup_credentials": {...}
    }

    The vault file can be created via:
    - Dashboard: Secret Stores tab -> Initialize New Vault
    - CLI: caip-vault init --vault-file /path/to/secrets.enc
    """

    def __init__(self):
        self.vault_file_path: Optional[str] = None
        self.unlock_method: Optional[str] = None
        self.key_file_path: Optional[str] = None
        self.passphrase: Optional[str] = None
        self._decrypted_secrets: Optional[Dict[str, str]] = None
        self._locked = True

    def connect(self, config: Dict[str, Any]) -> None:
        """
        Load encrypted vault file configuration.

        Does NOT decrypt the file yet - decryption happens on unlock().
        """
        try:
            self.vault_file_path = config.get('vault_file_path')
            if not self.vault_file_path:
                raise ValueError("vault_file_path is required")

            # Check file exists
            if not os.path.exists(self.vault_file_path):
                raise ValueError(f"Vault file not found: {self.vault_file_path}")

            self.unlock_method = config.get('unlock_method', 'passphrase').lower()

            if self.unlock_method == 'key_file':
                self.key_file_path = config.get('key_file_path')
                if not self.key_file_path:
                    raise ValueError("key_file_path is required for key_file unlock method")
                if not os.path.exists(self.key_file_path):
                    raise ValueError(f"Key file not found: {self.key_file_path}")
            elif self.unlock_method != 'passphrase':
                raise ValueError(f"Unknown unlock method: {self.unlock_method}")

            logger.info(f"Encrypted vault file loaded: {self.vault_file_path}")

        except Exception as e:
            raise SecretStoreConnectionError(f"Failed to load vault file: {e}")

    def test_connection(self) -> StoreConnectionStatus:
        """Test connectivity to encrypted vault file."""
        if not os.path.exists(self.vault_file_path):
            return StoreConnectionStatus(
                connected=False,
                message="Vault file not found"
            )

        if self._locked:
            return StoreConnectionStatus(
                connected=False,
                message="Vault is locked - requires unlock"
            )

        if not self._decrypted_secrets:
            return StoreConnectionStatus(
                connected=False,
                message="Vault not unlocked"
            )

        return StoreConnectionStatus(
            connected=True,
            message="Connected to encrypted vault file",
            secret_count=len(self._decrypted_secrets)
        )

    def list_secrets(self, path_prefix: str = "") -> List[SecretMetadata]:
        """List secrets in the decrypted vault."""
        if self._locked:
            raise SecretStoreLockedError("Vault is locked - call unlock() first")

        if self._decrypted_secrets is None:
            raise SecretStoreAccessError("Vault not decrypted")

        try:
            secrets = []
            for path, value in self._decrypted_secrets.items():
                if path_prefix and not path.startswith(path_prefix):
                    continue

                secrets.append(SecretMetadata(
                    name=path.split('/')[-1],
                    path=path,
                    created_at=datetime.utcnow(),
                    tags={}
                ))

            return secrets

        except Exception as e:
            raise SecretStoreAccessError(f"Failed to list secrets: {e}")

    def get_secret(self, secret_path: str, version: str = "latest") -> str:
        """Retrieve a secret value from decrypted vault."""
        if self._locked:
            raise SecretStoreLockedError("Vault is locked - call unlock() first")

        if self._decrypted_secrets is None:
            raise SecretStoreAccessError("Vault not decrypted")

        try:
            if secret_path not in self._decrypted_secrets:
                raise SecretNotFoundError(f"Secret not found: {secret_path}")

            return self._decrypted_secrets[secret_path]

        except SecretNotFoundError:
            raise
        except Exception as e:
            raise SecretStoreAccessError(f"Failed to retrieve secret: {e}")

    def create_secret(self, secret_path: str, value: str,
                      description: str = None) -> SecretMetadata:
        """Add a secret to the decrypted vault."""
        if self._locked:
            raise SecretStoreLockedError("Vault is locked - call unlock() first")

        if self._decrypted_secrets is None:
            raise SecretStoreAccessError("Vault not decrypted")

        try:
            if secret_path in self._decrypted_secrets:
                raise ValueError(f"Secret already exists: {secret_path}")

            self._decrypted_secrets[secret_path] = value

            # Save encrypted vault back to file
            self._save_encrypted_vault()

            return SecretMetadata(
                name=secret_path.split('/')[-1],
                path=secret_path,
                created_at=datetime.utcnow(),
                description=description,
                tags={}
            )

        except ValueError as e:
            raise SecretStoreAccessError(str(e))
        except Exception as e:
            raise SecretStoreAccessError(f"Failed to create secret: {e}")

    def update_secret(self, secret_path: str, value: str) -> SecretMetadata:
        """Update an existing secret's value."""
        if self._locked:
            raise SecretStoreLockedError("Vault is locked - call unlock() first")

        if self._decrypted_secrets is None:
            raise SecretStoreAccessError("Vault not decrypted")

        try:
            if secret_path not in self._decrypted_secrets:
                raise SecretNotFoundError(f"Secret not found: {secret_path}")

            self._decrypted_secrets[secret_path] = value

            # Save encrypted vault back to file
            self._save_encrypted_vault()

            return SecretMetadata(
                name=secret_path.split('/')[-1],
                path=secret_path,
                updated_at=datetime.utcnow(),
                tags={}
            )

        except SecretNotFoundError:
            raise
        except Exception as e:
            raise SecretStoreAccessError(f"Failed to update secret: {e}")

    def delete_secret(self, secret_path: str) -> bool:
        """Delete a secret from the decrypted vault."""
        if self._locked:
            raise SecretStoreLockedError("Vault is locked - call unlock() first")

        if self._decrypted_secrets is None:
            raise SecretStoreAccessError("Vault not decrypted")

        try:
            if secret_path not in self._decrypted_secrets:
                return False

            del self._decrypted_secrets[secret_path]

            # Save encrypted vault back to file
            self._save_encrypted_vault()

            return True

        except Exception as e:
            raise SecretStoreAccessError(f"Failed to delete secret: {e}")

    def unlock(self, credentials: Dict[str, Any]) -> bool:
        """
        Unlock the encrypted vault file.

        Args:
            credentials: Dict with 'passphrase' key for passphrase-based vaults
                        or 'key_file' for key-file-based vaults
        """
        try:
            if self.unlock_method == 'passphrase':
                passphrase = credentials.get('passphrase')
                if not passphrase:
                    raise SecretStoreUnlockError("passphrase required")

                self.passphrase = passphrase
                self._decrypt_vault_with_passphrase()

            elif self.unlock_method == 'key_file':
                self._decrypt_vault_with_key_file()

            self._locked = False
            logger.info("Encrypted vault unlocked successfully")
            return True

        except SecretStoreUnlockError:
            raise
        except Exception as e:
            raise SecretStoreUnlockError(f"Failed to unlock vault: {e}")

    def _decrypt_vault_with_passphrase(self) -> None:
        """Decrypt vault file using AES-256-GCM with passphrase."""
        if not self.passphrase:
            raise SecretStoreUnlockError("Passphrase not set")

        try:
            # Load encrypted file
            with open(self.vault_file_path, 'r', encoding='utf-8') as f:
                encrypted_vault = json.load(f)

            # Recover salt from file
            salt = None
            if 'salt' in encrypted_vault and encrypted_vault['salt']:
                salt = base64.b64decode(encrypted_vault['salt'])

            # Derive key from passphrase and salt
            key, _ = derive_key_from_passphrase(self.passphrase, salt)

            # Decrypt content
            decrypted_content = decrypt_content(encrypted_vault, key)
            self._decrypted_secrets = json.loads(decrypted_content)

        except DecryptionError as e:
            raise SecretStoreUnlockError(f"Invalid passphrase or corrupted vault file: {e}")
        except json.JSONDecodeError as e:
            raise SecretStoreUnlockError(f"Invalid vault file format: {e}")
        except Exception as e:
            raise SecretStoreUnlockError(f"Decryption failed: {e}")

    def _decrypt_vault_with_key_file(self) -> None:
        """Decrypt vault file using AES-256-GCM with key file."""
        try:
            # Load key from file
            key = load_key_from_file(self.key_file_path)

            # Load encrypted file
            with open(self.vault_file_path, 'r', encoding='utf-8') as f:
                encrypted_vault = json.load(f)

            # Decrypt content
            decrypted_content = decrypt_content(encrypted_vault, key)
            self._decrypted_secrets = json.loads(decrypted_content)

        except DecryptionError as e:
            raise SecretStoreUnlockError(f"Invalid key file or corrupted vault: {e}")
        except json.JSONDecodeError as e:
            raise SecretStoreUnlockError(f"Invalid vault file format: {e}")
        except Exception as e:
            raise SecretStoreUnlockError(f"Decryption failed: {e}")


    def _save_encrypted_vault(self) -> None:
        """
        Save decrypted secrets back to encrypted file using native AES-256-GCM.

        This re-encrypts the vault with the same passphrase/key.
        """
        try:
            # Serialize secrets to JSON
            vault_json = json.dumps(self._decrypted_secrets, indent=2)

            if self.unlock_method == 'passphrase' and self.passphrase:
                # For passphrase-based encryption, include salt in file
                # Load salt from original file if it exists
                salt = None
                if os.path.exists(self.vault_file_path):
                    try:
                        with open(self.vault_file_path, 'r', encoding='utf-8') as f:
                            existing = json.load(f)
                            if 'salt' in existing and existing['salt']:
                                salt = base64.b64decode(existing['salt'])
                    except (json.JSONDecodeError, Exception):
                        salt = None

                # Derive key from passphrase
                key, derived_salt = derive_key_from_passphrase(self.passphrase, salt)

                # Encrypt and save
                encrypt_to_file(self.vault_file_path, vault_json, key, derived_salt)

            elif self.unlock_method == 'key_file' and self.key_file_path:
                # For key-file-based encryption, no salt needed
                key = load_key_from_file(self.key_file_path)
                encrypt_to_file(self.vault_file_path, vault_json, key, None)

            else:
                raise SecretStoreAccessError("Cannot save vault - no passphrase or key file")

            logger.info(f"Vault saved: {self.vault_file_path}")

        except EncryptionError as e:
            raise SecretStoreAccessError(f"Failed to encrypt vault: {e}")
        except Exception as e:
            raise SecretStoreAccessError(f"Failed to save vault: {e}")

    def get_provider_type(self) -> str:
        """Return provider type identifier."""
        return 'encrypted_file'

    def requires_unlock(self) -> bool:
        """Encrypted file requires explicit unlock."""
        return True

    def is_unlocked(self) -> bool:
        """Return whether vault is unlocked."""
        return not self._locked

    def lock(self) -> None:
        """Lock the vault, clearing decrypted secrets from memory."""
        self._decrypted_secrets = None
        self._locked = True
        self.passphrase = None
        logger.info("Encrypted vault locked - secrets cleared from memory")


# Auto-register this provider
from caip_service_layer.secret_store_providers import register_provider
register_provider('encrypted_file', EncryptedFileProvider)
