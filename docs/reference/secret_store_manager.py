"""
Secret Store Manager Service

Central service for managing external secret store connections and resolving
secret references at runtime.

This service:
- Maintains connections to registered secret stores
- Lists available secrets (metadata only, not values)
- Resolves secret references at scan/connector runtime
- Supports adding new secrets to stores (via UI)

IMPORTANT: This service never stores secret values - it only facilitates
access to external stores owned and managed by users.
"""

import json
import logging
import copy
from typing import Dict, List, Optional, Any, Type
from datetime import datetime

from database_service import DatabaseService
from caip_service_layer.secret_store_providers.base import (
    SecretStoreProvider,
    SecretMetadata,
    StoreConnectionStatus
)
from caip_service_layer.secret_service import (
    SecretStoreError,
    SecretStoreConnectionError,
    SecretStoreNotFoundError,
    SecretStoreLockedError,
    SecretNotFoundError
)
# Import provider registry from the providers package
from caip_service_layer.secret_store_providers import PROVIDER_REGISTRY

logger = logging.getLogger('caip.operational')


class SecretStoreManager:
    """
    Manages registered secret stores and resolves secret references.

    This is the central service that:
    - Maintains connections to registered secret stores
    - Lists available secrets (metadata only)
    - Resolves secret references at scan runtime
    - Supports adding new secrets to stores (via UI)

    IMPORTANT: This service never stores secret values - it only
    facilitates access to external stores.
    """

    def __init__(self, startup_credentials: Dict[str, str] = None):
        """
        Initialize the SecretStoreManager.

        Args:
            startup_credentials: Dict of credentials collected at startup
                               for stores using 'prompt' credential source.
                               Key format: "{store_id}_{credential_name}"
        """
        self._providers: Dict[str, SecretStoreProvider] = {}
        self._store_configs: Dict[str, Dict] = {}
        self._startup_credentials = startup_credentials or {}
        self._load_registered_stores()

    def _load_registered_stores(self):
        """Load all registered stores from database and initialize providers."""
        try:
            with DatabaseService.get_connection_context() as conn:
                c = conn.cursor()
                c.execute('''
                    SELECT id, name, provider_type, connection_config, status
                    FROM secret_stores
                    WHERE status != ?
                ''', ('deleted',))
                rows = c.fetchall()

            for row in rows:
                store_id = str(row['id'])
                try:
                    self._init_provider(
                        store_id=store_id,
                        name=row['name'],
                        provider_type=row['provider_type'],
                        config=json.loads(row['connection_config'])
                    )
                    logger.info(f"Loaded secret store: {row['name']} ({row['provider_type']})")
                except Exception as e:
                    logger.warning(f"Failed to initialize store '{row['name']}': {e}")
                    self._update_store_status(store_id, 'error', str(e))

        except Exception as e:
            logger.error(f"Failed to load secret stores: {e}")

    def _init_provider(self, store_id: str, name: str,
                       provider_type: str, config: Dict) -> SecretStoreProvider:
        """Initialize a provider instance for a store."""
        provider_class = PROVIDER_REGISTRY.get(provider_type)
        if not provider_class:
            raise ValueError(f"Unknown provider type: {provider_type}. "
                           f"Available: {list(PROVIDER_REGISTRY.keys())}")

        provider = provider_class()

        # Pass startup credentials for 'prompt' sources
        config['_startup_credentials'] = self._startup_credentials
        config['_store_id'] = store_id

        provider.connect(config)

        self._providers[store_id] = provider
        self._store_configs[store_id] = {
            'name': name,
            'provider_type': provider_type,
            'config': config
        }

        return provider

    def _update_store_status(self, store_id: str, status: str, message: str = None):
        """Update store status in database."""
        try:
            with DatabaseService.get_connection_context() as conn:
                c = conn.cursor()
                c.execute('''
                    UPDATE secret_stores
                    SET status = ?, status_message = ?, updated_at = ?
                    WHERE id = ?
                ''', (status, message, datetime.utcnow(), store_id))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to update store status: {e}")

    # =========================================================================
    # STORE MANAGEMENT
    # =========================================================================

    def register_store(self, name: str, provider_type: str,
                       config: Dict[str, Any], created_by: int = None) -> Dict:
        """
        Register a new secret store.

        Args:
            name: User-friendly store name
            provider_type: One of the registered provider types
            config: Provider-specific configuration
            created_by: User ID who created the store

        Returns:
            Dict with store details including ID

        Raises:
            ValueError: If provider_type is invalid
            SecretStoreConnectionError: If connection test fails
        """
        # Validate provider type
        if provider_type not in PROVIDER_REGISTRY:
            raise ValueError(f"Invalid provider type: {provider_type}. "
                           f"Must be one of: {list(PROVIDER_REGISTRY.keys())}")

        # Create provider and test connection (unless it requires unlock)
        provider_class = PROVIDER_REGISTRY[provider_type]
        provider = provider_class()

        # Add startup credentials context
        config_with_context = config.copy()
        config_with_context['_startup_credentials'] = self._startup_credentials

        provider.connect(config_with_context)

        status = 'pending'
        status_message = None
        secret_count = None

        if not provider.requires_unlock():
            # Test connection for online stores
            test_result = provider.test_connection()
            if test_result.connected:
                status = 'active'
                status_message = test_result.message
                secret_count = test_result.secret_count
            else:
                status = 'error'
                status_message = test_result.message
        else:
            status = 'locked'
            status_message = 'Store requires unlock (passphrase or key)'

        # Save to database
        with DatabaseService.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO secret_stores
                (name, provider_type, connection_config, status, status_message,
                 secret_count, created_by, last_verified_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                name,
                provider_type,
                json.dumps(config),
                status,
                status_message,
                secret_count,
                created_by,
                datetime.utcnow() if status == 'active' else None
            ))
            store_id = str(c.lastrowid)
            conn.commit()

        # Cache provider
        self._providers[store_id] = provider
        self._store_configs[store_id] = {
            'name': name,
            'provider_type': provider_type,
            'config': config
        }

        logger.info(f"Registered secret store: {name} ({provider_type}) - status: {status}")

        return {
            'id': store_id,
            'name': name,
            'provider_type': provider_type,
            'status': status,
            'status_message': status_message,
            'secret_count': secret_count
        }

    def list_stores(self) -> List[Dict]:
        """List all registered secret stores with their status."""
        stores = []

        with DatabaseService.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT id, name, provider_type, connection_config, status, status_message,
                       secret_count, last_verified_at, created_at
                FROM secret_stores
                WHERE status != 'deleted'
                ORDER BY name
            ''')
            rows = c.fetchall()

        for row in rows:
            store_id = str(row['id'])
            provider = self._providers.get(store_id)

            # Parse connection config if it's a JSON string
            try:
                connection_config = json.loads(row['connection_config']) if isinstance(row['connection_config'], str) else row['connection_config']
            except (json.JSONDecodeError, TypeError):
                connection_config = {}

            # For stores that require unlock, dynamically check their actual status
            requires_unlock = provider.requires_unlock() if provider else False
            is_unlocked = provider.is_unlocked() if provider else False

            # Determine the real status based on unlock state
            display_status = row['status']
            display_message = row['status_message']

            if requires_unlock:
                # For locked stores, always show 'locked' status regardless of database
                if not is_unlocked:
                    display_status = 'locked'
                    display_message = 'Vault is locked - requires unlock'
                else:
                    # If unlocked, show active
                    display_status = 'active'

            stores.append({
                'id': store_id,
                'name': row['name'],
                'provider_type': row['provider_type'],
                'connection_config': connection_config,
                'status': display_status,
                'status_message': display_message,
                'secret_count': row['secret_count'] if is_unlocked else None,
                'last_verified_at': row['last_verified_at'],
                'created_at': row['created_at'],
                'requires_unlock': requires_unlock,
                'is_unlocked': is_unlocked
            })

        return stores

    def get_store(self, store_id: str) -> Optional[Dict]:
        """Get details of a specific store."""
        with DatabaseService.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM secret_stores WHERE id = ?', (store_id,))
            row = c.fetchone()

        if not row:
            return None

        provider = self._providers.get(store_id)

        return {
            'id': str(row['id']),
            'name': row['name'],
            'provider_type': row['provider_type'],
            'status': row['status'],
            'status_message': row['status_message'],
            'secret_count': row['secret_count'],
            'last_verified_at': row['last_verified_at'],
            'requires_unlock': provider.requires_unlock() if provider else False,
            'is_unlocked': provider.is_unlocked() if provider else False
        }

    def delete_store(self, store_id: str) -> bool:
        """
        Delete a secret store registration.

        NOTE: This only removes CAIP's reference to the store.
        It does NOT delete the actual vault or its secrets.
        """
        with DatabaseService.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                UPDATE secret_stores
                SET status = 'deleted', updated_at = ?
                WHERE id = ?
            ''', (datetime.utcnow(), store_id))
            conn.commit()

        # Remove from cache
        self._providers.pop(store_id, None)
        self._store_configs.pop(store_id, None)

        logger.info(f"Deleted secret store: {store_id}")
        return True

    def test_store_connection(self, store_id: str) -> StoreConnectionStatus:
        """Test connectivity to a store."""
        provider = self._providers.get(store_id)
        if not provider:
            return StoreConnectionStatus(
                connected=False,
                message="Store not found or not initialized"
            )

        status = provider.test_connection()

        # Update database with test results
        with DatabaseService.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                UPDATE secret_stores
                SET status = ?, status_message = ?, secret_count = ?,
                    last_verified_at = ?, updated_at = ?
                WHERE id = ?
            ''', (
                'active' if status.connected else 'error',
                status.message,
                status.secret_count,
                datetime.utcnow() if status.connected else None,
                datetime.utcnow(),
                store_id
            ))
            conn.commit()

        return status

    def unlock_store(self, store_id: str, credentials: Dict[str, Any]) -> bool:
        """
        Unlock a store that requires authentication (e.g., encrypted file).

        Args:
            store_id: Store ID
            credentials: Provider-specific unlock credentials
                        (e.g., {'passphrase': '...'} for encrypted files)

        Returns:
            True if unlocked successfully
        """
        provider = self._providers.get(store_id)
        if not provider:
            raise SecretStoreNotFoundError(f"Store not found: {store_id}")

        if not provider.requires_unlock():
            return True  # Already unlocked (online stores)

        success = provider.unlock(credentials)

        if success:
            # Update status and get secret count
            status = provider.test_connection()
            self._update_store_status(
                store_id,
                'active',
                f"Unlocked - {status.secret_count} secrets available"
            )

        return success

    def lock_store(self, store_id: str) -> bool:
        """
        Lock a store that requires authentication (e.g., encrypted file).

        This clears the decryption key from memory, requiring re-entry of
        passphrase to access secrets again.

        Args:
            store_id: Store ID

        Returns:
            True if locked successfully
        """
        provider = self._providers.get(store_id)
        if not provider:
            raise SecretStoreNotFoundError(f"Store not found: {store_id}")

        if not provider.requires_unlock():
            return True  # Already locked (online stores)

        try:
            provider.lock()
            # Update status to locked
            self._update_store_status(
                store_id,
                'locked',
                'Locked - enter passphrase to unlock'
            )
            return True
        except Exception:
            return False

    def initialize_encrypted_vault(self, vault_file_path: str, passphrase: str) -> Dict:
        """
        Initialize a new encrypted vault file.

        This is used when creating a new encrypted file store through the UI.
        Creates an empty encrypted vault file that can then be registered as
        a store in CAIP.

        Args:
            vault_file_path: Path where the vault file will be created
            passphrase: Passphrase to encrypt the vault

        Returns:
            Dict with initialization status

        Raises:
            FileExistsError: If vault file already exists
            EncryptionError: If encryption fails
        """
        import os
        from caip_service_layer.encryption_utils import (
            derive_key_from_passphrase,
            encrypt_file
        )

        try:
            if os.path.exists(vault_file_path):
                raise FileExistsError(f"Vault file already exists: {vault_file_path}")

            # Create parent directory if needed
            os.makedirs(os.path.dirname(vault_file_path), exist_ok=True)

            # Derive key from passphrase
            key, salt = derive_key_from_passphrase(passphrase)

            # Create empty vault
            empty_vault_json = "{}"

            # Encrypt and save
            encrypt_file(vault_file_path, empty_vault_json, key, salt)

            logger.info(f"Initialized encrypted vault: {vault_file_path}")

            return {
                'success': True,
                'message': f"Vault initialized at {vault_file_path}",
                'vault_file_path': vault_file_path,
                'can_register': True  # Ready to register as a store
            }

        except FileExistsError:
            raise
        except Exception as e:
            logger.error(f"Failed to initialize vault: {e}")
            raise

    # =========================================================================
    # SECRET OPERATIONS
    # =========================================================================

    def list_secrets(self, store_id: str, path_prefix: str = "") -> List[SecretMetadata]:
        """
        List available secrets in a store (metadata only, not values).

        Args:
            store_id: Store ID
            path_prefix: Optional prefix to filter secrets

        Returns:
            List of SecretMetadata objects
        """
        provider = self._providers.get(store_id)
        if not provider:
            raise SecretStoreNotFoundError(f"Store not found: {store_id}")

        if provider.requires_unlock() and not provider.is_unlocked():
            raise SecretStoreLockedError(
                f"Store '{store_id}' is locked. Unlock before listing secrets."
            )

        return provider.list_secrets(path_prefix)

    def resolve_secret_ref(self, secret_ref: Dict[str, Any]) -> str:
        """
        Resolve a secret reference to its actual value.

        This is called at scan/connector runtime to get the actual
        secret value. The value is returned but NEVER stored by CAIP.

        Args:
            secret_ref: Secret reference dict with:
                - store_id: Store ID
                - path: Secret path/name
                - version: Optional version (default: "latest")

        Returns:
            Secret value as string
        """
        store_id = secret_ref.get('store_id')
        path = secret_ref.get('path')
        version = secret_ref.get('version', 'latest')

        if not store_id or not path:
            raise ValueError("Invalid secret reference: missing store_id or path")

        provider = self._providers.get(store_id)
        if not provider:
            raise SecretStoreNotFoundError(f"Store not found: {store_id}")

        if provider.requires_unlock() and not provider.is_unlocked():
            raise SecretStoreLockedError(
                f"Store '{store_id}' is locked. Unlock before accessing secrets."
            )

        # Log secret access (for audit - never log the value)
        logger.info(f"Resolving secret: store={store_id}, path={path}")

        return provider.get_secret(path, version)

    def add_secret_to_store(self, store_id: str, secret_name: str,
                            secret_value: str, description: str = None) -> SecretMetadata:
        """
        Add a new secret to a store.

        This is used by the UI when users want to add a new secret
        to their vault directly from CAIP.

        Args:
            store_id: Store ID
            secret_name: Name/path for the new secret
            secret_value: The secret value
            description: Optional description

        Returns:
            Metadata of the created secret
        """
        provider = self._providers.get(store_id)
        if not provider:
            raise SecretStoreNotFoundError(f"Store not found: {store_id}")

        if provider.requires_unlock() and not provider.is_unlocked():
            raise SecretStoreLockedError(
                f"Store '{store_id}' is locked. Unlock before adding secrets."
            )

        metadata = provider.create_secret(secret_name, secret_value, description)

        # Update secret count in database
        with DatabaseService.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                UPDATE secret_stores
                SET secret_count = secret_count + 1, updated_at = ?
                WHERE id = ?
            ''', (datetime.utcnow(), store_id))
            conn.commit()

        logger.info(f"Added secret to store: store={store_id}, name={secret_name}")

        return metadata

    def update_secret_in_store(self, store_id: str, secret_path: str,
                                secret_value: str) -> SecretMetadata:
        """
        Update an existing secret in a store.

        Args:
            store_id: Store ID
            secret_path: Path/name of the secret to update
            secret_value: New secret value

        Returns:
            Metadata of the updated secret
        """
        provider = self._providers.get(store_id)
        if not provider:
            raise SecretStoreNotFoundError(f"Store not found: {store_id}")

        if provider.requires_unlock() and not provider.is_unlocked():
            raise SecretStoreLockedError(
                f"Store '{store_id}' is locked. Unlock before updating secrets."
            )

        metadata = provider.update_secret(secret_path, secret_value)

        # Update timestamp in database
        with DatabaseService.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                UPDATE secret_stores
                SET updated_at = ?
                WHERE id = ?
            ''', (datetime.utcnow(), store_id))
            conn.commit()

        logger.info(f"Updated secret in store: store={store_id}, path={secret_path}")

        return metadata

    def delete_secret_from_store(self, store_id: str, secret_path: str) -> bool:
        """
        Delete a secret from a store.

        Args:
            store_id: Store ID
            secret_path: Path/name of the secret to delete

        Returns:
            True if deleted successfully, False if not found
        """
        provider = self._providers.get(store_id)
        if not provider:
            raise SecretStoreNotFoundError(f"Store not found: {store_id}")

        if provider.requires_unlock() and not provider.is_unlocked():
            raise SecretStoreLockedError(
                f"Store '{store_id}' is locked. Unlock before deleting secrets."
            )

        success = provider.delete_secret(secret_path)

        if success:
            # Update secret count in database
            with DatabaseService.get_connection_context() as conn:
                c = conn.cursor()
                c.execute('''
                    UPDATE secret_stores
                    SET secret_count = MAX(0, secret_count - 1), updated_at = ?
                    WHERE id = ?
                ''', (datetime.utcnow(), store_id))
                conn.commit()

            logger.info(f"Deleted secret from store: store={store_id}, path={secret_path}")

        return success

    # =========================================================================
    # CONFIGURATION RESOLUTION
    # =========================================================================

    def resolve_config_secrets(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Resolve all secret references in a configuration dict.

        Recursively walks the config and replaces any $secret_ref
        objects with their actual values. Returns a NEW dict -
        does not modify the original.

        This is called at scan/connector runtime.

        Args:
            config: Configuration dict potentially containing secret refs

        Returns:
            New config dict with secrets resolved
        """
        resolved = copy.deepcopy(config)
        self._resolve_refs_recursive(resolved)
        return resolved

    def _resolve_refs_recursive(self, obj: Any) -> Any:
        """
        Recursively resolve secret references in an object.

        Returns the resolved value if obj is a secret ref, otherwise None.
        Modifies obj in place for dicts and lists.
        """
        if isinstance(obj, dict):
            # Check if this is a secret reference
            if '$secret_ref' in obj:
                ref = obj['$secret_ref']
                return self.resolve_secret_ref(ref)

            # Otherwise recurse into dict values
            for key, value in list(obj.items()):
                resolved = self._resolve_refs_recursive(value)
                if resolved is not None:
                    obj[key] = resolved

        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                resolved = self._resolve_refs_recursive(item)
                if resolved is not None:
                    obj[i] = resolved

        return None


# =============================================================================
# Global instance management
# =============================================================================

_secret_store_manager: Optional[SecretStoreManager] = None


def get_secret_store_manager() -> Optional[SecretStoreManager]:
    """Get the global SecretStoreManager instance."""
    return _secret_store_manager


def init_secret_store_manager(startup_credentials: Dict[str, str] = None) -> SecretStoreManager:
    """
    Initialize and return the global SecretStoreManager.

    Args:
        startup_credentials: Dict of credentials collected at startup
                           for stores using 'prompt' credential source.

    Returns:
        Initialized SecretStoreManager instance
    """
    global _secret_store_manager
    _secret_store_manager = SecretStoreManager(startup_credentials)
    logger.info(f"SecretStoreManager initialized with {len(_secret_store_manager.list_stores())} stores")
    return _secret_store_manager
