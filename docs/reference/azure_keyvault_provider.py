"""
Azure Key Vault Secret Store Provider

Integrates with Azure Key Vault for centralized secret management.
Supports both Service Principal and Managed Identity authentication.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

from azure.identity import ClientSecretCredential, ManagedIdentityCredential, DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.core.exceptions import (
    ResourceNotFoundError,
    HttpResponseError
)

from caip_service_layer.secret_store_providers.base import (
    SecretStoreProvider,
    SecretMetadata,
    StoreConnectionStatus,
    resolve_bootstrap_credential
)
from caip_service_layer.secret_service import (
    SecretStoreConnectionError,
    SecretStoreAccessError,
    SecretNotFoundError
)

logger = logging.getLogger('caip.operational')


class AzureKeyVaultProvider(SecretStoreProvider):
    """
    Azure Key Vault implementation of SecretStoreProvider.

    Supports three authentication methods:
    1. Service Principal (client_id + client_secret)
    2. Managed Identity (no credentials needed)
    3. Default Azure Credentials (tries multiple sources in order)
    """

    def __init__(self):
        self.client: Optional[SecretClient] = None
        self.vault_url: Optional[str] = None
        self._connected = False

    def connect(self, config: Dict[str, Any]) -> None:
        """
        Connect to Azure Key Vault.

        Config options:
        {
            "vault_url": "https://<vault-name>.vault.azure.net/",
            "auth_method": "service_principal" | "managed_identity" | "default",

            # For service_principal:
            "client_id_source": "env" | "prompt" | "value",
            "client_id_env_var": "AZURE_CLIENT_ID",
            "client_secret_source": "env" | "prompt" | "value",
            "client_secret_env_var": "AZURE_CLIENT_SECRET",
            "tenant_id_source": "env" | "prompt" | "value",
            "tenant_id_env_var": "AZURE_TENANT_ID",

            # Optional startup credentials (injected by SecretStoreManager)
            "_startup_credentials": {...}
        }
        """
        try:
            self.vault_url = config.get('vault_url')
            if not self.vault_url:
                raise ValueError("vault_url is required")

            # Normalize URL
            if not self.vault_url.endswith('/'):
                self.vault_url += '/'

            auth_method = config.get('auth_method', 'default').lower()

            # Get credentials based on method
            if auth_method == 'service_principal':
                credentials = self._get_service_principal_credentials(config)
            elif auth_method == 'managed_identity':
                credentials = ManagedIdentityCredential()
            else:  # 'default'
                credentials = DefaultAzureCredential()

            # Create client
            self.client = SecretClient(vault_url=self.vault_url, credential=credentials)

            # Test connection
            list(self.client.list_properties_of_secrets())
            self._connected = True

            logger.info(f"Connected to Azure Key Vault: {self.vault_url}")

        except Exception as e:
            raise SecretStoreConnectionError(f"Failed to connect to Azure Key Vault: {e}")

    def _get_service_principal_credentials(self, config: Dict[str, Any]):
        """Get service principal credentials from config."""
        startup_creds = config.get('_startup_credentials', {})

        client_id = resolve_bootstrap_credential(config, 'client_id', startup_creds)
        client_secret = resolve_bootstrap_credential(config, 'client_secret', startup_creds)
        tenant_id = resolve_bootstrap_credential(config, 'tenant_id', startup_creds)

        if not client_id:
            raise ValueError("client_id is required for service_principal auth")
        if not client_secret:
            raise ValueError("client_secret is required for service_principal auth")
        if not tenant_id:
            raise ValueError("tenant_id is required for service_principal auth")

        return ClientSecretCredential(
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id
        )

    def test_connection(self) -> StoreConnectionStatus:
        """Test connectivity to Azure Key Vault."""
        if not self._connected or not self.client:
            return StoreConnectionStatus(
                connected=False,
                message="Not connected"
            )

        try:
            # List secrets to verify access
            secret_count = 0

            # Get total count (may be slow for large vaults)
            try:
                secret_count = sum(1 for _ in self.client.list_properties_of_secrets())
            except Exception:
                # If enumeration fails, return 0 but still connected
                pass

            return StoreConnectionStatus(
                connected=True,
                message="Connected to Azure Key Vault",
                secret_count=secret_count
            )

        except (HttpResponseError, Exception) as e:
            return StoreConnectionStatus(
                connected=False,
                message=f"Authentication failed: {e}"
            )
        except Exception as e:
            return StoreConnectionStatus(
                connected=False,
                message=f"Connection test failed: {e}"
            )

    def list_secrets(self, path_prefix: str = "") -> List[SecretMetadata]:
        """List secrets in the vault."""
        if not self.client:
            raise SecretStoreConnectionError("Not connected to Azure Key Vault")

        try:
            secrets = []
            for secret_props in self.client.list_properties_of_secrets():
                # Filter by prefix if provided
                if path_prefix and not secret_props.name.startswith(path_prefix):
                    continue

                secrets.append(SecretMetadata(
                    name=secret_props.name,
                    path=secret_props.name,
                    created_at=secret_props.created_on,
                    updated_at=secret_props.updated_on,
                    version=secret_props.version,
                    tags=secret_props.tags or {}
                ))

            return secrets

        except Exception as e:
            raise SecretStoreAccessError(f"Failed to list secrets: {e}")

    def get_secret(self, secret_path: str, version: str = "latest") -> str:
        """Retrieve a secret value."""
        if not self.client:
            raise SecretStoreConnectionError("Not connected to Azure Key Vault")

        try:
            if version and version != "latest":
                secret = self.client.get_secret(secret_path, version=version)
            else:
                secret = self.client.get_secret(secret_path)

            return secret.value

        except ResourceNotFoundError:
            raise SecretNotFoundError(f"Secret not found: {secret_path}")
        except Exception as e:
            raise SecretStoreAccessError(f"Failed to retrieve secret: {e}")

    def create_secret(self, secret_path: str, value: str,
                      description: str = None) -> SecretMetadata:
        """Create a new secret in the vault."""
        if not self.client:
            raise SecretStoreConnectionError("Not connected to Azure Key Vault")

        try:
            # Check if secret already exists
            try:
                self.client.get_secret(secret_path)
                raise ValueError(f"Secret already exists: {secret_path}")
            except ResourceNotFoundError:
                pass  # Good, doesn't exist yet

            # Create the secret
            secret_props = self.client.set_secret(
                name=secret_path,
                value=value,
                tags={'description': description} if description else None
            )

            return SecretMetadata(
                name=secret_props.name,
                path=secret_props.name,
                created_at=secret_props.created_on,
                updated_at=secret_props.updated_on,
                version=secret_props.version,
                description=description
            )

        except ValueError as e:
            raise SecretStoreAccessError(str(e))
        except Exception as e:
            raise SecretStoreAccessError(f"Failed to create secret: {e}")

    def update_secret(self, secret_path: str, value: str) -> SecretMetadata:
        """Update an existing secret's value."""
        if not self.client:
            raise SecretStoreConnectionError("Not connected to Azure Key Vault")

        try:
            secret_props = self.client.set_secret(
                name=secret_path,
                value=value
            )

            return SecretMetadata(
                name=secret_props.name,
                path=secret_props.name,
                created_at=secret_props.created_on,
                updated_at=secret_props.updated_on,
                version=secret_props.version
            )

        except Exception as e:
            raise SecretStoreAccessError(f"Failed to update secret: {e}")

    def delete_secret(self, secret_path: str) -> bool:
        """Delete a secret from the vault."""
        if not self.client:
            raise SecretStoreConnectionError("Not connected to Azure Key Vault")

        try:
            self.client.begin_delete_secret(secret_path).result()
            return True
        except ResourceNotFoundError:
            return False
        except Exception as e:
            raise SecretStoreAccessError(f"Failed to delete secret: {e}")

    def get_provider_type(self) -> str:
        """Return provider type identifier."""
        return 'azure_key_vault'

    def requires_unlock(self) -> bool:
        """Azure Key Vault doesn't require explicit unlock (always online)."""
        return False

    def unlock(self, credentials: Dict[str, Any]) -> bool:
        """Unlock is not needed for Azure Key Vault."""
        return True

    def is_unlocked(self) -> bool:
        """Return whether connected."""
        return self._connected


# Auto-register this provider
from caip_service_layer.secret_store_providers import register_provider
register_provider('azure_key_vault', AzureKeyVaultProvider)
