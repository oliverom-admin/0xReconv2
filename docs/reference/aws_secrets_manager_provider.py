"""
AWS Secrets Manager Secret Store Provider

Integrates with AWS Secrets Manager for centralized secret management.
Supports both long-lived credentials and temporary credentials.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

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


class AWSSecretsManagerProvider(SecretStoreProvider):
    """
    AWS Secrets Manager implementation of SecretStoreProvider.

    Supports authentication via:
    1. Long-lived access keys (access_key_id + secret_access_key)
    2. Temporary credentials (access_key_id + secret_access_key + session_token)
    3. IAM Role (when running on EC2, ECS, Lambda, or other AWS service)
    """

    def __init__(self):
        self.client = None
        self.region: Optional[str] = None
        self._connected = False

    def connect(self, config: Dict[str, Any]) -> None:
        """
        Connect to AWS Secrets Manager.

        Config options:
        {
            "region": "us-east-1",
            "auth_method": "credentials" | "role",

            # For credentials auth:
            "access_key_id_source": "env" | "prompt" | "value",
            "access_key_id_env_var": "AWS_ACCESS_KEY_ID",
            "secret_access_key_source": "env" | "prompt" | "value",
            "secret_access_key_env_var": "AWS_SECRET_ACCESS_KEY",
            "session_token_source": "env" | "prompt" | "value" (optional),
            "session_token_env_var": "AWS_SESSION_TOKEN",

            # Optional startup credentials (injected by SecretStoreManager)
            "_startup_credentials": {...}
        }
        """
        try:
            self.region = config.get('region', 'us-east-1')
            auth_method = config.get('auth_method', 'role').lower()

            # Create client based on auth method
            if auth_method == 'credentials':
                self.client = self._create_client_with_credentials(config)
            else:  # 'role' - uses IAM role or default credential chain
                self.client = boto3.client('secretsmanager', region_name=self.region)

            # Test connection
            self.client.list_secrets(MaxResults=1)
            self._connected = True

            logger.info(f"Connected to AWS Secrets Manager in region: {self.region}")

        except Exception as e:
            raise SecretStoreConnectionError(f"Failed to connect to AWS Secrets Manager: {e}")

    def _create_client_with_credentials(self, config: Dict[str, Any]) -> Any:
        """Create AWS client with explicit credentials."""
        startup_creds = config.get('_startup_credentials', {})

        access_key_id = resolve_bootstrap_credential(config, 'access_key_id', startup_creds)
        secret_access_key = resolve_bootstrap_credential(config, 'secret_access_key', startup_creds)
        session_token = resolve_bootstrap_credential(config, 'session_token', startup_creds)

        if not access_key_id:
            raise ValueError("access_key_id is required for credentials auth")
        if not secret_access_key:
            raise ValueError("secret_access_key is required for credentials auth")

        # Build kwargs for client creation
        kwargs = {
            'region_name': self.region,
            'aws_access_key_id': access_key_id,
            'aws_secret_access_key': secret_access_key
        }

        if session_token:
            kwargs['aws_session_token'] = session_token

        return boto3.client('secretsmanager', **kwargs)

    def test_connection(self) -> StoreConnectionStatus:
        """Test connectivity to AWS Secrets Manager."""
        if not self._connected or not self.client:
            return StoreConnectionStatus(
                connected=False,
                message="Not connected"
            )

        try:
            # List secrets to verify access
            response = self.client.list_secrets(MaxResults=100)

            secret_count = response.get('SecretList')
            if secret_count:
                secret_count = len(secret_count)
            else:
                secret_count = 0

            return StoreConnectionStatus(
                connected=True,
                message="Connected to AWS Secrets Manager",
                secret_count=secret_count
            )

        except ClientError as e:
            return StoreConnectionStatus(
                connected=False,
                message=f"AWS error: {e.response['Error']['Message']}"
            )
        except NoCredentialsError:
            return StoreConnectionStatus(
                connected=False,
                message="AWS credentials not found"
            )
        except Exception as e:
            return StoreConnectionStatus(
                connected=False,
                message=f"Connection test failed: {e}"
            )

    def list_secrets(self, path_prefix: str = "") -> List[SecretMetadata]:
        """List secrets in AWS Secrets Manager."""
        if not self.client:
            raise SecretStoreConnectionError("Not connected to AWS Secrets Manager")

        try:
            secrets = []
            paginator = self.client.get_paginator('list_secrets')

            for page in paginator.paginate():
                for secret_metadata in page.get('SecretList', []):
                    # Filter by prefix if provided
                    name = secret_metadata.get('Name', '')
                    if path_prefix and not name.startswith(path_prefix):
                        continue

                    secrets.append(SecretMetadata(
                        name=name,
                        path=name,
                        created_at=secret_metadata.get('CreatedDate'),
                        updated_at=secret_metadata.get('LastChangedDate'),
                        description=secret_metadata.get('Description'),
                        tags=self._format_tags(secret_metadata.get('Tags', []))
                    ))

            return secrets

        except ClientError as e:
            raise SecretStoreAccessError(f"Failed to list secrets: {e.response['Error']['Message']}")
        except Exception as e:
            raise SecretStoreAccessError(f"Failed to list secrets: {e}")

    @staticmethod
    def _format_tags(tag_list: List[Dict]) -> Dict[str, str]:
        """Convert AWS tag list to dict."""
        if not tag_list:
            return {}

        return {tag.get('Key'): tag.get('Value') for tag in tag_list}

    def get_secret(self, secret_path: str, version: str = "latest") -> str:
        """Retrieve a secret value."""
        if not self.client:
            raise SecretStoreConnectionError("Not connected to AWS Secrets Manager")

        try:
            kwargs = {'SecretId': secret_path}

            if version and version != "latest":
                kwargs['VersionId'] = version

            response = self.client.get_secret_value(**kwargs)

            # AWS Secrets Manager returns either SecretString or SecretBinary
            if 'SecretString' in response:
                return response['SecretString']
            else:
                # For binary secrets, return as-is (caller should handle)
                return response.get('SecretBinary', '')

        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                raise SecretNotFoundError(f"Secret not found: {secret_path}")
            raise SecretStoreAccessError(f"Failed to retrieve secret: {e.response['Error']['Message']}")
        except Exception as e:
            raise SecretStoreAccessError(f"Failed to retrieve secret: {e}")

    def create_secret(self, secret_path: str, value: str,
                      description: str = None) -> SecretMetadata:
        """Create a new secret in AWS Secrets Manager."""
        if not self.client:
            raise SecretStoreConnectionError("Not connected to AWS Secrets Manager")

        try:
            kwargs = {
                'Name': secret_path,
                'SecretString': value
            }

            if description:
                kwargs['Description'] = description

            response = self.client.create_secret(**kwargs)

            return SecretMetadata(
                name=secret_path,
                path=secret_path,
                created_at=response.get('CreatedDate'),
                version=response.get('VersionId'),
                description=description,
                tags={}
            )

        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceExistsException':
                raise SecretStoreAccessError(f"Secret already exists: {secret_path}")
            raise SecretStoreAccessError(f"Failed to create secret: {e.response['Error']['Message']}")
        except Exception as e:
            raise SecretStoreAccessError(f"Failed to create secret: {e}")

    def update_secret(self, secret_path: str, value: str) -> SecretMetadata:
        """Update an existing secret's value."""
        if not self.client:
            raise SecretStoreConnectionError("Not connected to AWS Secrets Manager")

        try:
            response = self.client.update_secret(
                SecretId=secret_path,
                SecretString=value
            )

            return SecretMetadata(
                name=secret_path,
                path=secret_path,
                updated_at=datetime.utcnow(),
                version=response.get('VersionId'),
                tags={}
            )

        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                raise SecretNotFoundError(f"Secret not found: {secret_path}")
            raise SecretStoreAccessError(f"Failed to update secret: {e.response['Error']['Message']}")
        except Exception as e:
            raise SecretStoreAccessError(f"Failed to update secret: {e}")

    def delete_secret(self, secret_path: str) -> bool:
        """Delete a secret from AWS Secrets Manager."""
        if not self.client:
            raise SecretStoreConnectionError("Not connected to AWS Secrets Manager")

        try:
            # AWS requires a recovery window; set to minimum 7 days
            self.client.delete_secret(
                SecretId=secret_path,
                RecoveryWindowInDays=7
            )
            return True

        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return False
            raise SecretStoreAccessError(f"Failed to delete secret: {e.response['Error']['Message']}")
        except Exception as e:
            raise SecretStoreAccessError(f"Failed to delete secret: {e}")

    def get_provider_type(self) -> str:
        """Return provider type identifier."""
        return 'aws_secrets_manager'

    def requires_unlock(self) -> bool:
        """AWS Secrets Manager doesn't require explicit unlock (always online)."""
        return False

    def unlock(self, credentials: Dict[str, Any]) -> bool:
        """Unlock is not needed for AWS Secrets Manager."""
        return True

    def is_unlocked(self) -> bool:
        """Return whether connected."""
        return self._connected


# Auto-register this provider
from caip_service_layer.secret_store_providers import register_provider
register_provider('aws_secrets_manager', AWSSecretsManagerProvider)
