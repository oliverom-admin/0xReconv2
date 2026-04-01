# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: caip_service_layer/secret_resolution_service.py
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
Secret Resolution Service

Resolves secret references in configurations to actual plaintext values at scan runtime.

This service:
- Takes configurations with secret references (store_id, path, version)
- Resolves them to actual plaintext values using SecretStoreManager
- Returns resolved configurations with plaintext credentials
- Handles errors gracefully with audit logging

IMPORTANT: Plaintext values are ONLY used in memory during scan execution,
never stored in database or logs.

Usage:
    resolver = SecretResolutionService(secret_store_manager)
    resolved_config = resolver.resolve_config_credentials(config)
    # Use resolved_config for scan execution
"""

import logging
from typing import Dict, Any, Optional, Tuple
from datetime import datetime

from caip_service_layer.secret_store_manager import (
    SecretStoreManager,
    SecretStoreError,
    SecretStoreNotFoundError,
    SecretStoreLockedError,
    SecretNotFoundError
)

logger = logging.getLogger('caip.operational')
audit_logger = logging.getLogger('caip.security_audit')


class SecretResolutionError(Exception):
    """Base exception for secret resolution errors."""
    pass


class InvalidSecretReferenceError(SecretResolutionError):
    """Raised when a secret reference is invalid or incomplete."""
    pass


class SecretResolutionFailedError(SecretResolutionError):
    """Raised when a secret cannot be resolved."""
    pass


class SecretResolutionService:
    """
    Service for resolving secret references in configurations.

    This service acts as a bridge between configuration data (which contains
    secret references) and the SecretStoreManager (which retrieves actual values).

    Typical usage in scan route:
        resolver = SecretResolutionService(secret_store_manager)
        try:
            resolved_config = resolver.resolve_config_credentials(config)
            # Use resolved_config for scan
        except SecretResolutionError as e:
            # Handle resolution failure
            logger.error(f"Failed to resolve secrets: {e}")
    """

    def __init__(self, secret_store_manager: SecretStoreManager):
        """
        Initialize the SecretResolutionService.

        Args:
            secret_store_manager: SecretStoreManager instance for accessing stores
        """
        self.secret_store_manager = secret_store_manager

    def resolve_credential(self, credential_data: Dict[str, Any],
                          credential_name: str = None) -> str:
        """
        Resolve a single credential (either plaintext or secret reference).

        Args:
            credential_data: Dict with 'plaintext_value' and 'secret_reference' keys.
                           One should be set, the other None.
            credential_name: Optional name for logging/audit purposes

        Returns:
            Plaintext credential value

        Raises:
            InvalidSecretReferenceError: If credential_data is invalid
            SecretResolutionFailedError: If resolution fails
        """
        # Extract plaintext and reference from credential data
        plaintext_value = credential_data.get('plaintext_value')
        secret_reference = credential_data.get('secret_reference')

        # If plaintext is provided, use it (no resolution needed)
        if plaintext_value:
            logger.debug(f"Using plaintext credential: {credential_name or 'unnamed'}")
            return plaintext_value

        # If secret reference is provided, resolve it
        if secret_reference:
            try:
                # Validate reference has required fields
                if not isinstance(secret_reference, dict):
                    raise InvalidSecretReferenceError(
                        f"Secret reference must be a dict, got {type(secret_reference)}"
                    )

                store_id = secret_reference.get('store_id')
                path = secret_reference.get('path')

                if not store_id or not path:
                    raise InvalidSecretReferenceError(
                        f"Secret reference missing required fields: "
                        f"store_id={store_id}, path={path}"
                    )

                # Log access attempt (never log the actual value)
                audit_logger.info(
                    f"Resolving secret credential: name={credential_name}, "
                    f"store={store_id}, path={path}"
                )

                # Resolve using SecretStoreManager
                value = self.secret_store_manager.resolve_secret_ref(secret_reference)

                logger.debug(f"Successfully resolved secret: {credential_name or 'unnamed'}")
                return value

            except SecretStoreNotFoundError as e:
                error_msg = f"Secret store not found: {e}"
                audit_logger.warning(f"Secret resolution failed: {error_msg}")
                raise SecretResolutionFailedError(error_msg) from e

            except SecretStoreLockedError as e:
                error_msg = f"Secret store is locked: {e}"
                audit_logger.warning(f"Secret resolution failed: {error_msg}")
                raise SecretResolutionFailedError(error_msg) from e

            except SecretNotFoundError as e:
                error_msg = f"Secret not found: {e}"
                audit_logger.warning(f"Secret resolution failed: {error_msg}")
                raise SecretResolutionFailedError(error_msg) from e

            except SecretStoreError as e:
                error_msg = f"Secret store error: {e}"
                audit_logger.error(f"Secret resolution failed: {error_msg}")
                raise SecretResolutionFailedError(error_msg) from e

        # Neither plaintext nor secret reference provided
        raise InvalidSecretReferenceError(
            f"Credential has neither plaintext_value nor secret_reference: {credential_name or 'unnamed'}"
        )

    def resolve_config_credentials(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Resolve all credential fields in a configuration.

        This method processes a configuration object and replaces all secret
        references with their actual plaintext values. The configuration is
        modified in-place (a copy is not created).

        Args:
            config: Configuration dict with potential credential fields

        Returns:
            Configuration dict with all credentials resolved to plaintext

        Raises:
            SecretResolutionError: If any credential cannot be resolved

        Example:
            config = {
                'name': 'my-scan',
                'client_id': {
                    'plaintext_value': 'client123',
                    'secret_reference': None
                },
                'client_secret': {
                    'plaintext_value': None,
                    'secret_reference': {
                        'store_id': '1',
                        'path': '/azure/client-secret',
                        'version': 'latest'
                    }
                }
            }

            resolved = resolver.resolve_config_credentials(config)
            # Now resolved['client_id'] = 'client123'
            # And resolved['client_secret'] = actual_secret_value
        """
        resolved_config = config.copy()

        # Define all credential field names that should be resolved
        # These are top-level fields in the config dict
        credential_field_names = [
            # Azure Service Principal credentials
            'client_id',
            'client_secret',
            'tenant_id',

            # CLM Azure Key Vault credentials
            'spn_client_id',
            'spn_client_secret',
            'spn_tenant_id',

            # EJBCA credentials
            'username',
            'password',

            # HSM credentials
            'hsm_password',
            'hsm_partition_password',
        ]

        # Try to resolve credentials at each field
        failed_credentials = []

        for field_name in credential_field_names:
            if field_name not in resolved_config:
                continue

            credential_data = resolved_config[field_name]

            # Check if this looks like a credential object (has plaintext_value or secret_reference)
            if not isinstance(credential_data, dict) or \
               ('plaintext_value' not in credential_data and 'secret_reference' not in credential_data):
                # Not a credential object, skip it
                continue

            try:
                # Resolve the credential
                plaintext_value = self.resolve_credential(credential_data, field_name)

                # Replace the credential object with plaintext value
                resolved_config[field_name] = plaintext_value
                logger.debug(f"Resolved credential: {field_name}")

            except SecretResolutionError as e:
                # Track failed credentials but continue trying others
                failed_credentials.append((field_name, str(e)))
                logger.warning(f"Failed to resolve {field_name}: {e}")

        # PHASE 6.3: Resolve nested credentials in EJBCA servers array
        # Handle EJBCA servers with p12_password_plaintext/reference format
        # EJBCA servers are nested under config['ejbca']['servers']
        if 'ejbca' in resolved_config and isinstance(resolved_config.get('ejbca', {}), dict):
            ejbca_config = resolved_config['ejbca']
            logger.debug(f"Found EJBCA config with keys: {list(ejbca_config.keys())}")
            if 'servers' in ejbca_config and isinstance(ejbca_config['servers'], list):
                logger.info(f"✓ Processing {len(ejbca_config['servers'])} EJBCA servers for nested credential resolution")
                for server_idx, server in enumerate(ejbca_config['servers']):
                    if not isinstance(server, dict):
                        logger.debug(f"Server {server_idx} is not a dict, skipping nested credential resolution")
                        continue

                    server_name = server.get('name', f'server_{server_idx}')
                    logger.debug(f"Processing nested credentials for server: {server_name}")

                    # Look for hybrid format p12_password fields
                    for credential_variant in ['p12_password', 'password']:
                        plaintext_key = f"{credential_variant}_plaintext"
                        reference_key = f"{credential_variant}_reference"

                        if plaintext_key in server or reference_key in server:
                            logger.debug(f"  Found {credential_variant} fields: plaintext_key={plaintext_key in server}, reference_key={reference_key in server}")
                            try:
                                credential_data = {
                                    'plaintext_value': server.get(plaintext_key),
                                    'secret_reference': server.get(reference_key)
                                }

                                # Only resolve if credential data exists
                                if credential_data['plaintext_value'] or credential_data['secret_reference']:
                                    logger.debug(f"  Resolving {credential_variant}: has_plaintext={bool(credential_data['plaintext_value'])}, has_reference={bool(credential_data['secret_reference'])}")

                                    plaintext_value = self.resolve_credential(
                                        credential_data,
                                        f"server:{server_name}:{credential_variant}"
                                    )

                                    # Replace with plaintext and remove hybrid fields
                                    server[credential_variant] = plaintext_value
                                    server.pop(plaintext_key, None)
                                    server.pop(reference_key, None)
                                    logger.info(f"✓ Resolved server credential for {server_name}: {credential_variant}")
                                else:
                                    logger.debug(f"  {credential_variant} has no value, skipping resolution")

                            except SecretResolutionError as e:
                                failed_credentials.append(
                                    (f"{credential_variant} (server: {server_name})", str(e))
                                )
                                logger.warning(f"✗ Failed to resolve server {server_name} {credential_variant}: {e}")

        # PHASE 6.4: Resolve nested credentials in Azure Key Vault service principals
        # Handle Azure service principals with client_secret_plaintext/reference format
        # Azure credentials are nested under config['azure_keyvault']['tenancies'][n]['service_principals'][n]
        if 'azure_keyvault' in resolved_config and isinstance(resolved_config.get('azure_keyvault', {}), dict):
            akv_config = resolved_config['azure_keyvault']
            if 'tenancies' in akv_config and isinstance(akv_config['tenancies'], list):
                for tenancy_idx, tenancy in enumerate(akv_config['tenancies']):
                    if not isinstance(tenancy, dict):
                        continue

                    tenancy_name = tenancy.get('name', f'tenancy_{tenancy_idx}')

                    if 'service_principals' in tenancy and isinstance(tenancy['service_principals'], list):
                        for sp_idx, sp in enumerate(tenancy['service_principals']):
                            if not isinstance(sp, dict):
                                continue

                            sp_name = sp.get('name', f'sp_{sp_idx}')

                            # Look for hybrid format credential fields (client_secret, client_id, tenant_id)
                            for credential_variant in ['client_secret', 'client_id', 'tenant_id']:
                                plaintext_key = f"{credential_variant}_plaintext"
                                reference_key = f"{credential_variant}_reference"

                                if plaintext_key in sp or reference_key in sp:
                                    try:
                                        credential_data = {
                                            'plaintext_value': sp.get(plaintext_key),
                                            'secret_reference': sp.get(reference_key)
                                        }

                                        # Only resolve if credential data exists
                                        if credential_data['plaintext_value'] or credential_data['secret_reference']:
                                            plaintext_value = self.resolve_credential(
                                                credential_data,
                                                f"azure:tenancy:{tenancy_name}:sp:{sp_name}:{credential_variant}"
                                            )

                                            # Replace with plaintext and remove hybrid fields
                                            sp[credential_variant] = plaintext_value
                                            sp.pop(plaintext_key, None)
                                            sp.pop(reference_key, None)
                                            logger.info(f"✓ Resolved Azure credential for {tenancy_name}/{sp_name}: {credential_variant}")

                                    except SecretResolutionError as e:
                                        failed_credentials.append(
                                            (f"{credential_variant} (Azure: {tenancy_name}/{sp_name})", str(e))
                                        )
                                        logger.warning(f"✗ Failed to resolve Azure {tenancy_name}/{sp_name} {credential_variant}: {e}")

        # PHASE 6.5: Resolve nested credentials in Luna HSM partitions
        # Handle Luna HSM partitions with partition_password_plaintext/reference format
        # Luna HSM passwords are nested under config['luna_hsm']['hsms'][n]['partitions'][n]
        if 'luna_hsm' in resolved_config and isinstance(resolved_config.get('luna_hsm', {}), dict):
            hsm_config = resolved_config['luna_hsm']
            if 'hsms' in hsm_config and isinstance(hsm_config['hsms'], list):
                for hsm_idx, hsm in enumerate(hsm_config['hsms']):
                    if not isinstance(hsm, dict):
                        continue

                    hsm_name = hsm.get('name', f'hsm_{hsm_idx}')

                    if 'partitions' in hsm and isinstance(hsm['partitions'], list):
                        for partition_idx, partition in enumerate(hsm['partitions']):
                            if not isinstance(partition, dict):
                                continue

                            partition_name = partition.get('name', f'partition_{partition_idx}')

                            # Look for hybrid format partition_password fields
                            for credential_variant in ['partition_password']:
                                plaintext_key = f"{credential_variant}_plaintext"
                                reference_key = f"{credential_variant}_reference"

                                if plaintext_key in partition or reference_key in partition:
                                    try:
                                        credential_data = {
                                            'plaintext_value': partition.get(plaintext_key),
                                            'secret_reference': partition.get(reference_key)
                                        }

                                        # Only resolve if credential data exists
                                        if credential_data['plaintext_value'] or credential_data['secret_reference']:
                                            plaintext_value = self.resolve_credential(
                                                credential_data,
                                                f"hsm:device:{hsm_name}:partition:{partition_name}:{credential_variant}"
                                            )

                                            # Replace with plaintext and remove hybrid fields
                                            partition[credential_variant] = plaintext_value
                                            partition.pop(plaintext_key, None)
                                            partition.pop(reference_key, None)
                                            logger.info(f"✓ Resolved Luna HSM credential for {hsm_name}/{partition_name}: {credential_variant}")

                                    except SecretResolutionError as e:
                                        failed_credentials.append(
                                            (f"{credential_variant} (Luna HSM: {hsm_name}/{partition_name})", str(e))
                                        )
                                        logger.warning(f"✗ Failed to resolve Luna HSM {hsm_name}/{partition_name} {credential_variant}: {e}")

        # PHASE 6.6: Resolve flat Luna HSM PIN (from CLM integrations)
        # Handle flat config structure with pin_plaintext/pin_reference fields
        # This is for Luna HSM integrations stored as flat configs in clm_integrations table
        if 'pin_plaintext' in resolved_config or 'pin_reference' in resolved_config:
            try:
                credential_data = {
                    'plaintext_value': resolved_config.get('pin_plaintext'),
                    'secret_reference': resolved_config.get('pin_reference')
                }

                # Only resolve if credential data exists
                if credential_data['plaintext_value'] or credential_data['secret_reference']:
                    plaintext_value = self.resolve_credential(
                        credential_data,
                        credential_name=f"luna_hsm_pin"
                    )
                    resolved_config['pin'] = plaintext_value
                    resolved_config.pop('pin_plaintext', None)
                    resolved_config.pop('pin_reference', None)
                    logger.info(f"✓ Resolved Luna HSM PIN credential")
            except Exception as e:
                failed_credentials.append((f"luna_hsm_pin", str(e)))
                logger.warning(f"✗ Failed to resolve Luna HSM PIN: {e}")

        # If any credentials failed, raise error
        if failed_credentials:
            error_details = "; ".join([f"{name}: {error}" for name, error in failed_credentials])
            raise SecretResolutionFailedError(
                f"Failed to resolve {len(failed_credentials)} credential(s): {error_details}"
            )

        return resolved_config

