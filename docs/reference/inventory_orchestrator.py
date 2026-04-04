"""
InventoryOrchestrator - 6-phase integration collection orchestrator

Phases:
  1. Load & validate configuration
  2. Collect assets via registry pattern
  3. Normalize to unified format
  4. Enrich with metadata
  5. Detect changes & update inventory
  6. Update sync status

This orchestrator replaces the if-elif collector selection in InventoryService
with a registry-based pattern for extensibility and maintainability.

Usage:
    orchestrator = InventoryOrchestrator()
    result = orchestrator.execute(connector_id=1)
"""

import json
import logging
import traceback
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import asdict

logger = logging.getLogger('caip.inventory_orchestrator')


class InventoryOrchestrator:
    """
    Orchestrates 6-phase inventory sync pipeline.

    Replaces if-elif collector selection with registry pattern.
    Adds enrichment phase for metadata context.
    """

    # Registry: maps connector type to collector phase method
    PHASE_2_COLLECTORS = {
        'EJBCA': '_phase_2_collect_from_ejbca',
        'Azure Key Vault': '_phase_2_collect_from_azure_keyvault',
        'Luna HSM': '_phase_2_collect_from_luna_hsm',
    }

    def __init__(self):
        """Initialize orchestrator"""
        self.started_at = None
        self.connector = None
        self.connector_id = None
        self.connector_name = None

    def execute(self, connector_id: int) -> 'SyncResult':
        """Execute 6-phase orchestration"""
        self.started_at = datetime.now(timezone.utc)
        self.connector_id = connector_id

        try:
            logger.info(f"[InventoryOrchestrator] Starting sync for connector {connector_id}")

            # Phase 1: Load & validate
            self.connector, config = self._phase_1_load_and_validate(connector_id)
            self.connector_name = self.connector['name']

            # Phase 2: Collect
            raw_certs, raw_keys = self._phase_2_collect(
                self.connector['type'], config, self.connector_name
            )

            # Phase 3: Normalize & Enrich (unified - replaces old Phase 3, 4, 4.5)
            enriched_certs, enriched_keys = self._phase_3_normalize_and_enrich(
                raw_certs, raw_keys, self.connector['type']
            )

            # Phase 4: Detect & store (was Phase 5)
            cert_stats, key_stats = self._phase_4_detect_and_store(
                connector_id, enriched_certs, enriched_keys
            )

            # Phase 5: Update status (was Phase 6)
            result = self._phase_5_update_status(
                connector_id, self.connector, cert_stats, key_stats
            )

            logger.info(f"[InventoryOrchestrator] Sync completed successfully")
            return result

        except Exception as e:
            logger.error(f"[InventoryOrchestrator] Sync failed: {str(e)}")
            logger.error(traceback.format_exc())
            return self._handle_error(connector_id, str(e))

    # =========================================================================
    # PHASE 1: LOAD & VALIDATE CONFIGURATION
    # =========================================================================

    def _phase_1_load_and_validate(self, connector_id: int) -> tuple:
        """Phase 1: Load and validate connector configuration

        Steps:
        1. Load connector from database
        2. Parse config JSON
        3. Resolve secret references
        4. Validate connector exists

        Args:
            connector_id: Database ID of connector

        Returns:
            Tuple of (connector_dict, resolved_config_dict)

        Raises:
            ValueError: If connector not found
        """
        from database_service import DatabaseService
        from caip_service_layer.secret_resolution_service import SecretResolutionService
        from caip_service_layer.secret_store_manager import get_secret_store_manager

        logger.info(f"[Phase 1] Loading configuration for connector {connector_id}")

        try:
            # Load from database
            connector = DatabaseService.get_clm_integration(connector_id)
            if not connector:
                raise ValueError(f"Connector {connector_id} not found")

            logger.debug(f"[Phase 1] Loaded connector: {connector['name']} (type: {connector['type']})")

            # Parse config JSON
            config = json.loads(connector['config_json']) if isinstance(connector['config_json'], str) else connector['config_json']

            logger.debug(f"[Phase 1] Parsed config JSON")

            # Resolve secrets
            secret_store_mgr = get_secret_store_manager()
            if secret_store_mgr:
                resolver = SecretResolutionService(secret_store_mgr)
                config = resolver.resolve_config_credentials(config)
                logger.info(f"[Phase 1] Resolved credentials for connector {connector_id}")

            logger.info(f"[Phase 1] ✅ Loaded config for {connector['name']}")
            return connector, config

        except Exception as e:
            logger.error(f"[Phase 1] Failed: {str(e)}")
            raise

    # =========================================================================
    # PHASE 2: COLLECTION (WITH REGISTRY PATTERN)
    # =========================================================================

    def _phase_2_collect(self, connector_type: str, config: dict, connector_name: str = None) -> tuple:
        """Phase 2: Collect assets via registry dispatch

        Uses registry pattern to dispatch to appropriate collector.
        Replaces if-elif branches with dictionary lookup.

        Args:
            connector_type: Type of connector (EJBCA, Azure Key Vault, Luna HSM)
            config: Resolved configuration dictionary
            connector_name: Name of connector (for logging)

        Returns:
            Tuple of (raw_certificates_list, raw_keys_list)

        Raises:
            ValueError: If connector type not supported
        """
        logger.info(f"[Phase 2] Collecting from {connector_type}")

        try:
            # Look up collector in registry
            phase_method_name = self.PHASE_2_COLLECTORS.get(connector_type)

            if not phase_method_name:
                supported = list(self.PHASE_2_COLLECTORS.keys())
                raise ValueError(f"Unsupported connector type: {connector_type}. Supported: {supported}")

            logger.debug(f"[Phase 2] Dispatching to {phase_method_name}")

            # Get method and call it
            phase_method = getattr(self, phase_method_name)
            raw_certs, raw_keys = phase_method(config, connector_name)

            logger.info(f"[Phase 2] ✅ Collected {len(raw_certs)} certs, {len(raw_keys)} keys")
            return raw_certs, raw_keys

        except Exception as e:
            logger.error(f"[Phase 2] Collection failed: {str(e)}")
            raise

    def _phase_2_collect_from_ejbca(self, config: dict, connector_name: str = None) -> tuple:
        """Collect from EJBCA connector

        Args:
            config: Connector configuration
            connector_name: Name for logging

        Returns:
            Tuple of (certificates_list, keys_list) - EJBCA has no keys
        """
        from connector_service import ConnectorService
        import json

        try:
            logger.debug(f"[Phase 2] EJBCA: Transforming config")
            ejbca_config = self._transform_ejbca_config(config)

            logger.debug(f"[Phase 2] EJBCA: Retrieving CA metadata")
            try:
                # Always retrieve extended CA info for storage
                cas_extended = ConnectorService.get_ejbca_cas_with_counts(ejbca_config)
                logger.debug(f"[Phase 2] EJBCA: ✅ Retrieved metadata for {len(cas_extended)} CAs")

                # Store CA metadata in integration record
                if self.connector_id and cas_extended:
                    from database_service import DatabaseService
                    conn = DatabaseService.get_connection()
                    c = conn.cursor()
                    c.execute('UPDATE clm_integrations SET cas_metadata = ? WHERE id = ?',
                             (json.dumps(cas_extended), self.connector_id))
                    conn.commit()
                    conn.close()
                    logger.debug(f"[Phase 2] EJBCA: Stored CA metadata in database")
            except Exception as e:
                logger.warning(f"[Phase 2] EJBCA: Could not retrieve/store CA metadata: {e}")

            logger.debug(f"[Phase 2] EJBCA: Calling ConnectorService.collect_from_ejbca()")
            certs = ConnectorService.collect_from_ejbca(ejbca_config)

            logger.debug(f"[Phase 2] EJBCA: ✅ Collected {len(certs)} certificates")
            return [asdict(c) for c in certs], []

        except Exception as e:
            logger.error(f"[Phase 2] EJBCA collection failed: {str(e)}")
            raise

    def _phase_2_collect_from_azure_keyvault(self, config: dict, connector_name: str = None) -> tuple:
        """Collect from Azure Key Vault connector

        Args:
            config: Connector configuration
            connector_name: Name for logging

        Returns:
            Tuple of (certificates_list, keys_list)
        """
        from connector_service import ConnectorService

        try:
            logger.debug(f"[Phase 2] Azure: Transforming config")
            akv_config = self._transform_azure_config(config)

            logger.debug(f"[Phase 2] Azure: Calling ConnectorService.collect_from_azure_keyvault()")
            certs, keys = ConnectorService.collect_from_azure_keyvault(akv_config)

            logger.debug(f"[Phase 2] Azure: ✅ Collected {len(certs)} certificates, {len(keys)} keys")
            return [asdict(c) for c in certs], [asdict(k) for k in keys]

        except Exception as e:
            logger.error(f"[Phase 2] Azure Key Vault collection failed: {str(e)}")
            raise

    def _phase_2_collect_from_luna_hsm(self, config: dict, connector_name: str = None) -> tuple:
        """Collect from Luna HSM connector

        Args:
            config: Connector configuration
            connector_name: Name for logging (used by ConnectorService)

        Returns:
            Tuple of (certificates_list, keys_list)
        """
        from connector_service import ConnectorService

        try:
            logger.debug(f"[Phase 2] Luna: Transforming config")
            hsm_config = self._transform_luna_config(config)

            logger.debug(f"[Phase 2] Luna: Calling ConnectorService.collect_from_luna_hsm()")
            keys, certs = ConnectorService.collect_from_luna_hsm(hsm_config, connector_name)

            logger.debug(f"[Phase 2] Luna: ✅ Collected {len(certs)} certificates, {len(keys)} keys")
            return [asdict(c) for c in certs], [asdict(k) for k in keys]

        except Exception as e:
            logger.error(f"[Phase 2] Luna HSM collection failed: {str(e)}")
            raise

    # =========================================================================
    # PHASE 3: NORMALIZE & ENRICH (UNIFIED - STANDARDIZED APPROACH)
    # =========================================================================

    def _phase_3_normalize_and_enrich(
        self,
        raw_certs: List[Dict],
        raw_keys: List[Dict],
        connector_type: str
    ) -> Tuple[List[Dict], List[Dict]]:
        """
        Phase 3: Normalize and Enrich (unified approach).

        Combines old Phase 3, Phase 4, and Phase 4.5 into single orchestration.
        Uses standardized normalization layer to guarantee:
        - Unified field naming
        - Both security AND environment enrichment
        - Flat output structure for all fields

        Args:
            raw_certs: Raw certificates from collector
            raw_keys: Raw keys from collector
            connector_type: Type of connector ('Azure Key Vault', 'EJBCA', 'Luna HSM')

        Returns:
            Tuple of (enriched_certs, enriched_keys) with flat structure
        """
        from caip_service_layer.key_normalisation_service import KeyNormalisationService

        logger.info(f"[Phase 3] Normalizing and enriching data from {connector_type}")
        logger.info(f"[Phase 3] Processing {len(raw_certs)} certificates and {len(raw_keys)} keys")

        # ===================================================================
        # STEP 1: Normalize and enrich certificates
        # ===================================================================
        logger.info(f"[Phase 3] Processing certificates...")

        enriched_certs = KeyNormalisationService.normalise_and_enrich_certificates(
            raw_certs,
            enrichment_config={
                'enable_security_analysis': True,               # Apply cryptographic analysis
                'enable_environment_analysis': True,            # Infer environment from source
                'environment_enricher_type': connector_type,    # 'Azure Key Vault', 'EJBCA', 'Luna HSM'
                'source_type': connector_type,                  # Track source
                'capture_environment': True,                    # Enable multi-signal environment inference
                'capture_enrichment': True,                     # NEW: Enable metadata extraction (service identity, purpose, crypto, ha)
                'capture_security_analysis': True               # Flag for enricher if supported
            }
        )

        logger.info(f"[Phase 3] ✅ Enriched {len(enriched_certs)} certificates with flat structure")

        # ===================================================================
        # STEP 2: Normalize and enrich keys (optional, same pattern)
        # ===================================================================
        enriched_keys = []
        if raw_keys:
            logger.info(f"[Phase 3] Processing keys...")

            # Note: Currently keys may not have enrichment services available
            # But using same pattern for consistency
            enriched_keys = KeyNormalisationService.normalise_and_enrich_keys(raw_keys)

            logger.info(f"[Phase 3] ✅ Normalized {len(enriched_keys)} keys")

        # ===================================================================
        # STEP 3: Enrich with integration context
        # ===================================================================
        # Add fields that are only available at the orchestrator level (with connector context)
        logger.info(f"[Phase 3] Enriching with integration context...")
        for cert in enriched_certs:
            # Add integration name (from connector context)
            cert['integration_name'] = self.connector_name
            # Add promotion flags (default values - only set during actual promotion)
            # is_promoted is INTEGER in DB: 0 = not promoted, 1 = promoted
            cert['is_promoted'] = 0
            cert['promoted_from_scan_name'] = 'N/A'

        logger.info(f"[Phase 3] ✅ Phase complete - {len(enriched_certs)} certs, {len(enriched_keys)} keys")
        return enriched_certs, enriched_keys

    # =========================================================================
    # PHASE 3 (OLD): NORMALIZATION - KEPT FOR BACKWARD COMPATIBILITY
    # =========================================================================

    def _phase_3_normalize(self, raw_certs: list, raw_keys: list) -> tuple:
        """Phase 3: Normalize collected assets to unified format

        Converts collector-specific formats to unified internal format.
        Uses KeyNormalisationService for standardization.

        Args:
            raw_certs: Raw certificates from collectors
            raw_keys: Raw keys from collectors

        Returns:
            Tuple of (normalised_certs_list, normalised_keys_list)
        """
        from caip_service_layer.key_normalisation_service import KeyNormalisationService

        logger.info(f"[Phase 3] Normalizing {len(raw_certs)} certs, {len(raw_keys)} keys")

        try:
            norm_certs = KeyNormalisationService.normalise_certificates(raw_certs) if raw_certs else []
            norm_keys = KeyNormalisationService.normalise_keys(raw_keys) if raw_keys else []

            logger.info(f"[Phase 3] ✅ Normalized to {len(norm_certs)} certs, {len(norm_keys)} keys")
            return norm_certs, norm_keys

        except Exception as e:
            logger.error(f"[Phase 3] Normalization failed: {str(e)}")
            raise

    # =========================================================================
    # CONFIG TRANSFORMATION HELPERS (NO DUPLICATION)
    # =========================================================================

    def _transform_ejbca_config(self, config: dict) -> dict:
        """Transform nested EJBCA config to flat structure expected by ConnectorService

        Extracts the primary EJBCA server from nested database structure.

        Args:
            config: Database configuration (may have nested ejbca key)

        Returns:
            Flat EJBCA configuration dict for ConnectorService
        """
        if 'ejbca' in config and isinstance(config.get('ejbca'), dict):
            servers = config['ejbca'].get('servers', [])
            if servers and len(servers) > 0:
                server = servers[0]
                return {
                    'url': server.get('url'),
                    'p12_path': server.get('p12_path'),
                    'p12_password': server.get('p12_password') or server.get('p12_password_plaintext'),
                    'include_profiles': server.get('include_profiles', False)
                }
        return config

    def _transform_azure_config(self, config: dict) -> dict:
        """Transform nested Azure Key Vault config to flat structure

        Extracts the primary service principal from nested database structure.

        Args:
            config: Database configuration (may have nested azure_keyvault key)

        Returns:
            Flat Azure configuration dict for ConnectorService
        """
        if 'azure_keyvault' in config and isinstance(config.get('azure_keyvault'), dict):
            tenancies = config['azure_keyvault'].get('tenancies', [])
            if tenancies and len(tenancies) > 0:
                sps = tenancies[0].get('service_principals', [])
                if sps and len(sps) > 0:
                    sp = sps[0]
                    return {
                        'vault_url': sp.get('vault_url'),
                        'tenant_id': sp.get('tenant_id'),
                        'client_id': sp.get('client_id'),
                        'client_secret': sp.get('client_secret') or sp.get('client_secret_plaintext')
                    }
        return config

    def _transform_luna_config(self, config: dict) -> dict:
        """Transform Luna HSM config to format expected by ConnectorService

        Restructures Luna configuration to match ConnectorService expectations.

        Args:
            config: Database configuration with Luna HSM settings

        Returns:
            Transformed Luna configuration dict for ConnectorService
        """
        pwd = config.get('pin') or config.get('pin_plaintext')
        return {
            'pkcs11_module_path': config.get('library_path'),
            'partitions': [{
                'name': config.get('partition_name', config.get('device_name', 'Unknown')),
                'partition_password': pwd,
                'slot_index': config.get('slot', 0)
            }]
        }

    def _infer_environment(self, connector_type: str) -> str:
        """Infer environment/context based on connector type

        Args:
            connector_type: Type of connector

        Returns:
            Environment identifier (HSM, Cloud, PKI, Unknown)
        """
        if connector_type == 'Luna HSM':
            return 'HSM'
        elif connector_type == 'Azure Key Vault':
            return 'Cloud'
        elif connector_type == 'EJBCA':
            return 'PKI'
        else:
            return 'Unknown'

    # =========================================================================
    # PHASE 4: ENRICH METADATA
    # =========================================================================

    def _phase_4_enrich_metadata(self, norm_certs: list, norm_keys: list, connector_type: str) -> tuple:
        """Phase 4: Enrich with environment metadata

        Adds contextual metadata to normalized assets:
        - source_type: Identifies the connector type (Azure Key Vault, EJBCA, Luna HSM)
        - environment_metadata: Inferred environment type and discovery confidence

        NOTE: Security enrichment (signature_algorithm_analysis, key_strength_analysis, pqc_readiness)
        is handled in Phase 4.5 AFTER this phase completes.

        Args:
            norm_certs: Normalized certificates
            norm_keys: Normalized keys
            connector_type: Type of connector (EJBCA, Azure Key Vault, Luna HSM)

        Returns:
            Tuple of (enriched_certs_list, enriched_keys_list)
        """
        from caip_service_layer.metadata_enrichment_service import MetadataEnrichmentService
        from caip_service_layer.environment_inference_service import EnvironmentInferenceService

        logger.info(f"[Phase 4] Enriching {len(norm_certs)} certs, {len(norm_keys)} keys")

        try:
            # Determine enricher type from connector
            enricher_type = self._map_connector_to_enricher_type(connector_type)

            # Enrich certificates
            enriched_certs = []
            for cert in norm_certs:
                try:
                    enriched = self._enrich_certificate(cert, connector_type, enricher_type)
                    enriched_certs.append(enriched)
                except Exception as e:
                    logger.warning(f"[Phase 4] Failed to enrich certificate: {str(e)}")
                    enriched_certs.append(cert)  # Keep original if enrichment fails

            # Enrich keys
            enriched_keys = []
            for key in norm_keys:
                try:
                    enriched = self._enrich_key(key, connector_type, enricher_type)
                    enriched_keys.append(enriched)
                except Exception as e:
                    logger.warning(f"[Phase 4] Failed to enrich key: {str(e)}")
                    enriched_keys.append(key)  # Keep original if enrichment fails

            logger.info(f"[Phase 4] ✅ Enriched {len(enriched_certs)} certs, {len(enriched_keys)} keys")
            return enriched_certs, enriched_keys

        except Exception as e:
            logger.error(f"[Phase 4] Enrichment failed: {str(e)}")
            raise

    def _map_connector_to_enricher_type(self, connector_type: str) -> str:
        """Map connector type to enricher service type

        Args:
            connector_type: EJBCA, Azure Key Vault, or Luna HSM

        Returns:
            Enricher type for MetadataEnrichmentService
        """
        mapping = {
            'EJBCA': 'ejbca',
            'Azure Key Vault': 'azure',
            'Luna HSM': 'luna',
        }
        return mapping.get(connector_type, 'ejbca')

    def _enrich_certificate(self, cert: dict, connector_type: str, enricher_type: str) -> dict:
        """Enrich a single certificate with metadata

        Args:
            cert: Certificate dict
            connector_type: Connector type
            enricher_type: Enricher service type

        Returns:
            Enriched certificate dict
        """
        from caip_service_layer.environment_inference_service import EnvironmentInferenceService

        enriched = cert.copy()

        # Infer environment from connector type
        environment_type = self._infer_environment(connector_type)

        # Add source type
        enriched['source_type'] = connector_type

        # Add environment metadata if not present
        if 'environment_metadata' not in enriched:
            enriched['environment_metadata'] = {
                'environment_type': environment_type,
                'discovery_method': 'connector-type-inference',
                'discovery_confidence': 0.6
            }

        # Phase 4: Multi-signal inference from certificate data (Phase 1 + Phase 3)
        # Use orchestrator method that calls all 10 signals: relationship, source_string, issuer_patterns,
        # infrastructure_tier, cryptographic_properties, azure_tags, identity_analysis, purpose_analysis,
        # crypto_analysis, ha_analysis
        inferred = EnvironmentInferenceService.infer_from_scan_data(enriched, asset_type='certificate')

        # Extract the fused result and metadata
        if inferred and inferred.get('environment_type') != 'unknown':
            # Update environment metadata with multi-signal fusion result
            enriched['environment_metadata'] = {
                'environment_type': inferred.get('environment_type'),
                'discovery_method': inferred.get('discovery_method', 'multi_signal_fusion'),
                'discovery_confidence': inferred.get('discovery_confidence', 0.0),
                'signal_breakdown': inferred.get('signal_breakdown', [])  # Phase 1: Include signal breakdown
            }

            # Phase 3: Store extracted metadata for dashboard visualization
            if inferred.get('extracted_metadata'):
                enriched['extracted_metadata'] = inferred['extracted_metadata']

        return enriched

    def _phase_4_5_enrich_normalised_data(self, norm_certs: list, norm_keys: list,
                                          connector_type: str) -> tuple:
        """Phase 4.5: Add security analysis enrichment to normalized assets

        Called AFTER normalization (Phase 3) to add:
        - signature_algorithm_analysis
        - key_strength_analysis
        - pqc_readiness
        - revocation_status

        This ensures all collectors (Azure, EJBCA, Luna HSM) get consistent
        security enrichment applied uniformly.

        Args:
            norm_certs: Normalized certificates from Phase 3
            norm_keys: Normalized keys from Phase 3
            connector_type: Type of connector (Azure Key Vault, EJBCA, Luna HSM)

        Returns:
            Tuple of (enriched_certs, enriched_keys)
        """
        from caip_service_layer.metadata_enrichment_service import MetadataEnrichmentService

        logger.info(f"[Phase 4.5] Enriching {len(norm_certs)} certs, {len(norm_keys)} keys with security analysis")

        try:
            # Use universal security enricher for all connector types (TLSSecurityEnricher)
            # Note: Despite the name, 'tls_security' enricher works with any certificate
            enricher = MetadataEnrichmentService.get_enricher('tls_security')
            security_config = {'capture_security_analysis': True}

            # Enrich certificates with security analysis
            enriched_certs = []
            for cert in norm_certs:
                try:
                    enriched = enricher.enrich(cert, security_config)
                    enriched_certs.append(enriched)
                except Exception as e:
                    logger.warning(f"[Phase 4.5] Failed to enrich certificate: {str(e)}")
                    enriched_certs.append(cert)  # Keep original if enrichment fails

            # Enrich keys with security analysis
            enriched_keys = []
            for key in norm_keys:
                try:
                    enriched = enricher.enrich(key, security_config)
                    enriched_keys.append(enriched)
                except Exception as e:
                    logger.warning(f"[Phase 4.5] Failed to enrich key: {str(e)}")
                    enriched_keys.append(key)  # Keep original if enrichment fails

            logger.info(f"[Phase 4.5] ✅ Enriched {len(enriched_certs)} certs, {len(enriched_keys)} keys")
            return enriched_certs, enriched_keys

        except Exception as e:
            logger.error(f"[Phase 4.5] Enrichment failed: {str(e)}")
            # Don't fail the whole sync - return unenriched data
            logger.warning(f"[Phase 4.5] Returning unenriched data to prevent sync failure")
            return norm_certs, norm_keys

    def _enrich_key(self, key: dict, connector_type: str, enricher_type: str) -> dict:
        """Enrich a single key with metadata

        Args:
            key: Key dict
            connector_type: Connector type
            enricher_type: Enricher service type

        Returns:
            Enriched key dict
        """
        from caip_service_layer.environment_inference_service import EnvironmentInferenceService

        enriched = key.copy()

        # Infer environment from connector type
        environment_type = self._infer_environment(connector_type)

        # Add source type
        enriched['source_type'] = connector_type

        # Add environment metadata if not present
        if 'environment_metadata' not in enriched:
            enriched['environment_metadata'] = {
                'environment_type': environment_type,
                'discovery_method': 'connector-type-inference',
                'discovery_confidence': 0.6
            }

        # Try to infer from key label or name if available
        key_label = enriched.get('key_label') or enriched.get('name', '')
        if key_label:
            inferred = EnvironmentInferenceService.infer_from_source_string(key_label)
            # Use inferred metadata if confidence is higher
            if inferred.get('discovery_confidence', 0) > enriched['environment_metadata'].get('discovery_confidence', 0):
                enriched['environment_metadata'] = inferred

        return enriched

    # =========================================================================
    # PHASE 5: DETECT & STORE
    # =========================================================================

    def _phase_4_detect_and_store(self, connector_id: int, enriched_certs: list, enriched_keys: list) -> tuple:
        """Phase 4: Detect changes & store to database (renamed from Phase 5)

        Stores enriched certificates and keys to inventory database,
        detecting additions, updates, and removals.

        Args:
            connector_id: Connector database ID
            enriched_certs: Enriched certificates from phase 3
            enriched_keys: Enriched keys from phase 3

        Returns:
            Tuple of (cert_stats_dict, key_stats_dict)
        """
        logger.info(f"[Phase 5] Storing {len(enriched_certs)} certs, {len(enriched_keys)} keys")

        try:
            cert_stats = self._store_certificates(connector_id, enriched_certs)
            key_stats = self._store_keys(connector_id, enriched_keys)

            logger.info(f"[Phase 5] ✅ Certificates: {cert_stats['added']} added, {cert_stats['updated']} updated")
            logger.info(f"[Phase 5] ✅ Keys: {key_stats['added']} added, {key_stats['updated']} updated")

            return cert_stats, key_stats

        except Exception as e:
            logger.error(f"[Phase 5] Storage failed: {str(e)}")
            raise

    def _store_certificates(self, connector_id: int, certs: list) -> dict:
        """Store certificates and detect changes

        Args:
            connector_id: Connector ID for filtering
            certs: List of enriched certificate dicts

        Returns:
            Stats dict with added, updated, total counts
        """
        from database_service import DatabaseService

        stats = {'added': 0, 'updated': 0, 'total': len(certs)}

        for cert in certs:
            try:
                fingerprint = cert.get('fingerprint') or cert.get('fingerprint_sha256')
                if not fingerprint:
                    logger.warning("[Phase 5] Certificate missing fingerprint, skipping")
                    continue

                # Check if certificate exists
                existing = DatabaseService.get_certificate(fingerprint, connector_id)

                if existing:
                    # Update existing
                    self._update_certificate(connector_id, cert, existing)
                    stats['updated'] += 1
                else:
                    # Insert new
                    self._insert_certificate(connector_id, cert)
                    stats['added'] += 1

            except Exception as e:
                logger.warning(f"[Phase 5] Failed to store certificate {cert.get('fingerprint')}: {str(e)}")

        return stats

    def _store_keys(self, connector_id: int, keys: list) -> dict:
        """Store keys and detect changes

        Args:
            connector_id: Connector ID for filtering
            keys: List of enriched key dicts

        Returns:
            Stats dict with added, updated, total counts
        """
        from database_service import DatabaseService

        stats = {'added': 0, 'updated': 0, 'total': len(keys)}

        for key in keys:
            try:
                key_id = key.get('key_id') or key.get('id')
                if not key_id:
                    logger.warning("[Phase 5] Key missing ID, skipping")
                    continue

                # Check if key exists
                existing = DatabaseService.get_key(key_id, connector_id)

                if existing:
                    # Update existing
                    self._update_key(connector_id, key, existing)
                    stats['updated'] += 1
                else:
                    # Insert new
                    self._insert_key(connector_id, key)
                    stats['added'] += 1

            except Exception as e:
                logger.warning(f"[Phase 5] Failed to store key {key.get('key_id')}: {str(e)}")

        return stats

    def _insert_certificate(self, connector_id: int, cert: dict):
        """Insert new certificate to database

        Args:
            connector_id: Connector database ID
            cert: Enriched certificate dict
        """
        from database_service import DatabaseService
        import json

        try:
            fingerprint = cert.get('fingerprint') or cert.get('fingerprint_sha256')
            # Extract subject_cn from normalised data (after enrichment phase)
            subject_cn = cert.get('subject_cn', '')
            # issuer is a dict with commonName - extract the CN value
            issuer_dict = cert.get('issuer', {})
            issuer_cn = issuer_dict.get('commonName', '') if isinstance(issuer_dict, dict) else str(issuer_dict) if issuer_dict else ''
            not_after = cert.get('not_after')
            key_algorithm = cert.get('public_key_algorithm', '')
            key_size = cert.get('public_key_size', 0)
            source_type = cert.get('source_type', 'Unknown')
            days_until_expiry = cert.get('days_until_expiration', 0)
            is_promoted = 1 if cert.get('is_promoted') else 0
            promoted_from_scan_name = cert.get('promoted_from_scan_name')

            # Get connector name for integration_name
            conn = DatabaseService.get_connection()
            c = conn.cursor()
            c.execute('SELECT name FROM clm_integrations WHERE id = ?', (connector_id,))
            connector_row = c.fetchone()
            conn.close()
            integration_name = connector_row[0] if connector_row else f'Connector {connector_id}'

            # Store all enriched data as JSON
            normalised_data = cert

            DatabaseService.insert_certificate(
                connector_id=connector_id,
                fingerprint=fingerprint,
                subject_cn=subject_cn,
                issuer_cn=issuer_cn,
                not_after=not_after,
                key_algorithm=key_algorithm,
                key_size=key_size,
                source_type=source_type,
                normalised_data=json.dumps(normalised_data),
                integration_name=integration_name,
                days_until_expiry=days_until_expiry,
                is_promoted=is_promoted,
                promoted_from_scan_name=promoted_from_scan_name
            )
            logger.debug(f"[Phase 5] Inserted certificate {fingerprint}")

        except Exception as e:
            logger.warning(f"[Phase 5] Insert certificate error: {str(e)}")
            raise

    def _update_certificate(self, connector_id: int, cert: dict, existing: dict):
        """Update existing certificate in database

        Args:
            connector_id: Connector database ID
            cert: New enriched certificate dict
            existing: Existing certificate record
        """
        from database_service import DatabaseService
        import json

        try:
            fingerprint = cert.get('fingerprint') or cert.get('fingerprint_sha256')
            # Extract subject_cn from normalised data (after enrichment phase)
            subject_cn = cert.get('subject_cn', '')
            # issuer is a dict with commonName - extract the CN value
            issuer_dict = cert.get('issuer', {})
            issuer_cn = issuer_dict.get('commonName', '') if isinstance(issuer_dict, dict) else str(issuer_dict) if issuer_dict else ''
            not_after = cert.get('not_after')
            key_algorithm = cert.get('public_key_algorithm', '')
            key_size = cert.get('public_key_size', 0)
            source_type = cert.get('source_type', 'Unknown')
            days_until_expiry = cert.get('days_until_expiration', 0)
            is_promoted = 1 if cert.get('is_promoted') else 0
            promoted_from_scan_name = cert.get('promoted_from_scan_name')

            # Get connector name for integration_name
            conn = DatabaseService.get_connection()
            c = conn.cursor()
            c.execute('SELECT name FROM clm_integrations WHERE id = ?', (connector_id,))
            connector_row = c.fetchone()
            conn.close()
            integration_name = connector_row[0] if connector_row else f'Connector {connector_id}'

            # Store all enriched data as JSON
            normalised_data = cert

            DatabaseService.update_certificate(
                connector_id=connector_id,
                fingerprint=fingerprint,
                subject_cn=subject_cn,
                issuer_cn=issuer_cn,
                not_after=not_after,
                key_algorithm=key_algorithm,
                key_size=key_size,
                source_type=source_type,
                normalised_data=json.dumps(normalised_data),
                integration_name=integration_name,
                days_until_expiry=days_until_expiry,
                is_promoted=is_promoted,
                promoted_from_scan_name=promoted_from_scan_name
            )
            logger.debug(f"[Phase 5] Updated certificate {fingerprint}")

        except Exception as e:
            logger.warning(f"[Phase 5] Update certificate error: {str(e)}")
            raise

    def _insert_key(self, connector_id: int, key: dict):
        """Insert new key to database

        Args:
            connector_id: Connector database ID
            key: Enriched key dict
        """
        from database_service import DatabaseService
        import json

        try:
            key_id = key.get('key_id') or key.get('id')
            key_label = key.get('key_label') or key.get('name', '')
            key_type = key.get('key_type', '')
            key_size = key.get('key_size', 0)
            source_type = key.get('source_type', 'Unknown')

            # Store normalized data as JSON
            normalised_data = {
                k: v for k, v in key.items()
                if k not in ['key_id', 'id', 'key_label', 'name']
            }

            DatabaseService.insert_key(
                connector_id=connector_id,
                key_id=key_id,
                key_label=key_label,
                key_type=key_type,
                key_size=key_size,
                source_type=source_type,
                normalised_data=json.dumps(normalised_data)
            )
            logger.debug(f"[Phase 5] Inserted key {key_id}")

        except Exception as e:
            logger.warning(f"[Phase 5] Insert key error: {str(e)}")
            raise

    def _update_key(self, connector_id: int, key: dict, existing: dict):
        """Update existing key in database

        Args:
            connector_id: Connector database ID
            key: New enriched key dict
            existing: Existing key record
        """
        from database_service import DatabaseService
        import json

        try:
            key_id = key.get('key_id') or key.get('id')
            key_label = key.get('key_label') or key.get('name', '')
            key_type = key.get('key_type', '')
            key_size = key.get('key_size', 0)
            source_type = key.get('source_type', 'Unknown')

            # Store normalized data as JSON
            normalised_data = {
                k: v for k, v in key.items()
                if k not in ['key_id', 'id', 'key_label', 'name']
            }

            DatabaseService.update_key(
                connector_id=connector_id,
                key_id=key_id,
                key_label=key_label,
                key_type=key_type,
                key_size=key_size,
                source_type=source_type,
                normalised_data=json.dumps(normalised_data)
            )
            logger.debug(f"[Phase 5] Updated key {key_id}")

        except Exception as e:
            logger.warning(f"[Phase 5] Update key error: {str(e)}")
            raise

    # =========================================================================
    # PHASE 6: UPDATE STATUS
    # =========================================================================

    def _phase_5_update_status(self, connector_id: int, connector: dict, cert_stats: dict, key_stats: dict):
        """Phase 6: Update sync status with results

        Updates connector sync status, marking completion with statistics
        on certificates and keys processed.

        Args:
            connector_id: Connector database ID
            connector: Connector details dict
            cert_stats: Certificate statistics (added, updated, total)
            key_stats: Key statistics (added, updated, total)

        Returns:
            SyncResult object
        """
        from caip_service_layer.inventory_service import SyncResult
        from database_service import DatabaseService

        logger.info(f"[Phase 6] Updating sync status")

        try:
            # Update connector sync status with results
            try:
                DatabaseService.update_connector_sync_status(
                    connector_id=connector_id,
                    success=True,
                    certificates_total=cert_stats.get('total', 0),
                    certificates_added=cert_stats.get('added', 0),
                    certificates_updated=cert_stats.get('updated', 0),
                    keys_total=key_stats.get('total', 0),
                    keys_added=key_stats.get('added', 0),
                    keys_updated=key_stats.get('updated', 0)
                )
            except (AttributeError, Exception) as e:
                logger.warning(f"[Phase 6] Could not update connector status: {str(e)}")

            # Create result
            completed_at = datetime.now(timezone.utc)
            duration = (completed_at - self.started_at).total_seconds()

            result = SyncResult(
                connector_id=connector_id,
                connector_name=connector['name'],
                success=True,
                started_at=self.started_at.isoformat(),
                completed_at=completed_at.isoformat(),
                duration_seconds=duration,
                certificates_total=cert_stats.get('total', 0),
                certificates_added=cert_stats.get('added', 0),
                certificates_updated=cert_stats.get('updated', 0),
                certificates_removed=0,
                keys_total=key_stats.get('total', 0),
                keys_added=key_stats.get('added', 0),
                keys_updated=key_stats.get('updated', 0),
                keys_removed=0
            )

            logger.info(f"[Phase 6] ✅ Sync complete: {result.certificates_added}+{result.certificates_updated} certs, {result.keys_added}+{result.keys_updated} keys in {duration:.1f}s")

            return result

        except Exception as e:
            logger.error(f"[Phase 6] Status result creation failed: {str(e)}")
            raise

    # =========================================================================
    # ERROR HANDLING
    # =========================================================================

    def _handle_error(self, connector_id: int, error_msg: str):
        """Handle sync error and return error SyncResult

        Args:
            connector_id: Connector database ID
            error_msg: Error message

        Returns:
            SyncResult with success=False and error message
        """
        from caip_service_layer.inventory_service import SyncResult

        logger.error(f"[InventoryOrchestrator] Error for connector {connector_id}: {error_msg}")

        return SyncResult(
            connector_id=connector_id,
            connector_name=self.connector_name or 'Unknown',
            success=False,
            started_at=self.started_at.isoformat(),
            completed_at=datetime.now(timezone.utc).isoformat(),
            duration_seconds=(datetime.now(timezone.utc) - self.started_at).total_seconds(),
            error_message=error_msg
        )
