# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: caip_service_layer/asset_context_service.py
# Copied: 2026-04-01
# Used in: Phase 10 — Inventory and Enrichment
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
Asset Context Service for CAIP

Manages asset context enrichment data for PQC migration planning.
Provides:
- Context data storage linked to engagements
- Import of context from embedded dashboard exports
- Context retrieval for visualization services
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger('caip.operational')


class AssetContextService:
    """
    Service for managing asset context enrichment data.
    
    Context data includes:
    - business_function: Critical, Important, Standard, Unknown
    - data_classification: Restricted, Confidential, Internal, Public
    - dependencies: None, Low (1-2), Medium (3-5), High (5+)
    - compliance_scope: Multi-select (PCI-DSS, SOX, HIPAA, GDPR, NIS2, DORA, CNSA 2.0, None)
    - migration_path: Clear, Uncertain, Blocked
    - owner: Free text field for technical owner
    """
    
    # Valid options for context fields
    VALID_BUSINESS_UNITS = [
        'IT Operations', 'Security', 'Infrastructure', 'Development',
        'Finance', 'HR', 'Legal', 'Sales', 'Marketing', 'Customer Service',
        'R&D', 'Manufacturing', 'Supply Chain', 'Executive', 'External/Partner', 'Other'
    ]
    
    VALID_BUSINESS_FUNCTIONS = [
        'Critical', 'Important', 'Standard', 'Unknown'
    ]
    
    VALID_DATA_CLASSIFICATIONS = [
        'Restricted', 'Confidential', 'Internal', 'Public'
    ]
    
    VALID_DEPENDENCIES = [
        'None', 'Low (1-2)', 'Medium (3-5)', 'High (5+)'
    ]
    
    VALID_COMPLIANCE_SCOPES = [
        'PCI-DSS', 'SOX', 'HIPAA', 'GDPR', 'NIS2', 'DORA', 'CNSA 2.0', 'None'
    ]
    
    VALID_MIGRATION_PATHS = [
        'Clear', 'Uncertain', 'Blocked'
    ]

    VALID_ENVIRONMENT_TYPES = [
        'production', 'staging', 'development', 'testing', 'unknown'
    ]

    VALID_DISCOVERY_METHODS = [
        'manual',
        'tls-hostname-pattern',
        'tls-port-inference',
        'azure-tags',
        'ejbca-metadata',
        'luna-partition',
        'source-string-pattern',
        'collector-type-inference'
    ]

    # =========================================================================
    # DATABASE SCHEMA
    # =========================================================================
    
    @classmethod
    def init_context_tables(cls, db_service):
        """
        Initialize the asset_context table.
        
        Should be called from DatabaseService.init_db() or as a migration.
        
        Args:
            db_service: DatabaseService class reference
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            
            # Asset context table - stores enrichment data per asset per engagement
            c.execute('''CREATE TABLE IF NOT EXISTS asset_context
                         (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          engagement_id TEXT,
                          asset_id TEXT NOT NULL,
                          asset_name TEXT,
                          asset_type TEXT NOT NULL,
                          source TEXT,
                          business_unit TEXT,
                          business_function TEXT,
                          data_classification TEXT,
                          dependencies TEXT,
                          compliance_scope TEXT,
                          migration_path TEXT,
                          owner TEXT,
                          notes TEXT,
                          override_enabled INTEGER DEFAULT 0,
                          override_score INTEGER,
                          override_phase TEXT,
                          override_reason TEXT,
                          excluded INTEGER DEFAULT 0,
                          exclusion_reason TEXT,
                          last_modified_by TEXT,
                          last_modified_at TIMESTAMP,
                          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                          UNIQUE(engagement_id, asset_id))''')

            # Create indices for faster lookups
            c.execute('''CREATE INDEX IF NOT EXISTS idx_asset_context_engagement
                         ON asset_context(engagement_id)''')
            c.execute('''CREATE INDEX IF NOT EXISTS idx_asset_context_asset
                         ON asset_context(asset_id)''')
            c.execute('''CREATE INDEX IF NOT EXISTS idx_asset_context_excluded
                         ON asset_context(excluded)''')
            c.execute('''CREATE INDEX IF NOT EXISTS idx_asset_context_override
                         ON asset_context(override_enabled)''')

            # Create audit history table for enrichment changes
            c.execute('''CREATE TABLE IF NOT EXISTS asset_context_history
                         (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          context_id INTEGER NOT NULL,
                          engagement_id TEXT,
                          asset_id TEXT NOT NULL,
                          asset_type TEXT NOT NULL,
                          business_unit TEXT,
                          business_function TEXT,
                          data_classification TEXT,
                          dependencies TEXT,
                          compliance_scope TEXT,
                          migration_path TEXT,
                          owner TEXT,
                          notes TEXT,
                          override_enabled INTEGER,
                          override_score INTEGER,
                          override_phase TEXT,
                          override_reason TEXT,
                          excluded INTEGER,
                          exclusion_reason TEXT,
                          change_type TEXT NOT NULL,
                          changed_by TEXT NOT NULL,
                          changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                          previous_values TEXT,
                          FOREIGN KEY(context_id) REFERENCES asset_context(id))''')

            c.execute('''CREATE INDEX IF NOT EXISTS idx_context_history_context
                         ON asset_context_history(context_id)''')
            c.execute('''CREATE INDEX IF NOT EXISTS idx_context_history_asset
                         ON asset_context_history(asset_id)''')
            c.execute('''CREATE INDEX IF NOT EXISTS idx_context_history_changed_at
                         ON asset_context_history(changed_at DESC)''')

            conn.commit()
            logger.info("Asset context tables initialized with enrichment audit trail")
    
    # =========================================================================
    # CONTEXT CRUD OPERATIONS
    # =========================================================================
    
    @classmethod
    def upsert_context(cls,
                       db_service,
                       engagement_id: str,
                       asset_id: str,
                       asset_type: str,
                       asset_name: str = None,
                       source: str = None,
                       business_unit: str = None,
                       business_function: str = None,
                       data_classification: str = None,
                       dependencies: str = None,
                       compliance_scope: str = None,
                       migration_path: str = None,
                       owner: str = None,
                       notes: str = None,
                       override_enabled: int = None,
                       override_score: int = None,
                       override_phase: str = None,
                       override_reason: str = None,
                       excluded: int = None,
                       exclusion_reason: str = None,
                       changed_by: str = None,
                       environment_type: str = None,
                       service_name: str = None,
                       application_name: str = None,
                       discovery_method: str = None,
                       discovery_confidence: float = None,
                       extracted_service_name: str = None,
                       extracted_organization: str = None,
                       extracted_cloud_provider: str = None,
                       extracted_region: str = None,
                       extracted_service_tier: str = None,
                       extracted_domain_type: str = None,
                       extracted_primary_purpose: str = None,
                       extracted_ca_tier: str = None,
                       extracted_issuing_organization: str = None,
                       extracted_criticality_tier: str = None,
                       extracted_data_residency: str = None,
                       extracted_crypto_strength: str = None,
                       extracted_pqc_migration_needed: int = None,
                       extracted_key_algorithm: str = None,
                       extracted_key_size: int = None,
                       extracted_ha_enabled: int = None,
                       extracted_replication_count: int = None,
                       extracted_san_base_name: str = None,
                       extracted_is_replicated: int = None) -> Dict[str, Any]:
        """
        Insert or update context for an asset with audit trail.

        Args:
            db_service: DatabaseService class reference
            engagement_id: Engagement ID (e.g., 'ENG-2024-001')
            asset_id: Unique asset identifier (fingerprint, key_id, etc.)
            asset_type: 'certificate' or 'key'
            asset_name: Display name for the asset
            source: Source of the asset (TLS, Azure, Luna, etc.)
            business_unit: Business unit assignment
            business_function: Business function (Critical, Important, Standard, Unknown)
            data_classification: Data classification (Restricted, Confidential, Internal, Public)
            dependencies: Downstream dependencies (None, Low, Medium, High)
            compliance_scope: Compliance frameworks (comma-separated list)
            migration_path: Migration path status (Clear, Uncertain, Blocked)
            owner: Technical owner (free text)
            notes: Additional notes
            override_enabled: Whether score override is enabled (0/1)
            override_score: Override score value (0-100)
            override_phase: Override migration phase
            override_reason: Reason for override
            excluded: Whether asset is excluded from reports (0/1)
            exclusion_reason: Reason for exclusion
            changed_by: Username making the change (for audit trail)
            environment_type: Auto-discovered environment (production, staging, development, testing, unknown)
            service_name: Service name from hostname or tags
            application_name: Application name from certificate CN or tags
            discovery_method: How environment was discovered (manual, tls-hostname-pattern, azure-tags, etc.)
            discovery_confidence: Confidence score (0.0-1.0) where 1.0 = manual, <1.0 = auto-discovered

        Returns:
            Dict with operation result
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()

            # Check if context already exists
            c.execute('''SELECT id FROM asset_context
                         WHERE engagement_id = ? AND asset_id = ?''',
                     (engagement_id, asset_id))
            existing = c.fetchone()

            now = datetime.now().isoformat()

            if existing:
                context_id = existing[0]

                # Capture old values for history
                c.execute('''SELECT business_unit, business_function, data_classification,
                             dependencies, compliance_scope, migration_path, owner, notes,
                             override_enabled, override_score, override_phase, override_reason,
                             excluded, exclusion_reason
                             FROM asset_context WHERE id = ?''', (context_id,))
                old_values = c.fetchone()
                old_dict = {
                    'business_unit': old_values[0],
                    'business_function': old_values[1],
                    'data_classification': old_values[2],
                    'dependencies': old_values[3],
                    'compliance_scope': old_values[4],
                    'migration_path': old_values[5],
                    'owner': old_values[6],
                    'notes': old_values[7],
                    'override_enabled': old_values[8],
                    'override_score': old_values[9],
                    'override_phase': old_values[10],
                    'override_reason': old_values[11],
                    'excluded': old_values[12],
                    'exclusion_reason': old_values[13]
                } if old_values else {}

                # Update existing context
                c.execute('''UPDATE asset_context SET
                             asset_name = COALESCE(?, asset_name),
                             asset_type = ?,
                             source = COALESCE(?, source),
                             business_unit = ?,
                             business_function = ?,
                             data_classification = ?,
                             dependencies = ?,
                             compliance_scope = ?,
                             migration_path = ?,
                             owner = ?,
                             notes = ?,
                             override_enabled = COALESCE(?, override_enabled),
                             override_score = COALESCE(?, override_score),
                             override_phase = COALESCE(?, override_phase),
                             override_reason = COALESCE(?, override_reason),
                             excluded = COALESCE(?, excluded),
                             exclusion_reason = COALESCE(?, exclusion_reason),
                             environment_type = COALESCE(?, environment_type),
                             service_name = COALESCE(?, service_name),
                             application_name = COALESCE(?, application_name),
                             discovery_method = COALESCE(?, discovery_method),
                             discovery_confidence = COALESCE(?, discovery_confidence),
                             extracted_service_name = COALESCE(?, extracted_service_name),
                             extracted_organization = COALESCE(?, extracted_organization),
                             extracted_cloud_provider = COALESCE(?, extracted_cloud_provider),
                             extracted_region = COALESCE(?, extracted_region),
                             extracted_service_tier = COALESCE(?, extracted_service_tier),
                             extracted_domain_type = COALESCE(?, extracted_domain_type),
                             extracted_primary_purpose = COALESCE(?, extracted_primary_purpose),
                             extracted_ca_tier = COALESCE(?, extracted_ca_tier),
                             extracted_issuing_organization = COALESCE(?, extracted_issuing_organization),
                             extracted_criticality_tier = COALESCE(?, extracted_criticality_tier),
                             extracted_data_residency = COALESCE(?, extracted_data_residency),
                             extracted_crypto_strength = COALESCE(?, extracted_crypto_strength),
                             extracted_pqc_migration_needed = COALESCE(?, extracted_pqc_migration_needed),
                             extracted_key_algorithm = COALESCE(?, extracted_key_algorithm),
                             extracted_key_size = COALESCE(?, extracted_key_size),
                             extracted_ha_enabled = COALESCE(?, extracted_ha_enabled),
                             extracted_replication_count = COALESCE(?, extracted_replication_count),
                             extracted_san_base_name = COALESCE(?, extracted_san_base_name),
                             extracted_is_replicated = COALESCE(?, extracted_is_replicated),
                             last_modified_by = ?,
                             last_modified_at = ?,
                             updated_at = ?
                             WHERE engagement_id = ? AND asset_id = ?''',
                         (asset_name, asset_type, source, business_unit, business_function,
                          data_classification, dependencies, compliance_scope,
                          migration_path, owner, notes, override_enabled, override_score,
                          override_phase, override_reason, excluded, exclusion_reason,
                          environment_type, service_name, application_name, discovery_method,
                          discovery_confidence, extracted_service_name, extracted_organization,
                          extracted_cloud_provider, extracted_region, extracted_service_tier,
                          extracted_domain_type, extracted_primary_purpose, extracted_ca_tier,
                          extracted_issuing_organization, extracted_criticality_tier,
                          extracted_data_residency, extracted_crypto_strength,
                          extracted_pqc_migration_needed, extracted_key_algorithm,
                          extracted_key_size, extracted_ha_enabled, extracted_replication_count,
                          extracted_san_base_name, extracted_is_replicated,
                          changed_by, now, now, engagement_id, asset_id))

                # Log to history (inline to reuse connection)
                cls._log_context_change_inline(
                    c, context_id, engagement_id, asset_id, asset_type,
                    'updated', changed_by or 'system', old_dict, now)

                operation = 'updated'
            else:
                # Insert new context
                c.execute('''INSERT INTO asset_context
                             (engagement_id, asset_id, asset_name, asset_type, source,
                              business_unit, business_function, data_classification, dependencies,
                              compliance_scope, migration_path, owner, notes,
                              override_enabled, override_score, override_phase, override_reason,
                              excluded, exclusion_reason, environment_type, service_name,
                              application_name, discovery_method, discovery_confidence,
                              extracted_service_name, extracted_organization, extracted_cloud_provider,
                              extracted_region, extracted_service_tier, extracted_domain_type,
                              extracted_primary_purpose, extracted_ca_tier, extracted_issuing_organization,
                              extracted_criticality_tier, extracted_data_residency, extracted_crypto_strength,
                              extracted_pqc_migration_needed, extracted_key_algorithm, extracted_key_size,
                              extracted_ha_enabled, extracted_replication_count, extracted_san_base_name,
                              extracted_is_replicated, last_modified_by, last_modified_at, created_at, updated_at)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                         (engagement_id, asset_id, asset_name, asset_type, source,
                          business_unit, business_function, data_classification, dependencies,
                          compliance_scope, migration_path, owner, notes,
                          override_enabled or 0, override_score, override_phase, override_reason,
                          excluded or 0, exclusion_reason, environment_type, service_name,
                          application_name, discovery_method, discovery_confidence or 1.0,
                          extracted_service_name, extracted_organization, extracted_cloud_provider,
                          extracted_region, extracted_service_tier, extracted_domain_type,
                          extracted_primary_purpose, extracted_ca_tier, extracted_issuing_organization,
                          extracted_criticality_tier, extracted_data_residency, extracted_crypto_strength,
                          extracted_pqc_migration_needed, extracted_key_algorithm, extracted_key_size,
                          extracted_ha_enabled, extracted_replication_count, extracted_san_base_name,
                          extracted_is_replicated, changed_by or 'system', now, now, now))

                # Get new context ID and log to history (inline to reuse connection)
                context_id = c.lastrowid
                cls._log_context_change_inline(
                    c, context_id, engagement_id, asset_id, asset_type,
                    'created', changed_by or 'system', {}, now)

                operation = 'created'

            conn.commit()

            return {
                'success': True,
                'operation': operation,
                'engagement_id': engagement_id,
                'asset_id': asset_id,
                'context_id': context_id if existing else None
            }

    @staticmethod
    def _log_context_change_inline(cursor,
                                   context_id: int,
                                   engagement_id: str,
                                   asset_id: str,
                                   asset_type: str,
                                   change_type: str,
                                   changed_by: str,
                                   previous_values: Dict = None,
                                   timestamp: str = None):
        """
        Log enrichment change to history table (uses existing cursor).

        Args:
            cursor: Active database cursor
            context_id: ID of asset_context record
            engagement_id: Engagement ID
            asset_id: Asset ID
            asset_type: Type of asset (certificate/key)
            change_type: Type of change (created/updated/deleted)
            changed_by: Username making the change
            previous_values: Dict of previous values before update
            timestamp: ISO format timestamp (defaults to now)
        """
        try:
            import json
            now = timestamp or datetime.now().isoformat()

            # Get current context values
            cursor.execute('''SELECT business_unit, business_function, data_classification,
                             dependencies, compliance_scope, migration_path, owner, notes,
                             override_enabled, override_score, override_phase, override_reason,
                             excluded, exclusion_reason
                             FROM asset_context WHERE id = ?''', (context_id,))
            current = cursor.fetchone()

            if current:
                # Insert history record
                cursor.execute('''INSERT INTO asset_context_history
                                 (context_id, engagement_id, asset_id, asset_type,
                                  business_unit, business_function, data_classification,
                                  dependencies, compliance_scope, migration_path, owner, notes,
                                  override_enabled, override_score, override_phase, override_reason,
                                  excluded, exclusion_reason,
                                  change_type, changed_by, changed_at, previous_values)
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                             (context_id, engagement_id, asset_id, asset_type,
                              current[0], current[1], current[2], current[3], current[4],
                              current[5], current[6], current[7], current[8], current[9],
                              current[10], current[11], current[12], current[13],
                              change_type, changed_by, now,
                              json.dumps(previous_values) if previous_values else None))
        except Exception as e:
            logger.warning(f"Failed to log context change: {e}")
    
    @classmethod
    def get_context(cls,
                    db_service,
                    engagement_id: str,
                    asset_id: str) -> Optional[Dict[str, Any]]:
        """
        Get context for a specific asset.
        
        Args:
            db_service: DatabaseService class reference
            engagement_id: Engagement ID
            asset_id: Asset identifier
            
        Returns:
            Context dict or None if not found
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''SELECT * FROM asset_context 
                         WHERE engagement_id = ? AND asset_id = ?''',
                     (engagement_id, asset_id))
            row = c.fetchone()
            
            if row:
                return dict(row)
            return None
    
    @classmethod
    def get_engagement_context(cls,
                               db_service,
                               engagement_id: str) -> List[Dict[str, Any]]:
        """
        Get all context data for an engagement.
        
        Args:
            db_service: DatabaseService class reference
            engagement_id: Engagement ID
            
        Returns:
            List of context dicts
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''SELECT * FROM asset_context 
                         WHERE engagement_id = ?
                         ORDER BY asset_type, asset_name''',
                     (engagement_id,))
            rows = c.fetchall()
            
            return [dict(row) for row in rows]

    @classmethod
    def merge_auto_discovered_metadata(cls,
                                       db_service,
                                       engagement_id: str,
                                       asset_id: str,
                                       asset_type: str,
                                       auto_metadata: Dict[str, Any]) -> bool:
        """
        Merge auto-discovered metadata with existing enrichment.

        Only updates fields if no manual value exists OR auto-discovered confidence
        is higher than existing confidence.

        Args:
            db_service: DatabaseService class reference
            engagement_id: Engagement ID
            asset_id: Asset identifier
            asset_type: Type of asset (certificate/key)
            auto_metadata: Dict with environment_type, service_name, application_name,
                          discovery_method, discovery_confidence

        Returns:
            True if context was updated/created, False otherwise
        """
        # Get existing context
        existing = cls.get_context(db_service, engagement_id, asset_id)

        # If no existing context, create with auto-discovered data
        if not existing:
            return cls.upsert_context(
                db_service=db_service,
                engagement_id=engagement_id,
                asset_id=asset_id,
                asset_type=asset_type,
                asset_name=asset_id,
                environment_type=auto_metadata.get('environment_type'),
                service_name=auto_metadata.get('service_name'),
                application_name=auto_metadata.get('application_name'),
                discovery_method=auto_metadata.get('discovery_method', 'manual'),
                discovery_confidence=auto_metadata.get('discovery_confidence', 1.0),
                changed_by='system-auto-discovery'
            )

        # Only update if existing confidence is lower or field is empty
        update_needed = False
        updates = {}

        existing_confidence = existing.get('discovery_confidence') or 0.0
        auto_confidence = auto_metadata.get('discovery_confidence', 0.5)

        for field in ['environment_type', 'service_name', 'application_name']:
            auto_value = auto_metadata.get(field)
            existing_value = existing.get(field)

            # Update if: auto_value exists AND (no existing value OR auto is more confident)
            if auto_value and (not existing_value or auto_confidence > existing_confidence):
                updates[field] = auto_value
                update_needed = True

        if update_needed:
            updates['discovery_method'] = auto_metadata.get('discovery_method', 'manual')
            updates['discovery_confidence'] = auto_metadata.get('discovery_confidence', 1.0)
            updates['changed_by'] = 'system-auto-discovery'

            cls.upsert_context(
                db_service=db_service,
                engagement_id=engagement_id,
                asset_id=asset_id,
                asset_type=asset_type,
                **updates
            )
            return True

        return False

    @classmethod
    def auto_calculate_dependencies(cls, db_service, asset_id: str) -> str:
        """
        Auto-populate dependencies field based on relationship graph.

        Uses RelationshipService to calculate how many assets depend on this one,
        and maps the count to dependency level categories.

        Args:
            db_service: DatabaseService class reference
            asset_id: Asset identifier

        Returns:
            Dependency level string: 'None', 'Low (1-2)', 'Medium (3-5)', or 'High (5+)'
        """
        try:
            from caip_service_layer.relationship_service import RelationshipService
            return RelationshipService.calculate_dependency_level(asset_id)
        except Exception as e:
            logger.warning(f"Error calculating dependency level for {asset_id}: {e}")
            return 'None'

    @classmethod
    def delete_context(cls,
                       db_service,
                       engagement_id: str,
                       asset_id: str = None,
                       changed_by: str = None) -> Dict[str, Any]:
        """
        Delete context data with audit trail logging.

        Args:
            db_service: DatabaseService class reference
            engagement_id: Engagement ID
            asset_id: Optional - if provided, delete only this asset's context
                      If None, delete all context for the engagement
            changed_by: Username making the deletion (for audit trail)

        Returns:
            Dict with operation result
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()

            # Disable FK constraints temporarily for deletion
            c.execute('PRAGMA foreign_keys=OFF')

            # Get records to be deleted (for audit trail)
            if asset_id:
                c.execute('''SELECT id, asset_id, asset_type FROM asset_context
                             WHERE engagement_id = ? AND asset_id = ?''',
                         (engagement_id, asset_id))
            else:
                c.execute('''SELECT id, asset_id, asset_type FROM asset_context
                             WHERE engagement_id = ?''',
                         (engagement_id,))

            deleted_records = c.fetchall()
            now = datetime.now().isoformat()

            # Log deletions to history BEFORE deleting (to preserve FK)
            for record_id, rec_asset_id, asset_type in deleted_records:
                c.execute('''INSERT INTO asset_context_history
                             (context_id, engagement_id, asset_id, asset_type,
                              change_type, changed_by, changed_at)
                             VALUES (?, ?, ?, ?, ?, ?, ?)''',
                         (record_id, engagement_id, rec_asset_id, asset_type,
                          'deleted', changed_by or 'system', now))

            # Delete records
            if asset_id:
                c.execute('''DELETE FROM asset_context
                             WHERE engagement_id = ? AND asset_id = ?''',
                         (engagement_id, asset_id))
            else:
                c.execute('''DELETE FROM asset_context
                             WHERE engagement_id = ?''',
                         (engagement_id,))

            deleted_count = c.rowcount

            # Re-enable FK constraints
            c.execute('PRAGMA foreign_keys=ON')
            conn.commit()

            return {
                'success': True,
                'deleted_count': deleted_count
            }
    
    # =========================================================================
    # BULK IMPORT OPERATIONS
    # =========================================================================
    
    @classmethod
    def import_context_data(cls,
                            db_service,
                            engagement_id: str,
                            import_data: Dict[str, Any],
                            import_by: str = None) -> Dict[str, Any]:
        """
        Import context data from embedded dashboard export with audit trail.

        Expected import_data structure (from pki_report.html export):
        {
            "export_type": "caip_context_enrichment",
            "version": "1.0",
            "exported_at": "2024-01-15T...",
            "context_data": [
                {
                    "asset_id": "...",
                    "asset_name": "...",
                    "asset_type": "certificate|key",
                    "source": "...",
                    "context": {
                        "business_unit": "...",
                        "business_function": "...",
                        "data_classification": "...",
                        "dependencies": "...",
                        "compliance_scope": "...",
                        "migration_path": "...",
                        "owner": "..."
                    },
                    "override_enabled": false,
                    "override_score": null,
                    "override_reason": null,
                    "excluded": false,
                    "exclusion_reason": null,
                    "is_enriched": true
                },
                ...
            ]
        }

        Args:
            db_service: DatabaseService class reference
            engagement_id: Target engagement ID
            import_data: Context export data from embedded dashboard
            import_by: Username importing the data (for audit trail)

        Returns:
            Dict with import results
        """
        # Validate import data structure
        if import_data.get('export_type') != 'caip_context_enrichment':
            return {
                'success': False,
                'error': 'Invalid export type. Expected caip_context_enrichment'
            }

        context_items = import_data.get('context_data', [])
        if not context_items:
            return {
                'success': False,
                'error': 'No context data found in import file'
            }

        imported = 0
        skipped = 0
        errors = []

        for item in context_items:
            # Only import items marked as enriched
            if not item.get('is_enriched'):
                skipped += 1
                continue

            try:
                ctx = item.get('context', {})

                cls.upsert_context(
                    db_service,
                    engagement_id=engagement_id,
                    asset_id=item.get('asset_id'),
                    asset_type=item.get('asset_type', 'unknown'),
                    asset_name=item.get('asset_name'),
                    source=item.get('source'),
                    business_unit=ctx.get('business_unit'),
                    business_function=ctx.get('business_function'),
                    data_classification=ctx.get('data_classification'),
                    dependencies=ctx.get('dependencies'),
                    compliance_scope=ctx.get('compliance_scope'),
                    migration_path=ctx.get('migration_path'),
                    owner=ctx.get('owner'),
                    notes=ctx.get('notes'),
                    override_enabled=item.get('override_enabled'),
                    override_score=item.get('override_score'),
                    override_phase=item.get('override_phase'),
                    override_reason=item.get('override_reason'),
                    excluded=item.get('excluded'),
                    exclusion_reason=item.get('exclusion_reason'),
                    changed_by=import_by or 'import_system'
                )
                imported += 1
            except Exception as e:
                errors.append(f"Error importing {item.get('asset_id')}: {str(e)}")

        return {
            'success': True,
            'engagement_id': engagement_id,
            'total_items': len(context_items),
            'imported': imported,
            'skipped': skipped,
            'errors': errors if errors else None
        }

    # =========================================================================
    # ENRICHMENT MERGING (Manual Override > Inferred Priority)
    # =========================================================================

    @classmethod
    def get_merged_enrichment(cls,
                             db_service,
                             asset_id: str,
                             engagement_id: str = None) -> Dict[str, Any]:
        """
        Get enrichment data with priority: manual override > inferred > None

        Merges manual overrides from asset_context with inferred data from
        certificates_inventory.normalised_data, returning authoritative values.

        Args:
            db_service: DatabaseService class reference
            asset_id: Certificate fingerprint or asset ID
            engagement_id: Optional engagement ID (for engagement-specific context)

        Returns:
            Dict with merged enrichment data including:
            - All 19 extracted_* fields
            - *_source suffix ('manual', 'inferred', or 'none')
            - *_confidence suffix (1.0 for manual, <1.0 for inferred, 0.0 for none)
        """
        EXTRACTED_FIELDS = [
            'extracted_service_name', 'extracted_organization', 'extracted_cloud_provider',
            'extracted_region', 'extracted_service_tier', 'extracted_domain_type',
            'extracted_primary_purpose', 'extracted_ca_tier', 'extracted_issuing_organization',
            'extracted_criticality_tier', 'extracted_data_residency',
            'extracted_crypto_strength', 'extracted_pqc_migration_needed',
            'extracted_key_algorithm', 'extracted_key_size',
            'extracted_ha_enabled', 'extracted_replication_count',
            'extracted_san_base_name', 'extracted_is_replicated'
        ]

        try:
            with db_service.get_connection_context() as conn:
                c = conn.cursor()

                # Fetch manual overrides from asset_context
                if engagement_id:
                    c.execute('''SELECT {} FROM asset_context
                                 WHERE asset_id = ? AND engagement_id = ?'''.format(
                        ', '.join(EXTRACTED_FIELDS)),
                             (asset_id, engagement_id))
                else:
                    c.execute('''SELECT {} FROM asset_context
                                 WHERE asset_id = ?
                                 ORDER BY engagement_id DESC LIMIT 1'''.format(
                        ', '.join(EXTRACTED_FIELDS)),
                             (asset_id,))

                manual_row = c.fetchone()
                manual_context = dict(zip(EXTRACTED_FIELDS, manual_row)) if manual_row else {}

                # Fetch inferred data from certificates_inventory
                c.execute('''SELECT normalised_data FROM certificates_inventory
                             WHERE fingerprint_sha256 = ? OR subject_cn = ?
                             LIMIT 1''', (asset_id, asset_id))

                cert_row = c.fetchone()
                inferred_data = {}
                if cert_row and cert_row[0]:
                    try:
                        inferred_data = json.loads(cert_row[0])
                    except (json.JSONDecodeError, TypeError):
                        inferred_data = {}

                # Merge with priority: manual > inferred > none
                merged = {}
                for field in EXTRACTED_FIELDS:
                    manual_value = manual_context.get(field)
                    inferred_value = inferred_data.get(field)

                    if manual_value is not None:
                        merged[field] = manual_value
                        merged[f'{field}_source'] = 'manual'
                        merged[f'{field}_confidence'] = 1.0
                    elif inferred_value is not None:
                        merged[field] = inferred_value
                        merged[f'{field}_source'] = 'inferred'
                        # Use extracted confidence or default to 0.85
                        merged[f'{field}_confidence'] = inferred_data.get('inferred_discovery_confidence', 0.85)
                    else:
                        merged[field] = None
                        merged[f'{field}_source'] = 'none'
                        merged[f'{field}_confidence'] = 0.0

                return merged

        except Exception as e:
            logger.error(f"Error merging enrichment for {asset_id}: {e}")
            return {}

    # =========================================================================
    # STATISTICS AND REPORTING
    # =========================================================================
    
    @classmethod
    def get_context_statistics(cls,
                               db_service,
                               engagement_id: str) -> Dict[str, Any]:
        """
        Get context enrichment statistics for an engagement.
        
        Args:
            db_service: DatabaseService class reference
            engagement_id: Engagement ID
            
        Returns:
            Dict with statistics
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            
            # Total count
            c.execute('''SELECT COUNT(*) FROM asset_context 
                         WHERE engagement_id = ?''', (engagement_id,))
            total = c.fetchone()[0]
            
            # By asset type
            c.execute('''SELECT asset_type, COUNT(*) FROM asset_context 
                         WHERE engagement_id = ? GROUP BY asset_type''',
                     (engagement_id,))
            by_type = {row[0]: row[1] for row in c.fetchall()}
            
            # By business unit
            c.execute('''SELECT business_unit, COUNT(*) FROM asset_context 
                         WHERE engagement_id = ? AND business_unit IS NOT NULL
                         GROUP BY business_unit''',
                     (engagement_id,))
            by_business_unit = {row[0]: row[1] for row in c.fetchall()}
            
            # By business function
            c.execute('''SELECT business_function, COUNT(*) FROM asset_context 
                         WHERE engagement_id = ? AND business_function IS NOT NULL
                         GROUP BY business_function''',
                     (engagement_id,))
            by_business_function = {row[0]: row[1] for row in c.fetchall()}
            
            # By data classification
            c.execute('''SELECT data_classification, COUNT(*) FROM asset_context 
                         WHERE engagement_id = ? AND data_classification IS NOT NULL
                         GROUP BY data_classification''',
                     (engagement_id,))
            by_data_classification = {row[0]: row[1] for row in c.fetchall()}
            
            # By dependencies
            c.execute('''SELECT dependencies, COUNT(*) FROM asset_context 
                         WHERE engagement_id = ? AND dependencies IS NOT NULL
                         GROUP BY dependencies''',
                     (engagement_id,))
            by_dependencies = {row[0]: row[1] for row in c.fetchall()}
            
            # By migration path
            c.execute('''SELECT migration_path, COUNT(*) FROM asset_context 
                         WHERE engagement_id = ? AND migration_path IS NOT NULL
                         GROUP BY migration_path''',
                     (engagement_id,))
            by_migration_path = {row[0]: row[1] for row in c.fetchall()}
            
            return {
                'engagement_id': engagement_id,
                'total_assets_with_context': total,
                'by_asset_type': by_type,
                'by_business_unit': by_business_unit,
                'by_business_function': by_business_function,
                'by_data_classification': by_data_classification,
                'by_dependencies': by_dependencies,
                'by_migration_path': by_migration_path
            }
