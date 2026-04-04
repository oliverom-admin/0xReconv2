"""
Enrichment Service - Business logic for bulk enrichment operations

Handles:
- Querying assets with enrichment data (from inventory + asset_context)
- Filtering and sorting by source, confidence, enrichment status
- Saving bulk enrichment changes with audit trail
- Operation history tracking for future undo capability
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import uuid

logger = logging.getLogger('caip.enrichment')


class EnrichmentService:
    """Service for bulk asset enrichment operations"""

    # Valid field values (match AssetContextService)
    VALID_BUSINESS_UNITS = [
        'IT Operations', 'Security', 'Infrastructure', 'Development',
        'Finance', 'HR', 'Legal', 'Sales', 'Marketing', 'Customer Service',
        'R&D', 'Manufacturing', 'Supply Chain', 'Executive', 'External/Partner', 'Other'
    ]

    VALID_BUSINESS_FUNCTIONS = ['Critical', 'Important', 'Standard', 'Unknown']
    VALID_DATA_CLASSIFICATIONS = ['Restricted', 'Confidential', 'Internal', 'Public']
    VALID_DEPENDENCIES = ['None', 'Low (1-2)', 'Medium (3-5)', 'High (5+)']
    VALID_COMPLIANCE_SCOPES = ['PCI-DSS', 'SOX', 'HIPAA', 'GDPR', 'NIS2', 'DORA', 'CNSA 2.0', 'None']
    VALID_MIGRATION_PATHS = ['Clear', 'Uncertain', 'Blocked']

    # =========================================================================
    # QUERY OPERATIONS
    # =========================================================================

    @staticmethod
    def get_enrichment_list(db_service, engagement_id: str, page: int, limit: int,
                           filters: Dict, sort_by: str) -> Dict[str, Any]:
        """
        Get list of assets with enrichment data (inferred + manual).

        Pulls from:
        - certificates_inventory: inferred metadata (auto-discovered from syncs)
        - asset_context: manual enrichment data (user-provided)

        Filters by:
        - source: Integration name (EJBCA, Azure, etc.)
        - confidence_min/max: Discovery confidence (0.0-1.0)
        - enrichment_status: not_enriched, partial, complete

        Args:
            db_service: DatabaseService class reference
            engagement_id: Engagement ID
            page: Page number (1-indexed)
            limit: Items per page (capped at 500)
            filters: Dict with source, confidence_min, confidence_max, enrichment_status
            sort_by: Sort field (confidence, source, last_seen, or default)

        Returns:
            Dict with assets list and pagination info
        """
        try:
            with db_service.get_connection_context() as conn:
                c = conn.cursor()

                # Build query: certificates_inventory LEFT JOIN asset_context
                query = '''
                    SELECT DISTINCT
                        ci.fingerprint_sha256 as asset_id,
                        ci.connector_id,
                        clm.name as integration_name,
                        ci.normalised_data as cert_data,
                        ci.first_seen_at,
                        ci.last_seen_at,
                        ci.is_active,
                        ac.business_unit,
                        ac.business_function,
                        ac.data_classification,
                        ac.dependencies,
                        ac.compliance_scope,
                        ac.migration_path,
                        ac.owner,
                        ac.override_enabled,
                        ac.excluded,
                        ac.environment_type,
                        ac.service_name,
                        ac.discovery_method,
                        ac.discovery_confidence,
                        ac.extracted_cloud_provider,
                        ac.extracted_region,
                        ac.extracted_service_tier,
                        ac.extracted_domain_type,
                        ac.extracted_primary_purpose,
                        ac.extracted_ca_tier,
                        ac.extracted_issuing_organization,
                        ac.extracted_criticality_tier,
                        ac.extracted_data_residency,
                        ac.extracted_crypto_strength,
                        ac.extracted_pqc_migration_needed,
                        ac.extracted_ha_enabled,
                        ac.extracted_replication_count,
                        ac.extracted_san_base_name,
                        ac.extracted_is_replicated
                    FROM certificates_inventory ci
                    JOIN clm_integrations clm ON ci.connector_id = clm.id
                    LEFT JOIN asset_context ac ON (
                        ac.engagement_id = ? AND
                        ac.asset_id = ci.fingerprint_sha256
                    )
                '''

                params = [engagement_id]

                # Apply filters dynamically
                if filters.get('source'):
                    sources = filters['source'].split(',')
                    placeholders = ','.join(['?' for _ in sources])
                    query += f' AND clm.name IN ({placeholders})'
                    params.extend(sources)

                if filters.get('confidence_min') is not None:
                    query += ' AND (COALESCE(ac.discovery_confidence, 0) >= ?)'
                    params.append(filters['confidence_min'])

                if filters.get('confidence_max') is not None:
                    query += ' AND (COALESCE(ac.discovery_confidence, 1) <= ?)'
                    params.append(filters['confidence_max'])

                # Filter by enrichment status
                if filters.get('enrichment_status') == 'not_enriched':
                    query += ' AND ac.id IS NULL'
                elif filters.get('enrichment_status') == 'partial':
                    query += ' AND ac.id IS NOT NULL AND (ac.owner IS NULL OR ac.business_function IS NULL)'
                elif filters.get('enrichment_status') == 'complete':
                    query += ' AND ac.id IS NOT NULL AND ac.owner IS NOT NULL AND ac.business_function IS NOT NULL'

                # Add sort clause
                if sort_by == 'confidence':
                    query += ' ORDER BY COALESCE(ac.discovery_confidence, 0) DESC, ci.last_seen_at DESC'
                elif sort_by == 'source':
                    query += ' ORDER BY clm.name ASC, ci.last_seen_at DESC'
                elif sort_by == 'last_seen':
                    query += ' ORDER BY ci.last_seen_at DESC'
                else:
                    query += ' ORDER BY COALESCE(ac.discovery_confidence, 0) DESC, ci.last_seen_at DESC'

                # Get total count
                count_query = f'SELECT COUNT(*) as total FROM ({query})'
                c.execute(count_query, params)
                total = c.fetchone()['total']

                # Add pagination
                offset = (page - 1) * limit
                query += ' LIMIT ? OFFSET ?'
                params.extend([limit, offset])

                # Execute paginated query
                c.execute(query, params)
                rows = c.fetchall()

                # Format results into API response structure
                assets = []
                for row in rows:
                    # Parse inferred metadata from inventory JSON
                    try:
                        cert_data = json.loads(row['cert_data']) if row['cert_data'] else {}
                    except Exception:
                        cert_data = {}

                    # Calculate enrichment status based on what's filled
                    manual_fields = [
                        row['business_unit'],
                        row['business_function'],
                        row['data_classification'],
                        row['owner']
                    ]
                    manual_complete = all(f is not None for f in manual_fields)
                    manual_partial = any(f is not None for f in manual_fields)

                    inferred_confidence = row['discovery_confidence'] or 0
                    inferred_complete = inferred_confidence > 0.7

                    if manual_complete and inferred_complete:
                        enrichment_status = 'complete'
                    elif manual_partial or inferred_complete:
                        enrichment_status = 'partial'
                    else:
                        enrichment_status = 'not_enriched'

                    # Calculate completeness percentage (0.0-1.0)
                    total_fields = 12
                    filled_count = 0
                    for field in [row['environment_type'], row['service_name'], row['business_unit'],
                                 row['business_function'], row['data_classification'], row['owner'],
                                 row['compliance_scope'], row['migration_path']]:
                        if field:
                            filled_count += 1

                    completeness = round(filled_count / total_fields, 2)

                    # Build asset response object
                    assets.append({
                        'asset_id': row['asset_id'],
                        'connector_id': row['connector_id'],
                        'integration_name': row['integration_name'],
                        'inferred': {
                            'environment_type': row['environment_type'],
                            'service_name': row['service_name'],
                            'application_name': cert_data.get('application_name'),
                            'discovery_method': row['discovery_method'],
                            'discovery_confidence': row['discovery_confidence'] or 0,
                            'last_inferred_at': row['last_seen_at']
                        },
                        'inventory': {
                            'first_seen_at': row['first_seen_at'],
                            'last_seen_at': row['last_seen_at'],
                            'is_active': bool(row['is_active']),
                            'sync_source': row['integration_name']
                        },
                        'manual': {
                            'business_unit': row['business_unit'],
                            'business_function': row['business_function'],
                            'data_classification': row['data_classification'],
                            'dependencies': row['dependencies'],
                            'compliance_scope': row['compliance_scope'].split(',') if row['compliance_scope'] else [],
                            'migration_path': row['migration_path'],
                            'owner': row['owner'],
                            'override_enabled': bool(row['override_enabled']),
                            'excluded': bool(row['excluded'])
                        },
                        'extracted': {
                            'cloud_provider': row['extracted_cloud_provider'] or cert_data.get('extracted_cloud_provider'),
                            'region': row['extracted_region'] or cert_data.get('extracted_region'),
                            'service_tier': row['extracted_service_tier'] or cert_data.get('extracted_service_tier'),
                            'domain_type': row['extracted_domain_type'] or cert_data.get('extracted_domain_type'),
                            'primary_purpose': row['extracted_primary_purpose'] or cert_data.get('extracted_primary_purpose'),
                            'ca_tier': row['extracted_ca_tier'] or cert_data.get('extracted_ca_tier'),
                            'issuing_organization': row['extracted_issuing_organization'] or cert_data.get('extracted_issuing_organization'),
                            'criticality_tier': row['extracted_criticality_tier'] or cert_data.get('extracted_criticality_tier'),
                            'data_residency': row['extracted_data_residency'] or cert_data.get('extracted_data_residency'),
                            'crypto_strength': row['extracted_crypto_strength'] or cert_data.get('extracted_crypto_strength'),
                            'pqc_migration_needed': row['extracted_pqc_migration_needed'] if row['extracted_pqc_migration_needed'] is not None else cert_data.get('extracted_pqc_migration_needed'),
                            'ha_enabled': row['extracted_ha_enabled'] if row['extracted_ha_enabled'] is not None else cert_data.get('extracted_ha_enabled'),
                            'replication_count': row['extracted_replication_count'] if row['extracted_replication_count'] is not None else cert_data.get('extracted_replication_count'),
                            'san_base_name': row['extracted_san_base_name'] or cert_data.get('extracted_san_base_name'),
                            'is_replicated': row['extracted_is_replicated'] if row['extracted_is_replicated'] is not None else cert_data.get('extracted_is_replicated')
                        },
                        'enrichment_status': enrichment_status,
                        'enrichment_completeness': completeness
                    })

                return {
                    'assets': assets,
                    'pagination': {
                        'total': total,
                        'page': page,
                        'pages': (total + limit - 1) // limit,
                        'per_page': limit
                    }
                }

        except Exception as e:
            logger.error(f"Error in get_enrichment_list: {e}")
            raise


    # =========================================================================
    # SAVE OPERATIONS (with audit trail)
    # =========================================================================

    @staticmethod
    def save_enrichment(db_service, engagement_id: str, operations: List[Dict],
                       changed_by: str) -> Dict[str, Any]:
        """
        Save bulk enrichment changes to asset_context with audit trail.

        Validates all data before saving:
        - Enum fields checked against VALID_* lists
        - compliance_scope converted from list to comma-separated string
        - Warnings collected instead of throwing (fail-open approach)
        - Operation ID generated for audit trail tracking

        Args:
            db_service: DatabaseService class reference
            engagement_id: Engagement ID
            operations: List of {asset_id, updates} dicts
            changed_by: Username making changes (for audit trail)

        Returns:
            Dict with success, updated_count, assets_updated, operation_id, warnings
        """
        try:
            with db_service.get_connection_context() as conn:
                c = conn.cursor()

                # Generate operation ID for audit trail: op-YYYYMMDD-HHMMSS-RANDOMHEX
                operation_id = f"op-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
                timestamp = datetime.now(timezone.utc).isoformat()
                updated_assets = []
                validation_warnings = []

                # Process each enrichment update
                for op in operations:
                    asset_id = op.get('asset_id')
                    updates = op.get('updates', {})

                    if not asset_id:
                        logger.warning(f"Operation missing asset_id: {op}")
                        continue

                    # Validate enum fields (collect warnings, don't fail)
                    for field, value in updates.items():
                        if value is None:
                            continue

                        # Check enum fields against valid lists
                        if field == 'business_unit' and value not in EnrichmentService.VALID_BUSINESS_UNITS:
                            validation_warnings.append({
                                'asset_id': asset_id,
                                'field': field,
                                'warning': f'Invalid business_unit: {value}'
                            })
                            continue

                        if field == 'business_function' and value not in EnrichmentService.VALID_BUSINESS_FUNCTIONS:
                            validation_warnings.append({
                                'asset_id': asset_id,
                                'field': field,
                                'warning': f'Invalid business_function: {value}'
                            })
                            continue

                        if field == 'data_classification' and value not in EnrichmentService.VALID_DATA_CLASSIFICATIONS:
                            validation_warnings.append({
                                'asset_id': asset_id,
                                'field': field,
                                'warning': f'Invalid data_classification: {value}'
                            })
                            continue

                    # Upsert into asset_context using ON CONFLICT pattern
                    try:
                        # Convert compliance_scope list to comma-separated string if needed
                        compliance_str = None
                        if 'compliance_scope' in updates and updates['compliance_scope']:
                            if isinstance(updates['compliance_scope'], list):
                                compliance_str = ','.join(updates['compliance_scope'])
                            else:
                                compliance_str = updates['compliance_scope']

                        # Upsert using ON CONFLICT DO UPDATE pattern (matches existing code)
                        c.execute('''
                            INSERT INTO asset_context (
                                engagement_id, asset_id, asset_type,
                                business_unit, business_function, data_classification,
                                dependencies, compliance_scope, migration_path, owner,
                                extracted_cloud_provider, extracted_region, extracted_service_tier,
                                extracted_domain_type, extracted_primary_purpose, extracted_ca_tier,
                                extracted_issuing_organization, extracted_criticality_tier,
                                extracted_data_residency, extracted_crypto_strength,
                                extracted_pqc_migration_needed, extracted_ha_enabled,
                                extracted_replication_count, extracted_san_base_name, extracted_is_replicated,
                                last_modified_by, last_modified_at, updated_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                            ON CONFLICT(engagement_id, asset_id) DO UPDATE SET
                                business_unit = COALESCE(excluded.business_unit, business_unit),
                                business_function = COALESCE(excluded.business_function, business_function),
                                data_classification = COALESCE(excluded.data_classification, data_classification),
                                dependencies = COALESCE(excluded.dependencies, dependencies),
                                compliance_scope = COALESCE(excluded.compliance_scope, compliance_scope),
                                migration_path = COALESCE(excluded.migration_path, migration_path),
                                owner = COALESCE(excluded.owner, owner),
                                extracted_cloud_provider = COALESCE(excluded.extracted_cloud_provider, extracted_cloud_provider),
                                extracted_region = COALESCE(excluded.extracted_region, extracted_region),
                                extracted_service_tier = COALESCE(excluded.extracted_service_tier, extracted_service_tier),
                                extracted_domain_type = COALESCE(excluded.extracted_domain_type, extracted_domain_type),
                                extracted_primary_purpose = COALESCE(excluded.extracted_primary_purpose, extracted_primary_purpose),
                                extracted_ca_tier = COALESCE(excluded.extracted_ca_tier, extracted_ca_tier),
                                extracted_issuing_organization = COALESCE(excluded.extracted_issuing_organization, extracted_issuing_organization),
                                extracted_criticality_tier = COALESCE(excluded.extracted_criticality_tier, extracted_criticality_tier),
                                extracted_data_residency = COALESCE(excluded.extracted_data_residency, extracted_data_residency),
                                extracted_crypto_strength = COALESCE(excluded.extracted_crypto_strength, extracted_crypto_strength),
                                extracted_pqc_migration_needed = COALESCE(excluded.extracted_pqc_migration_needed, extracted_pqc_migration_needed),
                                extracted_ha_enabled = COALESCE(excluded.extracted_ha_enabled, extracted_ha_enabled),
                                extracted_replication_count = COALESCE(excluded.extracted_replication_count, extracted_replication_count),
                                extracted_san_base_name = COALESCE(excluded.extracted_san_base_name, extracted_san_base_name),
                                extracted_is_replicated = COALESCE(excluded.extracted_is_replicated, extracted_is_replicated),
                                last_modified_by = excluded.last_modified_by,
                                last_modified_at = excluded.last_modified_at,
                                updated_at = CURRENT_TIMESTAMP
                        ''', (
                            engagement_id,
                            asset_id,
                            'certificate',
                            updates.get('business_unit'),
                            updates.get('business_function'),
                            updates.get('data_classification'),
                            updates.get('dependencies'),
                            compliance_str,
                            updates.get('migration_path'),
                            updates.get('owner'),
                            updates.get('extracted_cloud_provider'),
                            updates.get('extracted_region'),
                            updates.get('extracted_service_tier'),
                            updates.get('extracted_domain_type'),
                            updates.get('extracted_primary_purpose'),
                            updates.get('extracted_ca_tier'),
                            updates.get('extracted_issuing_organization'),
                            updates.get('extracted_criticality_tier'),
                            updates.get('extracted_data_residency'),
                            updates.get('extracted_crypto_strength'),
                            updates.get('extracted_pqc_migration_needed'),
                            updates.get('extracted_ha_enabled'),
                            updates.get('extracted_replication_count'),
                            updates.get('extracted_san_base_name'),
                            updates.get('extracted_is_replicated'),
                            changed_by,
                            timestamp
                        ))

                        updated_assets.append(asset_id)

                    except Exception as e:
                        logger.error(f"Error saving asset {asset_id}: {e}")
                        validation_warnings.append({
                            'asset_id': asset_id,
                            'error': str(e)
                        })

                # Record operation to enrichment_operations table for audit trail
                try:
                    c.execute('''
                        INSERT INTO enrichment_operations (
                            operation_id, engagement_id, operation_type,
                            affected_count, asset_ids, changed_by, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        operation_id,
                        engagement_id,
                        'bulk_save',
                        len(updated_assets),
                        json.dumps(updated_assets),
                        changed_by,
                        timestamp
                    ))
                except Exception as e:
                    logger.warning(f"Failed to record enrichment operation: {e}")
                    # Don't fail the whole operation if audit trail fails

                conn.commit()

                return {
                    'success': True,
                    'updated_count': len(updated_assets),
                    'assets_updated': updated_assets,
                    'operation_id': operation_id,
                    'timestamp': timestamp,
                    'validation_warnings': validation_warnings if validation_warnings else None
                }

        except Exception as e:
            logger.error(f"Error in save_enrichment: {e}")
            raise


    # =========================================================================
    # UNDO OPERATIONS (Phase 1.1 - deferred)
    # =========================================================================

    @staticmethod
    def undo_operation(db_service, engagement_id: str, operation_id: str,
                      reverted_by: str) -> Dict[str, Any]:
        """
        Undo a previous bulk enrichment operation.

        DEFERRED to Phase 1.1 (v1.1 release).

        Args:
            db_service: DatabaseService class reference
            engagement_id: Engagement ID
            operation_id: Operation ID to revert
            reverted_by: Username reverting the operation

        Returns:
            Dict indicating deferred status
        """
        return {
            'success': False,
            'message': 'Undo functionality deferred to Phase 1.1 (v1.1 release)'
        }

    @staticmethod
    def get_operation_history(db_service, engagement_id: str, limit: int) -> List[Dict]:
        """
        Get history of bulk enrichment operations for undo capability.

        DEFERRED to Phase 1.1 (v1.1 release).

        Args:
            db_service: DatabaseService class reference
            engagement_id: Engagement ID
            limit: Max results to return

        Returns:
            Empty list (deferred implementation)
        """
        return []
