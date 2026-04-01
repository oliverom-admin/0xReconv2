# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: caip_service_layer/inventory_service.py
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
Inventory Service Layer for CAIP Continuous Monitoring

Manages the persistent inventory of certificates and keys from configured connectors.
This service provides:
- Background synchronisation of connector data to local inventory
- Fast queries against cached inventory data
- Change detection (added/updated/removed assets)
- Sync status tracking per connector

Architecture:
    Dashboard (Manage Tab)
           │
           ▼
    InventoryService.get_certificates()  ──▶  Returns from inventory DB (fast)
    InventoryService.get_keys()          ──▶  Returns from inventory DB (fast)
           │
           │ Background sync populates inventory
           ▼
    InventoryService.sync_connector()    ──▶  Calls ConnectorService
                                         ──▶  Normalises via KeyNormalisationService
                                         ──▶  Updates inventory tables

Usage:
    # Get certificates (fast, from cache)
    certs = InventoryService.get_certificates()
    
    # Get certificates for specific connector
    certs = InventoryService.get_certificates(connector_id=5)
    
    # Sync a connector (called by scheduler or manually)
    result = InventoryService.sync_connector(connector_id=5)
    
    # Get sync status
    status = InventoryService.get_sync_status()
"""

import json
import logging
import traceback
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger('caip.inventory')


class ChangeType(Enum):
    """Types of inventory changes"""
    ADDED = 'added'
    UPDATED = 'updated'
    REMOVED = 'removed'
    REAPPEARED = 'reappeared'
    UNCHANGED = 'unchanged'


@dataclass
class SyncResult:
    """Result of a connector sync operation"""
    connector_id: int
    connector_name: str
    success: bool
    started_at: str
    completed_at: str
    duration_seconds: float
    certificates_total: int = 0
    certificates_added: int = 0
    certificates_updated: int = 0
    certificates_removed: int = 0
    keys_total: int = 0
    keys_added: int = 0
    keys_updated: int = 0
    keys_removed: int = 0
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class InventoryService:
    """
    Manages the persistent inventory of certificates and keys.
    
    Provides:
    - Sync operations (fetch from connectors, update inventory)
    - Query operations (get certificates/keys with filtering)
    - Change detection (what's new/modified/removed)
    - Sync status tracking
    """
    
    # =========================================================================
    # SYNC OPERATIONS
    # =========================================================================
    
    @classmethod
    def sync_connector(cls, connector_id: int, force: bool = False) -> SyncResult:
        """
        Synchronise inventory for a single connector.

        Delegates to InventoryOrchestrator which executes the 6-phase pipeline:
        1. Load & Validate - Fetch connector config and validate
        2. Collect - Use registry pattern to dispatch to appropriate collector
        3. Normalize - Standardize assets to unified format
        4. Enrich - Add source type and environment metadata
        5. Detect & Store - Store assets and track statistics
        6. Update Status - Generate SyncResult with metrics

        Args:
            connector_id: ID of the connector to sync
            force: If True, sync even if not due yet (passed for compatibility)

        Returns:
            SyncResult with statistics and status
        """
        from caip_service_layer.inventory_orchestrator import InventoryOrchestrator

        logger.info(f"Starting inventory sync for connector {connector_id}")

        try:
            # Delegate to InventoryOrchestrator for the 6-phase pipeline
            orchestrator = InventoryOrchestrator()
            result = orchestrator.execute(connector_id)

            return result

        except Exception as e:
            # Graceful error handling - return failure result
            from database_service import DatabaseService

            connector = DatabaseService.get_clm_integration(connector_id)
            connector_name = connector['name'] if connector else 'Unknown'
            started_at = datetime.now(timezone.utc)

            error_msg = str(e)
            logger.error(f"Sync failed for connector {connector_id} ({connector_name}): {error_msg}")
            logger.error(traceback.format_exc())

            result = SyncResult(
                connector_id=connector_id,
                connector_name=connector_name,
                success=False,
                started_at=started_at.isoformat(),
                completed_at=datetime.now(timezone.utc).isoformat(),
                duration_seconds=0,
                error_message=error_msg
            )

            return result
    
    @classmethod
    def sync_all_connectors(cls, only_enabled: bool = True) -> Dict[int, SyncResult]:
        """
        Sync all connectors (or only enabled ones).
        
        Args:
            only_enabled: If True, only sync enabled connectors
            
        Returns:
            Dictionary mapping connector_id to SyncResult
        """
        from database_service import DatabaseService
        
        if only_enabled:
            connectors = DatabaseService.list_enabled_clm_integrations()
        else:
            # Get all connectors
            conn = DatabaseService.get_connection()
            c = conn.cursor()
            c.execute('SELECT * FROM clm_integrations')
            connectors = [DatabaseService.dict_from_row(row) for row in c.fetchall()]
            conn.close()
        
        results = {}
        for connector in connectors:
            connector_id = connector['id']
            results[connector_id] = cls.sync_connector(connector_id)
        
        return results
    
    # =========================================================================
    # QUERY OPERATIONS
    # =========================================================================
    
    @classmethod
    def get_certificates(cls, 
                         connector_id: int = None,
                         include_inactive: bool = False,
                         expiring_within_days: int = None,
                         limit: int = None) -> List[Dict[str, Any]]:
        """
        Get certificates from inventory.
        
        Args:
            connector_id: Filter by specific connector (None = all)
            include_inactive: Include certificates no longer seen in source
            expiring_within_days: Filter to certs expiring within N days
            limit: Maximum number of results
            
        Returns:
            List of normalised certificate dictionaries
        """
        from database_service import DatabaseService
        
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        
        query = 'SELECT * FROM certificates_inventory WHERE 1=1'
        params = []
        
        if connector_id is not None:
            query += ' AND connector_id = ?'
            params.append(connector_id)
        
        if not include_inactive:
            query += ' AND is_active = 1'
        
        if expiring_within_days is not None:
            query += ' AND days_until_expiry <= ? AND days_until_expiry >= 0'
            params.append(expiring_within_days)
        
        query += ' ORDER BY days_until_expiry ASC'
        
        if limit:
            query += ' LIMIT ?'
            params.append(limit)
        
        c.execute(query, params)
        rows = c.fetchall()
        conn.close()
        
        certificates = []
        for row in rows:
            cert_dict = DatabaseService.dict_from_row(row)
            # Parse the normalised_data JSON
            if cert_dict.get('normalised_data'):
                try:
                    normalised = json.loads(cert_dict['normalised_data'])
                    # Merge inventory metadata with normalised data
                    normalised['_inventory_id'] = cert_dict['id']
                    normalised['_connector_id'] = cert_dict['connector_id']
                    normalised['_first_seen_at'] = cert_dict['first_seen_at']
                    normalised['_last_seen_at'] = cert_dict['last_seen_at']
                    normalised['_is_active'] = cert_dict['is_active']
                    certificates.append(normalised)
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse normalised_data for cert inventory {cert_dict['id']}")
        
        return certificates
    
    @classmethod
    def get_keys(cls,
                 connector_id: int = None,
                 include_inactive: bool = False,
                 expiring_within_days: int = None,
                 limit: int = None) -> List[Dict[str, Any]]:
        """
        Get keys from inventory.
        
        Args:
            connector_id: Filter by specific connector (None = all)
            include_inactive: Include keys no longer seen in source
            expiring_within_days: Filter to keys expiring within N days
            limit: Maximum number of results
            
        Returns:
            List of normalised key dictionaries
        """
        from database_service import DatabaseService
        
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        
        query = 'SELECT * FROM keys_inventory WHERE 1=1'
        params = []
        
        if connector_id is not None:
            query += ' AND connector_id = ?'
            params.append(connector_id)
        
        if not include_inactive:
            query += ' AND is_active = 1'
        
        if expiring_within_days is not None:
            query += ' AND days_until_expiry <= ? AND days_until_expiry >= 0'
            params.append(expiring_within_days)
        
        query += ' ORDER BY key_name ASC'
        
        if limit:
            query += ' LIMIT ?'
            params.append(limit)
        
        c.execute(query, params)
        rows = c.fetchall()
        conn.close()
        
        keys = []
        for row in rows:
            key_dict = DatabaseService.dict_from_row(row)
            # Parse the normalised_data JSON
            if key_dict.get('normalised_data'):
                try:
                    normalised = json.loads(key_dict['normalised_data'])
                    # Merge inventory metadata with normalised data
                    normalised['_inventory_id'] = key_dict['id']
                    normalised['_connector_id'] = key_dict['connector_id']
                    normalised['_first_seen_at'] = key_dict['first_seen_at']
                    normalised['_last_seen_at'] = key_dict['last_seen_at']
                    normalised['_is_active'] = key_dict['is_active']
                    keys.append(normalised)
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse normalised_data for key inventory {key_dict['id']}")
        
        return keys
    
    @classmethod
    def get_inventory_summary(cls, include_inactive: bool = False) -> Dict[str, Any]:
        """
        Get summary statistics for the entire inventory.

        Args:
            include_inactive: Include inactive assets in summary (default: False)

        Returns:
            Dictionary with counts, expiry buckets, and per-connector breakdown
        """
        from database_service import DatabaseService

        conn = DatabaseService.get_connection()
        c = conn.cursor()

        # Build WHERE clause based on include_inactive parameter
        active_filter = '' if include_inactive else 'AND is_active = 1'

        # Total counts (only from enabled connectors)
        c.execute(f'''SELECT COUNT(*) FROM certificates_inventory
                     WHERE connector_id IN (SELECT id FROM clm_integrations WHERE enabled = 1)
                     {active_filter}''')
        total_certs = c.fetchone()[0]

        c.execute(f'''SELECT COUNT(*) FROM keys_inventory
                     WHERE connector_id IN (SELECT id FROM clm_integrations WHERE enabled = 1)
                     {active_filter}''')
        total_keys = c.fetchone()[0]

        # Expiry buckets for certificates (only from enabled connectors)
        c.execute(f'''SELECT
            SUM(CASE WHEN days_until_expiry < 0 THEN 1 ELSE 0 END) as expired,
            SUM(CASE WHEN days_until_expiry >= 0 AND days_until_expiry <= 7 THEN 1 ELSE 0 END) as expiring_7_days,
            SUM(CASE WHEN days_until_expiry > 7 AND days_until_expiry <= 30 THEN 1 ELSE 0 END) as expiring_30_days,
            SUM(CASE WHEN days_until_expiry > 30 AND days_until_expiry <= 90 THEN 1 ELSE 0 END) as expiring_90_days,
            SUM(CASE WHEN days_until_expiry > 90 THEN 1 ELSE 0 END) as valid
        FROM certificates_inventory
        WHERE connector_id IN (SELECT id FROM clm_integrations WHERE enabled = 1)
        {active_filter}''')
        expiry_row = c.fetchone()

        # Per-connector breakdown (only enabled connectors)
        c.execute(f'''SELECT
            ci.connector_id,
            cli.name as connector_name,
            cli.type as connector_type,
            COUNT(*) as certificate_count
        FROM certificates_inventory ci
        JOIN clm_integrations cli ON ci.connector_id = cli.id
        WHERE cli.enabled = 1
        {active_filter}
        GROUP BY ci.connector_id''')
        cert_by_connector = [DatabaseService.dict_from_row(row) for row in c.fetchall()]

        c.execute(f'''SELECT
            ki.connector_id,
            cli.name as connector_name,
            cli.type as connector_type,
            COUNT(*) as key_count
        FROM keys_inventory ki
        JOIN clm_integrations cli ON ki.connector_id = cli.id
        WHERE cli.enabled = 1
        {active_filter}
        GROUP BY ki.connector_id''')
        keys_by_connector = [DatabaseService.dict_from_row(row) for row in c.fetchall()]

        conn.close()

        return {
            'total_certificates': total_certs,
            'total_keys': total_keys,
            'certificate_expiry': {
                'expired': expiry_row[0] or 0,
                'expiring_7_days': expiry_row[1] or 0,
                'expiring_30_days': expiry_row[2] or 0,
                'expiring_90_days': expiry_row[3] or 0,
                'valid': expiry_row[4] or 0
            },
            'certificates_by_connector': cert_by_connector,
            'keys_by_connector': keys_by_connector
        }
    
    @classmethod
    def get_sync_status(cls, connector_id: int = None) -> Dict[str, Any]:
        """
        Get sync status for connector(s).
        
        Args:
            connector_id: Specific connector ID, or None for all
            
        Returns:
            Sync status dictionary (single or list)
        """
        from database_service import DatabaseService
        
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        
        if connector_id is not None:
            c.execute('''SELECT css.*, cli.name as connector_name, cli.type as connector_type
                        FROM connector_sync_status css
                        JOIN clm_integrations cli ON css.connector_id = cli.id
                        WHERE css.connector_id = ?''', (connector_id,))
            row = c.fetchone()
            conn.close()
            return DatabaseService.dict_from_row(row) if row else None
        else:
            c.execute('''SELECT css.*, cli.name as connector_name, cli.type as connector_type, cli.enabled,
                        (SELECT COUNT(*) FROM certificates_inventory ci WHERE ci.connector_id = css.connector_id AND ci.is_active = 1) as certificates_total,
                        (SELECT COUNT(*) FROM keys_inventory ki WHERE ki.connector_id = css.connector_id AND ki.is_active = 1) as keys_total
                        FROM connector_sync_status css
                        JOIN clm_integrations cli ON css.connector_id = cli.id
                        ORDER BY cli.name''')
            rows = c.fetchall()
            sync_statuses = [DatabaseService.dict_from_row(row) for row in rows]

            # Also add promoted scans integration with calculated totals
            c.execute('''SELECT id, name, type, enabled FROM clm_integrations WHERE type = 'promoted' ''')
            promoted_rows = c.fetchall()
            for promo_row in promoted_rows:
                promo_id = promo_row[0]
                promo_name = promo_row[1]
                promo_enabled = promo_row[3]

                # Calculate totals for promoted scans
                c.execute('SELECT COUNT(*) FROM certificates_inventory WHERE connector_id = ? AND is_active = 1',
                         (promo_id,))
                promo_certs = c.fetchone()[0] or 0

                c.execute('SELECT COUNT(*) FROM keys_inventory WHERE connector_id = ? AND is_active = 1',
                         (promo_id,))
                promo_keys = c.fetchone()[0] or 0

                sync_statuses.append({
                    'connector_id': promo_id,
                    'connector_name': promo_name,
                    'connector_type': 'promoted',
                    'enabled': promo_enabled,
                    'certificates_total': promo_certs,
                    'keys_total': promo_keys,
                    'items_total': promo_certs + promo_keys,
                    'last_sync_status': 'success',
                    'last_sync_completed': None
                })

            conn.close()
            return sync_statuses
    
    @classmethod
    def get_recent_changes(cls, 
                           since: datetime = None,
                           connector_id: int = None,
                           entity_type: str = None,
                           limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent inventory changes.
        
        Args:
            since: Only changes after this time
            connector_id: Filter by connector
            entity_type: 'certificate' or 'key'
            limit: Maximum results
            
        Returns:
            List of change records
        """
        from database_service import DatabaseService
        
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        
        query = 'SELECT * FROM inventory_changes WHERE 1=1'
        params = []
        
        if since:
            query += ' AND detected_at >= ?'
            params.append(since.isoformat())
        
        if connector_id:
            query += ' AND connector_id = ?'
            params.append(connector_id)
        
        if entity_type:
            query += ' AND entity_type = ?'
            params.append(entity_type)
        
        query += ' ORDER BY detected_at DESC LIMIT ?'
        params.append(limit)
        
        c.execute(query, params)
        rows = c.fetchall()
        conn.close()
        
        changes = []
        for row in rows:
            change = DatabaseService.dict_from_row(row)
            if change.get('change_details'):
                try:
                    change['change_details'] = json.loads(change['change_details'])
                except json.JSONDecodeError:
                    pass
            changes.append(change)
        
        return changes
    
    # =========================================================================
    # INTERNAL METHODS
    # =========================================================================
    
    @classmethod
    def _update_certificate_inventory(cls, connector_id: int,
                                       normalised_certs: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Update certificate inventory with change detection.

        Returns:
            Statistics dict with added/updated/removed counts
        """
        from database_service import DatabaseService

        stats = {'added': 0, 'updated': 0, 'removed': 0}
        now = datetime.now(timezone.utc).isoformat()

        conn = DatabaseService.get_connection()
        c = conn.cursor()

        # Get connector name for integration_name field
        c.execute('SELECT name FROM clm_integrations WHERE id = ?', (connector_id,))
        connector_row = c.fetchone()
        integration_name = connector_row[0] if connector_row else f'Connector {connector_id}'

        # Get ALL existing certificates for this connector (active AND inactive)
        # This is critical to handle reappeared certificates that were previously marked inactive
        c.execute('''SELECT id, fingerprint_sha256, normalised_data, is_active
                    FROM certificates_inventory
                    WHERE connector_id = ?''', (connector_id,))
        existing = {row[1]: {'id': row[0], 'data': row[2], 'is_active': row[3]} for row in c.fetchall()}
        
        # Track which fingerprints we've seen in this sync
        seen_fingerprints = set()
        
        for cert in normalised_certs:
            fingerprint = cert.get('fingerprint_sha256')
            if not fingerprint:
                logger.warning(f"Certificate missing fingerprint_sha256, skipping")
                continue
            
            seen_fingerprints.add(fingerprint)
            normalised_json = json.dumps(cert, default=str)
            
            # Extract denormalised fields for quick queries
            subject_cn = cert.get('subject_cn', '')
            issuer_cn = cert.get('issuer_cn', '')
            not_after = cert.get('not_after', '')
            days_until_expiry = cert.get('days_until_expiration', 0)
            key_algorithm = cert.get('public_key_algorithm', '')
            key_size = cert.get('public_key_size')
            source_type = cert.get('source_type', '')
            
            if fingerprint in existing:
                existing_record = existing[fingerprint]
                existing_data = existing_record['data']
                was_inactive = not existing_record['is_active']
                
                if was_inactive:
                    # Certificate reappeared - reactivate and update
                    c.execute('''UPDATE certificates_inventory
                                SET normalised_data = ?, last_seen_at = ?, is_active = 1,
                                    subject_cn = ?, issuer_cn = ?, not_after = ?,
                                    days_until_expiry = ?, key_algorithm = ?, key_size = ?,
                                    integration_name = ?
                                WHERE id = ?''',
                              (normalised_json, now, subject_cn, issuer_cn, not_after,
                               days_until_expiry, key_algorithm, key_size,
                               integration_name,
                               existing_record['id']))
                    stats['added'] += 1  # Count as added since it reappeared
                    
                    # Record change as REAPPEARED
                    cls._record_change(c, 'certificate', existing_record['id'],
                                      connector_id, ChangeType.REAPPEARED, 
                                      {'subject_cn': subject_cn})
                elif existing_data != normalised_json:
                    # Update existing active record (data changed)
                    c.execute('''UPDATE certificates_inventory
                                SET normalised_data = ?, last_seen_at = ?,
                                    subject_cn = ?, issuer_cn = ?, not_after = ?,
                                    days_until_expiry = ?, key_algorithm = ?, key_size = ?,
                                    integration_name = ?
                                WHERE id = ?''',
                              (normalised_json, now, subject_cn, issuer_cn, not_after,
                               days_until_expiry, key_algorithm, key_size,
                               integration_name,
                               existing_record['id']))
                    stats['updated'] += 1
                    
                    # Record change
                    cls._record_change(c, 'certificate', existing_record['id'],
                                      connector_id, ChangeType.UPDATED, 
                                      {'previous': existing_data[:500], 'current': normalised_json[:500]})
                else:
                    # Just update last_seen_at (no data change)
                    c.execute('''UPDATE certificates_inventory 
                                SET last_seen_at = ?, days_until_expiry = ?
                                WHERE id = ?''',
                              (now, days_until_expiry, existing_record['id']))
            else:
                # Insert new record
                c.execute('''INSERT INTO certificates_inventory
                            (fingerprint_sha256, connector_id, normalised_data,
                             subject_cn, issuer_cn, not_after, days_until_expiry,
                             key_algorithm, key_size, source_type, integration_name,
                             first_seen_at, last_seen_at, is_active)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)''',
                          (fingerprint, connector_id, normalised_json,
                           subject_cn, issuer_cn, not_after, days_until_expiry,
                           key_algorithm, key_size, source_type, integration_name, now, now))
                stats['added'] += 1
                
                # Record change
                cls._record_change(c, 'certificate', c.lastrowid,
                                  connector_id, ChangeType.ADDED,
                                  {'subject_cn': subject_cn})
        
        # Mark certificates not seen in this sync as inactive (only if currently active)
        for fingerprint, record in existing.items():
            if fingerprint not in seen_fingerprints and record['is_active']:
                c.execute('''UPDATE certificates_inventory 
                            SET is_active = 0 WHERE id = ?''', (record['id'],))
                stats['removed'] += 1
                
                # Record change
                cls._record_change(c, 'certificate', record['id'],
                                  connector_id, ChangeType.REMOVED, {})
        
        conn.commit()
        conn.close()
        
        return stats
    
    @classmethod
    def _update_key_inventory(cls, connector_id: int,
                              normalised_keys: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Update key inventory with change detection.

        Returns:
            Statistics dict with added/updated/removed counts
        """
        from database_service import DatabaseService

        stats = {'added': 0, 'updated': 0, 'removed': 0}
        now = datetime.now(timezone.utc).isoformat()

        conn = DatabaseService.get_connection()
        c = conn.cursor()

        # Get connector name for integration_name field
        c.execute('SELECT name FROM clm_integrations WHERE id = ?', (connector_id,))
        connector_row = c.fetchone()
        integration_name = connector_row[0] if connector_row else f'Connector {connector_id}'

        # Get ALL existing keys for this connector (active AND inactive)
        # This is critical to handle reappeared keys that were previously marked inactive
        c.execute('''SELECT id, key_identifier, normalised_data, is_active
                    FROM keys_inventory
                    WHERE connector_id = ?''', (connector_id,))
        existing = {row[1]: {'id': row[0], 'data': row[2], 'is_active': row[3]} for row in c.fetchall()}
        
        # Track which key identifiers we've seen in this sync
        seen_identifiers = set()
        
        for key in normalised_keys:
            # Use key_id as the primary identifier, with fallbacks
            # Skip 'unknown' values when selecting identifier
            key_id = key.get('key_id')
            name = key.get('name')
            label = key.get('label')
            object_id = key.get('object_id')
            
            # Pick first non-empty, non-'unknown' value
            key_identifier = None
            for candidate in [key_id, name, label, object_id, key.get('id')]:
                if candidate and candidate != 'unknown':
                    key_identifier = candidate
                    break
            
            if not key_identifier:
                logger.warning(f"Key missing identifier, skipping. key_id='{key_id}', name='{name}', label='{label}', object_id='{object_id}'")
                continue
            
            # Skip duplicate keys within the same batch
            if key_identifier in seen_identifiers:
                logger.warning(f"Duplicate key_identifier '{key_identifier}' in batch, skipping")
                continue

            seen_identifiers.add(key_identifier)
            normalised_json = json.dumps(key, default=str)
            
            # Extract denormalised fields for quick queries
            key_name = key.get('name', '')
            key_type = key.get('key_type', '')
            key_size = key.get('key_size')
            source_type = key.get('source_type', '')
            expires_on = key.get('expires_on', '')
            days_until_expiry = key.get('days_until_expiration')
            is_hsm_backed = 1 if key.get('is_hardware_protected') else 0
            
            if key_identifier in existing:
                existing_record = existing[key_identifier]
                existing_data = existing_record['data']
                was_inactive = not existing_record['is_active']
                
                if was_inactive:
                    # Key reappeared - reactivate and update
                    c.execute('''UPDATE keys_inventory
                                SET normalised_data = ?, last_seen_at = ?, is_active = 1,
                                    key_name = ?, key_type = ?, key_size = ?,
                                    expires_on = ?, days_until_expiry = ?, is_hsm_backed = ?,
                                    integration_name = ?
                                WHERE id = ?''',
                              (normalised_json, now, key_name, key_type, key_size,
                               expires_on, days_until_expiry, is_hsm_backed,
                               integration_name,
                               existing_record['id']))
                    stats['added'] += 1  # Count as added since it reappeared
                    
                    # Record change as REAPPEARED
                    cls._record_change(c, 'key', existing_record['id'],
                                      connector_id, ChangeType.REAPPEARED,
                                      {'key_name': key_name})
                elif existing_data != normalised_json:
                    # Update existing active record (data changed)
                    c.execute('''UPDATE keys_inventory
                                SET normalised_data = ?, last_seen_at = ?,
                                    key_name = ?, key_type = ?, key_size = ?,
                                    expires_on = ?, days_until_expiry = ?, is_hsm_backed = ?,
                                    integration_name = ?
                                WHERE id = ?''',
                              (normalised_json, now, key_name, key_type, key_size,
                               expires_on, days_until_expiry, is_hsm_backed,
                               integration_name,
                               existing_record['id']))
                    stats['updated'] += 1
                    
                    # Record change
                    cls._record_change(c, 'key', existing_record['id'],
                                      connector_id, ChangeType.UPDATED,
                                      {'previous': existing_data[:500], 'current': normalised_json[:500]})
                else:
                    # Just update last_seen_at (no data change)
                    c.execute('''UPDATE keys_inventory 
                                SET last_seen_at = ?, days_until_expiry = ?
                                WHERE id = ?''',
                              (now, days_until_expiry, existing_record['id']))
            else:
                # Insert new record
                c.execute('''INSERT INTO keys_inventory
                            (key_identifier, connector_id, normalised_data,
                             key_name, key_type, key_size, source_type, integration_name,
                             expires_on, days_until_expiry, is_hsm_backed,
                             first_seen_at, last_seen_at, is_active)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)''',
                          (key_identifier, connector_id, normalised_json,
                           key_name, key_type, key_size, source_type, integration_name,
                           expires_on, days_until_expiry, is_hsm_backed, now, now))
                stats['added'] += 1
                
                # Record change
                cls._record_change(c, 'key', c.lastrowid,
                                  connector_id, ChangeType.ADDED,
                                  {'key_name': key_name})
        
        # Mark keys not seen in this sync as inactive (only if currently active)
        for key_identifier, record in existing.items():
            if key_identifier not in seen_identifiers and record['is_active']:
                c.execute('''UPDATE keys_inventory 
                            SET is_active = 0 WHERE id = ?''', (record['id'],))
                stats['removed'] += 1
                
                # Record change
                cls._record_change(c, 'key', record['id'],
                                  connector_id, ChangeType.REMOVED, {})
        
        conn.commit()
        conn.close()
        
        return stats
    
    @classmethod
    def _record_change(cls, cursor, entity_type: str, entity_id: int,
                       connector_id: int, change_type: ChangeType,
                       details: Dict[str, Any]):
        """Record a change to the inventory_changes audit log"""
        cursor.execute('''INSERT INTO inventory_changes 
                         (entity_type, entity_id, connector_id, change_type, 
                          change_details, detected_at)
                         VALUES (?, ?, ?, ?, ?, ?)''',
                      (entity_type, entity_id, connector_id, change_type.value,
                       json.dumps(details, default=str),
                       datetime.now(timezone.utc).isoformat()))
    
    @classmethod
    def _update_sync_status(cls, connector_id: int, status: str,
                            started_at: datetime, completed_at: datetime = None,
                            duration: float = None, result: SyncResult = None,
                            error_message: str = None):
        """Update the sync status for a connector"""
        from database_service import DatabaseService
        
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        
        # Check if sync status record exists
        c.execute('SELECT connector_id FROM connector_sync_status WHERE connector_id = ?', 
                  (connector_id,))
        exists = c.fetchone() is not None
        
        if status == 'in_progress':
            if exists:
                c.execute('''UPDATE connector_sync_status 
                            SET last_sync_started = ?, last_sync_status = 'in_progress'
                            WHERE connector_id = ?''',
                          (started_at.isoformat(), connector_id))
            else:
                c.execute('''INSERT INTO connector_sync_status 
                            (connector_id, last_sync_started, last_sync_status)
                            VALUES (?, ?, 'in_progress')''',
                          (connector_id, started_at.isoformat()))
        
        elif status == 'success':
            # Calculate next sync time (default 30 minutes)
            c.execute('SELECT sync_interval_minutes FROM connector_sync_status WHERE connector_id = ?',
                      (connector_id,))
            row = c.fetchone()
            interval = row[0] if row else 30
            
            from datetime import timedelta
            next_sync = (completed_at + timedelta(minutes=interval)).isoformat()
            
            c.execute('''UPDATE connector_sync_status 
                        SET last_sync_completed = ?, last_sync_status = 'success',
                            last_sync_duration_seconds = ?,
                            items_total = ?, items_added = ?, items_updated = ?, items_removed = ?,
                            next_sync_due = ?, consecutive_failures = 0, last_sync_error = NULL
                        WHERE connector_id = ?''',
                      (completed_at.isoformat(), duration,
                       (result.certificates_total + result.keys_total) if result else 0,
                       (result.certificates_added + result.keys_added) if result else 0,
                       (result.certificates_updated + result.keys_updated) if result else 0,
                       (result.certificates_removed + result.keys_removed) if result else 0,
                       next_sync, connector_id))
        
        elif status == 'failed':
            c.execute('''UPDATE connector_sync_status 
                        SET last_sync_completed = ?, last_sync_status = 'failed',
                            last_sync_duration_seconds = ?, last_sync_error = ?,
                            consecutive_failures = consecutive_failures + 1
                        WHERE connector_id = ?''',
                      (completed_at.isoformat() if completed_at else None, 
                       duration, error_message, connector_id))
        
        conn.commit()
        conn.close()
    
    # =========================================================================
    # UTILITY METHODS
    # =========================================================================
    
    @classmethod
    def ensure_sync_status_exists(cls, connector_id: int, interval_minutes: int = 30):
        """
        Ensure a sync status record exists for a connector.
        Called when a connector is created/enabled.
        """
        from database_service import DatabaseService
        
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        
        c.execute('SELECT connector_id FROM connector_sync_status WHERE connector_id = ?',
                  (connector_id,))
        if not c.fetchone():
            c.execute('''INSERT INTO connector_sync_status 
                        (connector_id, sync_interval_minutes, last_sync_status)
                        VALUES (?, ?, 'pending')''',
                      (connector_id, interval_minutes))
            conn.commit()
        
        conn.close()
    
    @classmethod
    def set_sync_interval(cls, connector_id: int, interval_minutes: int):
        """Set the sync interval for a connector"""
        from database_service import DatabaseService
        
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('''UPDATE connector_sync_status 
                    SET sync_interval_minutes = ? WHERE connector_id = ?''',
                  (interval_minutes, connector_id))
        conn.commit()
        conn.close()
    
    @classmethod
    def get_connectors_due_for_sync(cls) -> List[int]:
        """Get list of connector IDs that are due for sync with proper connection handling"""
        from database_service import DatabaseService

        now = datetime.now(timezone.utc).isoformat()
        connector_ids = []

        try:
            # Use context manager for proper connection handling and cleanup
            with DatabaseService.get_connection_context() as conn:
                c = conn.cursor()

                # Get connectors where next_sync_due has passed, or never synced
                c.execute('''SELECT css.connector_id
                            FROM connector_sync_status css
                            JOIN clm_integrations cli ON css.connector_id = cli.id
                            WHERE cli.enabled = 1
                            AND (css.next_sync_due IS NULL OR css.next_sync_due <= ?)
                            AND css.last_sync_status != 'in_progress' ''', (now,))

                connector_ids = [row[0] for row in c.fetchall()]
        except Exception as e:
            logger.error(f"Error getting connectors due for sync: {e}")
            # Return empty list on error instead of crashing
            return []

        return connector_ids

    @classmethod
    def store_environment_metadata_for_certificate(cls, cert_fingerprint: str,
                                                   environment_metadata: Dict[str, Any],
                                                   engagement_id: str = 'default') -> bool:
        """
        Store auto-discovered environment metadata for a certificate.

        Called when TLS scans or other collectors discover environment information.

        Args:
            cert_fingerprint: SHA256 fingerprint of certificate
            environment_metadata: Dict with environment_type, service_name, application_name,
                                discovery_method, discovery_confidence
            engagement_id: Engagement to associate metadata with

        Returns:
            True if metadata was stored/merged, False otherwise
        """
        from database_service import DatabaseService
        from caip_service_layer.asset_context_service import AssetContextService

        try:
            # Use merge logic to preserve manual enrichment
            return AssetContextService.merge_auto_discovered_metadata(
                db_service=DatabaseService,
                engagement_id=engagement_id,
                asset_id=cert_fingerprint,
                asset_type='certificate',
                auto_metadata=environment_metadata
            )
        except Exception as e:
            logger.warning(f"Failed to store environment metadata for certificate {cert_fingerprint}: {e}")
            return False


# Module-level convenience functions
def sync_connector(connector_id: int) -> SyncResult:
    """Convenience function to sync a single connector"""
    return InventoryService.sync_connector(connector_id)


def get_certificates(**kwargs) -> List[Dict[str, Any]]:
    """Convenience function to get certificates"""
    return InventoryService.get_certificates(**kwargs)


def get_keys(**kwargs) -> List[Dict[str, Any]]:
    """Convenience function to get keys"""
    return InventoryService.get_keys(**kwargs)
