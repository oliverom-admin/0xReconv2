"""
Database Service Layer for CAIP

Centralizes all database operations to eliminate code duplication across Flask routes.
Provides standardized methods for:
- Database connection management with proper configuration
- CRUD operations for policies, configurations, scans, integrations
- Scan log management
- Report aggregation and reassessment record management

Previously scattered code locations consolidated here:
- app.py init_db() lines 204-327
- app.py get_db_connection() lines 333-341
- app.py dict_from_row() lines 343-347
- app.py add_scan_log(), increment_scan_run_number() lines 382-420
- Various CRUD operations throughout app.py routes
"""

import sqlite3
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from contextlib import contextmanager
from caip_document_assessment_functions.document_assessment_database import DocumentAssessmentDatabase 

logger = logging.getLogger('caip.operational')


class DatabaseService:
    """
    Centralized database operations service.
    
    Provides standardized methods for:
    - Connection management with WAL mode and timeouts
    - Policy CRUD operations
    - Configuration CRUD operations
    - Scan management and logging
    - CLM integration management
    - Reassessment and aggregation record management
    """
    
    # Default database path - can be overridden
    _database_path: str = 'pki_dashboard.db'
    _connection_timeout: float = 10.0

    @classmethod
    def configure(cls, database_path: str, timeout: float = 10.0):
        """
        Configure the database service.
        
        Args:
            database_path: Path to the SQLite database file
            timeout: Connection timeout in seconds (default 10.0)
        """
        cls._database_path = database_path
        cls._connection_timeout = timeout
        logger.info(f"DatabaseService configured: {database_path}")
    
    # =========================================================================
    # CONNECTION MANAGEMENT
    # =========================================================================
    
    @classmethod
    def get_connection(cls) -> sqlite3.Connection:
        """
        Get database connection with proper configuration.

        Returns:
            sqlite3.Connection with:
            - Row factory enabled for dict-like access
            - Foreign key constraints enabled
            - WAL mode for better concurrency
            - Configured timeout for lock handling
        """
        conn = sqlite3.connect(cls._database_path, timeout=cls._connection_timeout)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn
    
    @classmethod
    @contextmanager
    def get_connection_context(cls):
        """
        Context manager for database connections.
        
        Automatically closes connection when done.
        
        Usage:
            with DatabaseService.get_connection_context() as conn:
                c = conn.cursor()
                c.execute(...)
                conn.commit()
        """
        conn = cls.get_connection()
        try:
            yield conn
        finally:
            conn.close()
    
    @staticmethod
    def dict_from_row(row: sqlite3.Row) -> Optional[Dict[str, Any]]:
        """
        Convert sqlite3.Row to dictionary.
        
        Args:
            row: sqlite3.Row object or None
            
        Returns:
            Dictionary representation or None if row is None
        """
        if row is None:
            return None
        return dict(row)
    
    # =========================================================================
    # DATABASE INITIALIZATION
    # =========================================================================
    
    @classmethod
    def init_db(cls, default_admin_password: str = None):
        """
        Initialize the SQLite database with all required tables.
        
        Creates tables if they don't exist and runs migrations for
        schema updates. Optionally creates default admin user.
        
        Args:
            default_admin_password: Password for default admin user (if creating)
        """
        conn = sqlite3.connect(cls._database_path)
        c = conn.cursor()
        
        # Users table
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT UNIQUE NOT NULL,
                      password TEXT NOT NULL,
                      role TEXT DEFAULT 'scan-user',
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        # Configurations table
        c.execute('''CREATE TABLE IF NOT EXISTS configurations
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name TEXT UNIQUE NOT NULL,
                      config_json TEXT NOT NULL,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        # Policies table
        c.execute('''CREATE TABLE IF NOT EXISTS policies
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name TEXT UNIQUE NOT NULL,
                      policy_json TEXT NOT NULL,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        # Scans table
        c.execute('''CREATE TABLE IF NOT EXISTS scans
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      scan_uid TEXT UNIQUE,
                      name TEXT UNIQUE NOT NULL,
                      config_id INTEGER NOT NULL,
                      policy_id INTEGER NOT NULL,
                      status TEXT DEFAULT 'Never Run',
                      last_run TIMESTAMP,
                      report_path TEXT,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY(config_id) REFERENCES configurations(id),
                      FOREIGN KEY(policy_id) REFERENCES policies(id))''')
        
        # Migration: Add scan_uid column if it doesn't exist
        c.execute("PRAGMA table_info(scans)")
        columns = [col[1] for col in c.fetchall()]
        if 'scan_uid' not in columns:
            import uuid
            c.execute('ALTER TABLE scans ADD COLUMN scan_uid TEXT')
            # Backfill existing scans with UIDs
            c.execute('SELECT id FROM scans WHERE scan_uid IS NULL')
            for row in c.fetchall():
                uid = f"SCN-{uuid.uuid4().hex[:8].upper()}"
                c.execute('UPDATE scans SET scan_uid = ? WHERE id = ?', (uid, row[0]))
            # Create unique index after backfill
            c.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_uid ON scans(scan_uid)')
        
        # Scan logs table
        c.execute('''CREATE TABLE IF NOT EXISTS scan_logs
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      scan_id INTEGER NOT NULL,
                      run_number INTEGER DEFAULT 1,
                      log_entry TEXT NOT NULL,
                      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY(scan_id) REFERENCES scans(id))''')
        
        # CLM Integrations table
        c.execute('''CREATE TABLE IF NOT EXISTS clm_integrations
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name TEXT UNIQUE NOT NULL,
                      type TEXT NOT NULL,
                      config_json TEXT NOT NULL,
                      status TEXT DEFAULT 'Unknown',
                      enabled INTEGER DEFAULT 1,
                      last_sync TIMESTAMP,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        # =========================================================================
        # INVENTORY TABLES FOR CONTINUOUS MONITORING
        # =========================================================================
        
        # Certificates inventory - persistent cache of discovered certificates
        c.execute('''CREATE TABLE IF NOT EXISTS certificates_inventory
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      fingerprint_sha256 TEXT NOT NULL,
                      connector_id INTEGER NOT NULL,
                      normalised_data TEXT NOT NULL,
                      subject_cn TEXT,
                      issuer_cn TEXT,
                      not_after TEXT,
                      days_until_expiry INTEGER,
                      key_algorithm TEXT,
                      key_size INTEGER,
                      source_type TEXT,
                      integration_name TEXT,
                      first_seen_at TEXT NOT NULL,
                      last_seen_at TEXT NOT NULL,
                      is_active INTEGER DEFAULT 1,
                      is_promoted INTEGER,
                      promoted_from_scan_name TEXT,
                      promoted_at TIMESTAMP,
                      FOREIGN KEY (connector_id) REFERENCES clm_integrations(id))''')
        
        # Keys inventory - persistent cache of discovered keys
        c.execute('''CREATE TABLE IF NOT EXISTS keys_inventory
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      key_identifier TEXT NOT NULL,
                      connector_id INTEGER NOT NULL,
                      normalised_data TEXT NOT NULL,
                      key_name TEXT,
                      key_type TEXT,
                      key_size INTEGER,
                      source_type TEXT,
                      integration_name TEXT,
                      expires_on TEXT,
                      days_until_expiry INTEGER,
                      is_hsm_backed INTEGER DEFAULT 0,
                      first_seen_at TEXT NOT NULL,
                      last_seen_at TEXT NOT NULL,
                      is_active INTEGER DEFAULT 1,
                      is_promoted INTEGER,
                      promoted_from_scan_name TEXT,
                      promoted_at TIMESTAMP,
                      FOREIGN KEY (connector_id) REFERENCES clm_integrations(id))''')
        
        # Connector sync status - tracks sync state per connector
        c.execute('''CREATE TABLE IF NOT EXISTS connector_sync_status
                     (connector_id INTEGER PRIMARY KEY,
                      last_sync_started TEXT,
                      last_sync_completed TEXT,
                      last_sync_status TEXT DEFAULT 'pending',
                      last_sync_error TEXT,
                      last_sync_duration_seconds REAL,
                      items_total INTEGER DEFAULT 0,
                      items_added INTEGER DEFAULT 0,
                      items_updated INTEGER DEFAULT 0,
                      items_removed INTEGER DEFAULT 0,
                      next_sync_due TEXT,
                      sync_interval_minutes INTEGER DEFAULT 30,
                      consecutive_failures INTEGER DEFAULT 0,
                      FOREIGN KEY (connector_id) REFERENCES clm_integrations(id))''')

        # Lifecycle policies - renewal/rotation configuration per connector
        c.execute('''CREATE TABLE IF NOT EXISTS lifecycle_policies
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      connector_id INTEGER NOT NULL UNIQUE,
                      renewal_threshold_days INTEGER DEFAULT 90,
                      rotation_interval_days INTEGER,
                      auto_action INTEGER DEFAULT 0,
                      notification_enabled INTEGER DEFAULT 1,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY (connector_id) REFERENCES clm_integrations(id))''')

        # Inventory changes audit log
        c.execute('''CREATE TABLE IF NOT EXISTS inventory_changes
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      entity_type TEXT NOT NULL,
                      entity_id INTEGER NOT NULL,
                      connector_id INTEGER NOT NULL,
                      change_type TEXT NOT NULL,
                      change_details TEXT,
                      detected_at TEXT NOT NULL)''')
        
        # Create indexes for inventory tables
        c.execute('''CREATE INDEX IF NOT EXISTS idx_certs_inv_connector 
                     ON certificates_inventory(connector_id)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_certs_inv_fingerprint 
                     ON certificates_inventory(fingerprint_sha256)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_certs_inv_expiry 
                     ON certificates_inventory(days_until_expiry)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_certs_inv_active 
                     ON certificates_inventory(is_active)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_keys_inv_connector 
                     ON keys_inventory(connector_id)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_keys_inv_identifier 
                     ON keys_inventory(key_identifier)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_keys_inv_active 
                     ON keys_inventory(is_active)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_inv_changes_detected 
                     ON inventory_changes(detected_at)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_inv_changes_connector
                     ON inventory_changes(connector_id)''')

        # Search performance indexes
        c.execute('''CREATE INDEX IF NOT EXISTS idx_certs_inv_subject_cn
                     ON certificates_inventory(subject_cn COLLATE NOCASE)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_certs_inv_algorithm
                     ON certificates_inventory(key_algorithm)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_certs_inv_source_type
                     ON certificates_inventory(source_type)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_keys_inv_key_name
                     ON keys_inventory(key_name COLLATE NOCASE)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_keys_inv_key_type
                     ON keys_inventory(key_type)''')

        # Composite UNIQUE indexes for promoted scans
        # Allows multiple promoted versions to coexist without overwrites
        c.execute('''CREATE UNIQUE INDEX IF NOT EXISTS idx_certs_fingerprint_connector_scan
                     ON certificates_inventory(fingerprint_sha256, connector_id, promoted_from_scan_name)
                     WHERE source_type = 'Promoted Scans' OR source_type IS NULL''')
        c.execute('''CREATE UNIQUE INDEX IF NOT EXISTS idx_keys_identifier_connector_scan
                     ON keys_inventory(key_identifier, connector_id, promoted_from_scan_name)
                     WHERE source_type = 'Promoted Scans' OR source_type IS NULL''')

        # Reassessments table
        c.execute('''CREATE TABLE IF NOT EXISTS reassessments
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name TEXT NOT NULL,
                      original_report_filename TEXT NOT NULL,
                      policy_id INTEGER NOT NULL,
                      report_data TEXT NOT NULL,
                      reassessed_report_path TEXT,
                      status TEXT DEFAULT 'Pending',
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY(policy_id) REFERENCES policies(id))''')
        
        # Report Aggregations table
        c.execute('''CREATE TABLE IF NOT EXISTS report_aggregations
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name TEXT NOT NULL,
                      policy_id INTEGER NOT NULL,
                      merge_strategy TEXT DEFAULT 'deduplicate',
                      source_reports TEXT NOT NULL,
                      aggregated_report_path TEXT,
                      report_data TEXT NOT NULL,
                      status TEXT DEFAULT 'Completed',
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY(policy_id) REFERENCES policies(id))''')
        
        # Engagements table - container for customer project reports
        c.execute('''CREATE TABLE IF NOT EXISTS engagements
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      engagement_id TEXT UNIQUE NOT NULL,
                      customer_name TEXT NOT NULL,
                      project_name TEXT NOT NULL,
                      description TEXT,
                      status TEXT DEFAULT 'Active',
                      start_date TEXT,
                      end_date TEXT,
                      lead_consultant TEXT,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        # Engagement reports - links reports to engagements
        c.execute('''CREATE TABLE IF NOT EXISTS engagement_reports
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      engagement_id TEXT NOT NULL,
                      report_type TEXT NOT NULL,
                      report_reference_id INTEGER NOT NULL,
                      report_name TEXT NOT NULL,
                      report_path TEXT,
                      include_in_executive INTEGER DEFAULT 1,
                      display_order INTEGER DEFAULT 0,
                      added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY(engagement_id) REFERENCES engagements(engagement_id))''')
        
        # Engagement executive summaries - versioned summaries
        c.execute('''CREATE TABLE IF NOT EXISTS engagement_executive_summaries
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      engagement_id TEXT NOT NULL,
                      version INTEGER DEFAULT 1,
                      report_name TEXT,
                      report_path TEXT,
                      included_reports_json TEXT,
                      generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      generated_by TEXT,
                      FOREIGN KEY(engagement_id) REFERENCES engagements(engagement_id))''')
        
         # Create indexes for engagement tables
        c.execute('''CREATE INDEX IF NOT EXISTS idx_engagement_id 
                     ON engagements(engagement_id)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_engagement_reports_engagement 
                     ON engagement_reports(engagement_id)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_engagement_exec_summaries 
                     ON engagement_executive_summaries(engagement_id)''')
        
        # Initialize asset context tables for PQC migration planning
        from caip_service_layer.asset_context_service import AssetContextService
        AssetContextService.init_context_tables(cls)

        from caip_document_assessment_functions.document_assessment_database import DocumentAssessmentDatabase
        DocumentAssessmentDatabase.init_document_assessment_tables(cls)

        # =========================================================================
        # OAUTH AUTHENTICATION PROVIDER TABLES
        # =========================================================================

        # Auth providers - OAuth/SAML/OIDC identity providers
        c.execute('''CREATE TABLE IF NOT EXISTS auth_providers
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name TEXT UNIQUE NOT NULL,
                      type TEXT NOT NULL,
                      config_json TEXT NOT NULL,
                      enabled INTEGER DEFAULT 1,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

        # OAuth user links - map OAuth users to local users
        c.execute('''CREATE TABLE IF NOT EXISTS oauth_user_links
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER NOT NULL,
                      provider_id INTEGER NOT NULL,
                      provider_user_id TEXT NOT NULL,
                      email TEXT,
                      name TEXT,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      UNIQUE(provider_id, provider_user_id),
                      FOREIGN KEY(user_id) REFERENCES users(id),
                      FOREIGN KEY(provider_id) REFERENCES auth_providers(id))''')

        # Create indexes for auth provider tables
        c.execute('''CREATE INDEX IF NOT EXISTS idx_auth_providers_type
                     ON auth_providers(type)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_auth_providers_enabled
                     ON auth_providers(enabled)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_oauth_links_user
                     ON oauth_user_links(user_id)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_oauth_links_provider
                     ON oauth_user_links(provider_id)''')

        # =========================================================================
        # UNIFIED VAULT METADATA TABLE
        # =========================================================================
        # Tracks system vault and other managed vaults for UI visibility
        c.execute('''CREATE TABLE IF NOT EXISTS unified_vaults
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      vault_id TEXT UNIQUE NOT NULL,
                      name TEXT NOT NULL,
                      file_path TEXT NOT NULL,
                      vault_type TEXT DEFAULT 'system',
                      version TEXT DEFAULT '1.0',
                      algorithm TEXT DEFAULT 'AES-256-GCM',
                      is_system BOOLEAN DEFAULT FALSE,
                      is_locked BOOLEAN DEFAULT FALSE,
                      key_count INTEGER DEFAULT 0,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      last_accessed_at TIMESTAMP,
                      last_modified_at TIMESTAMP,
                      status TEXT DEFAULT 'active',
                      status_message TEXT,
                      error_message TEXT)''')

        # Indexes for vault queries
        c.execute('''CREATE INDEX IF NOT EXISTS idx_unified_vaults_vault_id
                     ON unified_vaults(vault_id)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_unified_vaults_is_system
                     ON unified_vaults(is_system)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_unified_vaults_status
                     ON unified_vaults(status)''')

        # =========================================================================
        # PHASE 2: USER IDENTITY CERTIFICATES
        # =========================================================================
        # User digital identities - tracks user certificates and their lifecycle
        c.execute('''CREATE TABLE IF NOT EXISTS user_digital_identities
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER UNIQUE NOT NULL,
                      certificate_pem TEXT NOT NULL,
                      certificate_serial TEXT UNIQUE NOT NULL,
                      public_key_pem TEXT NOT NULL,
                      issued_at TIMESTAMP NOT NULL,
                      expires_at TIMESTAMP NOT NULL,
                      p12_generated_at TIMESTAMP,
                      p12_downloaded_at TIMESTAMP,
                      p12_deleted_at TIMESTAMP,
                      private_key_destroyed_at TIMESTAMP,
                      status TEXT DEFAULT 'pending_p12_creation',
                      rotation_count INTEGER DEFAULT 0,
                      last_rotation_at TIMESTAMP,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      FOREIGN KEY(user_id) REFERENCES users(id))''')

        # Temporary P12 downloads - tracks secure download tokens and expiry
        c.execute('''CREATE TABLE IF NOT EXISTS temp_p12_downloads
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER NOT NULL,
                      p12_file_path TEXT,
                      download_token TEXT UNIQUE NOT NULL,
                      p12_password TEXT NOT NULL,
                      created_at TIMESTAMP NOT NULL,
                      expires_at TIMESTAMP NOT NULL,
                      downloaded_at TIMESTAMP,
                      deleted_at TIMESTAMP,
                      status TEXT DEFAULT 'pending',
                      created_by INTEGER,
                      FOREIGN KEY(user_id) REFERENCES users(id),
                      FOREIGN KEY(created_by) REFERENCES users(id))''')

        # Indexes for user certificate queries
        c.execute('''CREATE INDEX IF NOT EXISTS idx_user_identities_user_id
                     ON user_digital_identities(user_id)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_user_identities_status
                     ON user_digital_identities(status)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_user_identities_expires
                     ON user_digital_identities(expires_at)''')
        c.execute('''CREATE UNIQUE INDEX IF NOT EXISTS idx_user_identities_serial
                     ON user_digital_identities(certificate_serial)''')

        c.execute('''CREATE INDEX IF NOT EXISTS idx_p12_downloads_user
                     ON temp_p12_downloads(user_id)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_p12_downloads_token
                     ON temp_p12_downloads(download_token)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_p12_downloads_status
                     ON temp_p12_downloads(status)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_p12_downloads_expires
                     ON temp_p12_downloads(expires_at)''')

        conn.commit()
        
        # Run migrations
        cls._run_migrations(conn)
        
        # Create default admin user if password provided
        if default_admin_password:
            cls._create_default_admin(conn, default_admin_password)
        
        conn.close()
        logger.info("Database initialized successfully")
    
    @classmethod
    def _run_migrations(cls, conn: sqlite3.Connection):
        """Run database migrations for schema updates."""
        c = conn.cursor()
        
        # Migration: Add enabled column to clm_integrations if it doesn't exist
        try:
            c.execute('SELECT enabled FROM clm_integrations LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such column' in str(e):
                logger.info("Migrating clm_integrations table: adding enabled column")
                c.execute('ALTER TABLE clm_integrations ADD COLUMN enabled INTEGER DEFAULT 1')
                logger.info("Migration complete: enabled column added")
        
        # Migration: Add run_number column to scan_logs if it doesn't exist
        try:
            c.execute('SELECT run_number FROM scan_logs LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such column' in str(e):
                logger.info("Migrating scan_logs table: adding run_number column")
                c.execute('ALTER TABLE scan_logs ADD COLUMN run_number INTEGER DEFAULT 1')
                logger.info("Migration complete: run_number column added")
        
        # Migration: Add assessment_type column to scans if it doesn't exist
        try:
            c.execute('SELECT assessment_type FROM scans LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such column' in str(e):
                logger.info("Migrating scans table: adding assessment_type column")
                c.execute("ALTER TABLE scans ADD COLUMN assessment_type TEXT DEFAULT 'pki_health_check'")
                logger.info("Migration complete: assessment_type column added")

                # Migration: Add engagement_id column to scans if it doesn't exist
        try:
            c.execute('SELECT engagement_id FROM scans LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such column' in str(e):
                logger.info("Migrating scans table: adding engagement_id column")
                c.execute('ALTER TABLE scans ADD COLUMN engagement_id TEXT REFERENCES engagements(engagement_id)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_scans_engagement ON scans(engagement_id)')
                logger.info("Migration complete: engagement_id column added to scans")
        
        # Migration: Add engagement_id column to configurations if it doesn't exist
        try:
            c.execute('SELECT engagement_id FROM configurations LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such column' in str(e):
                logger.info("Migrating configurations table: adding engagement_id column")
                c.execute('ALTER TABLE configurations ADD COLUMN engagement_id TEXT REFERENCES engagements(engagement_id)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_configurations_engagement ON configurations(engagement_id)')
                logger.info("Migration complete: engagement_id column added to configurations")
        
        # Migration: Add engagement_id column to reassessments if it doesn't exist
        try:
            c.execute('SELECT engagement_id FROM reassessments LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such column' in str(e):
                logger.info("Migrating reassessments table: adding engagement_id column")
                c.execute('ALTER TABLE reassessments ADD COLUMN engagement_id TEXT REFERENCES engagements(engagement_id)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_reassessments_engagement ON reassessments(engagement_id)')
                logger.info("Migration complete: engagement_id column added to reassessments")
        
        # Migration: Add engagement_id column to report_aggregations if it doesn't exist
        try:
            c.execute('SELECT engagement_id FROM report_aggregations LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such column' in str(e):
                logger.info("Migrating report_aggregations table: adding engagement_id column")
                c.execute('ALTER TABLE report_aggregations ADD COLUMN engagement_id TEXT REFERENCES engagements(engagement_id)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_report_aggregations_engagement ON report_aggregations(engagement_id)')
                logger.info("Migration complete: engagement_id column added to report_aggregations")

        # Migration: Create secret_references table for secure secret storage
        try:
            c.execute('SELECT 1 FROM secret_references LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such table' in str(e):
                logger.info("Creating secret_references table for secure secret management")
                c.execute('''CREATE TABLE secret_references (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    secret_id TEXT UNIQUE NOT NULL,
                    backend_type TEXT NOT NULL,
                    kv_secret_name TEXT,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')
                c.execute('CREATE INDEX IF NOT EXISTS idx_secret_refs_backend ON secret_references(backend_type)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_secret_refs_id ON secret_references(secret_id)')
                logger.info("Migration complete: secret_references table created")

        # Migration: Add MFA columns to users table
        try:
            c.execute('SELECT mfa_enabled FROM users LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such column' in str(e):
                logger.info("Migrating users table: adding MFA columns")
                c.execute('ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 0')
                c.execute('ALTER TABLE users ADD COLUMN mfa_secret_ref TEXT')
                c.execute('ALTER TABLE users ADD COLUMN password_algorithm TEXT DEFAULT "pbkdf2"')
                logger.info("Migration complete: MFA columns added to users table")

        # Migration: Add collector_id column to scans for remote execution routing
        try:
            c.execute('SELECT collector_id FROM scans LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such column' in str(e):
                logger.info("Migrating scans table: adding collector_id column for remote execution")
                c.execute('ALTER TABLE scans ADD COLUMN collector_id TEXT REFERENCES remote_collectors(collector_id)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_scans_collector ON scans(collector_id)')
                logger.info("Migration complete: collector_id column added to scans")

        # Migration: Add collector_results column to scans for tracking partial success
        try:
            c.execute('SELECT collector_results FROM scans LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such column' in str(e):
                logger.info("Migrating scans table: adding collector_results column for partial success tracking")
                c.execute('ALTER TABLE scans ADD COLUMN collector_results TEXT')
                logger.info("Migration complete: collector_results column added to scans")

        # Migration: Create secret_stores table for external secret store connections
        try:
            c.execute('SELECT 1 FROM secret_stores LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such table' in str(e):
                logger.info("Creating secret_stores table for external secret store management")
                c.execute('''CREATE TABLE secret_stores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    provider_type TEXT NOT NULL,
                    connection_config TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    status_message TEXT,
                    last_verified_at TIMESTAMP,
                    secret_count INTEGER DEFAULT 0,
                    created_by INTEGER REFERENCES users(id),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')
                c.execute('CREATE INDEX IF NOT EXISTS idx_secret_stores_provider ON secret_stores(provider_type)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_secret_stores_status ON secret_stores(status)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_secret_stores_created_by ON secret_stores(created_by)')
                logger.info("Migration complete: secret_stores table created")

        # Migration: Create engagement_dashboard_certificates table for per-engagement server certs
        try:
            c.execute('SELECT 1 FROM engagement_dashboard_certificates LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such table' in str(e):
                logger.info("Creating engagement_dashboard_certificates table for mTLS endpoint certificates")
                c.execute('''CREATE TABLE engagement_dashboard_certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id TEXT NOT NULL,
                    certificate_pem TEXT NOT NULL,
                    private_key_encrypted TEXT NOT NULL,
                    public_key_pem TEXT NOT NULL,
                    serial_number TEXT UNIQUE NOT NULL,
                    subject TEXT NOT NULL,
                    issued_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (engagement_id) REFERENCES engagements(id),
                    UNIQUE(engagement_id, status)
                )''')
                c.execute('CREATE INDEX IF NOT EXISTS idx_engagement_dashboard_certs_engagement ON engagement_dashboard_certificates(engagement_id)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_engagement_dashboard_certs_status ON engagement_dashboard_certificates(status)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_engagement_dashboard_certs_expires ON engagement_dashboard_certificates(expires_at)')
                logger.info("Migration complete: engagement_dashboard_certificates table created")

        # =========================================================================
        # STAGE 1: ENRICHMENT OVERRIDE & AUDIT TRAIL MIGRATIONS
        # =========================================================================

        # Migration: Add override columns to asset_context table
        try:
            c.execute('SELECT override_enabled FROM asset_context LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such column' in str(e):
                logger.info("Migrating asset_context table: adding override/exclusion columns")
                c.execute('ALTER TABLE asset_context ADD COLUMN override_enabled INTEGER DEFAULT 0')
                c.execute('ALTER TABLE asset_context ADD COLUMN override_score INTEGER')
                c.execute('ALTER TABLE asset_context ADD COLUMN override_phase TEXT')
                c.execute('ALTER TABLE asset_context ADD COLUMN override_reason TEXT')
                c.execute('ALTER TABLE asset_context ADD COLUMN excluded INTEGER DEFAULT 0')
                c.execute('ALTER TABLE asset_context ADD COLUMN exclusion_reason TEXT')
                c.execute('ALTER TABLE asset_context ADD COLUMN last_modified_by TEXT')
                c.execute('ALTER TABLE asset_context ADD COLUMN last_modified_at TIMESTAMP')
                logger.info("Migration complete: override/exclusion columns added to asset_context")

        # Migration: Create asset_context_history table for audit trail
        try:
            c.execute('SELECT 1 FROM asset_context_history LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such table' in str(e):
                logger.info("Creating asset_context_history table for enrichment audit trail")
                c.execute('''CREATE TABLE asset_context_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                    FOREIGN KEY(context_id) REFERENCES asset_context(id)
                )''')
                c.execute('CREATE INDEX IF NOT EXISTS idx_context_history_context ON asset_context_history(context_id)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_context_history_asset ON asset_context_history(asset_id)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_context_history_changed_at ON asset_context_history(changed_at DESC)')
                logger.info("Migration complete: asset_context_history table created")

        # Migration: Add promotion columns to certificates_inventory
        try:
            c.execute('SELECT is_promoted FROM certificates_inventory LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such column' in str(e):
                logger.info("Migrating certificates_inventory table: adding promotion columns")
                c.execute('ALTER TABLE certificates_inventory ADD COLUMN is_promoted INTEGER DEFAULT 0')
                c.execute('ALTER TABLE certificates_inventory ADD COLUMN promoted_from_scan_name TEXT')
                c.execute('ALTER TABLE certificates_inventory ADD COLUMN promoted_at TIMESTAMP')
                c.execute('CREATE INDEX IF NOT EXISTS idx_certs_inv_promoted ON certificates_inventory(is_promoted)')
                logger.info("Migration complete: promotion columns added to certificates_inventory")

        # Migration: Add promotion columns to keys_inventory
        try:
            c.execute('SELECT is_promoted FROM keys_inventory LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such column' in str(e):
                logger.info("Migrating keys_inventory table: adding promotion columns")
                c.execute('ALTER TABLE keys_inventory ADD COLUMN is_promoted INTEGER DEFAULT 0')
                c.execute('ALTER TABLE keys_inventory ADD COLUMN promoted_from_scan_name TEXT')
                c.execute('ALTER TABLE keys_inventory ADD COLUMN promoted_at TIMESTAMP')
                c.execute('CREATE INDEX IF NOT EXISTS idx_keys_inv_promoted ON keys_inventory(is_promoted)')
                logger.info("Migration complete: promotion columns added to keys_inventory")

        # Migration: Add CA metadata storage to clm_integrations
        try:
            c.execute('SELECT cas_metadata FROM clm_integrations LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such column' in str(e):
                logger.info("Migrating clm_integrations table: adding cas_metadata column for storing CA information")
                c.execute('ALTER TABLE clm_integrations ADD COLUMN cas_metadata TEXT')
                logger.info("Migration complete: cas_metadata column added to clm_integrations")

        # Migration: Add version and enrichment_snapshot to reassessments table
        try:
            c.execute('SELECT version FROM reassessments LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such column' in str(e):
                logger.info("Migrating reassessments table: adding version and enrichment_snapshot columns")
                c.execute('ALTER TABLE reassessments ADD COLUMN version INTEGER DEFAULT 1')
                c.execute('ALTER TABLE reassessments ADD COLUMN enrichment_snapshot TEXT')
                c.execute('ALTER TABLE reassessments ADD COLUMN created_by TEXT')
                logger.info("Migration complete: version tracking added to reassessments")

        # Migration: Add environment metadata columns to asset_context for auto-discovery
        try:
            c.execute('SELECT environment_type FROM asset_context LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such column' in str(e):
                logger.info("Migrating asset_context table: adding environment metadata columns for auto-discovery")
                c.execute('ALTER TABLE asset_context ADD COLUMN environment_type TEXT CHECK(environment_type IN ("production", "staging", "development", "testing", "unknown"))')
                c.execute('ALTER TABLE asset_context ADD COLUMN service_name TEXT')
                c.execute('ALTER TABLE asset_context ADD COLUMN application_name TEXT')
                c.execute('ALTER TABLE asset_context ADD COLUMN discovery_method TEXT')
                c.execute('ALTER TABLE asset_context ADD COLUMN discovery_confidence REAL DEFAULT 1.0 CHECK(discovery_confidence >= 0.0 AND discovery_confidence <= 1.0)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_asset_context_environment ON asset_context(environment_type)')
                logger.info("Migration complete: environment metadata columns added to asset_context")

        # Migration: Create asset_relationships table for dependency graph
        try:
            c.execute('SELECT 1 FROM asset_relationships LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such table' in str(e):
                logger.info("Creating asset_relationships table for dependency graph storage")
                c.execute('''CREATE TABLE asset_relationships (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    parent_asset_id TEXT NOT NULL,
                    parent_asset_type TEXT NOT NULL CHECK(parent_asset_type IN ('certificate', 'key')),
                    child_asset_id TEXT NOT NULL,
                    child_asset_type TEXT NOT NULL CHECK(child_asset_type IN ('certificate', 'key')),
                    relationship_type TEXT NOT NULL,
                    confidence REAL DEFAULT 1.0 CHECK(confidence >= 0.0 AND confidence <= 1.0),
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    source TEXT,
                    metadata TEXT,
                    UNIQUE(parent_asset_id, child_asset_id, relationship_type)
                )''')
                c.execute('CREATE INDEX IF NOT EXISTS idx_relationships_parent ON asset_relationships(parent_asset_id, parent_asset_type)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_relationships_child ON asset_relationships(child_asset_id, child_asset_type)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_relationships_type ON asset_relationships(relationship_type)')
                logger.info("Migration complete: asset_relationships table created")

        # Migration: Create enrichment_operations table for audit trail
        try:
            c.execute('SELECT 1 FROM enrichment_operations LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such table' in str(e):
                logger.info("Creating enrichment_operations table for bulk enrichment audit trail")
                c.execute('''CREATE TABLE IF NOT EXISTS enrichment_operations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation_id TEXT UNIQUE NOT NULL,
                    engagement_id TEXT NOT NULL,
                    operation_type TEXT NOT NULL,
                    affected_count INTEGER DEFAULT 0,
                    asset_ids TEXT,
                    changed_by TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')
                c.execute('CREATE INDEX IF NOT EXISTS idx_enrichment_operations_engagement ON enrichment_operations(engagement_id)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_enrichment_operations_operation_id ON enrichment_operations(operation_id)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_enrichment_operations_created_at ON enrichment_operations(created_at DESC)')
                logger.info("Migration complete: enrichment_operations table created")

        # =========================================================================
        # PHASE 3: ENGAGEMENT CA & REPORT SIGNING CERTIFICATES
        # =========================================================================

        # Migration: Create engagement_ca_certificates table
        try:
            c.execute('SELECT 1 FROM engagement_ca_certificates LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such table' in str(e):
                logger.info("Creating engagement_ca_certificates table for Phase 3")
                c.execute('''CREATE TABLE IF NOT EXISTS engagement_ca_certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id TEXT NOT NULL,
                    certificate_pem TEXT NOT NULL,
                    certificate_serial TEXT UNIQUE NOT NULL,
                    subject TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    public_key_pem TEXT NOT NULL,
                    private_key_ref TEXT NOT NULL,
                    issued_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    status TEXT DEFAULT 'active',
                    rotation_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (engagement_id) REFERENCES engagements(engagement_id),
                    UNIQUE(engagement_id, status)
                )''')
                c.execute('CREATE INDEX IF NOT EXISTS idx_engagement_ca_certs_engagement ON engagement_ca_certificates(engagement_id)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_engagement_ca_certs_status ON engagement_ca_certificates(status)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_engagement_ca_certs_serial ON engagement_ca_certificates(certificate_serial)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_engagement_ca_certs_expires ON engagement_ca_certificates(expires_at)')
                logger.info("Migration complete: engagement_ca_certificates table created")

        # Migration: Create report_signing_certificates table
        try:
            c.execute('SELECT 1 FROM report_signing_certificates LIMIT 1')
        except sqlite3.OperationalError as e:
            if 'no such table' in str(e):
                logger.info("Creating report_signing_certificates table for Phase 3")
                c.execute('''CREATE TABLE IF NOT EXISTS report_signing_certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id TEXT NOT NULL,
                    certificate_pem TEXT NOT NULL,
                    certificate_serial TEXT UNIQUE NOT NULL,
                    subject TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    public_key_pem TEXT NOT NULL,
                    private_key_ref TEXT NOT NULL,
                    issued_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    status TEXT DEFAULT 'active',
                    rotation_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (engagement_id) REFERENCES engagements(engagement_id),
                    UNIQUE(engagement_id, status)
                )''')
                c.execute('CREATE INDEX IF NOT EXISTS idx_report_signing_certs_engagement ON report_signing_certificates(engagement_id)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_report_signing_certs_status ON report_signing_certificates(status)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_report_signing_certs_serial ON report_signing_certificates(certificate_serial)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_report_signing_certs_expires ON report_signing_certificates(expires_at)')
                logger.info("Migration complete: report_signing_certificates table created")

        # Phase A1: Drop legacy engagement_cas table (consolidated to engagement_ca_certificates)
        # Private keys now stored exclusively in vault
        try:
            c.execute('SELECT 1 FROM engagement_cas LIMIT 1')
            logger.info("Dropping legacy engagement_cas table (consolidated to engagement_ca_certificates)")
            c.execute('DROP TABLE IF EXISTS engagement_cas')
            logger.info("Migration complete: engagement_cas table dropped")
        except sqlite3.OperationalError as e:
            if 'no such table' in str(e):
                logger.info("engagement_cas table does not exist, skipping drop")
            else:
                logger.warning(f"Could not check engagement_cas table: {e}")

        # Phase A2: Migrate dashboard_certificates and engagement_dashboard_certificates to vault-only keys
        # Add private_key_ref columns, drop private_key_encrypted columns
        try:
            c.execute('PRAGMA table_info(dashboard_certificates)')
            columns = [col[1] for col in c.fetchall()]
            if 'private_key_encrypted' in columns and 'private_key_ref' not in columns:
                logger.info("Migrating dashboard_certificates: replacing private_key_encrypted with private_key_ref")
                c.execute('ALTER TABLE dashboard_certificates RENAME TO dashboard_certificates_old')
                c.execute('''CREATE TABLE dashboard_certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    certificate_pem TEXT NOT NULL,
                    private_key_ref TEXT NOT NULL,
                    serial_number TEXT UNIQUE NOT NULL,
                    issued_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    hostname TEXT DEFAULT 'caip-dashboard',
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')
                c.execute('''INSERT INTO dashboard_certificates
                    (id, certificate_pem, private_key_ref, serial_number, issued_at, expires_at, hostname, status, created_at, updated_at)
                    SELECT id, certificate_pem, 'dashboard-cert-key-main', serial_number, issued_at, expires_at, hostname, status, created_at, updated_at
                    FROM dashboard_certificates_old''')
                c.execute('DROP TABLE dashboard_certificates_old')
                logger.info("Migration complete: dashboard_certificates updated")
        except sqlite3.OperationalError as e:
            logger.warning(f"Could not migrate dashboard_certificates: {e}")

        try:
            c.execute('PRAGMA table_info(engagement_dashboard_certificates)')
            columns = [col[1] for col in c.fetchall()]
            if 'private_key_encrypted' in columns and 'private_key_ref' not in columns:
                logger.info("Migrating engagement_dashboard_certificates: replacing private_key_encrypted with private_key_ref")
                c.execute('ALTER TABLE engagement_dashboard_certificates RENAME TO engagement_dashboard_certificates_old')
                c.execute('''CREATE TABLE engagement_dashboard_certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id TEXT NOT NULL,
                    certificate_pem TEXT NOT NULL,
                    private_key_ref TEXT NOT NULL,
                    public_key_pem TEXT NOT NULL,
                    serial_number TEXT UNIQUE NOT NULL,
                    subject TEXT NOT NULL,
                    issued_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (engagement_id) REFERENCES engagements(engagement_id),
                    UNIQUE(engagement_id, status)
                )''')
                c.execute('''INSERT INTO engagement_dashboard_certificates
                    (id, engagement_id, certificate_pem, private_key_ref, public_key_pem, serial_number, subject, issued_at, expires_at, status, created_at, updated_at)
                    SELECT id, engagement_id, certificate_pem, ('engagement-dashboard-key-' || engagement_id), public_key_pem, serial_number, subject, issued_at, expires_at, status, created_at, updated_at
                    FROM engagement_dashboard_certificates_old''')
                c.execute('DROP TABLE engagement_dashboard_certificates_old')
                logger.info("Migration complete: engagement_dashboard_certificates updated")
        except sqlite3.OperationalError as e:
            logger.warning(f"Could not migrate engagement_dashboard_certificates: {e}")

        # Phase A3: Remove database fallback for internal_ca (vault-only going forward)
        try:
            c = conn.cursor()
            c.execute('PRAGMA table_info(internal_ca)')
            columns = c.fetchall()
            has_ca_private_key_encrypted = any(col[1] == 'ca_private_key_encrypted' for col in columns)

            if has_ca_private_key_encrypted:
                logger.info("Phase A3: Migrating internal_ca to vault-only (removing DB fallback)...")
                c.execute('ALTER TABLE internal_ca RENAME TO internal_ca_old')
                c.execute('''
                    CREATE TABLE internal_ca (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ca_certificate_pem TEXT NOT NULL,
                        serial_number TEXT UNIQUE NOT NULL,
                        subject TEXT NOT NULL,
                        issued_at TIMESTAMP NOT NULL,
                        expires_at TIMESTAMP NOT NULL,
                        rotation_count INTEGER DEFAULT 0,
                        status TEXT DEFAULT 'active',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                c.execute('''
                    INSERT INTO internal_ca
                    (id, ca_certificate_pem, serial_number, subject, issued_at, expires_at, rotation_count, status, created_at, updated_at)
                    SELECT id, ca_certificate_pem, serial_number, subject, issued_at, expires_at, rotation_count, status, created_at, updated_at
                    FROM internal_ca_old
                ''')
                c.execute('DROP TABLE internal_ca_old')
                logger.info("Migration complete: internal_ca now vault-only (private_key_encrypted column dropped)")
        except sqlite3.OperationalError as e:
            logger.warning(f"Could not migrate internal_ca: {e}")

        # Phase A4: Drop internal_certificates dead table (never written to by Python code)
        try:
            c = conn.cursor()
            c.execute('DROP TABLE IF EXISTS internal_certificates')
            logger.info("Phase A4: Dropped internal_certificates table (dead table)")
        except sqlite3.OperationalError as e:
            logger.warning(f"Could not drop internal_certificates table: {e}")

        # Phase B: Evolve user_digital_identities with engagement_id and cert_purpose
        try:
            c = conn.cursor()
            c.execute('PRAGMA table_info(user_digital_identities)')
            columns = c.fetchall()
            has_engagement_id = any(col[1] == 'engagement_id' for col in columns)
            has_cert_purpose = any(col[1] == 'cert_purpose' for col in columns)

            if not has_engagement_id or not has_cert_purpose:
                logger.info("Phase B: Evolving user_digital_identities schema...")

                # Rename old table
                c.execute('ALTER TABLE user_digital_identities RENAME TO user_digital_identities_old')

                # Create new table with evolved schema
                c.execute('''
                    CREATE TABLE user_digital_identities (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        engagement_id TEXT,
                        cert_purpose TEXT NOT NULL DEFAULT 'identity',
                        report_ref TEXT,
                        validity_days INTEGER NOT NULL DEFAULT 365,
                        certificate_pem TEXT NOT NULL,
                        certificate_serial TEXT UNIQUE NOT NULL,
                        public_key_pem TEXT NOT NULL,
                        private_key_ref TEXT,
                        issued_at TIMESTAMP NOT NULL,
                        expires_at TIMESTAMP NOT NULL,
                        p12_generated_at TIMESTAMP,
                        p12_downloaded_at TIMESTAMP,
                        p12_deleted_at TIMESTAMP,
                        private_key_destroyed_at TIMESTAMP,
                        status TEXT DEFAULT 'pending_p12_creation',
                        rotation_count INTEGER DEFAULT 0,
                        last_rotation_at TIMESTAMP,
                        revoked_at TIMESTAMP,
                        revocation_reason TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(user_id) REFERENCES users(id),
                        FOREIGN KEY(engagement_id) REFERENCES engagements(engagement_id),
                        UNIQUE(user_id, engagement_id, cert_purpose, report_ref)
                    )
                ''')

                # Migrate existing rows: existing certs become identity certs with NULL engagement_id
                c.execute('''
                    INSERT INTO user_digital_identities
                    (user_id, engagement_id, cert_purpose, report_ref, validity_days,
                     certificate_pem, certificate_serial, public_key_pem, private_key_ref,
                     issued_at, expires_at, p12_generated_at, p12_downloaded_at, p12_deleted_at,
                     private_key_destroyed_at, status, rotation_count, last_rotation_at, created_at, updated_at)
                    SELECT user_id, NULL, 'identity', NULL, 365,
                           certificate_pem, certificate_serial, public_key_pem, NULL,
                           issued_at, expires_at, p12_generated_at, p12_downloaded_at, p12_deleted_at,
                           private_key_destroyed_at, status, rotation_count, last_rotation_at, created_at, updated_at
                    FROM user_digital_identities_old
                ''')

                # Drop old table
                c.execute('DROP TABLE user_digital_identities_old')

                logger.info("Migration complete: user_digital_identities evolved with engagement_id and cert_purpose")
        except sqlite3.OperationalError as e:
            logger.warning(f"Could not migrate user_digital_identities: {e}")

        conn.commit()




    @classmethod
    def _create_default_admin(cls, conn: sqlite3.Connection, password_hash: str):
        """Create default admin user if not exists."""
        c = conn.cursor()
        try:
            c.execute('SELECT * FROM users WHERE username = ?', ('admin',))
            if not c.fetchone():
                c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                         ('admin', password_hash, 'admin'))
                conn.commit()
                logger.info("Default admin user created")
        except Exception as e:
            logger.error(f"Error creating default admin user: {e}")

    @classmethod
    def init_system_vault_metadata(cls):
        """
        Initialize or update system vault metadata in database.

        This registers the system vault (system_vault.enc) in the unified_vaults
        table so it can be displayed in the UI as a read-only system vault.
        """
        try:
            with cls.get_connection_context() as conn:
                c = conn.cursor()

                # Check if system vault already exists
                c.execute('SELECT id FROM unified_vaults WHERE vault_id = ?', ('system_vault',))
                existing = c.fetchone()

                if existing:
                    # Update last accessed time
                    c.execute('''UPDATE unified_vaults
                                SET last_accessed_at = CURRENT_TIMESTAMP,
                                    status = 'active'
                                WHERE vault_id = ?''', ('system_vault',))
                    logger.debug("System vault metadata updated")
                else:
                    # Create new system vault entry
                    c.execute('''INSERT INTO unified_vaults
                                (vault_id, name, file_path, vault_type, is_system, status)
                                VALUES (?, ?, ?, ?, ?, ?)''',
                             ('system_vault', 'System Vault', 'system_vault.enc', 'system', True, 'active'))
                    logger.info("System vault metadata initialized")

                conn.commit()
        except Exception as e:
            logger.error(f"Failed to initialize system vault metadata: {e}")

    # =========================================================================
    # POLICY OPERATIONS
    # =========================================================================
    
    @classmethod
    def get_policy(cls, policy_id: int) -> Optional[Dict[str, Any]]:
        """
        Get a policy by ID.
        
        Args:
            policy_id: Database ID of the policy
            
        Returns:
            Policy dict with parsed policy_json, or None if not found
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('SELECT id, name, policy_json, created_at, updated_at FROM policies WHERE id = ?', 
                     (policy_id,))
            row = c.fetchone()
            
            if not row:
                return None
            
            policy = cls.dict_from_row(row)
            policy['policy_json'] = json.loads(policy['policy_json'])
            return policy
    
    @classmethod
    def get_policy_json(cls, policy_id: int) -> Optional[Dict[str, Any]]:
        """
        Get just the parsed policy JSON for a policy.
        
        Args:
            policy_id: Database ID of the policy
            
        Returns:
            Parsed policy dictionary, or None if not found
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('SELECT policy_json FROM policies WHERE id = ?', (policy_id,))
            row = c.fetchone()
            
            if not row:
                return None
            
            return json.loads(row['policy_json'])
    
    @classmethod
    def list_policies(cls) -> List[Dict[str, Any]]:
        """
        List all policies.
        
        Returns:
            List of policy dictionaries (policy_json NOT parsed for performance)
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('SELECT id, name, policy_json, created_at FROM policies ORDER BY created_at DESC')
            return [cls.dict_from_row(row) for row in c.fetchall()]
    
    # =========================================================================
    # SCAN LOG OPERATIONS
    # =========================================================================
    
    @classmethod
    def add_scan_log(cls, scan_id: int, log_entry: str, run_number: int = None):
        """
        Add a log entry to the database with run tracking.
        
        Args:
            scan_id: ID of the scan
            log_entry: Log message to record
            run_number: Run number (auto-detected if not specified)
        """
        try:
            # If run_number not specified, get the current run number
            if run_number is None:
                with cls.get_connection_context() as conn:
                    c = conn.cursor()
                    c.execute('SELECT COALESCE(MAX(run_number), 0) FROM scan_logs WHERE scan_id = ?', 
                             (scan_id,))
                    row = c.fetchone()
                    current_run = row[0] if row[0] > 0 else 1
                    run_number = current_run
            
            with cls.get_connection_context() as conn:
                c = conn.cursor()
                c.execute('INSERT INTO scan_logs (scan_id, run_number, log_entry) VALUES (?, ?, ?)', 
                         (scan_id, run_number, log_entry))
                conn.commit()
        except Exception as e:
            logger.error(f"Error adding scan log: {e}")
    
    @classmethod
    def increment_scan_run_number(cls, scan_id: int) -> int:
        """
        Increment the run number for a scan.
        
        Args:
            scan_id: ID of the scan
            
        Returns:
            New run number
        """
        try:
            with cls.get_connection_context() as conn:
                c = conn.cursor()
                c.execute('SELECT COALESCE(MAX(run_number), 0) FROM scan_logs WHERE scan_id = ?', 
                         (scan_id,))
                row = c.fetchone()
                new_run_number = (row[0] if row else 0) + 1
                return new_run_number
        except Exception as e:
            logger.error(f"Error incrementing run number: {e}")
            return 1
    
    # =========================================================================
    # REASSESSMENT OPERATIONS
    # =========================================================================
    
    @classmethod
    def create_reassessment(cls, 
                            name: str,
                            original_filename: str,
                            policy_id: int,
                            report_data: Dict[str, Any],
                            report_path: str,
                            status: str = 'Completed',
                            engagement_id: str = None) -> int:
        """
        Create a reassessment record.
        
        Args:
            name: Name of the reassessment
            original_filename: Original report filename
            policy_id: ID of the policy used
            report_data: Original report data (will be JSON serialized)
            report_path: Path to the reassessed report file
            status: Status of the reassessment
            engagement_id: Optional engagement ID to associate with
            
        Returns:
            ID of the created reassessment record
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO reassessments 
                         (name, original_report_filename, policy_id, report_data, reassessed_report_path, status, engagement_id)
                         VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (name, original_filename, policy_id, json.dumps(report_data), report_path, status, engagement_id))
            conn.commit()
            return c.lastrowid
    
    @classmethod
    def get_reassessment(cls, reassessment_id: int) -> Optional[Dict[str, Any]]:
        """
        Get a reassessment by ID.
        
        Args:
            reassessment_id: Database ID of the reassessment
            
        Returns:
            Reassessment dict or None if not found
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM reassessments WHERE id = ?', (reassessment_id,))
            return cls.dict_from_row(c.fetchone())
    
    @classmethod
    def list_reassessments(cls) -> List[Dict[str, Any]]:
        """
        List all reassessments with policy names.
        
        Returns:
            List of reassessment dictionaries with policy_name included
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''SELECT r.*, p.name as policy_name
                         FROM reassessments r
                         JOIN policies p ON r.policy_id = p.id
                         ORDER BY r.created_at DESC''')
            return [cls.dict_from_row(row) for row in c.fetchall()]
    
    # =========================================================================
    # AGGREGATION OPERATIONS
    # =========================================================================
    
    @classmethod
    def create_aggregation(cls,
                           name: str,
                           policy_id: int,
                           merge_strategy: str,
                           source_reports: List[str],
                           report_path: str,
                           report_data: Dict[str, Any],
                           status: str = 'Completed',
                           engagement_id: str = None) -> int:
        """
        Create a report aggregation record.
        
        Args:
            name: Name of the aggregation
            policy_id: ID of the policy used
            merge_strategy: Merge strategy used ('deduplicate' or 'merge_all')
            source_reports: List of source report filenames
            report_path: Path to the aggregated report file
            report_data: Aggregated report data (will be JSON serialized)
            status: Status of the aggregation
            engagement_id: Optional engagement ID to associate with
            
        Returns:
            ID of the created aggregation record
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO report_aggregations 
                         (name, policy_id, merge_strategy, source_reports, aggregated_report_path, report_data, status, engagement_id)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                     (name, policy_id, merge_strategy, json.dumps(source_reports), 
                      report_path, json.dumps(report_data), status, engagement_id))
            conn.commit()
            return c.lastrowid
    
    @classmethod
    def get_aggregation(cls, aggregation_id: int) -> Optional[Dict[str, Any]]:
        """
        Get an aggregation by ID.
        
        Args:
            aggregation_id: Database ID of the aggregation
            
        Returns:
            Aggregation dict or None if not found
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM report_aggregations WHERE id = ?', (aggregation_id,))
            return cls.dict_from_row(c.fetchone())
    
    @classmethod
    def list_aggregations(cls) -> List[Dict[str, Any]]:
        """
        List all aggregations with policy names.
        
        Returns:
            List of aggregation dictionaries with policy_name included
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''SELECT a.id, a.name, a.policy_id, a.merge_strategy, 
                                a.source_reports, a.status, a.created_at,
                                p.name as policy_name
                         FROM report_aggregations a
                         JOIN policies p ON a.policy_id = p.id
                         ORDER BY a.created_at DESC''')
            return [cls.dict_from_row(row) for row in c.fetchall()]
    
    # =========================================================================
    # CLM INTEGRATION OPERATIONS
    # =========================================================================
    
    @classmethod
    def get_clm_integration(cls, integration_id: int) -> Optional[Dict[str, Any]]:
        """
        Get a CLM integration by ID.
        
        Args:
            integration_id: Database ID of the integration
            
        Returns:
            Integration dict with parsed config_json, or None if not found
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM clm_integrations WHERE id = ?', (integration_id,))
            row = c.fetchone()
            
            if not row:
                return None
            
            integration = cls.dict_from_row(row)
            integration['config_json'] = json.loads(integration['config_json'])
            return integration
    
    @classmethod
    def get_clm_integration_raw(cls, integration_id: int) -> Optional[Dict[str, Any]]:
        """
        Get a CLM integration by ID without parsing config_json.
        
        Args:
            integration_id: Database ID of the integration
            
        Returns:
            Integration dict with raw config_json string, or None if not found
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM clm_integrations WHERE id = ?', (integration_id,))
            return cls.dict_from_row(c.fetchone())
    
    
    @classmethod
    def list_engagements_summary(cls) -> List[Dict[str, Any]]:
        """
        Quick summary list of engagements for dropdowns/selects.
        
        Returns:
            List of engagement summary dicts
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''SELECT engagement_id, customer_name, project_name, status
                         FROM engagements ORDER BY created_at DESC''')
            return [cls.dict_from_row(row) for row in c.fetchall()]
    
    @classmethod
    def list_enabled_clm_integrations(cls) -> List[Dict[str, Any]]:
        """
        List all enabled CLM integrations.
        
        Returns:
            List of integration dicts with parsed config_json
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM clm_integrations WHERE enabled = 1')
            integrations = [cls.dict_from_row(row) for row in c.fetchall()]
            
            for integration in integrations:
                integration['config_json'] = json.loads(integration['config_json'])
            
            return integrations
    
    @classmethod
    def get_clm_integration(cls, integration_id: int) -> Optional[Dict[str, Any]]:
        """
        Get a single CLM integration by ID.
        
        Args:
            integration_id: Database ID of the integration
            
        Returns:
            Integration dict or None if not found
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM clm_integrations WHERE id = ?', (integration_id,))
            row = c.fetchone()
            return cls.dict_from_row(row) if row else None
    
    @classmethod
    def update_clm_integration_status(cls, integration_id: int, status: str, enabled: bool = None):
        """
        Update CLM integration status.
        
        Args:
            integration_id: Database ID of the integration
            status: New status string
            enabled: Optional enabled flag to update
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            
            if enabled is not None:
                c.execute('''UPDATE clm_integrations 
                             SET status = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP 
                             WHERE id = ?''',
                         (status, 1 if enabled else 0, integration_id))
            else:
                c.execute('''UPDATE clm_integrations 
                             SET status = ?, last_sync = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                             WHERE id = ?''',
                         (status, integration_id))
            
            conn.commit()

    # =========================================================================
    # INVENTORY CERTIFICATE & KEY OPERATIONS
    # =========================================================================

    @classmethod
    def get_certificate(cls, fingerprint: str, connector_id: int = None) -> Optional[Dict[str, Any]]:
        """
        Get certificate from inventory by fingerprint.

        Args:
            fingerprint: SHA256 fingerprint of the certificate
            connector_id: Optional connector ID to filter by

        Returns:
            Certificate dict or None if not found
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            if connector_id:
                c.execute('SELECT * FROM certificates_inventory WHERE fingerprint_sha256 = ? AND connector_id = ?',
                         (fingerprint, connector_id))
            else:
                c.execute('SELECT * FROM certificates_inventory WHERE fingerprint_sha256 = ?', (fingerprint,))
            row = c.fetchone()
            return cls.dict_from_row(row) if row else None

    @classmethod
    def get_key(cls, key_id: str, connector_id: int = None) -> Optional[Dict[str, Any]]:
        """
        Get key from inventory by key ID.

        Args:
            key_id: Unique identifier of the key
            connector_id: Optional connector ID to filter by

        Returns:
            Key dict or None if not found
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            if connector_id:
                c.execute('SELECT * FROM keys_inventory WHERE key_identifier = ? AND connector_id = ?',
                         (key_id, connector_id))
            else:
                c.execute('SELECT * FROM keys_inventory WHERE key_identifier = ?', (key_id,))
            row = c.fetchone()
            return cls.dict_from_row(row) if row else None

    @classmethod
    def insert_certificate(cls, connector_id: int, fingerprint: str, subject_cn: str,
                          issuer_cn: str, not_after: str, key_algorithm: str,
                          key_size: int, source_type: str, normalised_data: str,
                          integration_name: str = None, days_until_expiry: int = None,
                          is_promoted: int = None, promoted_from_scan_name: str = None) -> int:
        """
        Insert a new certificate into inventory.

        Args:
            connector_id: Connector database ID
            fingerprint: SHA256 fingerprint
            subject_cn: Subject Common Name
            issuer_cn: Issuer Common Name
            not_after: Expiration date
            key_algorithm: Public key algorithm
            key_size: Key size in bits
            source_type: Source type (e.g., 'EJBCA', 'Azure')
            normalised_data: JSON-serialized normalized certificate data
            integration_name: Integration/connector name
            days_until_expiry: Days until certificate expiration
            is_promoted: Whether certificate is promoted from scan
            promoted_from_scan_name: Name of scan it was promoted from

        Returns:
            ID of inserted certificate
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO certificates_inventory
                         (connector_id, fingerprint_sha256, subject_cn, issuer_cn, not_after,
                          key_algorithm, key_size, source_type, normalised_data, integration_name,
                          days_until_expiry, is_promoted, promoted_from_scan_name, first_seen_at, last_seen_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)''',
                     (connector_id, fingerprint, subject_cn, issuer_cn, not_after,
                      key_algorithm, key_size, source_type, normalised_data, integration_name,
                      days_until_expiry, is_promoted, promoted_from_scan_name))
            conn.commit()
            return c.lastrowid

    @classmethod
    def update_certificate(cls, connector_id: int, fingerprint: str, subject_cn: str,
                          issuer_cn: str, not_after: str, key_algorithm: str,
                          key_size: int, source_type: str, normalised_data: str,
                          integration_name: str = None, days_until_expiry: int = None,
                          is_promoted: int = None, promoted_from_scan_name: str = None) -> bool:
        """
        Update an existing certificate in inventory.

        Args:
            connector_id: Connector database ID
            fingerprint: SHA256 fingerprint
            subject_cn: Subject Common Name
            issuer_cn: Issuer Common Name
            not_after: Expiration date
            key_algorithm: Public key algorithm
            key_size: Key size in bits
            source_type: Source type
            normalised_data: JSON-serialized normalized certificate data
            integration_name: Integration/connector name
            days_until_expiry: Days until certificate expiration
            is_promoted: Whether certificate is promoted from scan
            promoted_from_scan_name: Name of scan it was promoted from

        Returns:
            True if updated, False if not found
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''UPDATE certificates_inventory
                         SET subject_cn = ?, issuer_cn = ?, not_after = ?,
                             key_algorithm = ?, key_size = ?, source_type = ?,
                             normalised_data = ?, integration_name = ?, days_until_expiry = ?,
                             is_promoted = ?, promoted_from_scan_name = ?, last_seen_at = CURRENT_TIMESTAMP
                         WHERE fingerprint_sha256 = ? AND connector_id = ?''',
                     (subject_cn, issuer_cn, not_after, key_algorithm, key_size,
                      source_type, normalised_data, integration_name, days_until_expiry,
                      is_promoted, promoted_from_scan_name, fingerprint, connector_id))
            conn.commit()
            return c.rowcount > 0

    @classmethod
    def insert_key(cls, connector_id: int, key_id: str, key_label: str,
                   key_type: str, key_size: int, source_type: str, normalised_data: str) -> int:
        """
        Insert a new key into inventory.

        Args:
            connector_id: Connector database ID
            key_id: Unique key identifier
            key_label: Human-readable key label/name
            key_type: Key type (e.g., 'RSA', 'ECDSA')
            key_size: Key size in bits
            source_type: Source type (e.g., 'EJBCA', 'Azure')
            normalised_data: JSON-serialized normalized key data

        Returns:
            ID of inserted key
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO keys_inventory
                         (connector_id, key_identifier, key_name, key_type, key_size,
                          source_type, normalised_data, first_seen_at, last_seen_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)''',
                     (connector_id, key_id, key_label, key_type, key_size, source_type, normalised_data))
            conn.commit()
            return c.lastrowid

    @classmethod
    def update_key(cls, connector_id: int, key_id: str, key_label: str,
                   key_type: str, key_size: int, source_type: str, normalised_data: str) -> bool:
        """
        Update an existing key in inventory.

        Args:
            connector_id: Connector database ID
            key_id: Unique key identifier
            key_label: Human-readable key label/name
            key_type: Key type
            key_size: Key size in bits
            source_type: Source type
            normalised_data: JSON-serialized normalized key data

        Returns:
            True if updated, False if not found
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''UPDATE keys_inventory
                         SET key_name = ?, key_type = ?, key_size = ?, source_type = ?,
                             normalised_data = ?, last_seen_at = CURRENT_TIMESTAMP
                         WHERE key_identifier = ? AND connector_id = ?''',
                     (key_label, key_type, key_size, source_type, normalised_data, key_id, connector_id))
            conn.commit()
            return c.rowcount > 0

    @classmethod
    def update_connector_sync_status(cls, connector_id: int, success: bool,
                                     certificates_total: int = 0, certificates_added: int = 0,
                                     certificates_updated: int = 0, keys_total: int = 0,
                                     keys_added: int = 0, keys_updated: int = 0,
                                     error_message: str = None) -> bool:
        """
        Update connector sync status after orchestrator completes.

        Args:
            connector_id: Connector database ID
            success: Whether sync succeeded
            certificates_total: Total certificates discovered
            certificates_added: New certificates added
            certificates_updated: Existing certificates updated
            keys_total: Total keys discovered
            keys_added: New keys added
            keys_updated: Existing keys updated
            error_message: Error message if sync failed

        Returns:
            True if updated, False if not found
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()

            items_total = certificates_total + keys_total
            items_added = certificates_added + keys_added
            items_updated = certificates_updated + keys_updated

            c.execute('''UPDATE connector_sync_status
                         SET last_sync_completed = CURRENT_TIMESTAMP,
                             next_sync_due = datetime('now', '+30 minutes'),
                             last_sync_status = ?,
                             items_total = ?,
                             items_added = ?,
                             items_updated = ?,
                             consecutive_failures = CASE WHEN ? THEN 0 ELSE consecutive_failures + 1 END
                         WHERE connector_id = ?''',
                     ('success' if success else 'failed', items_total, items_added, items_updated, success, connector_id))
            conn.commit()
            return c.rowcount > 0



    # =========================================================================
    # ENGAGEMENT-SCOPED QUERY OPERATIONS
    # =========================================================================
    
    @classmethod
    def list_scans_by_engagement(cls, engagement_id: str = None) -> List[Dict[str, Any]]:
        """
        List scans, optionally filtered by engagement.

        Args:
            engagement_id: If provided, filter to this engagement only.
                          If None, returns all scans.

        Returns:
            List of scan dictionaries with config, policy, and collector names
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()

            if engagement_id:
                c.execute('''SELECT s.*, c.name as config_name, p.name as policy_name,
                             rc.collector_name as collector_name
                             FROM scans s
                             JOIN configurations c ON s.config_id = c.id
                             JOIN policies p ON s.policy_id = p.id
                             LEFT JOIN remote_collectors rc ON s.collector_id = rc.collector_id
                             WHERE s.engagement_id = ?
                             ORDER BY s.created_at DESC''', (engagement_id,))
            else:
                c.execute('''SELECT s.*, c.name as config_name, p.name as policy_name,
                             rc.collector_name as collector_name
                             FROM scans s
                             JOIN configurations c ON s.config_id = c.id
                             JOIN policies p ON s.policy_id = p.id
                             LEFT JOIN remote_collectors rc ON s.collector_id = rc.collector_id
                             ORDER BY s.created_at DESC''')

            rows = [cls.dict_from_row(row) for row in c.fetchall()]

            # Deserialize collector_results JSON string to dict for each scan
            for row in rows:
                if row.get('collector_results'):
                    try:
                        import json
                        row['collector_results'] = json.loads(row['collector_results'])
                    except (json.JSONDecodeError, TypeError):
                        row['collector_results'] = None

            return rows
    
    @classmethod
    def list_configurations_by_engagement(cls, engagement_id: str = None) -> List[Dict[str, Any]]:
        """
        List configurations, optionally filtered by engagement.
        
        Args:
            engagement_id: If provided, filter to this engagement only.
                          If None, returns all configurations.
        
        Returns:
            List of configuration dictionaries
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            
            if engagement_id:
                c.execute('''SELECT id, name, config_json, engagement_id, created_at, updated_at
                             FROM configurations
                             WHERE engagement_id = ?
                             ORDER BY created_at DESC''', (engagement_id,))
            else:
                c.execute('''SELECT id, name, config_json, engagement_id, created_at, updated_at
                             FROM configurations
                             ORDER BY created_at DESC''')
            
            return [cls.dict_from_row(row) for row in c.fetchall()]
    
    @classmethod
    def list_reassessments_by_engagement(cls, engagement_id: str = None) -> List[Dict[str, Any]]:
        """
        List reassessments, optionally filtered by engagement.
        
        Args:
            engagement_id: If provided, filter to this engagement only.
                          If None, returns all reassessments.
        
        Returns:
            List of reassessment dictionaries with policy_name included
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            
            if engagement_id:
                c.execute('''SELECT r.*, p.name as policy_name
                             FROM reassessments r
                             JOIN policies p ON r.policy_id = p.id
                             WHERE r.engagement_id = ?
                             ORDER BY r.created_at DESC''', (engagement_id,))
            else:
                c.execute('''SELECT r.*, p.name as policy_name
                             FROM reassessments r
                             JOIN policies p ON r.policy_id = p.id
                             ORDER BY r.created_at DESC''')
            
            return [cls.dict_from_row(row) for row in c.fetchall()]
    
    @classmethod
    def list_aggregations_by_engagement(cls, engagement_id: str = None) -> List[Dict[str, Any]]:
        """
        List aggregations, optionally filtered by engagement.
        
        Args:
            engagement_id: If provided, filter to this engagement only.
                          If None, returns all aggregations.
        
        Returns:
            List of aggregation dictionaries with policy_name included
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            
            if engagement_id:
                c.execute('''SELECT a.id, a.name, a.policy_id, a.merge_strategy, 
                                    a.source_reports, a.status, a.created_at, a.engagement_id,
                                    p.name as policy_name
                             FROM report_aggregations a
                             JOIN policies p ON a.policy_id = p.id
                             WHERE a.engagement_id = ?
                             ORDER BY a.created_at DESC''', (engagement_id,))
            else:
                c.execute('''SELECT a.id, a.name, a.policy_id, a.merge_strategy, 
                                    a.source_reports, a.status, a.created_at, a.engagement_id,
                                    p.name as policy_name
                             FROM report_aggregations a
                             JOIN policies p ON a.policy_id = p.id
                             ORDER BY a.created_at DESC''')
            
            return [cls.dict_from_row(row) for row in c.fetchall()]
    
    @classmethod
    def get_engagement_report_summary(cls, engagement_id: str) -> Dict[str, Any]:
        """
        Get a summary of all reports associated with an engagement.
        
        Args:
            engagement_id: The engagement ID to query
            
        Returns:
            Dict with counts and lists of associated reports by type
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            
            # Get scans
            c.execute('''SELECT id, name, status, report_path, last_run
                         FROM scans WHERE engagement_id = ?
                         ORDER BY last_run DESC''', (engagement_id,))
            scans = [cls.dict_from_row(row) for row in c.fetchall()]
            
            # Get configurations
            c.execute('''SELECT id, name, created_at
                         FROM configurations WHERE engagement_id = ?
                         ORDER BY created_at DESC''', (engagement_id,))
            configurations = [cls.dict_from_row(row) for row in c.fetchall()]
            
            # Get reassessments
            c.execute('''SELECT id, name, status, reassessed_report_path, created_at
                         FROM reassessments WHERE engagement_id = ?
                         ORDER BY created_at DESC''', (engagement_id,))
            reassessments = [cls.dict_from_row(row) for row in c.fetchall()]
            
            # Get aggregations
            c.execute('''SELECT id, name, status, aggregated_report_path, created_at
                         FROM report_aggregations WHERE engagement_id = ?
                         ORDER BY created_at DESC''', (engagement_id,))
            aggregations = [cls.dict_from_row(row) for row in c.fetchall()]
            
            return {
                'engagement_id': engagement_id,
                'scans': scans,
                'scan_count': len(scans),
                'configurations': configurations,
                'configuration_count': len(configurations),
                'reassessments': reassessments,
                'reassessment_count': len(reassessments),
                'aggregations': aggregations,
                'aggregation_count': len(aggregations),
                'total_reports': len(scans) + len(reassessments) + len(aggregations)
            }
    
    @classmethod
    def update_scan_engagement(cls, scan_id: int, engagement_id: str) -> bool:
        """
        Associate a scan with an engagement.
        
        Args:
            scan_id: Database ID of the scan
            engagement_id: Engagement ID to associate
            
        Returns:
            True if updated successfully
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''UPDATE scans 
                         SET engagement_id = ?, updated_at = CURRENT_TIMESTAMP 
                         WHERE id = ?''', (engagement_id, scan_id))
            conn.commit()
            return c.rowcount > 0
    
    @classmethod
    def update_configuration_engagement(cls, config_id: int, engagement_id: str) -> bool:
        """
        Associate a configuration with an engagement.
        
        Args:
            config_id: Database ID of the configuration
            engagement_id: Engagement ID to associate
            
        Returns:
            True if updated successfully
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''UPDATE configurations 
                         SET engagement_id = ?, updated_at = CURRENT_TIMESTAMP 
                         WHERE id = ?''', (engagement_id, config_id))
            conn.commit()
            return c.rowcount > 0
    
    @classmethod
    def update_reassessment_engagement(cls, reassessment_id: int, engagement_id: str) -> bool:
        """
        Associate a reassessment with an engagement.
        
        Args:
            reassessment_id: Database ID of the reassessment
            engagement_id: Engagement ID to associate
            
        Returns:
            True if updated successfully
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''UPDATE reassessments 
                         SET engagement_id = ? 
                         WHERE id = ?''', (engagement_id, reassessment_id))
            conn.commit()
            return c.rowcount > 0
    
    @classmethod
    def update_aggregation_engagement(cls, aggregation_id: int, engagement_id: str) -> bool:
        """
        Associate an aggregation with an engagement.

        Args:
            aggregation_id: Database ID of the aggregation
            engagement_id: Engagement ID to associate

        Returns:
            True if updated successfully
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''UPDATE report_aggregations
                         SET engagement_id = ?
                         WHERE id = ?''', (engagement_id, aggregation_id))
            conn.commit()
            return c.rowcount > 0

    # =========================================================================
    # ASSET RELATIONSHIP OPERATIONS
    # =========================================================================

    @classmethod
    def upsert_relationship(cls, parent_id: str, parent_type: str, child_id: str,
                           child_type: str, relationship_type: str,
                           confidence: float = 1.0, source: str = None,
                           metadata: Dict[str, Any] = None) -> bool:
        """
        Create or update asset relationship.

        Args:
            parent_id: Parent asset ID (fingerprint, key_id, etc.)
            parent_type: Type of parent asset ('certificate' or 'key')
            child_id: Child asset ID
            child_type: Type of child asset ('certificate' or 'key')
            relationship_type: Type of relationship (ca_to_cert, cert_to_cert, etc.)
            confidence: Confidence score (0.0-1.0)
            source: Source of the relationship (tls_certificate_chain, ejbca_metadata, etc.)
            metadata: Optional JSON-serializable metadata dict

        Returns:
            True if relationship was inserted/updated, False otherwise
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()

            metadata_json = json.dumps(metadata) if metadata else None

            c.execute('''INSERT INTO asset_relationships
                        (parent_asset_id, parent_asset_type, child_asset_id, child_asset_type,
                         relationship_type, confidence, source, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(parent_asset_id, child_asset_id, relationship_type)
                        DO UPDATE SET
                            confidence = excluded.confidence,
                            source = excluded.source,
                            metadata = excluded.metadata,
                            discovered_at = CURRENT_TIMESTAMP''',
                     (parent_id, parent_type, child_id, child_type, relationship_type,
                      confidence, source, metadata_json))

            conn.commit()
            return c.rowcount > 0

    @classmethod
    def get_child_relationships(cls, asset_id: str, relationship_type: str = None) -> List[Dict[str, Any]]:
        """
        Get all assets that depend on this asset (child relationships).

        Args:
            asset_id: Parent asset ID
            relationship_type: Optional - filter by relationship type

        Returns:
            List of child relationship dicts
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()

            if relationship_type:
                c.execute('''SELECT child_asset_id, child_asset_type, relationship_type,
                                   confidence, source, metadata, discovered_at
                            FROM asset_relationships
                            WHERE parent_asset_id = ? AND relationship_type = ?
                            ORDER BY discovered_at DESC''',
                         (asset_id, relationship_type))
            else:
                c.execute('''SELECT child_asset_id, child_asset_type, relationship_type,
                                   confidence, source, metadata, discovered_at
                            FROM asset_relationships
                            WHERE parent_asset_id = ?
                            ORDER BY discovered_at DESC''',
                         (asset_id,))

            return [dict(row) for row in c.fetchall()]

    @classmethod
    def get_parent_relationships(cls, asset_id: str, relationship_type: str = None) -> List[Dict[str, Any]]:
        """
        Get all assets this asset depends on (parent relationships).

        Args:
            asset_id: Child asset ID
            relationship_type: Optional - filter by relationship type

        Returns:
            List of parent relationship dicts
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()

            if relationship_type:
                c.execute('''SELECT parent_asset_id, parent_asset_type, relationship_type,
                                   confidence, source, metadata, discovered_at
                            FROM asset_relationships
                            WHERE child_asset_id = ? AND relationship_type = ?
                            ORDER BY discovered_at DESC''',
                         (asset_id, relationship_type))
            else:
                c.execute('''SELECT parent_asset_id, parent_asset_type, relationship_type,
                                   confidence, source, metadata, discovered_at
                            FROM asset_relationships
                            WHERE child_asset_id = ?
                            ORDER BY discovered_at DESC''',
                         (asset_id,))

            return [dict(row) for row in c.fetchall()]

    @classmethod
    def delete_relationship(cls, parent_id: str, child_id: str, relationship_type: str) -> bool:
        """
        Delete a specific relationship.

        Args:
            parent_id: Parent asset ID
            child_id: Child asset ID
            relationship_type: Relationship type to delete

        Returns:
            True if relationship was deleted, False otherwise
        """
        with cls.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''DELETE FROM asset_relationships
                        WHERE parent_asset_id = ? AND child_asset_id = ? AND relationship_type = ?''',
                     (parent_id, child_id, relationship_type))
            conn.commit()
            return c.rowcount > 0
