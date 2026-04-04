"""
Remote Collector Service for CAIP

Manages edge/remote collectors that perform distributed cryptographic asset discovery.
Provides:
- Bootstrap token generation and validation
- Collector registration and lifecycle management
- API key generation and validation
- Heartbeat processing and status tracking
- Report reception and storage

Authentication Flow:
1. Admin generates bootstrap token (24h TTL, single-use)
2. Collector registers using bootstrap token
3. Collector receives API key for ongoing authentication
4. Future: Upgrade to mTLS certificates
"""

import os
import time
import secrets
import hashlib
import hmac
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger('caip.operational')
security_logger = logging.getLogger('caip.security')


class TransmissionMode(Enum):
    """Collector transmission modes for data privacy control."""
    FULL = 'full'              # Send all certificate data
    SELECTIVE = 'selective'    # Send metadata + findings, cache full data locally
    ANONYMIZED = 'anonymized'  # Send only hashes + findings, full anonymisation


class CollectorStatus(Enum):
    """Collector lifecycle status."""
    PENDING = 'pending'            # Registered but not yet connected
    ACTIVE = 'active'              # Online and healthy
    DEGRADED = 'degraded'          # Online but with issues
    OFFLINE = 'offline'            # Not responding to heartbeats
    SUSPENDED = 'suspended'        # Administratively disabled
    DECOMMISSIONED = 'decommissioned'  # Permanently removed


@dataclass
class BootstrapToken:
    """Bootstrap token for collector registration."""
    token_hash: str
    token_prefix: str
    collector_name: str
    organization: str
    location: Optional[str]
    environment: str
    transmission_mode: str
    expires_at: datetime
    max_uses: int
    current_uses: int
    ip_restriction: Optional[str]
    status: str
    created_by: str
    created_at: datetime


@dataclass
class RemoteCollector:
    """Registered remote collector."""
    id: int
    collector_id: str
    collector_name: str
    organization: str
    location: Optional[str]
    environment: str
    transmission_mode: str
    api_key_hash: str
    api_key_prefix: str
    status: str
    last_heartbeat: Optional[datetime]
    last_report: Optional[datetime]
    report_count: int
    last_source_ip: Optional[str]
    registered_at: datetime


class RemoteCollectorService:
    """
    Service layer for remote collector management.

    Handles:
    - Bootstrap token generation and validation
    - Collector registration
    - API key generation and validation
    - Heartbeat processing
    - Report storage
    """

    # Token configuration
    TOKEN_PREFIX_LENGTH = 6
    TOKEN_RANDOM_LENGTH = 24
    TOKEN_DEFAULT_TTL_HOURS = 24

    # API key configuration
    API_KEY_PREFIX_LENGTH = 8
    API_KEY_LENGTH = 32

    # Heartbeat configuration
    HEARTBEAT_TIMEOUT_SECONDS = 300  # 5 minutes
    OFFLINE_THRESHOLD_SECONDS = 900   # 15 minutes

    @classmethod
    def init_tables(cls, db_service):
        """
        Initialize remote collector tables in database.

        Called during database initialization to create required tables.

        Args:
            db_service: DatabaseService class reference
        """
        conn = db_service.get_connection()
        c = conn.cursor()

        # Bootstrap tokens table
        c.execute('''CREATE TABLE IF NOT EXISTS remote_collector_tokens
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      token_hash TEXT UNIQUE NOT NULL,
                      token_prefix TEXT NOT NULL,
                      collector_name TEXT NOT NULL,
                      organization TEXT NOT NULL,
                      location TEXT,
                      environment TEXT DEFAULT 'production',
                      transmission_mode TEXT DEFAULT 'selective',
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      expires_at TIMESTAMP NOT NULL,
                      max_uses INTEGER DEFAULT 1,
                      current_uses INTEGER DEFAULT 0,
                      ip_restriction TEXT,
                      status TEXT DEFAULT 'active',
                      created_by TEXT NOT NULL)''')

        # Remote collectors table
        c.execute('''CREATE TABLE IF NOT EXISTS remote_collectors
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      collector_id TEXT UNIQUE NOT NULL,
                      collector_name TEXT NOT NULL,
                      organization TEXT NOT NULL,
                      location TEXT,
                      environment TEXT DEFAULT 'production',
                      transmission_mode TEXT DEFAULT 'selective',
                      api_key_hash TEXT NOT NULL,
                      api_key_prefix TEXT NOT NULL,
                      status TEXT DEFAULT 'pending',
                      last_heartbeat TIMESTAMP,
                      last_report TIMESTAMP,
                      report_count INTEGER DEFAULT 0,
                      last_source_ip TEXT,
                      ip_whitelist TEXT,
                      config_json TEXT,
                      registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      registered_by_token TEXT,
                      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

        # Remote collector reports table
        c.execute('''CREATE TABLE IF NOT EXISTS remote_collector_reports
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      collector_id TEXT NOT NULL,
                      scan_id TEXT NOT NULL,
                      transmission_mode TEXT NOT NULL,
                      certificate_count INTEGER DEFAULT 0,
                      findings_count INTEGER DEFAULT 0,
                      risk_score REAL,
                      report_data TEXT NOT NULL,
                      received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      source_ip TEXT,
                      FOREIGN KEY(collector_id) REFERENCES remote_collectors(collector_id))''')

        # Remote collector audit log
        c.execute('''CREATE TABLE IF NOT EXISTS remote_collector_audit
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      collector_id TEXT,
                      event_type TEXT NOT NULL,
                      event_details TEXT,
                      source_ip TEXT,
                      performed_by TEXT,
                      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

        # Collector configurations (centrally managed)
        c.execute('''CREATE TABLE IF NOT EXISTS collector_configs
                     (collector_id TEXT PRIMARY KEY,
                      config_version INTEGER DEFAULT 1,
                      transmission_mode TEXT DEFAULT 'selective',
                      scan_targets TEXT,
                      schedule TEXT,
                      policy_id INTEGER,
                      heartbeat_interval INTEGER DEFAULT 60,
                      enabled_collectors TEXT,
                      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      updated_by TEXT,
                      FOREIGN KEY(collector_id) REFERENCES remote_collectors(collector_id))''')

        # Add enabled_collectors column if it doesn't exist (migration)
        try:
            c.execute('PRAGMA table_info(collector_configs)').fetchall()
            cols = [col[1] for col in c.execute('PRAGMA table_info(collector_configs)').fetchall()]
            if 'enabled_collectors' not in cols:
                c.execute('ALTER TABLE collector_configs ADD COLUMN enabled_collectors TEXT')
                logger.info("Added enabled_collectors column to collector_configs table")
        except Exception as e:
            logger.debug(f"Column migration check: {e}")

        # Job queue for collectors
        c.execute('''CREATE TABLE IF NOT EXISTS collector_jobs
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      collector_id TEXT NOT NULL,
                      job_type TEXT NOT NULL,
                      priority TEXT DEFAULT 'normal',
                      status TEXT DEFAULT 'pending',
                      payload TEXT,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      created_by TEXT,
                      acknowledged_at TIMESTAMP,
                      started_at TIMESTAMP,
                      completed_at TIMESTAMP,
                      result TEXT,
                      error_message TEXT,
                      FOREIGN KEY(collector_id) REFERENCES remote_collectors(collector_id))''')

        # Policy templates (reusable across collectors)
        c.execute('''CREATE TABLE IF NOT EXISTS collector_policies
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name TEXT NOT NULL UNIQUE,
                      description TEXT,
                      rules TEXT,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      created_by TEXT)''')

        # Create indexes
        c.execute('''CREATE INDEX IF NOT EXISTS idx_rc_tokens_status
                     ON remote_collector_tokens(status)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_rc_tokens_expires
                     ON remote_collector_tokens(expires_at)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_rc_collectors_status
                     ON remote_collectors(status)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_rc_collectors_heartbeat
                     ON remote_collectors(last_heartbeat)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_rc_reports_collector
                     ON remote_collector_reports(collector_id)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_rc_reports_received
                     ON remote_collector_reports(received_at)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_rc_audit_collector
                     ON remote_collector_audit(collector_id)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_rc_audit_timestamp
                     ON remote_collector_audit(timestamp)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_collector_jobs_status
                     ON collector_jobs(collector_id, status)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_collector_jobs_created
                     ON collector_jobs(created_at)''')

        conn.commit()
        conn.close()
        logger.info("Remote collector tables initialized")

    # =========================================================================
    # BOOTSTRAP TOKEN OPERATIONS
    # =========================================================================

    @classmethod
    def generate_bootstrap_token(
        cls,
        db_service,
        collector_name: str,
        organization: str,
        created_by: str,
        location: Optional[str] = None,
        environment: str = 'production',
        transmission_mode: str = 'selective',
        ttl_hours: int = 24,
        max_uses: int = 1,
        ip_restriction: Optional[str] = None,
        engagement_ca_id: Optional[str] = None
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Generate a bootstrap token for collector registration.

        Args:
            db_service: DatabaseService class
            collector_name: Human-readable name for the collector
            organization: Organization/customer name
            created_by: Username of admin creating the token
            location: Physical location (optional)
            environment: Environment type (production/staging/dev)
            transmission_mode: Data transmission mode
            ttl_hours: Token validity in hours
            max_uses: Maximum number of registrations with this token
            ip_restriction: CIDR restriction for registration (optional)
            engagement_ca_id: Engagement CA ID for certificate issuance (optional)

        Returns:
            Tuple of (plaintext_token, token_metadata)

        Note:
            The plaintext token is returned only once and must be securely
            transmitted to the edge admin. Only the hash is stored.
            If engagement_ca_id is provided, the collector will be bound to
            that CA for certificate issuance during registration.
        """
        # Generate token: prefix.random
        prefix = secrets.token_hex(cls.TOKEN_PREFIX_LENGTH // 2)
        random_part = secrets.token_hex(cls.TOKEN_RANDOM_LENGTH // 2)
        plaintext_token = f"{prefix}.{random_part}"

        # Hash the token for storage
        token_hash = hashlib.sha256(plaintext_token.encode()).hexdigest()

        # Calculate expiry
        expires_at = datetime.now() + timedelta(hours=ttl_hours)

        # Store in database
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO remote_collector_tokens
                (token_hash, token_prefix, collector_name, organization, location,
                 environment, transmission_mode, expires_at, max_uses, ip_restriction,
                 engagement_ca_id, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                token_hash, prefix, collector_name, organization, location,
                environment, transmission_mode, expires_at.isoformat(), max_uses,
                ip_restriction, engagement_ca_id, created_by
            ))
            token_id = c.lastrowid
            conn.commit()

        # Log the event
        cls._log_audit_event(
            db_service,
            collector_id=None,
            event_type='token_generated',
            event_details={
                'token_prefix': prefix,
                'collector_name': collector_name,
                'organization': organization,
                'ttl_hours': ttl_hours,
                'max_uses': max_uses
            },
            performed_by=created_by
        )

        security_logger.info(f"Bootstrap token generated: {prefix}... for {collector_name}")

        token_metadata = {
            'id': token_id,
            'token_prefix': prefix,
            'collector_name': collector_name,
            'organization': organization,
            'location': location,
            'environment': environment,
            'transmission_mode': transmission_mode,
            'expires_at': expires_at.isoformat(),
            'max_uses': max_uses,
            'ip_restriction': ip_restriction,
            'engagement_ca_id': engagement_ca_id
        }

        return plaintext_token, token_metadata

    @classmethod
    def validate_bootstrap_token(
        cls,
        db_service,
        token: str,
        source_ip: Optional[str] = None
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Validate a bootstrap token for registration.

        Args:
            db_service: DatabaseService class
            token: Plaintext bootstrap token
            source_ip: IP address of registration request (optional)

        Returns:
            Tuple of (is_valid, token_data, error_message)
        """
        # Hash the provided token
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT * FROM remote_collector_tokens
                WHERE token_hash = ?
            ''', (token_hash,))
            row = c.fetchone()

            if not row:
                security_logger.warning(f"Invalid bootstrap token attempted from {source_ip}")
                return False, None, "Invalid token"

            token_data = dict(row)

            # Check status
            if token_data['status'] != 'active':
                security_logger.warning(f"Inactive token used: {token_data['token_prefix']}... status={token_data['status']}")
                return False, None, f"Token is {token_data['status']}"

            # Check expiry
            expires_at = datetime.fromisoformat(token_data['expires_at'])
            if datetime.now() > expires_at:
                # Mark as expired
                c.execute('''
                    UPDATE remote_collector_tokens
                    SET status = 'expired'
                    WHERE token_hash = ?
                ''', (token_hash,))
                conn.commit()
                security_logger.warning(f"Expired token used: {token_data['token_prefix']}...")
                return False, None, "Token has expired"

            # Check usage limit
            if token_data['current_uses'] >= token_data['max_uses']:
                c.execute('''
                    UPDATE remote_collector_tokens
                    SET status = 'exhausted'
                    WHERE token_hash = ?
                ''', (token_hash,))
                conn.commit()
                security_logger.warning(f"Exhausted token used: {token_data['token_prefix']}...")
                return False, None, "Token usage limit reached"

            # Check IP restriction
            if token_data['ip_restriction'] and source_ip:
                if not cls._ip_matches_cidr(source_ip, token_data['ip_restriction']):
                    security_logger.warning(
                        f"Token {token_data['token_prefix']}... used from unauthorized IP: {source_ip}"
                    )
                    return False, None, "Registration not allowed from this IP"

            return True, token_data, None

    @classmethod
    def consume_bootstrap_token(cls, db_service, token_hash: str):
        """
        Increment usage count for a bootstrap token.

        Called after successful registration.
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                UPDATE remote_collector_tokens
                SET current_uses = current_uses + 1
                WHERE token_hash = ?
            ''', (token_hash,))

            # Check if exhausted
            c.execute('''
                UPDATE remote_collector_tokens
                SET status = 'exhausted'
                WHERE token_hash = ? AND current_uses >= max_uses
            ''', (token_hash,))

            conn.commit()

    @classmethod
    def list_bootstrap_tokens(cls, db_service, include_expired: bool = False) -> List[Dict[str, Any]]:
        """
        List all bootstrap tokens.

        Args:
            db_service: DatabaseService class
            include_expired: Whether to include expired/exhausted tokens

        Returns:
            List of token metadata (without hashes)
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()

            if include_expired:
                c.execute('''
                    SELECT id, token_prefix, collector_name, organization, location,
                           environment, transmission_mode, created_at, expires_at,
                           max_uses, current_uses, ip_restriction, status, created_by
                    FROM remote_collector_tokens
                    ORDER BY created_at DESC
                ''')
            else:
                c.execute('''
                    SELECT id, token_prefix, collector_name, organization, location,
                           environment, transmission_mode, created_at, expires_at,
                           max_uses, current_uses, ip_restriction, status, created_by
                    FROM remote_collector_tokens
                    WHERE status = 'active'
                    ORDER BY created_at DESC
                ''')

            return [dict(row) for row in c.fetchall()]

    @classmethod
    def revoke_bootstrap_token(cls, db_service, token_id: int, revoked_by: str) -> bool:
        """Revoke a bootstrap token."""
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                UPDATE remote_collector_tokens
                SET status = 'revoked'
                WHERE id = ? AND status = 'active'
            ''', (token_id,))
            conn.commit()

            if c.rowcount > 0:
                cls._log_audit_event(
                    db_service,
                    collector_id=None,
                    event_type='token_revoked',
                    event_details={'token_id': token_id},
                    performed_by=revoked_by
                )
                return True
            return False

    # =========================================================================
    # COLLECTOR REGISTRATION
    # =========================================================================

    @classmethod
    def register_collector(
        cls,
        db_service,
        token: str,
        collector_id: str,
        source_ip: Optional[str] = None
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Register a new collector using a bootstrap token.

        Args:
            db_service: DatabaseService class
            token: Bootstrap token
            collector_id: Requested collector ID
            source_ip: IP address of registration request

        Returns:
            Tuple of (success, registration_data, error_message)

            On success, registration_data contains:
            - collector_id: Assigned collector ID
            - api_key: API key for authentication (shown once only)
            - config: Collector configuration
        """
        # Validate token
        is_valid, token_data, error = cls.validate_bootstrap_token(db_service, token, source_ip)
        if not is_valid:
            return False, None, error

        token_hash = hashlib.sha256(token.encode()).hexdigest()

        # Check if collector_id already exists
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('SELECT id FROM remote_collectors WHERE collector_id = ?', (collector_id,))
            if c.fetchone():
                return False, None, f"Collector ID already registered: {collector_id}"

        # Generate API key
        api_key_prefix = secrets.token_hex(cls.API_KEY_PREFIX_LENGTH // 2)
        api_key_secret = secrets.token_hex(cls.API_KEY_LENGTH // 2)
        api_key = f"{api_key_prefix}.{api_key_secret}"
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        # Create collector record
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO remote_collectors
                (collector_id, collector_name, organization, location, environment,
                 transmission_mode, api_key_hash, api_key_prefix, status,
                 last_source_ip, registered_by_token)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                collector_id,
                token_data['collector_name'],
                token_data['organization'],
                token_data['location'],
                token_data['environment'],
                token_data['transmission_mode'],
                api_key_hash,
                api_key_prefix,
                'active',
                source_ip,
                token_data['token_prefix']
            ))
            conn.commit()

        # Consume the token
        cls.consume_bootstrap_token(db_service, token_hash)

        # Log the event
        cls._log_audit_event(
            db_service,
            collector_id=collector_id,
            event_type='collector_registered',
            event_details={
                'collector_name': token_data['collector_name'],
                'organization': token_data['organization'],
                'transmission_mode': token_data['transmission_mode'],
                'registered_by_token': token_data['token_prefix']
            },
            source_ip=source_ip,
            performed_by='system'
        )

        security_logger.info(f"Collector registered: {collector_id} ({token_data['collector_name']})")

        registration_data = {
            'collector_id': collector_id,
            'api_key': api_key,  # Shown only once
            'collector_name': token_data['collector_name'],
            'organization': token_data['organization'],
            'transmission_mode': token_data['transmission_mode'],
            'config': {
                'heartbeat_interval_seconds': 60,
                'report_endpoint': '/api/remote/report',
                'heartbeat_endpoint': '/api/remote/heartbeat'
            }
        }

        return True, registration_data, None

    # =========================================================================
    # API KEY VALIDATION
    # =========================================================================

    @classmethod
    def validate_api_key(
        cls,
        db_service,
        api_key: str,
        source_ip: Optional[str] = None
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Validate an API key for collector authentication.

        Args:
            db_service: DatabaseService class
            api_key: API key to validate
            source_ip: Source IP of request (optional)

        Returns:
            Tuple of (is_valid, collector_data, error_message)
        """
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT * FROM remote_collectors
                WHERE api_key_hash = ?
            ''', (api_key_hash,))
            row = c.fetchone()

            if not row:
                security_logger.warning(f"Invalid API key attempted from {source_ip}")
                return False, None, "Invalid API key"

            collector = dict(row)

            # Check status
            if collector['status'] not in ('active', 'degraded'):
                security_logger.warning(
                    f"API key for {collector['collector_id']} used but status is {collector['status']}"
                )
                return False, None, f"Collector is {collector['status']}"

            # Check IP whitelist if configured
            if collector['ip_whitelist'] and source_ip:
                whitelist = json.loads(collector['ip_whitelist'])
                if not any(cls._ip_matches_cidr(source_ip, cidr) for cidr in whitelist):
                    security_logger.warning(
                        f"Collector {collector['collector_id']} request from unauthorized IP: {source_ip}"
                    )
                    return False, None, "Request not allowed from this IP"

            return True, collector, None

    # =========================================================================
    # HEARTBEAT OPERATIONS
    # =========================================================================

    @classmethod
    def process_heartbeat(
        cls,
        db_service,
        collector_id: str,
        heartbeat_data: Dict[str, Any],
        source_ip: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Process a heartbeat from a collector.

        Args:
            db_service: DatabaseService class
            collector_id: Collector ID
            heartbeat_data: Heartbeat payload
            source_ip: Source IP of request

        Returns:
            Response data including any configuration updates
        """
        now = datetime.now()

        with db_service.get_connection_context() as conn:
            c = conn.cursor()

            # Update collector status
            c.execute('''
                UPDATE remote_collectors
                SET last_heartbeat = ?,
                    last_source_ip = ?,
                    status = 'active',
                    updated_at = ?
                WHERE collector_id = ?
            ''', (now.isoformat(), source_ip, now.isoformat(), collector_id))
            conn.commit()

        # Build response
        response = {
            'status': 'ok',
            'server_time': now.isoformat(),
            'config_changed': False,
            'policy_version': None  # TODO: Implement policy sync
        }

        return response

    @classmethod
    def update_collector_statuses(cls, db_service):
        """
        Update status of collectors based on heartbeat times.

        Should be called periodically (e.g., every minute) to detect offline collectors.
        """
        now = datetime.now()
        offline_threshold = now - timedelta(seconds=cls.OFFLINE_THRESHOLD_SECONDS)

        with db_service.get_connection_context() as conn:
            c = conn.cursor()

            # Mark collectors as offline if no recent heartbeat
            c.execute('''
                UPDATE remote_collectors
                SET status = 'offline'
                WHERE status = 'active'
                AND last_heartbeat < ?
            ''', (offline_threshold.isoformat(),))

            updated = c.rowcount
            conn.commit()

            if updated > 0:
                logger.warning(f"Marked {updated} collectors as offline (no heartbeat)")

    # =========================================================================
    # REPORT OPERATIONS
    # =========================================================================

    @classmethod
    def store_report(
        cls,
        db_service,
        collector_id: str,
        scan_id: str,
        transmission_mode: str,
        report_data: Dict[str, Any],
        source_ip: Optional[str] = None
    ) -> int:
        """
        Store a report from a collector.

        Args:
            db_service: DatabaseService class
            collector_id: Collector ID
            scan_id: Unique scan identifier
            transmission_mode: Transmission mode used
            report_data: Report payload
            source_ip: Source IP of request

        Returns:
            Report ID
        """
        certificate_count = report_data.get('certificate_count', 0)
        findings = report_data.get('findings', [])
        findings_count = len(findings) if isinstance(findings, list) else 0
        risk_score = report_data.get('risk_score')

        with db_service.get_connection_context() as conn:
            c = conn.cursor()

            # Store report
            c.execute('''
                INSERT INTO remote_collector_reports
                (collector_id, scan_id, transmission_mode, certificate_count,
                 findings_count, risk_score, report_data, source_ip)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                collector_id, scan_id, transmission_mode, certificate_count,
                findings_count, risk_score, json.dumps(report_data), source_ip
            ))
            report_id = c.lastrowid

            # Update collector stats
            c.execute('''
                UPDATE remote_collectors
                SET last_report = ?,
                    report_count = report_count + 1,
                    updated_at = ?
                WHERE collector_id = ?
            ''', (datetime.now().isoformat(), datetime.now().isoformat(), collector_id))

            conn.commit()

        # Log the event
        cls._log_audit_event(
            db_service,
            collector_id=collector_id,
            event_type='report_received',
            event_details={
                'scan_id': scan_id,
                'transmission_mode': transmission_mode,
                'certificate_count': certificate_count,
                'findings_count': findings_count,
                'risk_score': risk_score
            },
            source_ip=source_ip,
            performed_by='system'
        )

        logger.info(f"Report stored: {scan_id} from {collector_id} ({certificate_count} certs, {findings_count} findings)")

        return report_id

    # =========================================================================
    # COLLECTOR QUERIES
    # =========================================================================

    @classmethod
    def get_collector(cls, db_service, collector_id: str) -> Optional[Dict[str, Any]]:
        """Get collector by ID."""
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM remote_collectors WHERE collector_id = ?', (collector_id,))
            row = c.fetchone()
            return dict(row) if row else None

    @classmethod
    def list_collectors(
        cls,
        db_service,
        status_filter: Optional[str] = None,
        include_decommissioned: bool = False
    ) -> List[Dict[str, Any]]:
        """
        List all collectors.

        Args:
            db_service: DatabaseService class
            status_filter: Filter by status (optional)
            include_decommissioned: Whether to include decommissioned collectors

        Returns:
            List of collector records (without sensitive data)
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()

            query = '''
                SELECT id, collector_id, collector_name, organization, location,
                       environment, transmission_mode, api_key_prefix, status,
                       last_heartbeat, last_report, report_count, last_source_ip,
                       registered_at, updated_at
                FROM remote_collectors
            '''
            conditions = []
            params = []

            if status_filter:
                conditions.append('status = ?')
                params.append(status_filter)
            elif not include_decommissioned:
                conditions.append("status != 'decommissioned'")

            if conditions:
                query += ' WHERE ' + ' AND '.join(conditions)

            query += ' ORDER BY collector_name'

            c.execute(query, params)
            return [dict(row) for row in c.fetchall()]

    @classmethod
    def get_collector_reports(
        cls,
        db_service,
        collector_id: str,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """Get recent reports for a collector."""
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT id, collector_id, scan_id, transmission_mode, certificate_count,
                       findings_count, risk_score, received_at
                FROM remote_collector_reports
                WHERE collector_id = ?
                ORDER BY received_at DESC
                LIMIT ?
            ''', (collector_id, limit))
            return [dict(row) for row in c.fetchall()]

    @classmethod
    def get_report(cls, db_service, report_id: int) -> Optional[Dict[str, Any]]:
        """Get a specific report by ID."""
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM remote_collector_reports WHERE id = ?', (report_id,))
            row = c.fetchone()
            if row:
                report = dict(row)
                report['report_data'] = json.loads(report['report_data'])
                return report
            return None

    @classmethod
    def get_statistics(cls, db_service) -> Dict[str, Any]:
        """Get aggregate statistics across all collectors."""
        with db_service.get_connection_context() as conn:
            c = conn.cursor()

            # Collector counts by status
            c.execute('''
                SELECT status, COUNT(*) as count
                FROM remote_collectors
                WHERE status != 'decommissioned'
                GROUP BY status
            ''')
            status_counts = {row['status']: row['count'] for row in c.fetchall()}

            # Total collectors
            total_collectors = sum(status_counts.values())

            # Report statistics
            c.execute('''
                SELECT
                    COUNT(*) as total_reports,
                    SUM(certificate_count) as total_certificates,
                    SUM(findings_count) as total_findings,
                    AVG(risk_score) as avg_risk_score
                FROM remote_collector_reports
            ''')
            report_stats = dict(c.fetchone())

            # Mode distribution
            c.execute('''
                SELECT transmission_mode, COUNT(*) as count
                FROM remote_collectors
                WHERE status != 'decommissioned'
                GROUP BY transmission_mode
            ''')
            mode_counts = {row['transmission_mode']: row['count'] for row in c.fetchall()}

            return {
                'total_collectors': total_collectors,
                'collectors_by_status': status_counts,
                'collectors_by_mode': mode_counts,
                'total_reports': report_stats['total_reports'] or 0,
                'total_certificates': report_stats['total_certificates'] or 0,
                'total_findings': report_stats['total_findings'] or 0,
                'avg_risk_score': round(report_stats['avg_risk_score'] or 0, 2)
            }

    # =========================================================================
    # COLLECTOR MANAGEMENT
    # =========================================================================

    @classmethod
    def suspend_collector(cls, db_service, collector_id: str, suspended_by: str, reason: str = None) -> bool:
        """Suspend a collector."""
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                UPDATE remote_collectors
                SET status = 'suspended', updated_at = ?
                WHERE collector_id = ? AND status NOT IN ('suspended', 'decommissioned')
            ''', (datetime.now().isoformat(), collector_id))
            conn.commit()

            if c.rowcount > 0:
                cls._log_audit_event(
                    db_service,
                    collector_id=collector_id,
                    event_type='collector_suspended',
                    event_details={'reason': reason},
                    performed_by=suspended_by
                )
                security_logger.warning(f"Collector suspended: {collector_id} by {suspended_by}")
                return True
            return False

    @classmethod
    def reactivate_collector(cls, db_service, collector_id: str, reactivated_by: str) -> bool:
        """Reactivate a suspended collector."""
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                UPDATE remote_collectors
                SET status = 'active', updated_at = ?
                WHERE collector_id = ? AND status = 'suspended'
            ''', (datetime.now().isoformat(), collector_id))
            conn.commit()

            if c.rowcount > 0:
                cls._log_audit_event(
                    db_service,
                    collector_id=collector_id,
                    event_type='collector_reactivated',
                    event_details={},
                    performed_by=reactivated_by
                )
                logger.info(f"Collector reactivated: {collector_id} by {reactivated_by}")
                return True
            return False

    @classmethod
    def decommission_collector(cls, db_service, collector_id: str, decommissioned_by: str, reason: str = None) -> bool:
        """Permanently decommission a collector."""
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                UPDATE remote_collectors
                SET status = 'decommissioned', updated_at = ?
                WHERE collector_id = ? AND status != 'decommissioned'
            ''', (datetime.now().isoformat(), collector_id))
            conn.commit()

            if c.rowcount > 0:
                cls._log_audit_event(
                    db_service,
                    collector_id=collector_id,
                    event_type='collector_decommissioned',
                    event_details={'reason': reason},
                    performed_by=decommissioned_by
                )
                security_logger.warning(f"Collector decommissioned: {collector_id} by {decommissioned_by}")
                return True
            return False

    @classmethod
    def delete_collector(cls, db_service, collector_id: str, deleted_by: str, reason: str = None) -> Tuple[bool, Optional[str]]:
        """
        Permanently delete a collector and all its dependent data.

        Cascades delete to:
        - remote_collector_reports
        - collector_jobs
        - collector_configs
        - remote_collector_audit (audit records only)
        - scans with collector_id reference

        Args:
            db_service: DatabaseService class
            collector_id: Collector ID to delete
            deleted_by: Username performing deletion
            reason: Optional reason for deletion

        Returns:
            Tuple of (success, error_message)
        """
        # Retry logic for database lock handling
        max_retries = 3
        retry_delay = 2

        for attempt in range(max_retries):
            try:
                with db_service.get_connection_context() as conn:
                    c = conn.cursor()

                    # Verify collector exists
                    c.execute('SELECT id FROM remote_collectors WHERE collector_id = ?', (collector_id,))
                    if not c.fetchone():
                        return False, f"Collector {collector_id} not found"

                    # Delete in correct order (foreign key constraints)
                    # 1. Delete reports referencing this collector
                    c.execute('DELETE FROM remote_collector_reports WHERE collector_id = ?', (collector_id,))
                    reports_deleted = c.rowcount
                    logger.info(f"Deleted {reports_deleted} reports for collector {collector_id}")

                    # 2. Delete jobs for this collector
                    c.execute('DELETE FROM collector_jobs WHERE collector_id = ?', (collector_id,))
                    jobs_deleted = c.rowcount
                    logger.info(f"Deleted {jobs_deleted} jobs for collector {collector_id}")

                    # 3. Delete collector config
                    c.execute('DELETE FROM collector_configs WHERE collector_id = ?', (collector_id,))
                    configs_deleted = c.rowcount
                    logger.info(f"Deleted {configs_deleted} configs for collector {collector_id}")

                    # 4. Clear collector_id from scans (don't delete scans, just clear reference)
                    c.execute('''UPDATE scans SET collector_id = NULL
                                 WHERE collector_id = ?''', (collector_id,))
                    scans_updated = c.rowcount
                    logger.info(f"Updated {scans_updated} scans to remove collector reference")

                    # 5. Delete audit records
                    c.execute('DELETE FROM remote_collector_audit WHERE collector_id = ?', (collector_id,))
                    audit_deleted = c.rowcount
                    logger.info(f"Deleted {audit_deleted} audit records for collector {collector_id}")

                    # 6. Finally, delete the collector itself
                    c.execute('DELETE FROM remote_collectors WHERE collector_id = ?', (collector_id,))
                    collector_deleted = c.rowcount

                    conn.commit()

                    # Log the deletion event
                    cls._log_audit_event(
                        db_service,
                        collector_id=collector_id,
                        event_type='collector_deleted',
                        event_details={
                            'reason': reason,
                            'reports_deleted': reports_deleted,
                            'jobs_deleted': jobs_deleted,
                            'configs_deleted': configs_deleted,
                            'scans_updated': scans_updated,
                            'audit_records_deleted': audit_deleted
                        },
                        performed_by=deleted_by
                    )

                    security_logger.warning(
                        f"Collector deleted: {collector_id} by {deleted_by} "
                        f"(reason: {reason or 'no reason'}, "
                        f"reports: {reports_deleted}, jobs: {jobs_deleted}, configs: {configs_deleted})"
                    )

                    return True, None

            except Exception as e:
                error_str = str(e)
                # Check if this is a database lock error and we can retry
                if 'database is locked' in error_str and attempt < max_retries - 1:
                    logger.warning(
                        f"Database locked while deleting collector {collector_id}, "
                        f"retrying in {retry_delay}s (attempt {attempt + 1}/{max_retries})"
                    )
                    time.sleep(retry_delay)
                    continue

                # For other errors or final retry exhausted, return error
                error_msg = f"Failed to delete collector {collector_id}: {error_str}"
                logger.error(error_msg, exc_info=True)
                return False, error_msg

        # Should not reach here, but just in case
        return False, f"Failed to delete collector {collector_id} after {max_retries} attempts"

    # =========================================================================
    # UTILITY METHODS
    # =========================================================================

    @classmethod
    def _log_audit_event(
        cls,
        db_service,
        collector_id: Optional[str],
        event_type: str,
        event_details: Dict[str, Any],
        source_ip: Optional[str] = None,
        performed_by: Optional[str] = None
    ):
        """Log an audit event."""
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO remote_collector_audit
                (collector_id, event_type, event_details, source_ip, performed_by)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                collector_id,
                event_type,
                json.dumps(event_details),
                source_ip,
                performed_by
            ))
            conn.commit()

    @classmethod
    def _ip_matches_cidr(cls, ip: str, cidr: str) -> bool:
        """Check if an IP matches a CIDR range."""
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except (ValueError, ImportError):
            # If ipaddress module unavailable or invalid IP/CIDR, be safe and deny
            return False

    # =========================================================================
    # CENTRAL CONFIGURATION MANAGEMENT
    # =========================================================================

    @classmethod
    def get_collector_config(cls, db_service, collector_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the central configuration for a collector.

        Args:
            db_service: DatabaseService class
            collector_id: Collector identifier

        Returns:
            Configuration dict or None if not found
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT cc.*, rc.transmission_mode as base_mode, rc.environment
                FROM collector_configs cc
                JOIN remote_collectors rc ON cc.collector_id = rc.collector_id
                WHERE cc.collector_id = ?
            ''', (collector_id,))
            row = c.fetchone()

            if not row:
                # Return default config if none exists
                c.execute('''
                    SELECT transmission_mode, environment
                    FROM remote_collectors
                    WHERE collector_id = ?
                ''', (collector_id,))
                collector = c.fetchone()
                if collector:
                    return {
                        'config_version': 0,
                        'transmission_mode': collector['transmission_mode'],
                        'environment': collector['environment'],
                        'scan_targets': [],
                        'schedule': {'enabled': False, 'interval_minutes': 60},
                        'heartbeat_interval': 60,
                        'enabled_collectors': ['tls', 'file', 'ejbca', 'azure_keyvault', 'luna_hsm', 'crl']
                    }
                return None

            config = dict(row)
            # Parse JSON fields
            if config.get('scan_targets'):
                config['scan_targets'] = json.loads(config['scan_targets'])
            else:
                config['scan_targets'] = []

            if config.get('schedule'):
                config['schedule'] = json.loads(config['schedule'])
            else:
                config['schedule'] = {'enabled': False, 'interval_minutes': 60}

            if config.get('enabled_collectors'):
                config['enabled_collectors'] = json.loads(config['enabled_collectors'])
            else:
                config['enabled_collectors'] = ['tls', 'file', 'ejbca', 'azure_keyvault', 'luna_hsm', 'crl']

            logger.info(f"[get_collector_config] Returning for {collector_id}: enabled_collectors = {config['enabled_collectors']}")
            return config

    @classmethod
    def update_collector_config(
        cls,
        db_service,
        collector_id: str,
        updated_by: str,
        transmission_mode: Optional[str] = None,
        scan_targets: Optional[List[Dict]] = None,
        schedule: Optional[Dict] = None,
        heartbeat_interval: Optional[int] = None,
        policy_id: Optional[int] = None,
        enabled_collectors: Optional[List[str]] = None
    ) -> Tuple[bool, int]:
        """
        Update collector configuration (central management).

        Args:
            db_service: DatabaseService class
            collector_id: Collector identifier
            updated_by: Username making the change
            transmission_mode: New transmission mode
            scan_targets: New scan targets list
            schedule: New schedule configuration
            heartbeat_interval: New heartbeat interval
            policy_id: Policy template to assign
            enabled_collectors: List of enabled collector types

        Returns:
            Tuple of (success, new_config_version)
        """
        logger.info(f"[update_collector_config] Called for collector {collector_id}")
        logger.info(f"[update_collector_config] enabled_collectors parameter: {enabled_collectors}")

        with db_service.get_connection_context() as conn:
            c = conn.cursor()

            # Check if config exists
            c.execute('SELECT config_version FROM collector_configs WHERE collector_id = ?', (collector_id,))
            existing = c.fetchone()

            if existing:
                new_version = existing['config_version'] + 1

                # Build update query dynamically
                updates = ['config_version = ?', 'updated_at = ?', 'updated_by = ?']
                params = [new_version, datetime.now().isoformat(), updated_by]

                if transmission_mode is not None:
                    updates.append('transmission_mode = ?')
                    params.append(transmission_mode)
                if scan_targets is not None:
                    updates.append('scan_targets = ?')
                    params.append(json.dumps(scan_targets))
                if schedule is not None:
                    updates.append('schedule = ?')
                    params.append(json.dumps(schedule))
                if heartbeat_interval is not None:
                    updates.append('heartbeat_interval = ?')
                    params.append(heartbeat_interval)
                if policy_id is not None:
                    updates.append('policy_id = ?')
                    params.append(policy_id)
                if enabled_collectors is not None:
                    updates.append('enabled_collectors = ?')
                    params.append(json.dumps(enabled_collectors))

                params.append(collector_id)
                logger.info(f"[update_collector_config] SQL: UPDATE collector_configs SET {', '.join(updates)} WHERE collector_id = ?")
                logger.info(f"[update_collector_config] Params: {params}")
                c.execute(f'''
                    UPDATE collector_configs
                    SET {', '.join(updates)}
                    WHERE collector_id = ?
                ''', params)
                logger.info(f"[update_collector_config] UPDATE executed, rows affected: {c.rowcount}")
            else:
                # Insert new config
                new_version = 1
                c.execute('''
                    INSERT INTO collector_configs
                    (collector_id, config_version, transmission_mode, scan_targets,
                     schedule, heartbeat_interval, policy_id, updated_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    collector_id,
                    new_version,
                    transmission_mode or 'selective',
                    json.dumps(scan_targets or []),
                    json.dumps(schedule or {'enabled': False, 'interval_minutes': 60}),
                    heartbeat_interval or 60,
                    policy_id,
                    updated_by
                ))

            conn.commit()

        cls._log_audit_event(
            db_service,
            collector_id=collector_id,
            event_type='config_updated',
            event_details={
                'new_version': new_version,
                'changes': {
                    'transmission_mode': transmission_mode,
                    'scan_targets_count': len(scan_targets) if scan_targets else None,
                    'schedule': schedule,
                    'heartbeat_interval': heartbeat_interval,
                    'policy_id': policy_id
                }
            },
            performed_by=updated_by
        )

        logger.info(f"Collector config updated: {collector_id} -> v{new_version}")
        return True, new_version

    # =========================================================================
    # JOB QUEUE MANAGEMENT
    # =========================================================================

    @classmethod
    def create_job(
        cls,
        db_service,
        collector_id: str,
        job_type: str,
        created_by: str,
        payload: Optional[Dict] = None,
        priority: str = 'normal'
    ) -> int:
        """
        Create a job for a collector.

        Args:
            db_service: DatabaseService class
            collector_id: Target collector
            job_type: Type of job (scan, config_refresh, policy_update)
            created_by: Username creating the job
            payload: Job-specific parameters
            priority: Job priority (low, normal, high, urgent)

        Returns:
            Job ID
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO collector_jobs
                (collector_id, job_type, priority, payload, created_by)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                collector_id,
                job_type,
                priority,
                json.dumps(payload) if payload else None,
                created_by
            ))
            job_id = c.lastrowid
            conn.commit()

        cls._log_audit_event(
            db_service,
            collector_id=collector_id,
            event_type='job_created',
            event_details={'job_id': job_id, 'job_type': job_type, 'priority': priority},
            performed_by=created_by
        )

        logger.info(f"Job created: {job_id} ({job_type}) for {collector_id}")
        return job_id

    @classmethod
    def get_job(cls, db_service, job_id: int) -> Optional[Dict[str, Any]]:
        """
        Get a specific job by ID.

        Args:
            db_service: DatabaseService class
            job_id: Job identifier

        Returns:
            Job dictionary or None if not found
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT id, collector_id, job_type, priority, status, payload,
                       created_at, created_by, acknowledged_at, started_at,
                       completed_at, result, error_message
                FROM collector_jobs
                WHERE id = ?
            ''', (job_id,))
            row = c.fetchone()
            if row:
                return dict(row)
            return None

    @classmethod
    def get_pending_jobs(cls, db_service, collector_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get pending jobs for a collector.

        Args:
            db_service: DatabaseService class
            collector_id: Collector identifier
            limit: Maximum jobs to return

        Returns:
            List of pending jobs ordered by priority and creation time
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT id, job_type, priority, payload, created_at
                FROM collector_jobs
                WHERE collector_id = ? AND status = 'pending'
                ORDER BY
                    CASE priority
                        WHEN 'urgent' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'normal' THEN 3
                        WHEN 'low' THEN 4
                        ELSE 5
                    END,
                    created_at ASC
                LIMIT ?
            ''', (collector_id, limit))

            jobs = []
            for row in c.fetchall():
                job = dict(row)
                if job.get('payload'):
                    job['payload'] = json.loads(job['payload'])
                jobs.append(job)

            return jobs

    @classmethod
    def acknowledge_job(cls, db_service, job_id: int, collector_id: str) -> bool:
        """
        Mark a job as acknowledged by the collector.

        Args:
            db_service: DatabaseService class
            job_id: Job identifier
            collector_id: Collector claiming the job

        Returns:
            True if successfully acknowledged
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                UPDATE collector_jobs
                SET status = 'acknowledged', acknowledged_at = ?
                WHERE id = ? AND collector_id = ? AND status = 'pending'
            ''', (datetime.now().isoformat(), job_id, collector_id))
            conn.commit()
            return c.rowcount > 0

    @classmethod
    def start_job(cls, db_service, job_id: int, collector_id: str) -> bool:
        """
        Mark a job as started.
        Also updates the corresponding scan status to 'Running' if this is a scan job.
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            now = datetime.now().isoformat()

            # Update job status to running
            c.execute('''
                UPDATE collector_jobs
                SET status = 'running', started_at = ?
                WHERE id = ? AND collector_id = ? AND status IN ('pending', 'acknowledged')
            ''', (now, job_id, collector_id))

            job_updated = c.rowcount > 0

            if job_updated:
                # Get the job payload to extract scan_id
                c.execute('SELECT payload FROM collector_jobs WHERE id = ?', (job_id,))
                row = c.fetchone()
                if row:
                    try:
                        payload = json.loads(row[0]) if isinstance(row[0], str) else row[0]
                        scan_id = payload.get('scan_id')

                        if scan_id:
                            # Update corresponding scan status to Running
                            c.execute('''
                                UPDATE scans
                                SET status = 'Running', updated_at = CURRENT_TIMESTAMP
                                WHERE id = ?
                            ''', (scan_id,))
                            logger.info(f"Scan {scan_id} status updated to Running (job {job_id})")
                    except (json.JSONDecodeError, TypeError, KeyError) as e:
                        logger.warning(f"Could not extract scan_id from job {job_id} payload: {e}")

            conn.commit()
            return job_updated

    @classmethod
    def complete_job(
        cls,
        db_service,
        job_id: int,
        collector_id: str,
        success: bool,
        result: Optional[Dict] = None,
        error_message: Optional[str] = None
    ) -> bool:
        """
        Mark a job as completed.
        Also updates the corresponding scan status if this is a scan job.

        Args:
            db_service: DatabaseService class
            job_id: Job identifier
            collector_id: Collector completing the job
            success: Whether job succeeded
            result: Job result data
            error_message: Error message if failed

        Returns:
            True if successfully updated
        """
        job_status = 'completed' if success else 'failed'

        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                UPDATE collector_jobs
                SET status = ?, completed_at = ?, result = ?, error_message = ?
                WHERE id = ? AND collector_id = ? AND status IN ('pending', 'acknowledged', 'running')
            ''', (
                job_status,
                datetime.now().isoformat(),
                json.dumps(result) if result else None,
                error_message,
                job_id,
                collector_id
            ))

            job_updated = c.rowcount > 0

            if job_updated:
                # Get the job payload to extract scan_id
                c.execute('SELECT payload FROM collector_jobs WHERE id = ?', (job_id,))
                row = c.fetchone()
                if row:
                    try:
                        payload = json.loads(row[0]) if isinstance(row[0], str) else row[0]
                        scan_id = payload.get('scan_id')

                        if scan_id:
                            # Map job status to scan status
                            scan_status = 'Successful' if success else 'Failed'
                            c.execute('''
                                UPDATE scans
                                SET status = ?, updated_at = CURRENT_TIMESTAMP
                                WHERE id = ?
                            ''', (scan_status, scan_id))
                            logger.info(f"Scan {scan_id} status updated to {scan_status} (job {job_id})")
                    except (json.JSONDecodeError, TypeError, KeyError) as e:
                        logger.warning(f"Could not extract scan_id from job {job_id} payload: {e}")

            conn.commit()

            if job_updated:
                cls._log_audit_event(
                    db_service,
                    collector_id=collector_id,
                    event_type='job_completed',
                    event_details={'job_id': job_id, 'success': success, 'error': error_message}
                )
                return True
            return False

    @classmethod
    def get_job_history(
        cls,
        db_service,
        collector_id: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get job history for a collector or all collectors."""
        with db_service.get_connection_context() as conn:
            c = conn.cursor()

            if collector_id:
                c.execute('''
                    SELECT * FROM collector_jobs
                    WHERE collector_id = ?
                    ORDER BY created_at DESC
                    LIMIT ?
                ''', (collector_id, limit))
            else:
                c.execute('''
                    SELECT * FROM collector_jobs
                    ORDER BY created_at DESC
                    LIMIT ?
                ''', (limit,))

            jobs = []
            for row in c.fetchall():
                job = dict(row)
                if job.get('payload'):
                    job['payload'] = json.loads(job['payload'])
                if job.get('result'):
                    job['result'] = json.loads(job['result'])
                jobs.append(job)

            return jobs

    # =========================================================================
    # ENHANCED HEARTBEAT WITH CONFIG SYNC
    # =========================================================================

    @classmethod
    def process_heartbeat_with_config(
        cls,
        db_service,
        collector_id: str,
        heartbeat_data: Dict[str, Any],
        source_ip: str
    ) -> Dict[str, Any]:
        """
        Process heartbeat and return config sync information.

        This is the enhanced heartbeat that supports central orchestration.
        It returns pending jobs and config updates in the response.

        Args:
            db_service: DatabaseService class
            collector_id: Collector identifier
            heartbeat_data: Heartbeat payload from collector
            source_ip: Source IP address

        Returns:
            Response dict with status, config, and pending jobs
        """
        # Update collector status
        cls.process_heartbeat(db_service, collector_id, heartbeat_data, source_ip)

        # Get collector's current config version (from heartbeat)
        collector_config_version = heartbeat_data.get('config_version', 0)

        # Get central config
        central_config = cls.get_collector_config(db_service, collector_id)
        central_version = central_config.get('config_version', 0) if central_config else 0

        # Check for pending jobs
        pending_jobs = cls.get_pending_jobs(db_service, collector_id, limit=5)

        # Build response
        response = {
            'status': 'ok',
            'server_time': datetime.now().isoformat(),
            'config_changed': central_version > collector_config_version,
            'config_version': central_version,
            'pending_jobs_count': len(pending_jobs)
        }

        # Include full config if changed
        if response['config_changed'] and central_config:
            response['config'] = {
                'version': central_config.get('config_version', 1),
                'transmission_mode': central_config.get('transmission_mode', 'selective'),
                'scan_targets': central_config.get('scan_targets', []),
                'schedule': central_config.get('schedule', {}),
                'heartbeat_interval': central_config.get('heartbeat_interval', 60)
            }

        # Include pending jobs summary
        if pending_jobs:
            response['pending_jobs'] = [
                {'id': j['id'], 'job_type': j['job_type'], 'priority': j['priority'], 'payload': j.get('payload')}
                for j in pending_jobs
            ]

        return response

    # =========================================================================
    # POLICY TEMPLATE MANAGEMENT
    # =========================================================================

    @classmethod
    def create_policy_template(
        cls,
        db_service,
        name: str,
        description: str,
        rules: List[Dict],
        created_by: str
    ) -> int:
        """Create a policy template."""
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO collector_policies (name, description, rules, created_by)
                VALUES (?, ?, ?, ?)
            ''', (name, description, json.dumps(rules), created_by))
            policy_id = c.lastrowid
            conn.commit()

        logger.info(f"Policy template created: {name} (ID: {policy_id})")
        return policy_id

    @classmethod
    def get_policy_template(cls, db_service, policy_id: int) -> Optional[Dict[str, Any]]:
        """Get a policy template by ID."""
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM collector_policies WHERE id = ?', (policy_id,))
            row = c.fetchone()
            if row:
                policy = dict(row)
                if policy.get('rules'):
                    policy['rules'] = json.loads(policy['rules'])
                return policy
            return None

    @classmethod
    def list_policy_templates(cls, db_service) -> List[Dict[str, Any]]:
        """List all policy templates."""
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('SELECT id, name, description, created_at, created_by FROM collector_policies')
            return [dict(row) for row in c.fetchall()]

    # =========================================================================
    # AD-HOC SCAN TRIGGER
    # =========================================================================

    @classmethod
    def trigger_scan(
        cls,
        db_service,
        collector_id: str,
        scan_id: int,
        triggered_by: str,
        priority: str = 'normal'
    ) -> int:
        """
        Trigger a remote collector scan job with self-contained configuration.

        The job payload contains the COMPLETE configuration and policy needed for
        execution, matching the dashboard's internal scan structure.

        Args:
            db_service: DatabaseService class
            collector_id: Target remote collector ID
            scan_id: Scan ID (configuration and policy retrieved from database)
            triggered_by: Username triggering the scan
            priority: Job priority (low, normal, high, urgent)

        Returns:
            Job ID

        Raises:
            ValueError: If scan, config, or policy not found
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()

            # Fetch scan with its configuration and policy
            c.execute('''
                SELECT
                    s.id,
                    s.name,
                    s.config_id,
                    s.policy_id,
                    conf.config_json,
                    pol.policy_json
                FROM scans s
                JOIN configurations conf ON s.config_id = conf.id
                JOIN policies pol ON s.policy_id = pol.id
                WHERE s.id = ?
            ''', (scan_id,))

            result = c.fetchone()
            if not result:
                raise ValueError(f"Scan {scan_id} not found or missing config/policy")

            scan_name = result[1]
            config_json = result[4]
            policy_json = result[5]

        # Parse configuration and policy
        config = json.loads(config_json)
        policy = json.loads(policy_json)

        # Fetch collector's transmission_mode setting and add to config
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('SELECT transmission_mode FROM remote_collectors WHERE collector_id = ?',
                     (collector_id,))
            collector_row = c.fetchone()
            transmission_mode = collector_row['transmission_mode'] if collector_row else 'full'

            # Add transmission_mode to config so it flows through the entire system
            config['transmission_mode'] = transmission_mode
            logger.info(f"Set transmission_mode to '{transmission_mode}' for collector {collector_id}")

        # Resolve credentials in configuration using SecretResolutionService
        try:
            from .secret_resolution_service import SecretResolutionService
            resolved_config = SecretResolutionService.resolve_config_credentials(
                db_service,
                config
            )
        except Exception as e:
            logger.error(f"Failed to resolve credentials for scan {scan_id}: {e}")
            raise ValueError(f"Credential resolution failed: {e}")

        # Embed P12 data for remote collector execution
        if resolved_config.get('ejbca', {}).get('enabled'):
            ejbca_servers = resolved_config['ejbca'].get('servers', [])
            for server in ejbca_servers:
                # Use P12 base64 data directly from config (already stored in DB)
                p12_data_base64 = server.get('p12_data_base64')
                p12_path = server.get('p12_path')

                # DEBUG: Log what's in the resolved config
                logger.debug(f"EJBCA Server '{server.get('name')}': p12_data_base64 present = {bool(p12_data_base64)}, p12_path = {p12_path}")
                logger.debug(f"  Server config keys: {list(server.keys())}")

                if p12_data_base64:
                    # Simply rename field for remote collector compatibility
                    server['p12_data'] = p12_data_base64
                    logger.info(f"Using P12 certificate from database for '{server.get('name')}' ({len(p12_data_base64)} chars base64)")
                else:
                    logger.warning(f"No P12 certificate available for EJBCA server '{server.get('name')}'")

        # Calculate the next run number for this scan
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('SELECT COALESCE(MAX(run_number), 0) FROM scan_logs WHERE scan_id = ?',
                     (scan_id,))
            row = c.fetchone()
            next_run_number = (row[0] if row else 0) + 1

        # Build self-contained job payload
        # Note: transmission_mode is already in resolved_config, added earlier
        payload = {
            'scan_id': scan_id,  # Use the actual scan_id from database
            'scan_name': scan_name,
            'run_number': next_run_number,  # Include run number for report filename
            'config': resolved_config,      # Full config with transmission_mode and all credentials resolved
            'policy': policy,                # Full policy with CEL rules
            'triggered_at': datetime.now().isoformat()
        }

        # Create job with self-contained payload
        job_id = cls.create_job(
            db_service,
            collector_id=collector_id,
            job_type='scan',
            created_by=triggered_by,
            payload=payload,
            priority=priority
        )

        logger.info(f"Remote scan job #{job_id} created for scan '{scan_name}' "
                   f"(ID: {scan_id}) on collector {collector_id}")
        return job_id
