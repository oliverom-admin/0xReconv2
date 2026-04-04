#!/usr/bin/env python3
"""
PKI Health Check Dashboard - Flask Application
Web-based management dashboard for PKI scanning and policy management
"""

import os
import sys

# Load environment variables from .env file (must be before any os.getenv calls)
try:
    from dotenv import load_dotenv
    load_dotenv(override=True)  # override=True ensures .env takes precedence over system env
except ImportError:
    pass  # python-dotenv not installed, rely on system environment variables

import json
import base64
import sqlite3
import threading
import datetime
from datetime import timezone
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional
import logging
import io
from io import StringIO
from contextlib import redirect_stdout, redirect_stderr
from functools import wraps

from caip_logging_functions.logging_config import setup_all_loggers, set_audit_context, get_audit_context
from caip_logging_functions.logging_helpers import init_loggers, log_auth_success, log_auth_failure, log_operational, log_permission_denied, log_scan_error, log_scan_event
from caip_document_assessment_functions.document_assessment_routes import register_document_assessment_routes
import uuid
from caip_service_layer.scheduler_service import SchedulerService

from caip_service_layer.auth_service import (
    ROLES, 
    login_required, 
    permission_required, 
    get_all_roles, 
    is_valid_role, 
    get_role_names
)

#from caip_policy_functions.rule_assessment import UnifiedAssessor, RuleRegistry, RuleEvaluator
#from caip_scanning_functions.health_check import PKIHealthCheck
from caip_scanning_functions.reporting import ReportGenerator
from caip_scanning_functions.collectors.ejbca_collector import EJBCACollector
from caip_scanning_functions.collectors.azure_keyvault import AzureKeyVaultCollector
from caip_scanning_functions.collectors.luna_hsm import LunaHSMCollector
from caip_scanning_functions.collectors.crl_collector import CRLCollector
from caip_scanning_functions.collectors.tls_scanner import TLSScanner
from caip_scanning_functions.collectors.file_share import FileShareScanner

from caip_scanning_functions.models import CertificateInfo, KeyInfo, TLSScanResult, CRLInfo, Finding, ScanResults

from connector_service import ConnectorService
from caip_scanning_functions._scan_orchestrator import ScanOrchestrator

from caip_engagement_functions.engagement_routes import register_engagement_routes
from caip_service_layer.assessment_routes import register_assessment_routes

from database_service import DatabaseService
from caip_policy_functions.policy_assessment_service import PolicyAssessmentService
from caip_reporting_functions.reporting_service import ReportingService
from caip_reporting_functions.executive_report_service import ExecutiveReportService, generate_executive_report_path
from caip_document_assessment_functions.document_assessment_database import DocumentAssessmentDatabase
from caip_service_layer.inventory_service import InventoryService

from caip_route_layer.cbom_routes import register_cbom_routes
from caip_engagement_functions.engagement_routes import register_engagement_routes
from caip_engagement_functions.engagement_service import EngagementService

# Import key normalisation service
try:
    from caip_service_layer.key_normalisation_service import KeyNormalisationService
    KEY_NORMALISATION_AVAILABLE = True
except ImportError:
    KEY_NORMALISATION_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)
logger = logging.getLogger('caip.operational')
# Suppress verbose HTTP/network logging
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)
logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger('httpcore').setLevel(logging.WARNING)

# Initialize Unified Vault Service (AES-256-GCM encryption)
from caip_service_layer.unified_vault_service import (
    init_unified_vault_service,
    get_unified_vault_service,
    VaultInitializationError
)

vault_init_error = None
unified_vault = None

try:
    vault_file_path = os.getenv('CAIP_VAULT_FILE', 'system_vault.enc')
    master_password = os.getenv('CAIP_MASTER_PASSWORD')

    if not master_password:
        raise ValueError("CAIP_MASTER_PASSWORD environment variable not set")

    unified_vault = init_unified_vault_service(vault_file_path, master_password)
    logger.info(f"Unified vault initialized: {vault_file_path}")

except VaultInitializationError as e:
    vault_init_error = str(e)
    logger.error(f"Failed to initialize unified vault: {e}")
except Exception as e:
    vault_init_error = str(e)
    logger.error(f"Unexpected error during vault initialization: {e}")

# Initialize Legacy Secret Service with AUTO backend detection
# This enables Azure Key Vault -> Unified Vault fallback chain
# The SecretService will detect the unified vault format (AES-256-GCM) and use it as file backend
import caip_service_layer.secret_service as secret_service_module
secret_service_module.secret_service = None
secret_service_init_error = vault_init_error

try:
    from caip_service_layer.secret_service import SecretService, SecretBackend

    # Initialize with AUTO backend detection
    # Azure Key Vault will be tried first, with unified vault as fallback
    secret_service_module.secret_service = SecretService(
        backend=SecretBackend.AUTO,
        azure_kv_url=os.getenv('AZURE_KEY_VAULT_URL'),
        azure_tenant_id=os.getenv('AZURE_TENANT_ID'),
        azure_client_id=os.getenv('AZURE_CLIENT_ID'),
        azure_client_secret=os.getenv('AZURE_CLIENT_SECRET'),
        secrets_file_path=vault_file_path,
        master_password=master_password
    )
    logger.info("Legacy Secret Service initialized with AUTO backend detection")
except Exception as e:
    logger.warning(f"Failed to initialize legacy Secret Service: {e}")
    secret_service_module.secret_service = None
    if not secret_service_init_error:
        secret_service_init_error = str(e)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['REPORTS_FOLDER'] = 'reports'
app.config['DATABASE'] = 'pki_dashboard.db'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['TEMPLATES_AUTO_RELOAD'] = True  # Force template reloading
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0  # Disable caching for development

# Configure Flask secret key from unified vault (new) or legacy secret service (old)
# Try unified vault first, fallback to legacy SecretService, then use random temporary key
flask_secret_key = None

if unified_vault:
    try:
        # Try new unified vault location
        flask_secret_key = unified_vault.get_secret('app_secrets/caipflasksecretkey')
        if flask_secret_key:
            logger.info("Flask secret key loaded from unified vault")
    except Exception as e:
        logger.debug(f"Failed to get secret from unified vault: {e}")

# Fallback to legacy secret service if unified vault didn't have it
if not flask_secret_key and secret_service_module.secret_service:
    try:
        flask_secret_key = secret_service_module.secret_service.get_secret('caipflasksecretkey')
        if flask_secret_key:
            logger.info("Flask secret key loaded from legacy secret service")
    except Exception as e:
        logger.debug(f"Failed to get secret from legacy service: {e}")

# If we still don't have a secret key, use temporary random key
if not flask_secret_key:
    import secrets as secrets_module
    flask_secret_key = secrets_module.token_hex(32)
    logger.warning("Flask secret key not found in vaults - using temporary session key")
    if not secret_service_init_error:
        secret_service_init_error = "Could not load Flask secret key from vault"

app.secret_key = flask_secret_key

# Session security configuration
app.config.update(
    SESSION_COOKIE_SECURE=False,  # Set to True when using HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(hours=8),
    SESSION_COOKIE_NAME='caip_session'
)

# Initialize enterprise logging (after Flask app creation)
loggers = setup_all_loggers(enable_syslog=False)  # Set to True to enable syslog
init_loggers()

log_operational(logging.INFO, "CAIP application starting", f"Flask v{__import__('flask').__version__}")

# =============================================================================
# Initialize Secret Store Manager (for external secret store architecture)
# =============================================================================
from caip_service_layer.secret_store_manager import init_secret_store_manager, get_secret_store_manager
from caip_service_layer.secret_resolution_service import SecretResolutionService

secret_store_manager_init_error = None
try:
    # Initialize the manager - it will load registered stores from database
    # Note: startup_credentials can be passed here for stores using 'prompt' source
    init_secret_store_manager(startup_credentials={})
    logger.info("Secret Store Manager initialized successfully")
except Exception as e:
    secret_store_manager_init_error = str(e)
    logger.warning(f"Failed to initialize Secret Store Manager: {e}")


# ==================== Export CA Chain on Startup ====================
# Ensure /etc/caip/certs/ca-chain.pem contains all active engagement CAs
# This is a safety net in case the file is stale after DB restore/migration
# NOTE: This will be called via a background task after Flask is fully initialized
# For now, the export happens when collectors register or on-demand


DOC_UPLOAD_FOLDER = os.path.join(app.config['UPLOAD_FOLDER'], 'documents')
os.makedirs(DOC_UPLOAD_FOLDER, exist_ok=True)

# ==================== DPOD Route ====================

@app.route('/dpod')
@login_required
def dpod_dashboard():
    """DPOD Management Dashboard"""
    return render_template('dpod_dashboard.html')

# ==================== Flask Request Hook for Audit Context ====================

@app.before_request
def before_request():
    """Set up audit context for each request"""
    # Generate request ID for tracking
    request_id = str(uuid.uuid4())[:8]
    set_audit_context(request_id=request_id)

    # Set user if authenticated
    if 'username' in session:
        set_audit_context(user=session['username'])

    # Log client certificate details for mTLS connections on port 5444
    if request.environ.get('SERVER_PORT') == '5444':
        mtls_logger = logging.getLogger('caip.operational')

        # DEBUG: Log all SSL-related environ variables
        ssl_keys = [k for k in request.environ.keys() if 'SSL' in k or 'CERT' in k or 'TLS' in k]
        if ssl_keys:
            mtls_logger.debug(f"[mTLS DEBUG] Available SSL/CERT keys: {ssl_keys}")
            for key in ssl_keys:
                value = request.environ.get(key)
                if isinstance(value, str) and len(value) > 100:
                    mtls_logger.debug(f"  {key}: {value[:80]}... ({len(value)} chars)")
                else:
                    mtls_logger.debug(f"  {key}: {value}")

        # Extract client certificate from WSGI environment
        client_cert_pem = request.environ.get('SSL_CLIENT_CERT')

        if client_cert_pem:
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend

                cert = x509.load_pem_x509_certificate(
                    client_cert_pem.encode(),
                    default_backend()
                )

                # Extract engagement_id from OU field
                engagement_id = None
                for attr in cert.subject:
                    if attr.oid == x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME:
                        engagement_id = attr.value
                        break

                # Extract collector_id from CN field
                collector_id = None
                for attr in cert.subject:
                    if attr.oid == x509.oid.NameOID.COMMON_NAME:
                        collector_id = attr.value
                        break

                mtls_logger.info(f"[mTLS] Client cert validated for collector: {collector_id}")
                mtls_logger.info(f"[mTLS] Client cert engagement_id: {engagement_id}")
                mtls_logger.info(f"[mTLS] Server cert presented: /etc/caip/certs/dashboard_cert.pem (default)")

                if engagement_id:
                    # Check if we have an engagement-specific cert in cache
                    try:
                        from production_config_collectors import _engagement_certs_cache
                        if engagement_id in _engagement_certs_cache:
                            mtls_logger.warning(
                                f"[mTLS] Engagement-specific cert EXISTS for {engagement_id} "
                                f"but was NOT presented (using default instead)"
                            )
                        else:
                            mtls_logger.error(
                                f"[mTLS] NO engagement-specific cert found for {engagement_id} "
                                f"in cache (only have: {list(_engagement_certs_cache.keys())})"
                            )
                    except ImportError:
                        mtls_logger.debug("[mTLS] Could not import engagement certs cache (normal in test environment)")
                else:
                    mtls_logger.warning("[mTLS] Client cert does NOT contain engagement_id in OU field")

            except Exception as e:
                mtls_logger.error(f"[mTLS] Error parsing client certificate: {e}")
        else:
            mtls_logger.debug("[mTLS] No client certificate presented on port 5444 (may not be mTLS request)")

        # NEW: Port 5444 (collectors endpoint) certificate validation using Python cryptography
        client_cert_pem = request.environ.get('SSL_CLIENT_CERT')
        if client_cert_pem:
            try:
                from caip_service_layer.mtls_validator import MTLSCertificateValidator
                validator = MTLSCertificateValidator(database_service)
                result = validator.validate_collector_certificate(client_cert_pem)

                if not result['valid']:
                    mtls_logger.warning(f"[mTLS] Certificate validation failed: {', '.join(result['errors'])}")
                    return jsonify({'error': 'Client certificate validation failed', 'details': result['errors']}), 403

                mtls_logger.info(f"[mTLS] Certificate validated - CN: {result['subject_cn']}, OU: {result['subject_ou']}")
            except Exception as e:
                mtls_logger.error(f"[mTLS] Validation error: {e}", exc_info=True)
                return jsonify({'error': 'Certificate validation error'}), 500

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)

# ==================== GLOBAL CONFIGURATION ====================
CLM_INTEGRATION_REFRESH_INTERVAL_SECONDS = 120  # 2 minutes


# ==================== Database Initialisation====================

# Configure and initialize database service
DatabaseService.configure(app.config['DATABASE'])
DatabaseService.init_db(default_admin_password=generate_password_hash('Willows83'))

# Initialize system vault metadata in database (for UI visibility)
DatabaseService.init_system_vault_metadata()

# Initialize Certificate Service for TLS/mTLS
try:
    from caip_service_layer.certificate_service import CertificateService
    from caip_service_layer.certificate_routes import register_certificate_routes

    # Initialize certificate service - pass unified vault for PKI key storage
    certificate_service = CertificateService(unified_vault or secret_service_module.secret_service, DatabaseService)

    # Ensure internal CA exists (auto-provision if missing) - must be before dashboard cert
    internal_ca = certificate_service.ensure_internal_ca()
    logger.info(f"Internal CA ready: {internal_ca.get('serial_number', 'unknown')}")

    # Ensure dashboard certificate exists (auto-generate if missing, signed by internal CA)
    cert_path, key_path = certificate_service.ensure_dashboard_certificate()
    app.config['TLS_CERT_PATH'] = cert_path
    app.config['TLS_KEY_PATH'] = key_path
    logger.info(f"Dashboard TLS certificate ready: {cert_path}")

    # Register certificate management routes
    register_certificate_routes(app, certificate_service, DatabaseService, login_required, permission_required)
    logger.info("Certificate management routes registered")
except Exception as e:
    logger.error(f"Failed to initialize certificate service: {e}")
    logger.warning("Continuing without certificate service. TLS will not be available.")

register_document_assessment_routes(
    app,
    DatabaseService,
    login_required,
    permission_required  # Optional
)
from caip_service_layer.assessment_service import AssessmentService
AssessmentService.init_assessment_tables(DatabaseService)
# Register engagement routes
register_engagement_routes(app, DatabaseService, login_required, permission_required, vault_service=unified_vault or secret_service_module.secret_service)
register_assessment_routes(app, DatabaseService, login_required, permission_required)
from caip_service_layer.asset_context_routes import register_context_routes
from caip_service_layer.relationship_routes import register_relationship_routes
from caip_service_layer.enrichment_routes import register_enrichment_routes
from caip_service_layer.pqc_reporting_service import generate_pqc_report
register_context_routes(app, DatabaseService, login_required, permission_required)
register_relationship_routes(app, login_required, permission_required)
register_enrichment_routes(app, DatabaseService, login_required, permission_required)
register_cbom_routes(app, DatabaseService, login_required, permission_required)

# Register inventory routes for continuous monitoring
from caip_route_layer.inventory_routes import register_inventory_routes
register_inventory_routes(app)

# Remote collector routes for distributed edge collectors
from caip_route_layer.remote_collector_routes import register_remote_collector_routes
register_remote_collector_routes(app)

# Secret store management routes for centralized credential management
from caip_route_layer.secret_store_routes import register_secret_store_routes
register_secret_store_routes(app)

# Unified vault routes for system vault display (read-only in UI)
from caip_service_layer.secret_store_routes import register_routes as register_unified_vault_routes
register_unified_vault_routes(app)

# Optionally start the background scheduler for automatic sync
# Uncomment the following lines to enable automatic inventory sync:
# from scheduler_service import SchedulerService
# SchedulerService.start(check_interval_seconds=60)

# Convenience aliases for backward compatibility during migration


# Convenience aliases for backward compatibility during migration
def get_db_connection():
    return DatabaseService.get_connection()

def dict_from_row(row):
    return DatabaseService.DatabaseService.dict_from_row(row)


# ==================== AUTHENTICATION ROUTES ====================

@app.route('/')
def index():
    """Redirect to dashboard or login"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/api/v1/auth/mode', methods=['GET'])
def get_auth_mode():
    """
    Get authentication mode information with Azure error details.

    Reflects the fallback chain:
    1. Primary: Azure Key Vault (online mode)
    2. Fallback: Unified Vault (offline mode)
    3. Error: If neither is available
    """
    # Check if we have legacy secret service (handles Azure -> File fallback)
    if secret_service_module.secret_service:
        backend = secret_service_module.secret_service.backend.value
        backend_error = secret_service_module.secret_service.backend_error

        backend_display = {
            'azure_kv': 'Online Mode',
            'file': 'Offline Mode',
            'auto': 'Auto-Detect'
        }.get(backend, backend)

        response = {
            'mode': backend,
            'mode_display': backend_display,
            'secure': True,
            'icon': '☁️' if backend == 'azure_kv' else '🔐',
            'is_offline': backend == 'file'  # Flag for hiding OAuth providers
        }

        # Include fallback reason if backend fell back to encrypted file due to Azure failure
        if backend == 'file' and backend_error:
            response['azure_error'] = 'Application credentials could not be received from our master keystore. You are working in an offline mode with time-restricted accounts.'
            response['fallback_reason'] = 'Using unified vault (Azure Key Vault unavailable)'

        return jsonify(response), 200

    # Fallback: No secret service but unified vault exists
    elif unified_vault:
        response = {
            'mode': 'file',
            'mode_display': 'Offline Mode',
            'secure': True,
            'icon': '🔐',
            'is_offline': True,
            'fallback_reason': 'Using unified vault (legacy SecretService unavailable)'
        }
        return jsonify(response), 200

    else:
        # Neither secret service nor unified vault - initialization failed
        error_msg = secret_service_init_error or 'Secret service not initialized'
        return jsonify({
            'mode': 'fallback',
            'mode_display': 'Secret Service Error',
            'secure': False,
            'icon': '❌',
            'error': error_msg,
            'is_offline': True  # Treat as offline - hide OAuth providers
        }), 200

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'GET':
        return render_template('login.html')

    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = DatabaseService.dict_from_row(c.fetchone())
        conn.close()

        if not user:
            log_auth_failure(username, 'Invalid credentials')
            return jsonify({'error': 'Invalid credentials'}), 401

        # Check if account is disabled
        if not user.get('enabled', 1):
            log_auth_failure(username, 'Account disabled')
            return jsonify({'error': 'Account disabled. Please contact your administrator.'}), 403

        if check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']

            # Check certificate status (Phase 2)
            certificate_status = None
            try:
                certificate_status = certificate_service.get_user_certificate_status(user['id'])
            except Exception as cert_error:
                logger.warning(f"Failed to get certificate status for user {username}: {cert_error}")

            log_auth_success(username, 'Password')
            return jsonify({
                'message': 'Login successful',
                'redirect': '/dashboard',
                'certificate_status': certificate_status
            }), 200
        else:
            log_auth_failure(username, 'Invalid credentials')
            return jsonify({'error': 'Invalid credentials'}), 401

    except Exception as e:
        log_auth_failure(username, f"Login error: {str(e)}")
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'An error occurred'}), 500

@app.route('/logout')
def logout():
    """Logout"""
    # Check if user logged in via OAuth and needs provider logout
    oauth_provider_id = session.get('oauth_provider_id')

    if oauth_provider_id:
        try:
            from caip_service_layer.oauth_service import OAuthService
            provider = OAuthService.get_provider(oauth_provider_id)

            if provider and hasattr(provider, 'get_logout_url'):
                session.clear()
                logout_url = provider.get_logout_url(
                    post_logout_redirect_uri=request.url_root.rstrip('/') + url_for('login')
                )
                return redirect(logout_url)
        except Exception as e:
            logger.error(f"Error getting OAuth logout URL: {e}")

    # Standard logout
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard page"""
    return render_template('dashboard.html')

@app.route('/admin/certificates')
@login_required
@permission_required('users:read')
def certificate_management():
    """Certificate management page (Phase 2)"""
    return render_template('certificate_management.html')

@app.route('/api/session', methods=['GET'])
@login_required
def get_session():
    """Get current user session information"""
    return jsonify({
        'username': session.get('username'),
        'role': session.get('role')
    }), 200

# ==================== BOOTSTRAP VERIFICATION ENDPOINT ====================

@app.route('/api/admin/bootstrap-verify', methods=['GET'])
@login_required
def verify_bootstrap():
    """
    Verify that vault storage is working before removing database fallback.

    Returns JSON with status of:
    - Vault accessibility
    - Database key accessibility
    - Whether keys match
    - Whether it's safe to remove database field (Phase 2)
    """
    import base64
    from caip_service_layer.unified_vault_service import get_unified_vault_service

    results = {
        "bootstrap_status": "unknown",
        "vault_status": None,
        "database_status": None,
        "key_accessible_from_vault": False,
        "key_accessible_from_db": False,
        "keys_match": False,
        "safe_to_remove_db_field": False,
        "errors": []
    }

    try:
        # Test 1: Is key in vault?
        try:
            vault = get_unified_vault_service()
            if vault:
                key_from_vault = vault.get_key_pem("internal_ca_private_key")
                if key_from_vault:
                    results["vault_status"] = "accessible"
                    results["key_accessible_from_vault"] = True
                else:
                    results["vault_status"] = "empty"
                    results["errors"].append("Vault initialized but key not found")
            else:
                results["vault_status"] = "not_initialized"
                results["errors"].append("Vault service not initialized")
        except Exception as e:
            results["vault_status"] = "error"
            results["errors"].append(f"Vault error: {str(e)}")
            key_from_vault = None

        # Test 2: Is key in database?
        try:
            conn = database_service.get_connection()
            row = conn.execute(
                "SELECT ca_private_key_encrypted FROM internal_ca WHERE status='active' LIMIT 1"
            ).fetchone()
            conn.close()

            if row and row['ca_private_key_encrypted']:
                try:
                    db_key = row['ca_private_key_encrypted']
                    # If base64, decode it
                    if not db_key.startswith('-----BEGIN'):
                        db_key = base64.b64decode(db_key).decode('utf-8')
                    results["database_status"] = "accessible"
                    results["key_accessible_from_db"] = True
                except Exception as e:
                    results["database_status"] = "corrupted"
                    results["errors"].append(f"Database key corrupted: {str(e)}")
                    db_key = None
            else:
                results["database_status"] = "empty"
                db_key = None
        except Exception as e:
            results["database_status"] = "error"
            results["errors"].append(f"Database error: {str(e)}")
            db_key = None

        # Test 3: Do vault and database keys match?
        if key_from_vault and db_key:
            results["keys_match"] = (key_from_vault == db_key)
            if not results["keys_match"]:
                results["errors"].append("Vault key differs from database key - MISMATCH")

        # Test 4: Safe to remove DB field?
        # Safe only if:
        # 1. Key in vault & accessible ✓
        # 2. Keys match (or DB empty) ✓
        # 3. No critical errors ✓
        results["safe_to_remove_db_field"] = (
            results["vault_status"] == "accessible" and
            (results["keys_match"] or results["database_status"] == "empty") and
            results["key_accessible_from_vault"] and
            len([e for e in results["errors"] if "MISMATCH" in e or "corrupted" in e]) == 0
        )

        # Overall bootstrap status
        if results["key_accessible_from_vault"]:
            results["bootstrap_status"] = "complete"
        else:
            results["bootstrap_status"] = "incomplete"

        return jsonify(results), 200

    except Exception as e:
        results["bootstrap_status"] = "error"
        results["errors"].append(f"Verification failed: {str(e)}")
        return jsonify(results), 500

# ==================== USER MANAGEMENT ROUTES ====================

@app.route('/api/v1/users', methods=['GET'])
@login_required
def get_users():
    """Get all users - accessible to admins and users with users:read permission"""
    try:
        from caip_service_layer.auth_service import get_user_role
        user_id = session.get('user_id')
        user_role = get_user_role(user_id)

        logger.info(f"User {user_id} with role '{user_role}' requesting users list")

        # Simplified check - allow admin and system-administrator roles
        # Also allow other roles temporarily for debugging
        allowed_roles = ['admin', 'system-administrator', 'engagement-manager', 'integration-manager']

        if user_role not in allowed_roles:
            logger.warning(f"User {user_id} with role '{user_role}' denied access to users list")
            return jsonify({'error': f'Admin access required. Your role: {user_role}'}), 403

        conn = DatabaseService.get_connection()
        c = conn.cursor()

        # Add auth_provider_id column if it doesn't exist
        c.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in c.fetchall()]
        if 'auth_provider_id' not in columns:
            c.execute('ALTER TABLE users ADD COLUMN auth_provider_id INTEGER')
            conn.commit()

        # Join with auth_providers to get provider name
        c.execute('''
            SELECT u.id, u.username, u.role, u.enabled, u.created_at, u.updated_at, u.auth_provider_id,
                   ap.name as auth_provider_name
            FROM users u
            LEFT JOIN auth_providers ap ON u.auth_provider_id = ap.id
        ''')
        users = [DatabaseService.dict_from_row(row) for row in c.fetchall()]
        conn.close()

        logger.info(f"Successfully retrieved {len(users)} users for user {user_id}")
        return jsonify({'users': users}), 200

    except Exception as e:
        logger.error(f"Error getting users: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/users', methods=['POST'])
@login_required
@permission_required('users:create')
def create_user():
    """Create new user with optional engagement assignments and per-engagement certificates"""
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'scan-user')
        enabled = 1 if data.get('enabled', True) else 0

        # Support both single engagement_id (backward compat) and engagement_ids array
        engagement_ids = data.get('engagement_ids', [])
        if not engagement_ids and data.get('engagement_id'):
            # Backward compatibility: single engagement_id becomes array
            engagement_ids = [data.get('engagement_id')]

        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400

        if not is_valid_role(role):
            return jsonify({'error': f'Invalid role. Must be one of: {", ".join(get_role_names())}'}), 400

        hashed_password = generate_password_hash(password)

        conn = DatabaseService.get_connection()
        c = conn.cursor()

        # Get role_id from roles table based on role name
        c.execute('SELECT id FROM roles WHERE name = ?', (role,))
        role_row = c.fetchone()
        role_id = role_row[0] if role_row else None

        # Insert user with both role (legacy) and role_id (RBAC)
        c.execute('INSERT INTO users (username, password, role, role_id, enabled) VALUES (?, ?, ?, ?, ?)',
                 (username, hashed_password, role, role_id, enabled))
        conn.commit()

        user_id = c.lastrowid
        conn.close()

        logger.info(f"Created user {username} with role {role} (role_id: {role_id})")

        # Assign user to engagements and create engagement_assignments records
        engagement_results = []
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        current_user_id = session.get('user_id') or user_id  # Fallback to created user if session not set

        for engagement_id in engagement_ids:
            try:
                # Verify engagement exists
                c.execute('SELECT id FROM engagements WHERE engagement_id = ?', (engagement_id,))
                eng_row = c.fetchone()
                if not eng_row:
                    engagement_results.append({
                        'engagement_id': engagement_id,
                        'status': 'error',
                        'message': f'Engagement {engagement_id} not found'
                    })
                    continue

                # Insert into engagement_assignments (with INSERT OR IGNORE for idempotence)
                c.execute('''
                    INSERT OR IGNORE INTO engagement_assignments
                    (user_id, engagement_id, assigned_by, assigned_at)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ''', (user_id, engagement_id, current_user_id))
                conn.commit()

                engagement_results.append({
                    'engagement_id': engagement_id,
                    'status': 'assigned',
                    'message': f'User assigned to engagement {engagement_id}'
                })
            except Exception as assign_error:
                logger.warning(f"Failed to assign user {username} to engagement {engagement_id}: {assign_error}")
                engagement_results.append({
                    'engagement_id': engagement_id,
                    'status': 'error',
                    'message': str(assign_error)
                })

        conn.close()

        # Issue identity certificates: one per engagement, or one internal CA cert if no engagements
        certificate_results = []
        if engagement_ids:
            # Issue per-engagement identity certificates
            for engagement_id in engagement_ids:
                try:
                    cert_info = certificate_service.issue_user_identity_certificate(
                        user_id=user_id,
                        username=username,
                        role=role,
                        engagement_id=engagement_id,
                        cert_purpose='identity',
                        validity_days=365
                    )
                    logger.info(f"Issued identity certificate {cert_info['certificate_serial']} for user {username} in engagement {engagement_id}")
                    certificate_results.append({
                        'engagement_id': engagement_id,
                        'cert_purpose': 'identity',
                        'certificate_serial': cert_info.get('certificate_serial'),
                        'status': 'issued',
                        'message': 'Identity certificate issued'
                    })
                except Exception as cert_error:
                    logger.warning(f"Failed to issue certificate for user {username} in engagement {engagement_id}: {cert_error}")
                    certificate_results.append({
                        'engagement_id': engagement_id,
                        'cert_purpose': 'identity',
                        'status': 'error',
                        'message': str(cert_error)
                    })
        else:
            # No engagements: issue Internal CA identity certificate
            try:
                cert_info = certificate_service.issue_user_identity_certificate(
                    user_id=user_id,
                    username=username,
                    role=role,
                    engagement_id=None,
                    cert_purpose='identity',
                    validity_days=365
                )
                logger.info(f"Issued internal CA identity certificate {cert_info['certificate_serial']} for user {username}")
                certificate_results.append({
                    'engagement_id': None,
                    'cert_purpose': 'identity',
                    'certificate_serial': cert_info.get('certificate_serial'),
                    'status': 'issued',
                    'message': 'Internal CA identity certificate issued'
                })
            except Exception as cert_error:
                logger.warning(f"Failed to issue internal CA certificate for user {username}: {cert_error}")
                certificate_results.append({
                    'cert_purpose': 'identity',
                    'status': 'error',
                    'message': str(cert_error)
                })

        # Backward compatibility: return first successful cert in 'certificate' field
        first_successful_cert = next((c for c in certificate_results if c['status'] == 'issued'), None)

        return jsonify({
            'id': user_id,
            'username': username,
            'role': role,
            'enabled': enabled,
            'engagement_results': engagement_results,
            'certificate_results': certificate_results,
            'certificate': first_successful_cert,  # Backward compat
            'message': 'User created successfully'
        }), 201

    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/users/<int:user_id>', methods=['PUT'])
@login_required
@permission_required('users:update')
def update_user(user_id):
    """Update user"""
    try:
        data = request.json

        conn = DatabaseService.get_connection()
        c = conn.cursor()

        # Check if user exists
        c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        if not c.fetchone():
            conn.close()
            return jsonify({'error': 'User not found'}), 404

        # Update role if provided
        if 'role' in data:
            role = data['role']
            if not is_valid_role(role):
                conn.close()
                return jsonify({'error': f'Invalid role. Must be one of: {", ".join(get_role_names())}'}), 400

            # Get role_id from roles table based on role name
            c.execute('SELECT id FROM roles WHERE name = ?', (role,))
            role_row = c.fetchone()
            role_id = role_row[0] if role_row else None

            # Update both role (legacy) and role_id (RBAC)
            c.execute('UPDATE users SET role = ?, role_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                     (role, role_id, user_id))
            logger.info(f"Updated user {user_id} role to {role} (role_id: {role_id})")

        # Update password if provided
        if 'password' in data:
            hashed_password = generate_password_hash(data['password'])
            c.execute('UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                     (hashed_password, user_id))

        # Update enabled status if provided
        if 'enabled' in data:
            enabled = 1 if data['enabled'] else 0
            c.execute('UPDATE users SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                     (enabled, user_id))

        conn.commit()
        conn.close()

        return jsonify({'message': 'User updated successfully'}), 200

    except Exception as e:
        logger.error(f"Error updating user: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/users/<int:user_id>', methods=['DELETE'])
@login_required
@permission_required('users:delete')
def delete_user(user_id):
    """Delete user"""
    try:
        # Prevent deleting your own account
        if user_id == session.get('user_id'):
            return jsonify({'error': 'Cannot delete your own account'}), 400
        
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'User deleted successfully'}), 200
    
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/users/roles', methods=['GET'])
@login_required
def get_roles():
    """Get available roles with full details for display"""
    return jsonify({'roles': get_all_roles()}), 200


# ==================== RBAC MANAGEMENT ROUTES ====================

@app.route('/api/v1/rbac/roles', methods=['GET'])
@login_required
@permission_required('users:read')
def get_rbac_roles():
    """Get all roles with their details and permissions"""
    try:
        from caip_service_layer.rbac_service import RBACService
        roles = RBACService.get_all_roles()

        # Enhance each role with permission names
        for role in roles:
            perms = RBACService.get_role_permissions(role['id'])
            # Extract just the permission names
            role['permissions'] = [p['name'] for p in perms] if perms else []

        return jsonify({'roles': roles}), 200
    except Exception as e:
        logger.error(f"Error getting RBAC roles: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/rbac/roles/<int:role_id>/permissions', methods=['GET'])
@login_required
@permission_required('users:read')
def get_role_permissions(role_id):
    """Get all permissions for a specific role"""
    try:
        from caip_service_layer.rbac_service import RBACService
        permissions = RBACService.get_role_permissions(role_id)
        return jsonify({'permissions': permissions}), 200
    except Exception as e:
        logger.error(f"Error getting role permissions: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/rbac/permissions', methods=['GET'])
@login_required
@permission_required('users:read')
def get_rbac_permissions():
    """Get all permissions in the system"""
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM permissions ORDER BY resource_type, action')
        rows = c.fetchall()
        conn.close()

        permissions = [DatabaseService.dict_from_row(row) for row in rows]
        return jsonify({'permissions': permissions}), 200
    except Exception as e:
        logger.error(f"Error getting permissions: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/rbac/users/<int:user_id>/permissions', methods=['GET'])
@login_required
def get_user_permissions(user_id):
    """Get all permissions for a specific user"""
    try:
        # Users can view their own permissions, admins can view anyone's
        if session.get('user_id') != user_id:
            from caip_service_layer.auth_service import check_user_permission
            if not check_user_permission(session['user_id'], 'users:read'):
                return jsonify({'error': 'Forbidden'}), 403

        from caip_service_layer.rbac_service import RBACService
        permissions = list(RBACService.get_user_permissions(user_id))
        return jsonify({'permissions': permissions}), 200
    except Exception as e:
        logger.error(f"Error getting user permissions: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/rbac/engagements/<engagement_id>/users', methods=['GET'])
@login_required
@permission_required('engagements:read')
def get_engagement_users(engagement_id):
    """Get all users assigned to an engagement"""
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('''
            SELECT u.*, ea.assigned_at
            FROM users u
            JOIN engagement_assignments ea ON u.id = ea.user_id
            WHERE ea.engagement_id = ?
            ORDER BY u.username
        ''', (engagement_id,))
        rows = c.fetchall()
        conn.close()

        users = [DatabaseService.dict_from_row(row) for row in rows]
        return jsonify({'users': users}), 200
    except Exception as e:
        logger.error(f"Error getting engagement users: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/rbac/engagements/<engagement_id>/assign', methods=['POST'])
@login_required
@permission_required('engagements:assign_users')
def assign_user_to_engagement(engagement_id):
    """Assign a user to an engagement"""
    try:
        data = request.json
        user_id = data.get('user_id')

        if not user_id:
            return jsonify({'error': 'user_id required'}), 400

        from caip_service_layer.rbac_service import RBACService
        success = RBACService.assign_user_to_engagement(
            user_id,
            engagement_id,
            session['user_id']
        )

        if success:
            return jsonify({'message': 'User assigned to engagement'}), 200
        else:
            return jsonify({'error': 'Failed to assign user'}), 500

    except Exception as e:
        logger.error(f"Error assigning user to engagement: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/rbac/engagements/<engagement_id>/unassign/<int:user_id>', methods=['DELETE'])
@login_required
@permission_required('engagements:assign_users')
def unassign_user_from_engagement(engagement_id, user_id):
    """Remove a user's assignment from an engagement"""
    try:
        from caip_service_layer.rbac_service import RBACService
        success = RBACService.unassign_user_from_engagement(user_id, engagement_id)

        if success:
            return jsonify({'message': 'User unassigned from engagement'}), 200
        else:
            return jsonify({'error': 'Failed to unassign user'}), 500

    except Exception as e:
        logger.error(f"Error unassigning user from engagement: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== OAUTH AUTHENTICATION ROUTES ====================

@app.route('/api/v1/auth/providers', methods=['GET'])
def get_auth_providers():
    """Get all enabled OAuth authentication providers"""
    try:
        from caip_service_layer.oauth_service import OAuthService
        providers = OAuthService.get_all_enabled_providers()
        return jsonify({'providers': providers}), 200
    except Exception as e:
        logger.error(f"Error getting auth providers: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/auth/oauth/login/<int:provider_id>', methods=['GET'])
def oauth_login(provider_id):
    """Initiate OAuth login flow for a provider"""
    try:
        from caip_service_layer.oauth_service import OAuthService

        # Get provider
        provider = OAuthService.get_provider(provider_id)
        if not provider:
            return jsonify({'error': 'Provider not found or disabled'}), 404

        # Generate state token
        redirect_after = request.args.get('redirect', '/dashboard')
        state = OAuthService.generate_state_token(provider_id, redirect_after)

        # Get authorization URL
        auth_url = provider.get_authorization_url(state)

        # Store state in session for additional validation
        session['oauth_state'] = state

        logger.info(f"Initiating OAuth login for provider {provider_id}")
        return redirect(auth_url)

    except Exception as e:
        logger.error(f"Error initiating OAuth login: {e}")
        return jsonify({'error': 'Failed to initiate OAuth login'}), 500


@app.route('/api/v1/auth/oauth/callback', methods=['GET'])
def oauth_callback():
    """Handle OAuth callback after user authentication"""
    try:
        from caip_service_layer.oauth_service import OAuthService

        # Get authorization code and state from callback
        code = request.args.get('code')
        state = request.args.get('state')
        error = request.args.get('error')

        # Check for OAuth errors
        if error:
            error_desc = request.args.get('error_description', error)
            logger.error(f"OAuth callback error: {error_desc}")
            return render_template('login.html', error=f"Authentication failed: {error_desc}")

        if not code or not state:
            logger.error("OAuth callback missing code or state")
            return render_template('login.html', error="Invalid authentication response")

        # Validate state token
        state_data = OAuthService.validate_state_token(state)
        if not state_data:
            logger.error("Invalid or expired OAuth state token")
            return render_template('login.html', error="Authentication session expired")

        # Verify state matches session (double-check)
        if session.get('oauth_state') != state:
            logger.error("OAuth state mismatch")
            return render_template('login.html', error="Authentication session mismatch")

        # Get provider
        provider_id = state_data['provider_id']
        provider = OAuthService.get_provider(provider_id)
        if not provider:
            logger.error(f"Provider {provider_id} not found during callback")
            return render_template('login.html', error="Authentication provider not found")

        # Exchange code for token
        token = provider.exchange_code_for_token(code, state)

        # Get user info
        user_info = provider.get_user_info(token)

        # Provision or link user
        auto_provision = provider.config.auto_provision_users
        user_id = OAuthService.provision_or_link_user(user_info, provider_id, auto_provision)

        if not user_id:
            logger.warning(f"User provisioning failed for {user_info.email}")
            return render_template('login.html',
                error="Your account is not authorized. Please contact your administrator.")

        # Get user details
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = DatabaseService.dict_from_row(c.fetchone())
        conn.close()

        if not user:
            logger.error(f"User {user_id} not found after provisioning")
            return render_template('login.html', error="User account error")

        # Check if account is disabled
        if not user.get('enabled', 1):
            log_auth_failure(user['username'], 'Account disabled (OAuth)')
            logger.warning(f"OAuth login blocked - account disabled: {user['username']}")
            return render_template('login.html', error="Account disabled. Please contact your administrator.")

        # Create session
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        session['oauth_provider_id'] = provider_id
        session['oauth_user_info'] = {
            'email': user_info.email,
            'name': user_info.name
        }

        # Clear OAuth state
        session.pop('oauth_state', None)

        # Log successful authentication
        log_auth_success(user['username'], f"OAuth ({provider.config.provider_name})")

        logger.info(f"OAuth login successful: user={user['username']}, provider={provider.config.provider_name}")

        # Redirect to original destination
        redirect_uri = state_data.get('redirect_uri', '/dashboard')
        return redirect(redirect_uri)

    except ValueError as e:
        logger.error(f"OAuth callback validation error: {e}")
        return render_template('login.html', error=f"Authentication failed: {str(e)}")
    except Exception as e:
        logger.error(f"OAuth callback error: {e}")
        import traceback
        traceback.print_exc()
        return render_template('login.html', error="Authentication error occurred")


# ==================== OAUTH PROVIDER MANAGEMENT ROUTES ====================

@app.route('/api/v1/settings/auth-providers', methods=['GET'])
@login_required
@permission_required('auth_providers:read')
def get_all_auth_providers():
    """Get all OAuth providers (enabled and disabled) for management"""
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM auth_providers ORDER BY name')
        rows = c.fetchall()
        conn.close()

        providers = []
        for row in rows:
            provider = DatabaseService.dict_from_row(row)
            # Parse config but mask secrets
            config = json.loads(provider['config_json'])
            provider['config_summary'] = {
                'client_id': config.get('client_id', ''),
                'tenant_id': config.get('tenant_id', ''),
                'redirect_uri': config.get('redirect_uri', ''),
                'scopes': config.get('scopes', []),
                'auto_provision_users': config.get('auto_provision_users', False),
                'default_role': config.get('default_role', 'report-user')
            }
            del provider['config_json']
            providers.append(provider)

        return jsonify({'providers': providers}), 200

    except Exception as e:
        logger.error(f"Error getting auth providers: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/settings/auth-providers', methods=['POST'])
@login_required
@permission_required('auth_providers:create')
def create_auth_provider():
    """Create new OAuth provider"""
    try:
        data = request.json
        name = data.get('name')
        provider_type = data.get('type')
        config = data.get('config', {})

        if not name or not provider_type:
            return jsonify({'error': 'Name and type are required'}), 400

        # Validate provider type
        supported_types = ['azure_entra_id', 'okta']
        if provider_type not in supported_types:
            return jsonify({'error': f'Provider type must be one of: {", ".join(supported_types)}'}), 400

        # Build redirect URI if not provided
        if 'redirect_uri' not in config:
            config['redirect_uri'] = request.url_root.rstrip('/') + '/api/v1/auth/oauth/callback'

        conn = DatabaseService.get_connection()
        c = conn.cursor()

        config_json = json.dumps(config)
        c.execute('''INSERT INTO auth_providers (name, type, config_json, enabled)
                     VALUES (?, ?, ?, ?)''',
                 (name, provider_type, config_json, data.get('enabled', True)))

        provider_id = c.lastrowid
        conn.commit()
        conn.close()

        logger.info(f"Created OAuth provider: {name} (type={provider_type})")

        return jsonify({
            'id': provider_id,
            'name': name,
            'type': provider_type,
            'message': 'OAuth provider created successfully'
        }), 201

    except sqlite3.IntegrityError:
        return jsonify({'error': 'Provider with this name already exists'}), 400
    except Exception as e:
        logger.error(f"Error creating auth provider: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/settings/auth-providers/<int:provider_id>', methods=['GET'])
@login_required
@permission_required('auth_providers:read')
def get_auth_provider(provider_id):
    """Get OAuth provider details including config"""
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM auth_providers WHERE id = ?', (provider_id,))
        row = c.fetchone()
        conn.close()

        if not row:
            return jsonify({'error': 'Provider not found'}), 404

        provider = DatabaseService.dict_from_row(row)
        provider['config'] = json.loads(provider['config_json'])
        del provider['config_json']

        return jsonify(provider), 200

    except Exception as e:
        logger.error(f"Error getting auth provider: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/settings/auth-providers/<int:provider_id>', methods=['PUT'])
@login_required
@permission_required('auth_providers:update')
def update_auth_provider(provider_id):
    """Update OAuth provider"""
    try:
        data = request.json

        conn = DatabaseService.get_connection()
        c = conn.cursor()

        # Check if provider exists
        c.execute('SELECT * FROM auth_providers WHERE id = ?', (provider_id,))
        existing = c.fetchone()
        if not existing:
            conn.close()
            return jsonify({'error': 'Provider not found'}), 404

        # Update fields
        if 'name' in data:
            c.execute('UPDATE auth_providers SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                     (data['name'], provider_id))

        if 'enabled' in data:
            c.execute('UPDATE auth_providers SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                     (1 if data['enabled'] else 0, provider_id))

        if 'config' in data:
            config_json = json.dumps(data['config'])
            c.execute('UPDATE auth_providers SET config_json = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                     (config_json, provider_id))

        conn.commit()
        conn.close()

        logger.info(f"Updated OAuth provider {provider_id}")

        return jsonify({'message': 'Provider updated successfully'}), 200

    except sqlite3.IntegrityError:
        return jsonify({'error': 'Provider name already exists'}), 400
    except Exception as e:
        logger.error(f"Error updating auth provider: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/settings/auth-providers/<int:provider_id>', methods=['DELETE'])
@login_required
@permission_required('auth_providers:delete')
def delete_auth_provider(provider_id):
    """Delete OAuth provider"""
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()

        # Check if provider exists
        c.execute('SELECT * FROM auth_providers WHERE id = ?', (provider_id,))
        if not c.fetchone():
            conn.close()
            return jsonify({'error': 'Provider not found'}), 404

        # Delete provider (cascade will handle user links)
        c.execute('DELETE FROM auth_providers WHERE id = ?', (provider_id,))
        conn.commit()
        conn.close()

        logger.info(f"Deleted OAuth provider {provider_id}")

        return jsonify({'message': 'Provider deleted successfully'}), 200

    except Exception as e:
        logger.error(f"Error deleting auth provider: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== ENGAGEMENT ROUTES ====================

@app.route('/api/v1/engagements/<engagement_id>/summary', methods=['GET'])
@login_required
@permission_required('engagements:read')
def get_engagement_summary(engagement_id):
    """
    Get summary of all reports associated with an engagement.
    
    Returns counts and lists of scans, configurations, reassessments, 
    aggregations, and document assessments.
    """
    try:
        # Verify engagement exists
        engagement = EngagementService.get_engagement(db_service, engagement_id)
        if not engagement:
            return jsonify({'error': 'Engagement not found'}), 404
        
        # Get report summary from DatabaseService
        summary = db_service.get_engagement_report_summary(engagement_id)
        
        # Add document assessments from DocumentAssessmentDatabase
        from caip_document_assessment_functions.document_assessment_database import DocumentAssessmentDatabase
        doc_assessments = DocumentAssessmentDatabase.list_assessments_by_engagement(
            db_service, engagement_id
        )
        summary['document_assessments'] = doc_assessments
        summary['document_assessment_count'] = len(doc_assessments)
        summary['total_reports'] += len(doc_assessments)
        
        return jsonify(summary), 200
        
    except Exception as e:
        logger.error(f"Error getting engagement summary: {e}")
        return jsonify({'error': str(e)}), 500

# ==================== CONFIGURATION ROUTES ====================

@app.route('/api/v1/scans/configurations', methods=['GET'])
@login_required
@permission_required('scan_configs:read')
def get_configurations():
    """Get all configurations, optionally filtered by engagement"""
    try:
        engagement_id = request.args.get('engagement_id')
        
        configs = DatabaseService.list_configurations_by_engagement(engagement_id)
        
        # Parse JSON strings
        for config in configs:
            config['config_json'] = json.loads(config['config_json'])
        
        return jsonify({'configurations': configs}), 200
    
    except Exception as e:
        logger.error(f"Error getting configurations: {e}")
        return jsonify({'error': str(e)}), 500


def validate_p12_base64(p12_data_base64: str) -> bool:
    """Validate that base64 string is a valid P12 certificate"""
    try:
        import base64

        # Decode base64
        p12_bytes = base64.b64decode(p12_data_base64)

        # Basic validation - P12 files are typically at least 100 bytes
        if len(p12_bytes) < 100:
            logger.warning(f"P12 validation: decoded size too small ({len(p12_bytes)} bytes)")
            return False

        # P12 files typically start with specific bytes (0x30 0x82 or 0x30 0x83 for DER)
        # But this is optional validation - just check it's not empty/small
        return True
    except Exception as e:
        logger.warning(f"P12 validation failed: {e}")
        return False

@app.route('/api/v1/scans/configurations', methods=['POST'])
@login_required
@permission_required('scan_configs:create')
def create_configuration():
    """Create new configuration"""
    conn = None
    try:
        data = request.json
        name = data.get('name')
        config = data.get('config')

        if not name or not config:
            return jsonify({'error': 'Name and configuration are required'}), 400

        # Debug: Log what was received for EJBCA
        if config.get('ejbca', {}).get('enabled'):
            logger.info(f"[CREATE CONFIG] EJBCA enabled, {len(config['ejbca'].get('servers', []))} servers")
            for idx, server in enumerate(config['ejbca'].get('servers', [])):
                p12_data = server.get('p12_data_base64')
                p12_path = server.get('p12_path')
                logger.info(f"[CREATE CONFIG] Server {idx}: name={server.get('name')}, "
                           f"has_p12_data_base64={bool(p12_data)} (len={len(p12_data) if p12_data else 0}), "
                           f"has_p12_path={bool(p12_path)}")
                if p12_data:
                    logger.info(f"[CREATE CONFIG] Server {idx} p12_data_base64 first 50 chars: {p12_data[:50]}")

        # Validate EJBCA P12 files if present
        if config.get('ejbca', {}).get('enabled'):
            for server in config['ejbca'].get('servers', []):
                p12_data = server.get('p12_data_base64')
                if p12_data:
                    if not validate_p12_base64(p12_data):
                        return jsonify({
                            'error': f"Invalid P12 certificate for server '{server.get('name')}'"
                        }), 400

        config_json = json.dumps(config)

        engagement_id = data.get('engagement_id')
        
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('INSERT INTO configurations (name, config_json, engagement_id) VALUES (?, ?, ?)',
                 (name, config_json, engagement_id))
        
        # Get the lastrowid BEFORE commit to ensure it's available
        config_id = c.lastrowid
        
        conn.commit()
        
        return jsonify({
            'id': config_id,
            'name': name,
            'message': 'Configuration created successfully'
        }), 201
    
    except sqlite3.IntegrityError as e:
        logger.error(f"Integrity error creating configuration: {e}")
        return jsonify({'error': 'Configuration name already exists'}), 409
    except sqlite3.OperationalError as e:
        if 'database is locked' in str(e):
            logger.error(f"Database locked when creating configuration: {e}")
            return jsonify({'error': 'Database is busy. Please try again.'}), 503
        logger.error(f"Database error creating configuration: {e}")
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        logger.error(f"Error creating configuration: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/v1/scans/configurations/<int:config_id>', methods=['PUT'])
@login_required
@permission_required('scan_configs:update')
def update_configuration(config_id):
    """Update configuration"""
    conn = None
    try:
        data = request.json
        name = data.get('name')
        config = data.get('config')
        
        if not name or not config:
            return jsonify({'error': 'Name and configuration are required'}), 400
        
        config_json = json.dumps(config)
        
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('''UPDATE configurations 
                     SET name = ?, config_json = ?, updated_at = CURRENT_TIMESTAMP 
                     WHERE id = ?''',
                 (name, config_json, config_id))
        conn.commit()
        
        return jsonify({'message': 'Configuration updated successfully'}), 200
    
    except sqlite3.IntegrityError as e:
        logger.error(f"Integrity error updating configuration: {e}")
        return jsonify({'error': 'Configuration name already exists'}), 409
    except Exception as e:
        logger.error(f"Error updating configuration: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/v1/scans/configurations/<int:config_id>', methods=['DELETE'])
@login_required
@permission_required('scan_configs:delete')
def delete_configuration(config_id):
    """Delete configuration"""
    conn = None
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        
        # Check if any scans are associated with this configuration
        c.execute('SELECT COUNT(*) as scan_count FROM scans WHERE config_id = ?', (config_id,))
        result = c.fetchone()
        scan_count = result['scan_count'] if result else 0
        
        if scan_count > 0:
            conn.close()
            return jsonify({
                'error': f'Cannot delete configuration: {scan_count} scan(s) are associated with this configuration. Please delete the associated scans first.'
            }), 409
        
        # Start explicit transaction
        c.execute('BEGIN EXCLUSIVE')
        
        # Delete the configuration
        c.execute('DELETE FROM configurations WHERE id = ?', (config_id,))
        logger.info(f"Deleted configuration record for config_id {config_id}")
        
        conn.commit()
        logger.info(f"Successfully deleted configuration {config_id}")
        
        return jsonify({'message': 'Configuration deleted successfully'}), 200
    
    except Exception as e:
        if conn:
            try:
                conn.rollback()
            except:
                pass
        logger.error(f"Error deleting configuration {config_id}: {e}", exc_info=True)
        return jsonify({'error': f'Failed to delete configuration: {str(e)}'}), 500
    
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass

@app.route('/api/v1/scans/configurations/<int:config_id>/export', methods=['GET'])
@login_required
@permission_required('scan_configs:read')
def export_configuration(config_id):
    """Export configuration as JSON file"""
    conn = None
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('SELECT id, name, config_json FROM configurations WHERE id = ?', (config_id,))
        row = c.fetchone()

        if not row:
            return jsonify({'error': 'Configuration not found'}), 404

        config_name = row['name']
        config_json = row['config_json']

        # Parse JSON to ensure it's valid
        config_data = json.loads(config_json)

        # Generate filename with timestamp
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{config_name}_{timestamp}.json"

        # Return JSON with download headers
        from flask import make_response
        response = make_response(json.dumps(config_data, indent=2))
        response.headers['Content-Type'] = 'application/json'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'

        logger.info(f"Exported configuration {config_id} ({config_name}) as {filename}")
        return response, 200

    except Exception as e:
        logger.error(f"Error exporting configuration {config_id}: {e}", exc_info=True)
        return jsonify({'error': f'Failed to export configuration: {str(e)}'}), 500

    finally:
        if conn:
            try:
                conn.close()
            except:
                pass

# ==================== POLICY ROUTES ====================  

@app.route('/api/v1/policies/upload', methods=['POST'])
@login_required
def upload_policy_v2():
    """Upload a policy file in v2 format"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        policy = json.load(file)
        
        # Validate format
        if policy.get('version') != '2.0':
            return jsonify({'error': 'Policy must be version 2.0'}), 400
        
        # Save to database
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        
        policy_json = json.dumps(policy)
        c.execute('''INSERT INTO policies (name, policy_json) 
                     VALUES (?, ?)''',
                 (policy.get('metadata', {}).get('name', 'imported'), 
                  policy_json))
        
        conn.commit()
        policy_id = c.lastrowid
        conn.close()
        
        return jsonify({
            'id': policy_id,
            'policy_name': policy.get('metadata', {}).get('name'),
            'rules_count': len(policy.get('rules', []))
        }), 201
        
    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid JSON'}), 400
    except Exception as e:
        logger.error(f"Policy upload error: {e}")
        return jsonify({'error': str(e)}), 500
    


@app.route('/api/v1/policies', methods=['GET'])
@login_required
def list_policies():
    """List all policies"""
    conn = DatabaseService.get_connection()
    c = conn.cursor()
    c.execute('SELECT id, name, policy_json, created_at FROM policies ORDER BY created_at DESC')
    policies = c.fetchall()
    conn.close()
    
    return jsonify({
        'policies': [dict(p) for p in policies]
    }), 200
    

@app.route('/api/v1/policies', methods=['POST'])
@login_required
def create_policy():
    """Create new policy"""
    data = request.json
    name = data.get('name')
    policy = data.get('policy')
    
    if not name or not policy:
        return jsonify({'error': 'Name and policy are required'}), 400
    
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('INSERT INTO policies (name, policy_json) VALUES (?, ?)',
                 (name, json.dumps(policy)))
        conn.commit()
        policy_id = c.lastrowid
        conn.close()
        
        return jsonify({
            'id': policy_id,
            'name': name,
            'message': 'Policy created successfully'
        }), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Policy name already exists'}), 409
    except Exception as e:
        logger.error(f"Error creating policy: {e}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/v1/policies/<int:policy_id>', methods=['GET'])
@login_required
def get_policy(policy_id):
    """Get a specific policy"""
    conn = DatabaseService.get_connection()
    c = conn.cursor()
    c.execute('SELECT id, name, policy_json, created_at FROM policies WHERE id = ?', (policy_id,))
    row = c.fetchone()
    conn.close()
    
    if not row:
        return jsonify({'error': 'Policy not found'}), 404
    
    return jsonify({
        'policy': {
            'id': row['id'],
            'name': row['name'],
            'policy_json': json.loads(row['policy_json']),
            'created_at': row['created_at']
        }
    }), 200
    
@app.route('/api/v1/policies/<int:policy_id>', methods=['PUT'])
@login_required
def update_policy(policy_id):
    """Update existing policy"""
    data = request.json
    name = data.get('name')
    policy = data.get('policy')
    
    if not name or not policy:
        return jsonify({'error': 'Name and policy are required'}), 400
    
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('UPDATE policies SET name = ?, policy_json = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                 (name, json.dumps(policy), policy_id))
        conn.commit()
        conn.close()
        
        return jsonify({
            'id': policy_id,
            'message': 'Policy updated successfully'
        }), 200
    except Exception as e:
        logger.error(f"Error updating policy: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/policies/<int:policy_id>', methods=['DELETE'])
@login_required
def delete_policy(policy_id):
    """Delete a policy with confirmation of related records"""
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()

        # Check for related records
        c.execute('SELECT id, name FROM policies WHERE id = ?', (policy_id,))
        policy = c.fetchone()

        if not policy:
            return jsonify({'error': 'Policy not found'}), 404

        policy_name = policy[1]

        # Find all related records
        related_records = {}

        # Check scans
        c.execute('SELECT id, name, status FROM scans WHERE policy_id = ?', (policy_id,))
        related_records['scans'] = [{'id': row[0], 'name': row[1], 'status': row[2]} for row in c.fetchall()]

        # Check reassessments
        c.execute('SELECT id FROM reassessments WHERE policy_id = ?', (policy_id,))
        related_records['reassessments'] = [{'id': row[0]} for row in c.fetchall()]

        # Check scan_logs (scans with logs for this policy)
        c.execute('''SELECT DISTINCT sl.scan_id FROM scan_logs sl
                     JOIN scans s ON sl.scan_id = s.id
                     WHERE s.policy_id = ?''', (policy_id,))
        related_records['scan_logs'] = [{'scan_id': row[0]} for row in c.fetchall()]

        # If user hasn't confirmed deletion yet, return the related records
        if request.args.get('confirm') != 'true':
            has_related = any(related_records.values())

            if has_related:
                return jsonify({
                    'warning': f'Policy "{policy_name}" has related records. Please confirm deletion.',
                    'policy_id': policy_id,
                    'policy_name': policy_name,
                    'related_records': related_records,
                    'requires_confirmation': True
                }), 200

        # User confirmed or no related records - proceed with deletion
        # Disable foreign keys temporarily for clean deletion
        c.execute('PRAGMA foreign_keys = OFF')

        # Delete related records
        c.execute('DELETE FROM scan_logs WHERE scan_id IN (SELECT id FROM scans WHERE policy_id = ?)', (policy_id,))
        c.execute('DELETE FROM scans WHERE policy_id = ?', (policy_id,))
        c.execute('DELETE FROM reassessments WHERE policy_id = ?', (policy_id,))

        # Delete the policy
        c.execute('DELETE FROM policies WHERE id = ?', (policy_id,))

        # Re-enable foreign keys
        c.execute('PRAGMA foreign_keys = ON')

        conn.commit()
        conn.close()

        deleted_summary = {
            'policy_name': policy_name,
            'scans_deleted': len(related_records.get('scans', [])),
            'reassessments_deleted': len(related_records.get('reassessments', [])),
            'scan_logs_deleted': len(related_records.get('scan_logs', []))
        }

        return jsonify({
            'message': 'Policy deleted successfully',
            'deleted_summary': deleted_summary
        }), 200
    except Exception as e:
        logger.error(f"Error deleting policy: {e}")
        return jsonify({'error': str(e)}), 500
    
# ==================== ASSESSMENT TYPE ROUTES ====================

@app.route('/api/v1/policies/by-assessment-type/<assessment_type>', methods=['GET'])
@login_required
@permission_required('view')
def get_policies_by_assessment_type(assessment_type):
    """Get policies filtered by assessment type"""
    try:
        valid_types = ['pki_health_check', 'pqc_assessment', 'all']
        if assessment_type not in valid_types:
            return jsonify({'error': f'assessment_type must be one of: {valid_types}'}), 400
        
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM policies')
        all_policies = [DatabaseService.dict_from_row(row) for row in c.fetchall()]
        conn.close()
        
        # Filter policies by assessment_type in metadata
        filtered_policies = []
        for policy in all_policies:
            try:
                policy_json = json.loads(policy['policy_json'])
                policy_assessment_type = policy_json.get('metadata', {}).get('assessment_type', 'pki_health_check')
                
                if assessment_type == 'all' or policy_assessment_type == assessment_type:
                    policy['policy_json'] = policy_json
                    policy['assessment_type'] = policy_assessment_type
                    filtered_policies.append(policy)
            except json.JSONDecodeError:
                # Include policies with invalid JSON as pki_health_check by default
                if assessment_type in ['all', 'pki_health_check']:
                    policy['assessment_type'] = 'pki_health_check'
                    filtered_policies.append(policy)
        
        return jsonify({'policies': filtered_policies}), 200
    
    except Exception as e:
        logger.error(f"Error getting policies by assessment type: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/assessment-types', methods=['GET'])
@login_required
def get_assessment_types():
    """Get available assessment types"""
    assessment_types = [
        {
            'id': 'pki_health_check',
            'name': 'PKI Health Check',
            'description': 'Traditional PKI and certificate health assessment',
            'icon': '🔬',
            'report_template': 'pki_report.html'
        },
        {
            'id': 'pqc_assessment',
            'name': 'PQC Migration Assessment',
            'description': 'Post-Quantum Cryptography migration readiness assessment',
            'icon': '🔐',
            'report_template': 'pqc_report.html'
        }
    ]
    return jsonify({'assessment_types': assessment_types}), 200

# ==================== SCAN ROUTES ====================

@app.route('/api/v1/scans', methods=['GET'])
@login_required
@permission_required('scans:read')
def get_scans():
    """Get all scans, optionally filtered by engagement"""
    try:
        engagement_id = request.args.get('engagement_id')
        
        scans = DatabaseService.list_scans_by_engagement(engagement_id)
        
        return jsonify({'scans': scans}), 200
    
    except Exception as e:
        logger.error(f"Error getting scans: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/scans', methods=['POST'])
@login_required
@permission_required('scans:create')
def create_scan():
    """Create new scan"""
    conn = None
    try:
        data = request.json
        name = data.get('name')
        config_id = data.get('config_id')
        policy_id = data.get('policy_id')
        assessment_type = data.get('assessment_type', 'pki_health_check')
        
        # Validate assessment_type
        valid_assessment_types = ['pki_health_check', 'pqc_assessment']
        if assessment_type not in valid_assessment_types:
            return jsonify({'error': f'assessment_type must be one of: {valid_assessment_types}'}), 400
        
        if not all([name, config_id, policy_id]):
            return jsonify({'error': 'Name, config_id, and policy_id are required'}), 400
        
        # Ensure IDs are integers
        try:
            config_id = int(config_id)
            policy_id = int(policy_id)
        except (ValueError, TypeError):
            return jsonify({'error': 'config_id and policy_id must be integers'}), 400
        
        # Validate that config_id and policy_id exist
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        
        # Check if config exists
        c.execute('SELECT id FROM configurations WHERE id = ?', (config_id,))
        if not c.fetchone():
            return jsonify({'error': f'Configuration with id {config_id} not found'}), 404
        
        # Check if policy exists
        c.execute('SELECT id FROM policies WHERE id = ?', (policy_id,))
        if not c.fetchone():
            return jsonify({'error': f'Policy with id {policy_id} not found'}), 404
        
        # Create the scan with optional engagement association and remote collector
        engagement_id = data.get('engagement_id')
        collector_id = data.get('collector_id')  # Optional: route to remote collector

        # Validate collector_id if provided
        if collector_id:
            c.execute('SELECT collector_id, status FROM remote_collectors WHERE collector_id = ?', (collector_id,))
            collector = c.fetchone()
            if not collector:
                return jsonify({'error': f'Collector with id {collector_id} not found'}), 404
            if collector['status'] not in ('active', 'pending'):
                return jsonify({'error': f'Collector {collector_id} is not active (status: {collector["status"]})'}), 400

        c.execute('INSERT INTO scans (name, config_id, policy_id, assessment_type, engagement_id, collector_id) VALUES (?, ?, ?, ?, ?, ?)',
                 (name, config_id, policy_id, assessment_type, engagement_id, collector_id))
        conn.commit()

        scan_id = c.lastrowid

        return jsonify({
            'id': scan_id,
            'name': name,
            'collector_id': collector_id,
            'message': 'Scan created successfully'
        }), 201
    
    except sqlite3.IntegrityError as e:
        #logger.error(f"Integrity error creating scan: {e}")
        log_scan_event(logging.ERROR, 'scan_create_integrity_error', f'Integrity error: {str(e)}')
        return jsonify({'error': 'Scan name already exists'}), 409
    except Exception as e:
        #logger.error(f"Error creating scan: {e}")
        log_scan_event(logging.ERROR, 'scan_create_error', f'Error creating scan: {str(e)}')
        import traceback
        log_scan_event(logging.ERROR, 'scan_create_exception', f'Exception: {traceback.format_exc()}')
        #logger.error(traceback.format_exc())
        return jsonify({'error': f'Error creating scan: {str(e)}'}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/v1/scans/<int:scan_id>', methods=['PUT'])
@login_required
@permission_required('scans:update')
def update_scan(scan_id):
    """Update scan"""
    try:
        data = request.json
        name = data.get('name')
        config_id = data.get('config_id')
        policy_id = data.get('policy_id')
        assessment_type = data.get('assessment_type', 'pki_health_check')
        collector_id = data.get('collector_id')  # Optional: route to remote collector (None = local)

        # Validate assessment_type
        valid_assessment_types = ['pki_health_check', 'pqc_assessment']
        if assessment_type not in valid_assessment_types:
            return jsonify({'error': f'assessment_type must be one of: {valid_assessment_types}'}), 400

        if not all([name, config_id, policy_id]):
            return jsonify({'error': 'Name, config_id, and policy_id are required'}), 400

        conn = DatabaseService.get_connection()
        c = conn.cursor()

        # Validate collector_id if provided
        if collector_id:
            c.execute('SELECT collector_id, status FROM remote_collectors WHERE collector_id = ?', (collector_id,))
            collector = c.fetchone()
            if not collector:
                conn.close()
                return jsonify({'error': f'Collector with id {collector_id} not found'}), 404
            if collector['status'] not in ('active', 'pending'):
                conn.close()
                return jsonify({'error': f'Collector {collector_id} is not active (status: {collector["status"]})'}), 400

        c.execute('''UPDATE scans
                     SET name = ?, config_id = ?, policy_id = ?, assessment_type = ?, collector_id = ?, updated_at = CURRENT_TIMESTAMP
                     WHERE id = ?''',
                 (name, config_id, policy_id, assessment_type, collector_id, scan_id))
        conn.commit()
        conn.close()

        return jsonify({'message': 'Scan updated successfully', 'collector_id': collector_id}), 200

    except Exception as e:
        logger.error(f"Error updating scan: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/scans/<int:scan_id>', methods=['DELETE'])
@login_required
@permission_required('scans:delete')
def delete_scan(scan_id):
    """Delete scan"""
    conn = None
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        
        # Start explicit transaction
        c.execute('BEGIN EXCLUSIVE')
        
        # Delete associated logs first
        c.execute('DELETE FROM scan_logs WHERE scan_id = ?', (scan_id,))
        logger.info(f"Deleted scan logs for scan_id {scan_id}")
        
        # Delete the scan
        c.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
        logger.info(f"Deleted scan record for scan_id {scan_id}")
        
        conn.commit()
        logger.info(f"Successfully deleted scan {scan_id}")
        
        return jsonify({'message': 'Scan deleted successfully'}), 200
    
    except Exception as e:
        if conn:
            try:
                conn.rollback()
            except:
                pass
        logger.error(f"Error deleting scan {scan_id}: {e}", exc_info=True)
        return jsonify({'error': f'Failed to delete scan: {str(e)}'}), 500
    
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass

@app.route('/api/v1/scans/<int:scan_id>/run', methods=['POST'])
@login_required
@permission_required('scans:execute')
def run_scan(scan_id):
    """Run a scan - either locally or on a remote collector"""
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()

        # Get scan details including collector_id
        c.execute('''SELECT s.*, c.config_json, p.policy_json
                     FROM scans s
                     JOIN configurations c ON s.config_id = c.id
                     JOIN policies p ON s.policy_id = p.id
                     WHERE s.id = ?''', (scan_id,))
        scan = DatabaseService.dict_from_row(c.fetchone())

        if not scan:
            conn.close()
            return jsonify({'error': 'Scan not found'}), 404

        # Check if this scan is routed to a remote collector
        collector_id = scan.get('collector_id')

        if collector_id:
            # REMOTE EXECUTION: Route to collector via job queue
            # Validate collector is still active
            c.execute('SELECT status, collector_name FROM remote_collectors WHERE collector_id = ?', (collector_id,))
            collector_row = c.fetchone()
            if not collector_row:
                conn.close()
                return jsonify({'error': f'Collector {collector_id} not found'}), 404

            # Convert to dict before closing connection
            collector = {
                'status': collector_row['status'],
                'collector_name': collector_row['collector_name']
            }

            if collector['status'] not in ('active', 'pending'):
                conn.close()
                return jsonify({'error': f'Collector {collector_id} is not active (status: {collector["status"]})'}), 400

            # Update scan status to indicate remote execution
            c.execute('''UPDATE scans
                         SET status = 'Queued', updated_at = CURRENT_TIMESTAMP
                         WHERE id = ?''', (scan_id,))
            conn.commit()
            conn.close()

            # Create job for the collector with scan configuration
            config = json.loads(scan['config_json'])
            from caip_service_layer.remote_collector_service import RemoteCollectorService

            # PHASE 6.3: Resolve secret references in configuration
            try:
                secret_store_mgr = get_secret_store_manager()
                if secret_store_mgr:
                    resolver = SecretResolutionService(secret_store_mgr)
                    config = resolver.resolve_config_credentials(config)
                else:
                    logger.warning("Secret store manager not available, skipping credential resolution")
            except Exception as e:
                logger.error(f"Failed to resolve secrets for scan {scan_id}: {e}", exc_info=True)
                return jsonify({'error': f'Failed to resolve secrets: {str(e)}'}), 500

            try:
                # Get policy for the scan (required for remote collector assessment)
                policy_data = json.loads(scan['policy_json'])
                logger.info(f"[REMOTE JOB] Including policy with {len(policy_data.get('rules', []))} rules for remote assessment")

                job_id = RemoteCollectorService.create_job(
                    db_service=DatabaseService,
                    collector_id=collector_id,
                    job_type='scan',
                    created_by=session.get('user', 'system'),
                    payload={
                        'scan_id': scan_id,
                        'scan_name': scan['name'],
                        'config': config,
                        'policy': policy_data,
                        'triggered_at': datetime.datetime.now().isoformat()
                    },
                    priority='normal'
                )

                # Log the remote scan trigger
                DatabaseService.add_scan_log(scan_id, f"Scan is currently being processed on remote collector: {collector['collector_name']}...", 1)

                logger.info(f"Scan {scan_id} routed to remote collector {collector_id}, job_id: {job_id}")
                return jsonify({
                    'status': 'queued',
                    'scan_id': scan_id,
                    'collector_id': collector_id,
                    'collector_name': collector['collector_name'],
                    'job_id': job_id,
                    'message': f'Scan queued for remote execution on {collector["collector_name"]}'
                }), 202
            except Exception as e:
                logger.error(f"Failed to create job for scan {scan_id}: {e}", exc_info=True)
                return jsonify({'error': f'Failed to queue scan: {str(e)}'}), 500

        # LOCAL EXECUTION: Run on this server
        # Update scan status to running
        c.execute('''UPDATE scans
                     SET status = 'Running', updated_at = CURRENT_TIMESTAMP
                     WHERE id = ?''', (scan_id,))
        conn.commit()
        conn.close()

        # Increment run number
        run_number = DatabaseService.increment_scan_run_number(scan_id)

        # Parse configuration and policy for orchestrator
        config = json.loads(scan['config_json'])
        policy_data = json.loads(scan['policy_json'])

        # Start scan in background thread using orchestrator
        def run_scan_background():
            conn = None
            nonlocal config  # Allow modification of outer scope config
            try:
                # PHASE 6.3: Resolve secret references in configuration
                try:
                    secret_store_mgr = get_secret_store_manager()
                    if secret_store_mgr:
                        resolver = SecretResolutionService(secret_store_mgr)
                        config = resolver.resolve_config_credentials(config)
                        logger.info(f"[AFTER SECRET RESOLUTION] Config top-level keys: {list(config.keys())}")
                        logger.info(f"[AFTER SECRET RESOLUTION] azure_keyvault config: {config.get('azure_keyvault', 'KEY_MISSING')}")
                    else:
                        logger.warning("Secret store manager not available, skipping credential resolution")
                except Exception as e:
                    logger.error(f"Failed to resolve secrets for scan {scan_id}: {e}", exc_info=True)
                    # Update scan status to Failed
                    conn = DatabaseService.get_connection()
                    c = conn.cursor()
                    c.execute('''UPDATE scans
                                 SET status = 'Failed',
                                 last_run = CURRENT_TIMESTAMP,
                                 updated_at = CURRENT_TIMESTAMP
                                 WHERE id = ?''', (scan_id,))
                    conn.commit()
                    DatabaseService.add_scan_log(scan_id, f"Scan failed during secret resolution: {str(e)}", 3)
                    conn.close()
                    return

                logger.info(f"[ORCHESTRATOR INIT] Creating orchestrator with config keys: {list(config.keys())}")
                # Create and execute orchestrator
                orchestrator = ScanOrchestrator(
                    config=config,
                    policy=policy_data,
                    scan_id=scan_id,
                    run_number=run_number,
                    scan_name=scan['name'],
                    reports_folder=app.config['REPORTS_FOLDER'],
                    log_callback=DatabaseService.add_scan_log
                )
                
                result = orchestrator.execute()
                
                # Update scan status based on result
                conn = DatabaseService.get_connection()
                c = conn.cursor()
                
                # Check if scan was cancelled - don't overwrite Cancelled status
                c.execute('SELECT status FROM scans WHERE id = ?', (scan_id,))
                current_status = c.fetchone()
                
                if current_status and current_status['status'] == 'Cancelled':
                    logger.info(f"Scan {scan_id} was cancelled, preserving Cancelled status")
                    conn.close()
                elif result['success']:
                    # Determine final status based on collector results
                    collector_results = result.get('collector_results', {})

                    # Get counts of enabled collectors
                    enabled_collectors = [
                        info for info in collector_results.values()
                        if info.get('enabled')
                    ]
                    failed_collectors = [
                        k for k, v in collector_results.items()
                        if v.get('enabled') and not v.get('success')
                    ]

                    # Determine status:
                    # - If all enabled collectors failed → Failed
                    # - If some enabled collectors failed → Partial
                    # - If all enabled collectors succeeded → Successful
                    if enabled_collectors and len(failed_collectors) == len(enabled_collectors):
                        # All collectors failed
                        final_status = 'Failed'
                    elif failed_collectors:
                        # Some collectors failed
                        final_status = 'Partial'
                    else:
                        # All succeeded
                        final_status = 'Successful'

                    collector_results_json = json.dumps(collector_results) if collector_results else None

                    c.execute('''UPDATE scans
                                 SET status = ?,
                                 last_run = CURRENT_TIMESTAMP,
                                 report_path = ?,
                                 collector_results = ?,
                                 updated_at = CURRENT_TIMESTAMP
                                 WHERE id = ?''', (final_status, result['report_path'], collector_results_json, scan_id))
                    conn.commit()

                    # Log status for operator visibility
                    if final_status == 'Failed':
                        DatabaseService.add_scan_log(
                            scan_id,
                            f"Scan completed with all collectors failed: {', '.join(failed_collectors)}",
                            run_number
                        )
                    elif final_status == 'Partial':
                        DatabaseService.add_scan_log(
                            scan_id,
                            f"Scan completed with partial success. Failed collectors: {', '.join(failed_collectors)}",
                            run_number
                        )

                    # Auto-link completed scan to engagement if engagement_id exists
                    if scan.get('engagement_id'):
                        try:
                            EngagementService.add_report_to_engagement(
                                db_service=DatabaseService,
                                engagement_id=scan['engagement_id'],
                                report_type='scan',
                                report_reference_id=scan_id,
                                report_name=scan['name'],
                                report_path=result['report_path'],
                                include_in_executive=True
                            )
                            logger.info(f"Auto-linked scan {scan_id} to engagement {scan['engagement_id']}")
                        except ValueError as ve:
                            # Report already linked (duplicate) - not an error
                            logger.debug(f"Scan {scan_id} already linked to engagement: {ve}")
                        except Exception as link_error:
                            logger.warning(f"Failed to auto-link scan {scan_id} to engagement: {link_error}")
                else:
                    collector_results_json = json.dumps(result.get('collector_results', {}))
                    c.execute('''UPDATE scans
                                 SET status = 'Failed',
                                 collector_results = ?,
                                 updated_at = CURRENT_TIMESTAMP
                                 WHERE id = ?''', (collector_results_json, scan_id))
                    conn.commit()
                
            except Exception as e:
                logger.error(f"Error running scan {scan_id}: {e}")
                import traceback
                error_details = traceback.format_exc()
                DatabaseService.add_scan_log(scan_id, f"ERROR: {str(e)}\n\nTraceback:\n{error_details}", run_number)
                
                # Update scan status to failed
                try:
                    if conn is None:
                        conn = DatabaseService.get_connection()
                    c = conn.cursor()
                    c.execute('''UPDATE scans 
                                 SET status = 'Failed', updated_at = CURRENT_TIMESTAMP 
                                 WHERE id = ?''', (scan_id,))
                    conn.commit()
                except Exception:
                    pass
            finally:
                if conn:
                    conn.close()
        
        # Start background thread (non-daemon to ensure completion even if app restarts)
        thread = threading.Thread(target=run_scan_background, daemon=False)
        thread.start()
        
        return jsonify({'status': 'running', 'scan_id': scan_id, 'run_number': run_number}), 202
        
    except Exception as e:
        logger.error(f"Error initiating scan {scan_id}: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/scans/<int:scan_id>/status', methods=['GET'])
@login_required
@permission_required('scans:read')
def get_scan_status(scan_id):
    """Get scan status"""
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('SELECT status, last_run, collector_results FROM scans WHERE id = ?', (scan_id,))
        scan = DatabaseService.dict_from_row(c.fetchone())
        conn.close()

        if not scan:
            return jsonify({'error': 'Scan not found'}), 404

        # Deserialize collector_results JSON string to dict
        if scan.get('collector_results'):
            try:
                scan['collector_results'] = json.loads(scan['collector_results'])
            except (json.JSONDecodeError, TypeError):
                scan['collector_results'] = None

        return jsonify(scan), 200
    
    except Exception as e:
        logger.error(f"Error getting scan status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/scans/<int:scan_id>/cancel', methods=['POST'])
@login_required
@permission_required('scans:execute')
def cancel_scan(scan_id):
    """Cancel a running scan by updating its status to Cancelled"""
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        
        # Check current status
        c.execute('SELECT status, name FROM scans WHERE id = ?', (scan_id,))
        scan = DatabaseService.dict_from_row(c.fetchone())
        
        if not scan:
            conn.close()
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan['status'] != 'Running':
            conn.close()
            return jsonify({'error': f"Scan is not running (current status: {scan['status']})"}), 400
        
        # Update status to Cancelled
        c.execute('''UPDATE scans 
                     SET status = 'Cancelled', updated_at = CURRENT_TIMESTAMP 
                     WHERE id = ?''', (scan_id,))
        conn.commit()
        
        # Add log entry
        run_number = DatabaseService.get_current_run_number(scan_id) if hasattr(DatabaseService, 'get_current_run_number') else 1
        DatabaseService.add_scan_log(scan_id, "Scan cancelled by user", run_number)
        
        conn.close()
        
        logger.info(f"Scan {scan_id} ({scan['name']}) cancelled by user")
        return jsonify({'status': 'cancelled', 'scan_id': scan_id}), 200
        
    except Exception as e:
        logger.error(f"Error cancelling scan {scan_id}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/scans/<int:scan_id>/logs', methods=['GET'])
@login_required
@permission_required('scan_logs:read')
def get_scan_logs(scan_id):
    """Get scan logs with optional run number filter"""
    try:
        run_number = request.args.get('run_number', type=int)
        
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        
        if run_number:
            # Get logs for specific run
            c.execute('''SELECT * FROM scan_logs 
                        WHERE scan_id = ? AND run_number = ?
                        ORDER BY timestamp ASC''', (scan_id, run_number))
        else:
            # Get all logs for this scan
            c.execute('''SELECT * FROM scan_logs 
                        WHERE scan_id = ?
                        ORDER BY timestamp ASC''', (scan_id,))
        
        logs = [DatabaseService.dict_from_row(row) for row in c.fetchall()]
        
        # Get available run numbers for this scan
        c.execute('''SELECT DISTINCT run_number FROM scan_logs 
                    WHERE scan_id = ?
                    ORDER BY run_number DESC''', (scan_id,))
        run_numbers = [row['run_number'] for row in c.fetchall()]
        
        conn.close()
        
        return jsonify({
            'logs': logs,
            'run_numbers': run_numbers
        }), 200
    
    except Exception as e:
        logger.error(f"Error getting scan logs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/remote/logs', methods=['POST'])
def add_remote_scan_log():
    """Accept log entries from remote collectors"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400

        scan_id = data.get('scan_id')
        run_number = data.get('run_number', 1)
        log_entry = data.get('log_entry')

        # Validate required fields
        if not scan_id or not log_entry:
            return jsonify({'error': 'Missing scan_id or log_entry'}), 400

        # Validate token or collector origin
        auth_header = request.headers.get('Authorization', '')
        expected_token = os.getenv('COLLECTOR_API_TOKEN', 'default-collector-token')
        if auth_header != f'Bearer {expected_token}':
            return jsonify({'error': 'Unauthorized'}), 403

        # Write log to database
        DatabaseService.add_scan_log(scan_id, log_entry, run_number)

        # Mark "job retrieved" indicator if this is first log for the run
        # First log from collector indicates job was picked up
        conn = DatabaseService.get_connection()
        c = conn.cursor()

        # Check if this is the first log for this run
        c.execute('''SELECT COUNT(*) as count FROM scan_logs
                    WHERE scan_id = ? AND run_number = ?''', (scan_id, run_number))
        log_count = c.fetchone()['count']

        if log_count == 1:
            # This is the first log - update status to Running (changed from Queued)
            c.execute('''UPDATE scans SET status = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?''', ('Running', scan_id))
            conn.commit()
            logger.info(f"[Remote Scan {scan_id}] Status changed to Running on first log")

        # Detect and update scan status if completion indicator
        if 'successfully' in log_entry.lower():
            c.execute('''UPDATE scans SET status = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?''', ('Successful', scan_id))
            conn.commit()
            logger.info(f"[Remote Scan {scan_id}] Status changed to Successful")
        elif 'ERROR' in log_entry.upper() or 'error' in log_entry.lower():
            c.execute('''UPDATE scans SET status = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?''', ('Failed', scan_id))
            conn.commit()
            logger.info(f"[Remote Scan {scan_id}] Status changed to Failed")

        conn.close()

        return jsonify({'success': True}), 200

    except Exception as e:
        logger.error(f"Error adding remote scan log: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/scans/<int:scan_id>/runs', methods=['GET'])
@login_required
@permission_required('scans:read')
def get_scan_runs(scan_id):
    """Get scan run history with aggregated information including status and runtime"""
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        
        # Get the overall scan status from scans table
        c.execute('SELECT status FROM scans WHERE id = ?', (scan_id,))
        scan_row = c.fetchone()
        overall_status = scan_row['status'] if scan_row else 'Unknown'
        
        # Get distinct run numbers with first log timestamp and count
        c.execute('''SELECT 
                        run_number,
                        MIN(timestamp) as start_time,
                        MAX(timestamp) as end_time,
                        COUNT(*) as log_count
                     FROM scan_logs 
                     WHERE scan_id = ?
                     GROUP BY run_number
                     ORDER BY run_number DESC''', (scan_id,))
        
        runs = [DatabaseService.dict_from_row(row) for row in c.fetchall()]
        
        # For each run, determine status and calculate runtime
        for run in runs:
            # Get last log for status detection
            c.execute('''SELECT log_entry 
                        FROM scan_logs 
                        WHERE scan_id = ? AND run_number = ?
                        ORDER BY timestamp DESC
                        LIMIT 1''', (scan_id, run['run_number']))
            
            last_log = c.fetchone()
            
            # Determine status based on multiple indicators
            if last_log:
                log_text = last_log['log_entry']
                
                # Check for success indicators
                if 'Scan completed successfully' in log_text or 'Report saved' in log_text:
                    run['status'] = 'Successful'
                # Check for error indicators
                elif 'ERROR' in log_text or 'Failed' in log_text:
                    run['status'] = 'Failed'
                # Check for partial status
                elif 'Partial' in log_text or 'partial success' in log_text.lower():
                    run['status'] = 'Partial'
                # For the most recent run, use the overall scan status
                elif run == runs[0]:  # This is the most recent run
                    if overall_status in ['Successful', 'Failed', 'Running', 'Partial']:
                        run['status'] = overall_status
                    else:
                        run['status'] = 'Unknown'
                else:
                    # For older runs, check all logs for completion indicators
                    c.execute('''SELECT log_entry FROM scan_logs 
                                WHERE scan_id = ? AND run_number = ?
                                ORDER BY timestamp DESC''', 
                             (scan_id, run['run_number']))
                    all_logs = c.fetchall()
                    
                    # Look for success/failure in any log entry
                    found_status = False
                    for log in all_logs:
                        log_entry = log['log_entry']
                        if 'completed successfully' in log_entry.lower() or 'report saved' in log_entry.lower():
                            run['status'] = 'Successful'
                            found_status = True
                            break
                        elif 'partial' in log_entry.lower() or 'partial success' in log_entry.lower():
                            run['status'] = 'Partial'
                            found_status = True
                            break
                        elif 'error' in log_entry.lower() or 'failed' in log_entry.lower():
                            run['status'] = 'Failed'
                            found_status = True
                            break
                    
                    if not found_status:
                        run['status'] = 'Unknown'
            else:
                run['status'] = 'Unknown'
            
            # Calculate runtime in seconds
            if run['start_time'] and run['end_time']:
                start = datetime.datetime.fromisoformat(run['start_time'].replace('Z', '+00:00'))
                end = datetime.datetime.fromisoformat(run['end_time'].replace('Z', '+00:00'))
                runtime_seconds = int((end - start).total_seconds())
                run['runtime_seconds'] = runtime_seconds
                
                # Format as human-readable
                hours = runtime_seconds // 3600
                minutes = (runtime_seconds % 3600) // 60
                seconds = runtime_seconds % 60
                
                if hours > 0:
                    run['runtime'] = f"{hours}h {minutes}m {seconds}s"
                elif minutes > 0:
                    run['runtime'] = f"{minutes}m {seconds}s"
                else:
                    run['runtime'] = f"{seconds}s"
            else:
                run['runtime'] = 'N/A'
                run['runtime_seconds'] = 0
        
        conn.close()
        
        return jsonify({'runs': runs}), 200
    
    except Exception as e:
        logger.error(f"Error getting scan runs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/reports/scans/<int:scan_id>', methods=['GET'])
@login_required
@permission_required('reports:read')
def get_scan_report(scan_id):
    """Get scan report"""
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('SELECT report_path FROM scans WHERE id = ?', (scan_id,))
        scan = DatabaseService.dict_from_row(c.fetchone())
        conn.close()
        
        if not scan or not scan['report_path']:
            return jsonify({'error': 'Report not found'}), 404
        
        report_path = scan['report_path']
        
        if not os.path.exists(report_path):
            return jsonify({'error': 'Report file not found'}), 404
        
        # Determine file type from extension
        if report_path.endswith('.json'):
            with open(report_path, 'r') as f:
                report_data = json.load(f)
            return jsonify(report_data), 200
        elif report_path.endswith('.pdf'):
            return send_file(report_path, mimetype='application/pdf')
        else:
            return jsonify({'error': 'Unknown report format'}), 500
    
    except Exception as e:
        logger.error(f"Error getting scan report: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/reports/scans/<int:scan_id>/view', methods=['GET'])
@login_required
@permission_required('reports:read')
def view_scan_report(scan_id):
    """Render the pki_report.html template with scan data embedded"""
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('SELECT name, report_path, COALESCE(assessment_type, \'pki_health_check\') as assessment_type FROM scans WHERE id = ?', (scan_id,))
        scan = DatabaseService.dict_from_row(c.fetchone())
        
        if not scan:
            conn.close()
            return "Scan not found", 404
        
        # Check if a specific run_number was requested (for historical reports)
        run_number = request.args.get('run_number')

        if run_number:
            # Search for the report file with the matching run_number
            scan_name_safe = scan['name'].replace(' ', '_').replace('/', '_')
            reports_dir = app.config['REPORTS_FOLDER']
            pattern = f'{scan_name_safe}_run{run_number}_*.json'
            
            # Find matching report files
            import glob
            matching_files = glob.glob(os.path.join(reports_dir, pattern))
            # Sort by modification time (newest first) to get the latest report for this run
            if matching_files:
                matching_files.sort(key=lambda f: os.path.getmtime(f), reverse=True)
                report_path = matching_files[0]
            else:
                report_path = None
        else:
            # Use the latest report from the database
            report_path = scan['report_path']
        
        conn.close()
        
        if not report_path:
            return "Report not found", 404
        
        if not os.path.exists(report_path):
            return "Report file not found on disk", 404
        
        # Only handle JSON reports for the HTML viewer
        if not report_path.endswith('.json'):
            return "Only JSON reports can be viewed in the browser", 400
        
       # Read the JSON report data
        with open(report_path, 'r') as f:
            report_data = json.load(f)
        
        # Determine report template based on assessment type
        assessment_type = scan.get('assessment_type', 'pki_health_check')
        
        # Check if this scan is linked to an engagement and fetch context
        context_data_dict = {}
        engagement_id = None  # Initialize outside try block
        try:
            from caip_service_layer.asset_context_service import AssetContextService
            conn = DatabaseService.get_connection()
            c = conn.cursor()
            c.execute('''SELECT engagement_id FROM engagement_reports 
                        WHERE report_type = 'scan' AND report_reference_id = ?''', (scan_id,))
            row = c.fetchone()
            if row:
                engagement_id = row[0]
                context_list = AssetContextService.get_engagement_context(DatabaseService, engagement_id)
                if context_list:
                    # Keep raw list for backward compatibility
                    report_data['_context_enrichment'] = context_list
                    # Convert to dict keyed by asset_id for scoring service
                    context_data_dict = {
                        ctx['asset_id']: {
                            'business_unit': ctx.get('business_unit'),
                            'business_function': ctx.get('business_function') or ctx.get('criticality'),
                            'data_classification': ctx.get('data_classification') or ctx.get('data_sensitivity'),
                            'dependencies': ctx.get('dependencies'),
                            'migration_path': ctx.get('migration_path'),
                            'compliance_scope': ctx.get('compliance_scope'),
                            'owner': ctx.get('owner')
                        }
                        for ctx in context_list if ctx.get('asset_id')
                    }
        except Exception as e:
            logger.warning(f"Could not fetch context enrichment: {e}")
        
        # For PQC assessments, apply scoring via the PQC reporting service
        if assessment_type == 'pqc_assessment':
            try:
                certificates = report_data.get('certificates', [])
                keys = (report_data.get('keys', []) or []) + (report_data.get('azure_keys', []) or [])

                # Ensure keys are normalised before scoring
                if KEY_NORMALISATION_AVAILABLE:
                    keys = KeyNormalisationService.normalise_keys(keys)

                # Build metadata with engagement_id and db_service for assessment scoring
                report_metadata = report_data.get('metadata', {}).copy()
                report_metadata['scan_id'] = scan_id  # Add scan_id for promote functionality
                if engagement_id:
                    report_metadata['engagement_id'] = engagement_id
                    report_metadata['db_service'] = DatabaseService
                
                # Generate scored report
                scored_report = generate_pqc_report(
                    certificates=certificates,
                    keys=keys,
                    context_data=context_data_dict,
                    metadata=report_metadata
                )
                
                # Merge scored data back into report_data
                report_data['certificates'] = scored_report['certificates']
                report_data['keys'] = scored_report['keys']
                report_data['pqc_summary'] = scored_report['summary']
                report_data['phase_breakdown'] = scored_report['phase_breakdown']
                report_data['metadata'] = scored_report['metadata']
                
            except Exception as e:
                logger.warning(f"Could not apply PQC scoring: {e}")
        
        template_name = 'pqc_report.html' if assessment_type == 'pqc_assessment' else 'pki_report.html'
        
        # Fallback to pki_report.html if pqc_report.html doesn't exist yet
        pqc_template_path = os.path.join(app.template_folder or 'templates', 'pqc_report.html')
        if template_name == 'pqc_report.html' and not os.path.exists(pqc_template_path):
            template_name = 'pki_report.html'
        
        # Render the report template with the data embedded
        return render_template(template_name, 
                             scan_name=scan['name'],
                             report_data=json.dumps(report_data),
                             assessment_type=assessment_type)
    
    except Exception as e:
        logger.error(f"Error viewing scan report: {e}")
        return f"Error loading report: {str(e)}", 500


@app.route('/api/v1/reports/scans/<int:scan_id>/upload', methods=['POST'])
@login_required
@permission_required('reports:write')
def upload_scan_report(scan_id):
    """
    Upload a full JSON report file from remote collector.

    This endpoint receives complete report data from a remote collector
    and saves it to the reports folder, making it available for viewing
    via the standard report viewing endpoints.

    Request Body:
        {
            "report_json": { ... full report object ... },
            "collector_id": "RC-001",
            "scan_name": "Remote_Collector_Scan_57",
            "run_number": 1
        }

    Returns:
        {
            "status": "success",
            "report_path": "reports/Remote_Collector_Scan_57_run1_20251219_090548.json",
            "scan_id": 57
        }
    """
    try:
        # Verify scan exists
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('SELECT id, name FROM scans WHERE id = ?', (scan_id,))
        scan_row = c.fetchone()

        if not scan_row:
            conn.close()
            logger.warning(f"Upload report: Scan {scan_id} not found")
            return jsonify({'status': 'error', 'message': f'Scan {scan_id} not found'}), 404

        scan_name = scan_row[1]
        conn.close()

        # Get request data
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'Request body required'}), 400

        report_json = data.get('report_json')
        if not report_json:
            return jsonify({'status': 'error', 'message': 'report_json field required'}), 400

        # Get optional parameters
        run_number = data.get('run_number', 1)
        collector_id = data.get('collector_id', 'unknown')

        # Generate filename using standard convention
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        scan_name_safe = scan_name.replace(' ', '_').replace('/', '_')
        filename = f'{scan_name_safe}_run{run_number}_{timestamp}.json'

        # Ensure reports folder exists
        reports_folder = app.config.get('REPORTS_FOLDER', 'reports')
        if not os.path.exists(reports_folder):
            os.makedirs(reports_folder, exist_ok=True)

        # Save report file
        report_path = os.path.join(reports_folder, filename)

        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_json, f, indent=2)

        logger.info(f"Report uploaded from {collector_id}: {report_path}")

        # Update scans table with report path
        conn = DatabaseService.get_connection()
        try:
            c = conn.cursor()
            c.execute(
                'UPDATE scans SET report_path = ? WHERE id = ?',
                (report_path, scan_id)
            )
            conn.commit()
            logger.info(f"Scan {scan_id} updated with report_path: {report_path}")
        finally:
            conn.close()

        return jsonify({
            'status': 'success',
            'report_path': report_path,
            'scan_id': scan_id,
            'filename': filename
        }), 200

    except Exception as e:
        logger.error(f"Report upload error: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/v1/scans/<int:scan_id>/promote', methods=['POST'])
@login_required
@permission_required('inventory:update_context')
def promote_scan_to_inventory(scan_id):
    """
    Promote discovered assets from a scan to persistent inventory.

    Takes the scan report and adds discovered assets to the inventory tables
    as static snapshots with promotion tracking fields. Creates a "Promoted Scans"
    pseudo-connector if it doesn't exist.

    Request Body:
        {
            "asset_types": ["certificates"],  // Optional: which asset types to promote
            "include_enrichment": true        // Optional: copy enrichment to org-wide
        }

    Returns:
        {
            "status": "success",
            "promoted": {
                "certificates": 5,
                "keys": 2
            },
            "connector_id": 42,
            "promoted_assets": [...]
        }
    """
    try:
        # Verify scan exists and get its details
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('SELECT id, name, report_path FROM scans WHERE id = ?', (scan_id,))
        scan_row = c.fetchone()

        if not scan_row:
            conn.close()
            logger.warning(f"Promote scan: Scan {scan_id} not found")
            return jsonify({'status': 'error', 'message': f'Scan {scan_id} not found'}), 404

        scan_name = scan_row[1]
        report_path = scan_row[2]
        conn.close()

        # Load scan report
        if not report_path or not os.path.exists(report_path):
            logger.warning(f"Promote scan: Report file not found at {report_path}")
            return jsonify({'status': 'error', 'message': 'Scan report file not found'}), 404

        with open(report_path, 'r') as f:
            report_data = json.load(f)

        # Get request parameters
        data = request.json or {}
        asset_types = data.get('asset_types', ['certificates', 'keys'])
        include_enrichment = data.get('include_enrichment', False)

        # Get or create "Promoted Scans" pseudo-connector
        conn = DatabaseService.get_connection()
        c = conn.cursor()

        c.execute("SELECT id FROM clm_integrations WHERE type = 'promoted' LIMIT 1")
        promoted_integration = c.fetchone()

        if not promoted_integration:
            # Create the pseudo-connector
            c.execute('''
                INSERT INTO clm_integrations
                (name, type, enabled, status, config_json)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                'Promoted Scans',
                'promoted',
                1,
                'Healthy',
                json.dumps({
                    'description': 'Assets promoted from ad-hoc scan reports',
                    'read_only': True
                })
            ))
            connector_id = c.lastrowid
            conn.commit()
            logger.info(f"Created promoted scans connector: {connector_id}")
        else:
            connector_id = promoted_integration[0]

        conn.close()

        # Promote certificates
        promoted_certs = 0
        promoted_keys = 0
        promoted_assets = []

        if 'certificates' in asset_types and report_data.get('certificates'):
            for cert in report_data['certificates']:
                try:
                    # Extract certificate data
                    cert_id = cert.get('fingerprint_sha256') or cert.get('id')
                    if not cert_id:
                        logger.warning("Certificate missing fingerprint/id, skipping")
                        continue

                    # Extract subject and issuer CN from nested dict structures
                    subject_dict = cert.get('subject', {})
                    issuer_dict = cert.get('issuer', {})
                    subject_cn = subject_dict.get('commonName', 'N/A') if isinstance(subject_dict, dict) else cert.get('subject_cn', 'N/A')
                    issuer_cn = issuer_dict.get('commonName', 'N/A') if isinstance(issuer_dict, dict) else cert.get('issuer_cn', 'N/A')

                    # Extract key algorithm and size
                    key_type = cert.get('public_key_algorithm') or cert.get('key_type', 'N/A')
                    key_size = cert.get('public_key_size') or cert.get('key_size')

                    # Insert/update certificate in inventory
                    conn = DatabaseService.get_connection()
                    c = conn.cursor()

                    # Check if already exists (include scan_name for promoted duplicates)
                    # For promoted scans, each scan creates a separate record
                    # For synced sources, promoted_from_scan_name is NULL (no duplicates)
                    c.execute('''
                        SELECT id FROM certificates_inventory
                        WHERE fingerprint_sha256 = ? AND connector_id = ? AND promoted_from_scan_name = ?
                    ''', (cert_id, connector_id, scan_name))
                    existing = c.fetchone()

                    promoted_at = datetime.datetime.now().isoformat()

                    if existing:
                        # Update existing - store normalised cert data directly
                        normalised_data_dict = dict(cert)  # Make copy of scan report cert data
                        normalised_data_dict['source_type'] = 'Promoted Scans'
                        normalised_data_dict['is_promoted'] = True
                        normalised_data_dict['promoted_from_scan_name'] = scan_name
                        normalised_data_dict['promoted_at'] = promoted_at
                        c.execute('''
                            UPDATE certificates_inventory SET
                            subject_cn = ?, issuer_cn = ?, not_after = ?,
                            days_until_expiry = ?,
                            key_algorithm = ?, key_size = ?, source_type = ?,
                            promoted_from_scan_name = ?, promoted_at = ?,
                            is_promoted = 1, integration_name = ?, normalised_data = ?,
                            last_seen_at = CURRENT_TIMESTAMP
                            WHERE fingerprint_sha256 = ? AND connector_id = ? AND promoted_from_scan_name = ?
                        ''', (
                            subject_cn, issuer_cn,
                            cert.get('not_after'),
                            cert.get('days_until_expiration'),
                            key_type, key_size, 'Promoted Scans',
                            scan_name, promoted_at,
                            'Promoted Scans',
                            json.dumps(normalised_data_dict),
                            cert_id, connector_id, scan_name
                        ))
                        operation = 'updated'
                    else:
                        # Insert new - store normalised cert data directly
                        normalised_data_dict = dict(cert)  # Make copy of scan report cert data
                        normalised_data_dict['source_type'] = 'Promoted Scans'
                        normalised_data_dict['is_promoted'] = True
                        normalised_data_dict['promoted_from_scan_name'] = scan_name
                        normalised_data_dict['promoted_at'] = promoted_at
                        c.execute('''
                            INSERT INTO certificates_inventory
                            (connector_id, fingerprint_sha256, subject_cn, issuer_cn, not_after,
                             days_until_expiry, key_algorithm, key_size, source_type,
                             promoted_from_scan_name, promoted_at, is_promoted, integration_name, normalised_data,
                             is_active, first_seen_at, last_seen_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                        ''', (
                            connector_id, cert_id,
                            subject_cn, issuer_cn,
                            cert.get('not_after'),
                            cert.get('days_until_expiration'),
                            key_type, key_size, 'Promoted Scans',
                            scan_name, promoted_at,
                            'Promoted Scans',
                            json.dumps(normalised_data_dict)
                        ))
                        operation = 'inserted'

                    conn.commit()
                    conn.close()

                    promoted_certs += 1
                    promoted_assets.append({
                        'type': 'certificate',
                        'id': cert_id,
                        'subject': subject_cn,
                        'operation': operation
                    })

                    # Optionally copy enrichment to org-wide
                    if include_enrichment:
                        try:
                            from caip_service_layer.asset_context_service import AssetContextService
                            engagement_id = report_data.get('metadata', {}).get('engagement_id')
                            if engagement_id:
                                scan_enrichment = AssetContextService.get_context(
                                    DatabaseService,
                                    engagement_id,
                                    cert_id
                                )
                                if scan_enrichment:
                                    # Create org-wide enrichment
                                    AssetContextService.upsert_context(
                                        DatabaseService,
                                        engagement_id=None,  # Org-wide
                                        asset_id=cert_id,
                                        asset_type='certificate',
                                        business_unit=scan_enrichment.get('business_unit'),
                                        business_function=scan_enrichment.get('business_function'),
                                        data_classification=scan_enrichment.get('data_classification'),
                                        dependencies=scan_enrichment.get('dependencies'),
                                        migration_path=scan_enrichment.get('migration_path'),
                                        compliance_scope=scan_enrichment.get('compliance_scope'),
                                        owner=scan_enrichment.get('owner'),
                                        notes=scan_enrichment.get('notes'),
                                        changed_by=session.get('username', 'system')
                                    )
                        except Exception as e:
                            logger.warning(f"Could not copy enrichment for cert {cert_id}: {e}")

                except Exception as e:
                    logger.error(f"Error promoting certificate {cert_id}: {e}")
                    continue

        if 'keys' in asset_types and report_data.get('keys'):
            for key in report_data['keys']:
                try:
                    # Extract key data
                    key_id = key.get('key_id') or key.get('id')
                    if not key_id:
                        logger.warning("Key missing id, skipping")
                        continue

                    # Insert/update key in inventory
                    conn = DatabaseService.get_connection()
                    c = conn.cursor()

                    # Check if already exists (include scan_name for promoted duplicates)
                    # For promoted scans, each scan creates a separate record
                    # For synced sources, promoted_from_scan_name is NULL (no duplicates)
                    c.execute('''
                        SELECT id FROM keys_inventory
                        WHERE key_identifier = ? AND connector_id = ? AND promoted_from_scan_name = ?
                    ''', (key_id, connector_id, scan_name))
                    existing = c.fetchone()

                    promoted_at = datetime.datetime.now().isoformat()

                    if existing:
                        # Update existing - store normalised key data directly
                        normalised_data_dict = dict(key)  # Make copy of scan report key data
                        normalised_data_dict['source_type'] = 'Promoted Scans'
                        normalised_data_dict['is_promoted'] = True
                        normalised_data_dict['promoted_from_scan_name'] = scan_name
                        normalised_data_dict['promoted_at'] = promoted_at
                        c.execute('''
                            UPDATE keys_inventory SET
                            key_name = ?, key_type = ?, key_size = ?,
                            days_until_expiry = ?, source_type = ?,
                            promoted_from_scan_name = ?, promoted_at = ?,
                            is_promoted = 1, integration_name = ?, normalised_data = ?,
                            last_seen_at = CURRENT_TIMESTAMP
                            WHERE key_identifier = ? AND connector_id = ? AND promoted_from_scan_name = ?
                        ''', (
                            key.get('name') or key.get('label'), key.get('key_type'),
                            key.get('key_size'), key.get('days_until_expiration'),
                            'Promoted Scans',
                            scan_name, promoted_at,
                            'Promoted Scans',
                            json.dumps(normalised_data_dict),
                            key_id, connector_id, scan_name
                        ))
                        operation = 'updated'
                    else:
                        # Insert new - store normalised key data directly
                        normalised_data_dict = dict(key)  # Make copy of scan report key data
                        normalised_data_dict['source_type'] = 'Promoted Scans'
                        normalised_data_dict['is_promoted'] = True
                        normalised_data_dict['promoted_from_scan_name'] = scan_name
                        normalised_data_dict['promoted_at'] = promoted_at
                        c.execute('''
                            INSERT INTO keys_inventory
                            (connector_id, key_identifier, key_name, key_type, key_size,
                             days_until_expiry, source_type,
                             promoted_from_scan_name, promoted_at, is_promoted, integration_name, normalised_data,
                             is_active, first_seen_at, last_seen_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                        ''', (
                            connector_id, key_id, key.get('name') or key.get('label'),
                            key.get('key_type'), key.get('key_size'),
                            key.get('days_until_expiration'), 'Promoted Scans',
                            scan_name, promoted_at,
                            'Promoted Scans',
                            json.dumps(normalised_data_dict)
                        ))
                        operation = 'inserted'

                    conn.commit()
                    conn.close()

                    promoted_keys += 1
                    promoted_assets.append({
                        'type': 'key',
                        'id': key_id,
                        'name': key.get('name') or key.get('label') or 'N/A',
                        'operation': operation
                    })

                except Exception as e:
                    logger.error(f"Error promoting key {key_id}: {e}")
                    continue

        logger.info(f"Promoted scan {scan_id} ({scan_name}): {promoted_certs} certs, {promoted_keys} keys")

        return jsonify({
            'status': 'success',
            'message': f'Successfully promoted {promoted_certs + promoted_keys} assets',
            'promoted': {
                'certificates': promoted_certs,
                'keys': promoted_keys
            },
            'connector_id': connector_id,
            'promoted_assets': promoted_assets
        }), 200

    except Exception as e:
        logger.error(f"Error promoting scan to inventory: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ==================== REPORT ROUTES ====================

@app.route('/api/v1/reports/<filename>', methods=['GET'])
@login_required
@permission_required('reports:read')
def serve_report(filename):
    """Serve a report file from the reports folder"""
    try:
        report_path = os.path.join(app.config['REPORTS_FOLDER'], filename)
        
        # Security: prevent directory traversal
        if '..' in filename or filename.startswith('/'):
            return "Invalid filename", 400
        
        if not os.path.exists(report_path):
            return "Report file not found", 404
        
        if filename.endswith('.json'):
            with open(report_path, 'r') as f:
                report_data = json.load(f)
            # Try to detect assessment type from report data
            assessment_type = report_data.get('metadata', {}).get('assessment_type', 'pki_health_check')
            
            # For PQC assessments, apply scoring via the PQC reporting service
            if assessment_type == 'pqc_assessment':
                try:
                    certificates = report_data.get('certificates', [])
                    keys = (report_data.get('keys', []) or []) + (report_data.get('azure_keys', []) or [])
                    
                    # Build context dict from any embedded enrichment
                    context_data_dict = {}
                    context_list = report_data.get('_context_enrichment', [])
                    if context_list:
                        context_data_dict = {
                            ctx['asset_id']: {
                                'business_unit': ctx.get('business_unit'),
                                'business_function': ctx.get('business_function') or ctx.get('criticality'),
                                'data_classification': ctx.get('data_classification') or ctx.get('data_sensitivity'),
                                'dependencies': ctx.get('dependencies'),
                                'migration_path': ctx.get('migration_path'),
                                'compliance_scope': ctx.get('compliance_scope'),
                                'owner': ctx.get('owner')
                            }
                            for ctx in context_list if ctx.get('asset_id')
                        }
                    
                    # Generate scored report
                    scored_report = generate_pqc_report(
                        certificates=certificates,
                        keys=keys,
                        context_data=context_data_dict,
                        metadata=report_data.get('metadata', {})
                    )
                    
                    # Merge scored data back into report_data
                    report_data['certificates'] = scored_report['certificates']
                    report_data['keys'] = scored_report['keys']
                    report_data['pqc_summary'] = scored_report['summary']
                    report_data['phase_breakdown'] = scored_report['phase_breakdown']
                    report_data['metadata'] = scored_report['metadata']
                    
                except Exception as e:
                    logger.warning(f"Could not apply PQC scoring: {e}")
            
            template_name = 'pqc_report.html' if assessment_type == 'pqc_assessment' else 'pki_report.html'
            
            # Fallback if template doesn't exist
            pqc_template_path = os.path.join(app.template_folder or 'templates', 'pqc_report.html')
            if template_name == 'pqc_report.html' and not os.path.exists(pqc_template_path):
                template_name = 'pki_report.html'
            
            return render_template(template_name, 
                                 scan_name=filename,
                                 report_data=json.dumps(report_data),
                                 assessment_type=assessment_type)
        else:
            return "Only JSON reports can be viewed in the browser", 400
    
    except Exception as e:
        logger.error(f"Error serving report {filename}: {e}")
        return f"Error loading report: {str(e)}", 500
    


# ==================== REASSESSMENT ROUTES ====================

@app.route('/api/v1/reports/reassessments', methods=['GET'])
@login_required
@permission_required('reports:read')
def get_reassessments():
    """Get all reassessments, optionally filtered by engagement"""
    try:
        engagement_id = request.args.get('engagement_id')
        reassessments = DatabaseService.list_reassessments_by_engagement(engagement_id)
        
        return jsonify({'reassessments': reassessments}), 200
    
    except Exception as e:
        logger.error(f"Error getting reassessments: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/reports/reassessments', methods=['POST'])
@login_required
@permission_required('reports:generate')
def create_reassessment():
    """Create a new reassessment"""
    try:
        data = request.json
        name = data.get('name')
        policy_id = data.get('policy_id')
        report_data = data.get('report_data')
        original_filename = data.get('original_filename', 'uploaded_report.json')
        
        if not all([name, policy_id, report_data]):
            return jsonify({'error': 'Name, policy_id, and report_data are required'}), 400
        
        # Get policy using service
        policy_data = DatabaseService.get_policy_json(policy_id)
        if not policy_data:
            return jsonify({'error': 'Policy not found'}), 404
        
        # Validate policy can be loaded
        valid, error = PolicyAssessmentService.load_and_validate_policy(policy_data)
        if not valid:
            return jsonify({'error': error}), 400
        
        # Assess using service
        findings, summary = PolicyAssessmentService.assess_report_data(report_data, policy_data)
        
        # Build report using service
        policy_name = policy_data.get('metadata', {}).get('name', 'Unknown Policy')
        reassessed_report = ReportingService.build_reassessment_report(
            report_data, findings, original_filename, policy_name, policy_data
        )
        
        # Generate report path and save
        report_path = ReportingService.generate_report_path(
            app.config['REPORTS_FOLDER'], name, 'reassessed'
        )
        ReportingService.save_json_report(reassessed_report, report_path)
        
        # Create database record using service
        engagement_id = data.get('engagement_id')
        reassessment_id = DatabaseService.create_reassessment(
            name=name,
            original_filename=original_filename,
            policy_id=policy_id,
            report_data=report_data,
            report_path=report_path,
            engagement_id=engagement_id
        )
        
        return jsonify({
            'id': reassessment_id,
            'name': name,
            'message': 'Re-assessment completed successfully',
            'findings_count': len(findings)
        }), 201
    
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error creating reassessment: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/reports/reassessments/<int:reassessment_id>/report/view', methods=['GET'])
@login_required
@permission_required('reports:read')
def view_reassessment_report(reassessment_id):
    """View reassessment report"""
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('SELECT name, reassessed_report_path FROM reassessments WHERE id = ?', (reassessment_id,))
        reassessment = DatabaseService.dict_from_row(c.fetchone())
        conn.close()
        
        if not reassessment or not reassessment['reassessed_report_path']:
            return "Report not found", 404
        
        report_path = reassessment['reassessed_report_path']
        
        if not os.path.exists(report_path):
            return "Report file not found on disk", 404
        
        # Read the JSON report data
        with open(report_path, 'r') as f:
            report_data = json.load(f)
        
        # Render the template
        return render_template('pki_report.html', 
                             scan_name=reassessment['name'],
                             report_data=json.dumps(report_data))
    
    except Exception as e:
        logger.error(f"Error viewing reassessment report: {e}")
        return f"Error loading report: {str(e)}", 500


# ==================== UNIFIED EMBED DASHBOARD ROUTE ====================

def _generate_clm_embed_dashboard(data):
    """
    Helper function to generate embedded dashboard for CLM reports.
    
    Args:
        data: Request JSON containing:
            - assessment_data: CLM assessment results
            - report_name: Optional name for the report
    
    Returns:
        JSON response with filename and path
    """
    try:
        assessment_data = data.get('assessment_data')
        report_name = data.get('report_name', 'CLM Compliance Dashboard')
        
        if not assessment_data:
            return jsonify({'error': 'assessment_data is required for CLM reports'}), 400
        
        # Build report data structure compatible with pki_report.html
        report_data = {
            'certificates': assessment_data.get('certificates', []),
            'keys': [],
            'findings': assessment_data.get('findings', []),
            'crls': {},
            'file_scan': [],
            'collector_summaries': {},
            'metadata': {
                'report_type': 'clm_compliance',
                'report_name': report_name,
                'policy_name': assessment_data.get('policy_name', 'Unknown Policy'),
                'assessed_at': assessment_data.get('assessed_at', datetime.datetime.utcnow().isoformat()),
                'summary': assessment_data.get('summary', {}),
                'rule_statistics': assessment_data.get('rule_statistics', {}),
                'total_findings': len(assessment_data.get('findings', []))
            }
        }
        
        # Render the template with embedded data
        html_content = render_template('pki_report.html',
                                      scan_name=report_name,
                                      report_data=json.dumps(report_data))
        
        # Generate output filename
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        name_safe = report_name.replace(' ', '_').replace('/', '_')
        output_filename = f'{name_safe}_embedded_{timestamp}.html'
        output_path = os.path.join(app.config['REPORTS_FOLDER'], output_filename)
        
        # Write the self-contained HTML file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Generated CLM embedded dashboard: {output_path}")
        
        return jsonify({
            'message': 'CLM embedded dashboard generated successfully',
            'filename': output_filename,
            'path': output_path
        }), 200
        
    except Exception as e:
        logger.error(f"Error generating CLM embedded dashboard: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/reports/embed/config', methods=['POST'])
@login_required
@permission_required('reports:generate')
def get_embed_config():
    """
    Get configuration for embed modal (engagement members, validity options).

    Request: { "type": "scan|reassessment|aggregation", "id": <integer> }

    Response: {
        "engagement_id": "ENG-2025-001",
        "report_name": "TLS Scan",
        "members": [
            { "user_id": 1, "username": "alice@example.com" },
            ...
        ],
        "validity_options": [7, 30, 90],
        "default_validity": 30
    }
    """
    try:
        data = request.json
        report_type = data.get('type')
        report_id = data.get('id')

        if not report_type or not report_id:
            return jsonify({'error': 'type and id required'}), 400

        conn = DatabaseService.get_connection()
        c = conn.cursor()

        # Get report name
        if report_type == 'scan':
            c.execute('SELECT name FROM scans WHERE id = ?', (report_id,))
        elif report_type == 'reassessment':
            c.execute('SELECT name FROM reassessments WHERE id = ?', (report_id,))
        elif report_type == 'aggregation':
            c.execute('SELECT name FROM report_aggregations WHERE id = ?', (report_id,))
        else:
            conn.close()
            return jsonify({'error': 'invalid type'}), 400

        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({'error': 'report not found'}), 404

        report_name = row[0]

        # Get engagement ID
        engagement_id = None
        if report_type == 'scan':
            c.execute(
                'SELECT engagement_id FROM engagement_reports WHERE report_type=? AND report_reference_id=?',
                ('scan', report_id)
            )
            eng_row = c.fetchone()
            if eng_row:
                engagement_id = eng_row[0]

        # Get engagement members
        members = []
        if engagement_id:
            c.execute("""
                SELECT DISTINCT u.id, u.username
                FROM users u
                JOIN engagement_assignments ea ON u.id = ea.user_id
                WHERE ea.engagement_id = ?
                ORDER BY u.username
            """, (engagement_id,))

            members = [
                {
                    'user_id': row[0],
                    'username': row[1]
                }
                for row in c.fetchall()
            ]

        conn.close()

        return jsonify({
            'engagement_id': engagement_id,
            'report_name': report_name,
            'members': members,
            'validity_options': [7, 30, 90],
            'default_validity': 30
        }), 200

    except Exception as e:
        logger.error(f"Error getting embed config: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/reports/embed', methods=['POST'])
@login_required
@permission_required('reports:generate')
def generate_unified_embed_dashboard():
    """
    Generate embedded dashboard for any report type.

    Request JSON:
    {
        "type": "scan" | "reassessment" | "aggregation",
        "id": <integer>,
        "recipient_user_ids": [<user_id>, ...],  (optional, defaults to engagement members)
        "validity_days": 7 | 30 | 90             (optional, defaults to 30)
    }
    """
    try:
        data = request.json
        report_type = data.get('type')
        report_id = data.get('id')
        recipient_user_ids = data.get('recipient_user_ids')
        validity_days = data.get('validity_days', 30)

        # Handle CLM reports separately (they pass assessment_data instead of id)
        if report_type == 'clm':
            return _generate_clm_embed_dashboard(data)
        
        if not report_type or not report_id:
            return jsonify({'error': 'type and id are required'}), 400
        
        if report_type not in ['scan', 'reassessment', 'aggregation']:
            return jsonify({'error': 'type must be scan, reassessment, or aggregation'}), 400
        
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        
        # Get report details based on type
        if report_type == 'scan':
            c.execute('SELECT name, report_path, COALESCE(assessment_type, \'pki_health_check\') as assessment_type FROM scans WHERE id = ?', (report_id,))
            row = DatabaseService.dict_from_row(c.fetchone())
            if not row or not row.get('report_path'):
                conn.close()
                return jsonify({'error': 'Scan report not found'}), 404
            name = row['name']
            report_path = row['report_path']
            assessment_type = row.get('assessment_type', 'pki_health_check')
            
        elif report_type == 'reassessment':
            c.execute('SELECT name, reassessed_report_path FROM reassessments WHERE id = ?', (report_id,))
            row = DatabaseService.dict_from_row(c.fetchone())
            if not row or not row.get('reassessed_report_path'):
                conn.close()
                return jsonify({'error': 'Reassessment report not found'}), 404
            name = row['name']
            report_path = row['reassessed_report_path']
            
        elif report_type == 'aggregation':
            c.execute('SELECT name, aggregated_report_path FROM report_aggregations WHERE id = ?', (report_id,))
            row = DatabaseService.dict_from_row(c.fetchone())
            if not row or not row.get('aggregated_report_path'):
                conn.close()
                return jsonify({'error': 'Aggregation report not found'}), 404
            name = row['name']
            report_path = row['aggregated_report_path']
        
        conn.close()
        
        if not os.path.exists(report_path):
            return jsonify({'error': 'Report file not found on disk'}), 404
        
        # Read the JSON report data
        with open(report_path, 'r') as f:
            report_data = json.load(f)
        
        # Determine assessment type
        if report_type == 'scan':
            effective_assessment_type = assessment_type
        else:
            # For reassessments/aggregations, try to detect from report metadata
            effective_assessment_type = report_data.get('metadata', {}).get('assessment_type', 'pki_health_check')
        
        # Look up engagement_id for this scan to enable assessment enrichment
        engagement_id = None
        if report_type == 'scan':
            try:
                conn2 = DatabaseService.get_connection()
                c2 = conn2.cursor()
                c2.execute('''SELECT engagement_id FROM scans
                            WHERE id = ?''', (report_id,))
                eng_row = c2.fetchone()
                if eng_row:
                    engagement_id = eng_row[0]
                conn2.close()
            except Exception as e:
                logger.warning(f"Could not lookup engagement for embed: {e}")
        
        # For PQC assessments, apply scoring via the PQC reporting service
        if effective_assessment_type == 'pqc_assessment':
            try:
                certificates = report_data.get('certificates', [])
                keys = (report_data.get('keys', []) or []) + (report_data.get('azure_keys', []) or [])
                
                # Build context dict from any embedded enrichment
                context_data_dict = {}
                context_list = report_data.get('_context_enrichment', [])
                if context_list:
                    context_data_dict = {
                        ctx['asset_id']: {
                            'business_unit': ctx.get('business_unit'),
                            'business_function': ctx.get('business_function') or ctx.get('criticality'),
                            'data_classification': ctx.get('data_classification') or ctx.get('data_sensitivity'),
                            'dependencies': ctx.get('dependencies'),
                            'migration_path': ctx.get('migration_path'),
                            'compliance_scope': ctx.get('compliance_scope'),
                            'owner': ctx.get('owner')
                        }
                        for ctx in context_list if ctx.get('asset_id')
                    }
                
                # Build metadata with engagement_id and db_service for assessment scoring
                report_metadata = report_data.get('metadata', {}).copy()
                if report_type == 'scan':
                    report_metadata['scan_id'] = report_id  # Add scan_id for promote functionality
                if engagement_id:
                    report_metadata['engagement_id'] = engagement_id
                    report_metadata['db_service'] = DatabaseService

                # Generate scored report
                scored_report = generate_pqc_report(
                    certificates=certificates,
                    keys=keys,
                    context_data=context_data_dict,
                    metadata=report_metadata
                )

                # Merge scored data back into report_data
                report_data['certificates'] = scored_report['certificates']
                report_data['keys'] = scored_report['keys']
                report_data['pqc_summary'] = scored_report['summary']
                report_data['phase_breakdown'] = scored_report['phase_breakdown']
                report_data['metadata'] = scored_report['metadata']
                
            except Exception as e:
                logger.warning(f"Could not apply PQC scoring: {e}")
        
        template_name = 'pqc_report.html' if effective_assessment_type == 'pqc_assessment' else 'pki_report.html'

        # Fallback to pki_report.html if pqc_report.html doesn't exist
        pqc_template_path = os.path.join(app.template_folder or 'templates', 'pqc_report.html')
        if template_name == 'pqc_report.html' and not os.path.exists(pqc_template_path):
            template_name = 'pki_report.html'

        # Phase 4: Encrypt entire report and sign encrypted blob
        encrypted_blobs = {}
        signing_result = None
        encryption_metadata = None

        try:
            # Get recipient user IDs (from request or fall back to engagement members)
            if not recipient_user_ids:
                # Backward compatibility: use all engagement members if not specified
                if engagement_id:
                    conn3 = DatabaseService.get_connection()
                    c3 = conn3.cursor()
                    c3.execute('''SELECT DISTINCT user_id FROM engagement_assignments
                               WHERE engagement_id = ?''', (engagement_id,))
                    recipient_user_ids = [row[0] for row in c3.fetchall()]
                    conn3.close()

            # If still no recipients, use report generator
            if not recipient_user_ids:
                recipient_user_ids = [session.get('user_id')]

            # Phase 5: Create report_viewer certificates for recipients BEFORE encryption
            p12_info_for_recipients = {}
            recipient_cert_serials = {}  # Track certificate serials for metadata
            if recipient_user_ids and engagement_id:
                logger.info(f"Creating report_viewer certs for {len(recipient_user_ids)} recipients, validity {validity_days} days")
                for user_id in recipient_user_ids:
                    try:
                        cert = certificate_service.issue_report_viewer_certificate(
                            user_id=user_id,
                            engagement_id=engagement_id,
                            report_type=report_type,
                            report_id=report_id,
                            report_name=name,
                            validity_days=validity_days
                        )
                        logger.info(f"Created report_viewer cert for user {user_id}, expires {cert['expires_at']}")

                        # Generate P12 with password for this recipient
                        try:
                            p12_data = certificate_service.generate_p12_with_password(
                                user_id=user_id,
                                engagement_id=engagement_id
                            )
                            p12_b64 = base64.b64encode(p12_data['p12_bytes']).decode('utf-8')
                            username = p12_data['username']
                            p12_info_for_recipients[user_id] = {
                                'username': username,
                                'p12_password': p12_data['p12_password'],
                                'expires_at': p12_data['expires_at'],
                                'p12_b64': p12_b64
                            }
                            # Store certificate serial keyed by username (used in encrypted_blobs)
                            recipient_cert_serials[username] = cert['certificate_serial']
                            logger.info(f"Generated P12 password for user {user_id}")
                        except Exception as p12_error:
                            logger.warning(f"Failed to generate P12 for user {user_id}: {p12_error}")

                    except Exception as e:
                        logger.warning(f"Failed to create report_viewer cert for user {user_id}: {e}")

            # Encrypt report for each recipient (Phase 4: full payload encryption)
            if recipient_user_ids and engagement_id:
                encrypted_blobs = certificate_service.encrypt_report_data(
                    report_data=report_data,
                    recipient_user_ids=recipient_user_ids,
                    engagement_id=engagement_id
                )

                # Sign the encrypted blobs (entire structure as JSON)
                if encrypted_blobs:
                    encrypted_blobs_json = json.dumps(encrypted_blobs)
                    encrypted_blobs_b64 = base64.b64encode(encrypted_blobs_json.encode('utf-8')).decode('utf-8')
                    signing_result = certificate_service.sign_encrypted_blob(
                        encrypted_blob_b64=encrypted_blobs_b64,
                        engagement_id=engagement_id,
                        user_id=session.get('user_id'),
                        report_id=report_id,
                        report_type=report_type
                    )

                    # Prepare encryption metadata for Phase 5
                    # Use certificate serials captured during cert creation
                    encryption_metadata = {
                        'encryption_algorithm': 'RSA-OAEP-SHA256',
                        'encryption_recipients': list(encrypted_blobs.keys()),
                        'recipient_certificates': recipient_cert_serials,
                        'encryption_timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        'report_type': report_type
                    }

                    logger.info(f"Report encrypted for {len(encrypted_blobs)} recipients and signed")
            else:
                logger.warning(f"Skipping encryption: no engagement_id or recipients found")

        except Exception as e:
            logger.warning(f"Report encryption/signing failed (graceful degradation): {e}")
            # Continue without encryption if signing fails

        # Read forge.min.js for offline P12 decryption
        forge_js_content = ''
        try:
            forge_js_path = os.path.join(os.path.dirname(__file__), 'static', 'js', 'vendor', 'forge.min.js')
            with open(forge_js_path, 'r', encoding='utf-8') as f:
                forge_js_content = f.read()
        except Exception:
            pass  # Graceful degradation — decryption modal will still show but forge won't be available

        # Render the template with embedded data
        # Only include plaintext report_data if NO encryption occurred
        # If encryption occurred, template should only have encrypted_blobs and require decryption
        html_content = render_template(template_name,
                                      scan_name=name,
                                      report_data=json.dumps(report_data) if not encrypted_blobs else None,
                                      encrypted_blobs=json.dumps(encrypted_blobs) if encrypted_blobs else None,
                                      encryption_metadata=json.dumps(encryption_metadata) if encryption_metadata else None,
                                      signing_result=signing_result,
                                      assessment_type=effective_assessment_type,
                                      forge_js_content=forge_js_content)

        # Generate output filename
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        name_safe = name.replace(' ', '_').replace('/', '_')
        output_filename = f'{name_safe}_embedded_{timestamp}.html'

        logger.info(f"Generated embedded dashboard ({report_type}): {output_filename}")

        # Return HTML content and P12 info to frontend for client-side handling
        return jsonify({
            'html_filename': output_filename,
            'html_content': html_content,
            'p12_info': p12_info_for_recipients,
            'message': 'Report encrypted successfully. Download HTML and distribute P12 passwords separately.'
        }), 200
    
    except Exception as e:
        logger.error(f"Error generating embedded dashboard: {e}")
        return jsonify({'error': str(e)}), 500
    

@app.route('/api/v1/reports/executive-summary', methods=['POST'])
@login_required
@permission_required('reports:executive_summary')
def generate_executive_summary():
    """
    Generate executive summary PDF report for any report type.
    
    Request JSON:
    {
        "type": "scan" | "reassessment" | "aggregation",
        "id": <integer>
    }
    
    Returns:
    {
        "message": "Executive summary generated successfully",
        "filename": "<name>_executive_<timestamp>.pdf",
        "path": "<full_path_to_pdf>"
    }
    """
    try:
        data = request.json
        report_type = data.get('type')
        report_id = data.get('id')
        
        if not report_type or not report_id:
            return jsonify({'error': 'type and id are required'}), 400
        
        if report_type not in ['scan', 'reassessment', 'aggregation']:
            return jsonify({'error': 'type must be scan, reassessment, or aggregation'}), 400
        
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        
        # Get report details based on type
        if report_type == 'scan':
            c.execute('SELECT name, report_path FROM scans WHERE id = ?', (report_id,))
            row = DatabaseService.dict_from_row(c.fetchone())
            if not row or not row.get('report_path'):
                conn.close()
                return jsonify({'error': 'Scan report not found'}), 404
            name = row['name']
            report_path = row['report_path']
            
        elif report_type == 'reassessment':
            c.execute('SELECT name, reassessed_report_path FROM reassessments WHERE id = ?', (report_id,))
            row = DatabaseService.dict_from_row(c.fetchone())
            if not row or not row.get('reassessed_report_path'):
                conn.close()
                return jsonify({'error': 'Reassessment report not found'}), 404
            name = row['name']
            report_path = row['reassessed_report_path']
            
        elif report_type == 'aggregation':
            c.execute('SELECT name, aggregated_report_path FROM report_aggregations WHERE id = ?', (report_id,))
            row = DatabaseService.dict_from_row(c.fetchone())
            if not row or not row.get('aggregated_report_path'):
                conn.close()
                return jsonify({'error': 'Aggregation report not found'}), 404
            name = row['name']
            report_path = row['aggregated_report_path']
        
        conn.close()
        
        if not os.path.exists(report_path):
            return jsonify({'error': 'Report file not found on disk'}), 404
        
        # Read the JSON report data
        with open(report_path, 'r') as f:
            report_data = json.load(f)
        
        # Determine logo path (check common locations)
        logo_path = None
        for potential_path in ['static/images/Thales.png', 'Thales.png', 'static/Thales.png']:
            if os.path.exists(potential_path):
                logo_path = potential_path
                break
        
        # Initialize the executive report service
        exec_service = ExecutiveReportService(
            logo_path=logo_path,
            company_name="Thales"
        )
        
        # Generate output path
        output_path = generate_executive_report_path(
            app.config['REPORTS_FOLDER'],
            name
        )
        
        # Generate the executive summary PDF
        result_path = exec_service.generate_executive_report(
            report_data=report_data,
            report_name=name,
            report_type=report_type,
            output_path=output_path
        )
        
        output_filename = os.path.basename(result_path)
        
        logger.info(f"Generated executive summary ({report_type}): {result_path}")
        
        return jsonify({
            'message': 'Executive summary generated successfully',
            'filename': output_filename,
            'path': result_path
        }), 200
    
    except Exception as e:
        logger.error(f"Error generating executive summary: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# ==================== EXECUTIVE SUMMARY ROUTES ====================

@app.route('/api/v1/reports/executive-summary', methods=['POST'])
@login_required
@permission_required('reports:executive_summary')
def generate_executive_summary_report():
    """
    Generate executive summary report (PDF or DOCX format).

    Combines crypto asset scan findings with optional document assessment results.

    Request JSON:
    {
        "type": "scan" | "reassessment" | "aggregation",
        "id": <integer>,
        "format": "pdf" | "docx" (optional, default: "pdf"),
        "document_assessment_id": <optional integer>,
        "report_name": <optional string>
    }

    Returns:
        JSON with filename and path of generated report
    """
    try:
        data = request.json
        report_type = data.get('type')
        report_id = data.get('id')
        output_format = data.get('format', 'pdf').lower()
        document_assessment_id = data.get('document_assessment_id')
        report_name = data.get('report_name')

        if not report_type or not report_id:
            return jsonify({'error': 'type and id are required'}), 400

        if report_type not in ['scan', 'reassessment', 'aggregation']:
            return jsonify({'error': 'type must be scan, reassessment, or aggregation'}), 400

        if output_format not in ['pdf', 'docx']:
            return jsonify({'error': 'format must be pdf or docx'}), 400
        
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        
        # Load crypto asset report based on type
        if report_type == 'scan':
            c.execute('''SELECT s.name, s.report_path, p.policy_json 
                         FROM scans s 
                         LEFT JOIN policies p ON s.policy_id = p.id 
                         WHERE s.id = ?''', (report_id,))
        elif report_type == 'reassessment':
            c.execute('''SELECT r.name, r.reassessed_report_path as report_path, p.policy_json 
                         FROM reassessments r 
                         LEFT JOIN policies p ON r.policy_id = p.id 
                         WHERE r.id = ?''', (report_id,))
        elif report_type == 'aggregation':
            c.execute('''SELECT ra.name, ra.aggregated_report_path as report_path, p.policy_json 
                         FROM report_aggregations ra 
                         LEFT JOIN policies p ON ra.policy_id = p.id 
                         WHERE ra.id = ?''', (report_id,))
        
        row = DatabaseService.dict_from_row(c.fetchone())
        conn.close()
        
        if not row or not row.get('report_path'):
            return jsonify({'error': f'{report_type.title()} report not found'}), 404
        
        name = row['name']
        report_path = row['report_path']
        policy_json = row.get('policy_json')
        
        # Parse policy if available
        policy_data = None
        if policy_json:
            policy_data = json.loads(policy_json) if isinstance(policy_json, str) else policy_json
        
        # Verify report file exists
        if not os.path.exists(report_path):
            return jsonify({'error': 'Report file not found on disk'}), 404
        
        # Load crypto asset report data
        with open(report_path, 'r') as f:
            report_data = json.load(f)
        
        # Optionally load document assessment data
        document_assessment = None
        if document_assessment_id:
            document_assessment = DocumentAssessmentDatabase.get_assessment(
                DatabaseService, 
                document_assessment_id
            )
            if not document_assessment:
                return jsonify({'error': f'Document assessment {document_assessment_id} not found'}), 404
        
        # Use provided report name or default
        final_name = report_name if report_name else name

        # Generate executive summary (PDF or DOCX)
        reports_folder = app.config['REPORTS_FOLDER']
        os.makedirs(reports_folder, exist_ok=True)

        # Get logo path if exists
        logo_path = os.path.join(os.path.dirname(__file__), 'Thales.png')
        if not os.path.exists(logo_path):
            logo_path = None

        # Determine assessment type from report data
        assessment_type = report_data.get('metadata', {}).get('assessment_type', 'pki_health_check')

        logger.info(f"Generating executive summary - format={output_format}, report_type={report_type}, assessment={assessment_type}")

        if output_format == 'pdf':
            # Generate PDF using existing service
            output_path = generate_executive_report_path(reports_folder, final_name)
            logger.info(f"Using PDF service: {output_path}")
            service = ExecutiveReportService(logo_path=logo_path)
            service.generate_executive_report(
                report_data=report_data,
                report_name=final_name,
                report_type=report_type,
                output_path=output_path,
                document_assessment=document_assessment,
                policy=policy_data
            )
        elif output_format == 'docx':
            # Generate DOCX based on assessment type
            logger.info(f"Using DOCX service for format={output_format}")
            from caip_reporting_functions.executive_report_docx_service import ExecutiveReportDocxService

            docx_service = ExecutiveReportDocxService(logo_path=logo_path)
            output_path = docx_service.generate_executive_report(
                scan_data=report_data,
                engagement_name=final_name,
                organization_name=final_name,
                output_dir=reports_folder
            )
            logger.info(f"DOCX report generated: {output_path}")
        else:
            logger.error(f"Unknown format: {output_format}")
            return jsonify({'error': f'Unknown format: {output_format}'}), 400

        output_filename = os.path.basename(output_path)

        logger.info(f"Executive summary generated ({output_format}): {output_filename}")

        return jsonify({
            'message': 'Executive summary generated successfully',
            'filename': output_filename,
            'path': output_path,
            'format': output_format,
            'assessment_type': assessment_type
        }), 200
        
    except Exception as e:
        logger.error(f"Error generating executive summary: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500
    
# ==================== REPORT AGGREGATION ROUTES ====================

@app.route('/api/v1/reports/aggregations', methods=['GET'])
@login_required
@permission_required('reports:read')
def get_aggregations():
    """Get list of report aggregations, optionally filtered by engagement"""
    try:
        engagement_id = request.args.get('engagement_id')
        aggregations = DatabaseService.list_aggregations_by_engagement(engagement_id)
        
        return jsonify(aggregations), 200
    
    except Exception as e:
        logger.error(f"Error fetching aggregations: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/reports/aggregations', methods=['POST'])
@login_required
@permission_required('reports:aggregate')
def create_aggregation():
    """Create a new report aggregation"""
    try:
        data = request.json
        name = data.get('name')
        policy_id = data.get('policy_id')
        merge_strategy = data.get('merge_strategy', 'deduplicate')
        reports_data = data.get('reports', [])
        
        if not all([name, policy_id, reports_data]):
            return jsonify({'error': 'Name, policy_id, and reports are required'}), 400
        
        if len(reports_data) > 5:
            return jsonify({'error': 'Maximum 5 reports allowed'}), 400
        
        # Get policy using service
        policy_data = DatabaseService.get_policy_json(policy_id)
        if not policy_data:
            return jsonify({'error': 'Policy not found'}), 404
        
        # Validate policy can be loaded
        valid, error = PolicyAssessmentService.load_and_validate_policy(policy_data)
        if not valid:
            return jsonify({'error': error}), 400
        
        # Aggregate using service
        aggregated_data = ReportingService.aggregate_reports(reports_data, merge_strategy)
        
        # Assess using service
        findings, summary = PolicyAssessmentService.assess_report_data(aggregated_data, policy_data)
        
        # Build report using service
        policy_name = policy_data.get('metadata', {}).get('name', 'Unknown Policy')
        final_report = ReportingService.build_aggregation_report(
            aggregated_data, findings, merge_strategy, policy_name, policy_data
        )
        
        # Generate report path and save
        report_path = ReportingService.generate_report_path(
            app.config['REPORTS_FOLDER'], name, 'aggregated'
        )
        ReportingService.save_json_report(final_report, report_path)
        
        # Extract source filenames for DB record
        source_filenames = [r.get('filename', 'unknown') for r in reports_data]
        
        # Create database record using service
        engagement_id = data.get('engagement_id')
        aggregation_id = DatabaseService.create_aggregation(
            name=name,
            policy_id=policy_id,
            merge_strategy=merge_strategy,
            source_reports=source_filenames,
            report_path=report_path,
            report_data=final_report,
            engagement_id=engagement_id
        )
        
        return jsonify({
            'id': aggregation_id,
            'name': name,
            'message': 'Report aggregation completed successfully',
            'findings_count': len(findings),
            'certificates_count': len(aggregated_data.get('certificates', [])),
            'keys_count': len(aggregated_data.get('keys', []))
        }), 201
    
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error creating aggregation: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/reports/aggregations/<int:aggregation_id>/report/view', methods=['GET'])
@login_required
@permission_required('reports:read')
def view_aggregation_report(aggregation_id):
    """View aggregation report"""
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('SELECT name, aggregated_report_path FROM report_aggregations WHERE id = ?', (aggregation_id,))
        aggregation = DatabaseService.dict_from_row(c.fetchone())
        conn.close()
        
        if not aggregation or not aggregation['aggregated_report_path']:
            return "Report not found", 404
        
        report_path = aggregation['aggregated_report_path']
        
        if not os.path.exists(report_path):
            return "Report file not found on disk", 404
        
        # Read the JSON report data
        with open(report_path, 'r') as f:
            report_data = json.load(f)
        
        # Render the template
        return render_template('pki_report.html', 
                             scan_name=aggregation['name'],
                             report_data=json.dumps(report_data))
    
    except Exception as e:
        logger.error(f"Error viewing aggregation report: {e}")
        return f"Error loading report: {str(e)}", 500

# ==================== CLM ROUTES ====================

@app.route('/api/v1/inventory/integrations', methods=['GET'])
@login_required
@permission_required('integrations:read')
def get_inventory_integrations():
    """Get all inventory integrations"""
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM clm_integrations')
        integrations = [DatabaseService.dict_from_row(row) for row in c.fetchall()]
        conn.close()

        logger.info(f"[CLM Integrations] Found {len(integrations)} total integrations in database")

        # Parse config JSON
        for integration in integrations:
            try:
                integration['config'] = json.loads(integration['config_json'])
                logger.info(f"[CLM Integrations] Successfully parsed config for {integration['name']} (id: {integration['id']}, type: {integration['type']}, enabled: {integration.get('enabled')})")
            except json.JSONDecodeError as je:
                logger.error(f"[CLM Integrations] Failed to parse config_json for integration {integration['id']} ({integration['name']}): {je}")
                integration['config'] = {}

        logger.info(f"[CLM Integrations] Returning {len(integrations)} integrations to client")
        return jsonify({'integrations': integrations}), 200

    except Exception as e:
        logger.error(f"Error getting CLM integrations: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/inventory/integrations', methods=['POST'])
@login_required
@permission_required('integrations:create')
def create_inventory_integration():
    """Create new inventory integration"""
    try:
        data = request.json
        name = data.get('name')
        integration_type = data.get('type')
        config = data.get('config')

        logger.debug(f"Creating CLM integration: name={name}, type={integration_type}")
        logger.debug(f"Config structure keys: {list(config.keys()) if config else 'None'}")
        if config and 'ejbca' in config:
            logger.debug(f"EJBCA config keys: {list(config['ejbca'].keys())}")
            if 'servers' in config['ejbca']:
                servers = config['ejbca']['servers']
                logger.debug(f"EJBCA servers count: {len(servers)}")
                if servers:
                    logger.debug(f"First server keys: {list(servers[0].keys())}")
                    logger.debug(f"First server p12_password_plaintext: {servers[0].get('p12_password_plaintext')}")
                    logger.debug(f"First server p12_password_reference: {servers[0].get('p12_password_reference')}")

        if not all([name, integration_type, config]):
            return jsonify({'error': 'Name, type, and config are required'}), 400

        # Resolve credentials before health check so it tests with actual credential values
        try:
            from caip_service_layer.secret_resolution_service import SecretResolutionService
            from caip_service_layer.secret_store_manager import SecretStoreManager
            secret_store_mgr = SecretStoreManager()
            resolver = SecretResolutionService(secret_store_mgr)
            resolved_config = resolver.resolve_config_credentials(config)
        except Exception as e:
            # If credential resolution fails, still try health check with unresolved config
            logger.warning(f"Could not resolve credentials for health check: {e}")
            resolved_config = config

        # Test connection using ConnectorService with resolved credentials
        _, status = ConnectorService.check_integration_health(integration_type, resolved_config)
        
        # Create database connection
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        
        config_json = json.dumps(config)
        c.execute('''INSERT INTO clm_integrations (name, type, config_json, status, last_sync)
                     VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''',
                 (name, integration_type, config_json, status))
        conn.commit()
        
        integration_id = c.lastrowid
        conn.close()
        
        # Register with inventory scheduler
        from caip_service_layer.inventory_service import InventoryService
        InventoryService.ensure_sync_status_exists(integration_id, interval_minutes=30)
        logger.info(f"Registered connector {integration_id} with inventory scheduler")
        
        # Initialize sync status for the new connector
        try:
            from caip_service_layer.inventory_service import InventoryService
            InventoryService.ensure_sync_status_exists(integration_id, interval_minutes=30)
            logger.info(f"Initialized sync status for connector {integration_id}")
            
            # Trigger immediate sync for the new connector
            from caip_service_layer.scheduler_service import SchedulerService
            SchedulerService.trigger_immediate_sync(connector_id=integration_id, async_execution=True)
            logger.info(f"Triggered initial sync for connector {integration_id}")
        except Exception as sync_init_error:
            logger.warning(f"Could not initialize sync status for connector {integration_id}: {sync_init_error}")
            
        return jsonify({
            'id': integration_id,
            'name': name,
            'type': integration_type,
            'status': status,
            'message': 'Integration created successfully'
        }), 201
    
    except Exception as e:
        logger.error(f"Error creating CLM integration: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/inventory/integrations/<int:integration_id>/sync', methods=['POST'])
@login_required
@permission_required('integrations:sync')
def sync_inventory_integration(integration_id):
    """Sync inventory integration - collect and store certificates/keys in inventory"""
    try:
        from caip_service_layer.inventory_service import InventoryService

        # Verify integration exists
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM clm_integrations WHERE id = ?', (integration_id,))
        integration = DatabaseService.dict_from_row(c.fetchone())
        conn.close()

        if not integration:
            return jsonify({'error': 'Integration not found'}), 404

        if not integration['enabled']:
            return jsonify({'error': 'Integration is disabled. Enable it first.'}), 400

        logger.info(f"Starting sync for integration {integration_id} ({integration['name']})")

        # Actually sync the connector (collect certificates/keys and update inventory)
        result = InventoryService.sync_connector(integration_id)

        if result.success:
            # Update integration status and last sync time
            conn = DatabaseService.get_connection()
            c = conn.cursor()
            c.execute('''UPDATE clm_integrations
                         SET status = 'Healthy', last_sync = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                         WHERE id = ?''',
                     (integration_id,))
            conn.commit()
            conn.close()

            logger.info(f"Sync completed for {integration['name']}: "
                       f"{result.certificates_total} certs ({result.certificates_added} added, "
                       f"{result.certificates_updated} updated), "
                       f"{result.keys_total} keys ({result.keys_added} added, "
                       f"{result.keys_updated} updated)")

            return jsonify({
                'status': 'success',
                'message': f"Collected {result.certificates_total} certificates and {result.keys_total} keys",
                'certificates_total': result.certificates_total,
                'certificates_added': result.certificates_added,
                'certificates_updated': result.certificates_updated,
                'certificates_removed': result.certificates_removed,
                'keys_total': result.keys_total,
                'keys_added': result.keys_added,
                'keys_updated': result.keys_updated,
                'keys_removed': result.keys_removed,
                'duration_seconds': result.duration_seconds
            }), 200
        else:
            # Update integration status to reflect failure
            conn = DatabaseService.get_connection()
            c = conn.cursor()
            c.execute('''UPDATE clm_integrations
                         SET status = 'Unhealthy', last_sync = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                         WHERE id = ?''',
                     (integration_id,))
            conn.commit()
            conn.close()

            logger.error(f"Sync failed for {integration['name']}: {result.error_message}")

            return jsonify({
                'status': 'failed',
                'error': result.error_message
            }), 500

    except Exception as e:
        logger.error(f"Error syncing CLM integration {integration_id}: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/inventory/integrations/<int:integration_id>', methods=['DELETE'])
@login_required
@permission_required('integrations:delete')
def delete_inventory_integration(integration_id):
    """Delete inventory integration"""
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        
        # Clean up inventory data first (before deleting connector due to FK constraints)
        c.execute('DELETE FROM certificates_inventory WHERE connector_id = ?', (integration_id,))
        c.execute('DELETE FROM keys_inventory WHERE connector_id = ?', (integration_id,))
        c.execute('DELETE FROM connector_sync_status WHERE connector_id = ?', (integration_id,))
        c.execute('DELETE FROM inventory_changes WHERE connector_id = ?', (integration_id,))
        
        # Delete the connector
        c.execute('DELETE FROM clm_integrations WHERE id = ?', (integration_id,))
        conn.commit()
        conn.close()
        
        logger.info(f"Deleted connector {integration_id} and associated inventory data")
        return jsonify({'message': 'Integration deleted successfully'}), 200
    
    except Exception as e:
        logger.error(f"Error deleting CLM integration: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/inventory/integrations/<int:integration_id>', methods=['PUT'])
@login_required
@permission_required('integrations:update')
def update_inventory_integration(integration_id):
    """Update existing inventory integration"""
    try:
        data = request.json
        name = data.get('name')
        config = data.get('config')
        
        if not name:
            return jsonify({'error': 'Name is required'}), 400
        
        # Get existing integration
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('SELECT type, config_json FROM clm_integrations WHERE id = ?', (integration_id,))
        row = c.fetchone()
        
        if not row:
            conn.close()
            return jsonify({'error': 'Integration not found'}), 404
        
        integration_type = row[0]
        existing_config = json.loads(row[1]) if row[1] else {}
        
        # Merge config if provided
        if config:
            # Resolve credentials before health check
            try:
                from caip_service_layer.secret_resolution_service import SecretResolutionService
                from caip_service_layer.secret_store_manager import SecretStoreManager
                secret_store_mgr = SecretStoreManager()
                resolver = SecretResolutionService(secret_store_mgr)
                resolved_config = resolver.resolve_config_credentials(config)
            except Exception as e:
                logger.warning(f"Could not resolve credentials for health check: {e}")
                resolved_config = config

            # Test connection with resolved config
            _, status = ConnectorService.check_integration_health(integration_type, resolved_config)
            config_json = json.dumps(config)
        else:
            # Keep existing config
            config_json = row[1]
            status = 'Unknown'
        
        # Update database
        c.execute('''UPDATE clm_integrations 
                     SET name = ?, config_json = ?, status = ?
                     WHERE id = ?''',
                 (name, config_json, status, integration_id))
        conn.commit()
        conn.close()
        
        return jsonify({
            'id': integration_id,
            'name': name,
            'type': integration_type,
            'status': status,
            'message': 'Integration updated successfully'
        }), 200
    
    except Exception as e:
        logger.error(f"Error updating CLM integration: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/inventory/integrations/<int:integration_id>/toggle', methods=['PUT'])
@login_required
@permission_required('integrations:enable_disable')
def toggle_inventory_integration(integration_id):
    """Toggle inventory integration enabled/disabled status"""
    conn = None
    try:
        data = request.json
        enabled = data.get('enabled', True)

        conn = DatabaseService.get_connection()
        c = conn.cursor()

        # Get integration details
        c.execute('SELECT * FROM clm_integrations WHERE id = ?', (integration_id,))
        integration = DatabaseService.dict_from_row(c.fetchone())

        if not integration:
            conn.close()
            conn = None
            return jsonify({'error': 'Integration not found'}), 404

        integration_type = integration['type']
        integration_name = integration['name']
        is_virtual_connector = integration_type == 'promoted'  # Virtual connectors don't sync

        # Update enabled status
        if enabled:
            # When enabling, check health status with resolved credentials (skip for virtual connectors)
            if not is_virtual_connector:
                config = json.loads(integration['config_json'])
                try:
                    from caip_service_layer.secret_resolution_service import SecretResolutionService
                    from caip_service_layer.secret_store_manager import SecretStoreManager
                    secret_store_mgr = SecretStoreManager()
                    resolver = SecretResolutionService(secret_store_mgr)
                    resolved_config = resolver.resolve_config_credentials(config)
                except Exception as e:
                    logger.warning(f"Could not resolve credentials for health check: {e}")
                    resolved_config = config

                _, status = ConnectorService.check_integration_health(integration_type, resolved_config)
            else:
                status = 'Healthy'  # Virtual connectors are always healthy

            c.execute('''UPDATE clm_integrations
                         SET enabled = ?, status = ?, updated_at = CURRENT_TIMESTAMP
                         WHERE id = ?''',
                     (1, status, integration_id))

            # Only prepare sync for real connectors (not virtual ones like Promoted Scans)
            if not is_virtual_connector:
                from caip_service_layer.inventory_service import InventoryService
                InventoryService.ensure_sync_status_exists(integration_id, interval_minutes=30)

            conn.commit()
            conn.close()
            conn = None

            # Only trigger sync for real connectors (not virtual ones like Promoted Scans)
            if not is_virtual_connector:
                logger.info(f"Triggering sync for newly enabled integration {integration_id} ({integration_name})")
                from caip_service_layer.inventory_service import InventoryService
                sync_result = InventoryService.sync_connector(integration_id)

                if sync_result.success:
                    logger.info(f"Initial sync completed for {integration_name}: "
                               f"{sync_result.certificates_total} certs, {sync_result.keys_total} keys")
                    return jsonify({
                        'message': f'Integration enabled and synced successfully',
                        'enabled': True,
                        'sync_result': {
                            'certificates_total': sync_result.certificates_total,
                            'certificates_added': sync_result.certificates_added,
                            'keys_total': sync_result.keys_total,
                            'keys_added': sync_result.keys_added
                        }
                    }), 200
                else:
                    logger.warning(f"Initial sync failed for {integration_name}: {sync_result.error_message}")
                    return jsonify({
                        'message': f'Integration enabled but sync failed: {sync_result.error_message}',
                        'enabled': True,
                        'sync_error': sync_result.error_message
                    }), 200
            else:
                # Virtual connector - no sync needed
                logger.info(f"Integration enabled: {integration_name} (virtual connector, no sync required)")
                return jsonify({
                    'message': f'Integration enabled successfully',
                    'enabled': True
                }), 200
        else:
            # When disabling, set status to Disabled
            c.execute('''UPDATE clm_integrations
                         SET enabled = ?, status = 'Disabled', updated_at = CURRENT_TIMESTAMP
                         WHERE id = ?''',
                     (0, integration_id))

            conn.commit()
            conn.close()
            conn = None

            logger.info(f"Integration disabled: {integration_name}")
            return jsonify({
                'message': f'Integration disabled successfully',
                'enabled': False
            }), 200

    except Exception as e:
        logger.error(f"Error toggling CLM integration: {e}")
        if conn:
            try:
                conn.close()
            except:
                pass
        return jsonify({'error': str(e)}), 500
    finally:
        # Ensure connection is always closed
        if conn:
            try:
                conn.close()
            except:
                pass

@app.route('/api/v1/inventory/integrations/<int:integration_id>/certificates', methods=['GET'])
@login_required
@permission_required('inventory:read_certificates')
def get_inventory_integration_certificates(integration_id):
    """Get certificates from inventory integration"""
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM clm_integrations WHERE id = ?', (integration_id,))
        integration = DatabaseService.dict_from_row(c.fetchone())
        conn.close()
        
        if not integration:
            return jsonify({'error': 'Integration not found'}), 404
        
        config = json.loads(integration['config_json'])
        certificates = []
        
        try:
            if integration['type'] == 'EJBCA':
                certs = ConnectorService.collect_from_ejbca(config)
            elif integration['type'] == 'Azure Key Vault':
                logger.info(f"Creating AzureKeyVaultCollector for {integration['name']}")
                certs, _ = ConnectorService.collect_from_azure_keyvault(config)
            else:
                certs = []
            
            # Use centralized conversion (include_full_details=False for listing)
            certificates = ConnectorService.certificates_to_dict_list(
                certs, 
                source_integration=integration['name'],
                include_full_details=False
            )
        except Exception as e:
            logger.warning(f"Failed to collect certificates from {integration['type']}: {e}")
            certificates = []
        
        return jsonify({'certificates': certificates}), 200
    
    except Exception as e:
        logger.error(f"Error fetching CLM integration certificates: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/inventory/integrations/<int:integration_id>/cas', methods=['GET'])
@login_required
@permission_required('integrations:read')
def get_inventory_integration_cas(integration_id):
    """
    Get CAs from EJBCA integration with certificate counts.

    Query Parameters:
        include_profiles (optional, default: false) - Include profile information
    """
    try:
        # Check for include_profiles parameter
        include_profiles = request.args.get('include_profiles', 'false').lower() == 'true'

        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM clm_integrations WHERE id = ?', (integration_id,))
        integration = DatabaseService.dict_from_row(c.fetchone())
        conn.close()

        if not integration:
            return jsonify({'error': 'Integration not found'}), 404

        cas = []

        if integration['type'] == 'EJBCA':
            # First, try to return cached CA metadata from database
            if integration.get('cas_metadata'):
                try:
                    cas = json.loads(integration['cas_metadata'])
                    logger.debug(f"Returning cached CA metadata for integration {integration_id}")
                except Exception as e:
                    logger.warning(f"Could not parse cached CA metadata: {e}")
                    cas = []

            # If no cached data, fetch live (fallback)
            if not cas:
                try:
                    config = json.loads(integration['config_json'])
                    cas = ConnectorService.get_ejbca_cas_with_counts(config)
                    logger.debug(f"Fetched live CA data for integration {integration_id}")
                except Exception as e:
                    logger.error(f"Error fetching CAs from EJBCA: {e}")
                    cas = []

        return jsonify({'cas': cas}), 200

    except Exception as e:
        logger.error(f"Error fetching CLM integration CAs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/clm/integrations/<int:integration_id>/promoted-scans', methods=['GET'])
@login_required
@permission_required('integrations:read')
def get_promoted_scans(integration_id):
    """Get promoted scans from the Promoted Scans integration"""
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM clm_integrations WHERE id = ?', (integration_id,))
        integration = DatabaseService.dict_from_row(c.fetchone())

        if not integration:
            conn.close()
            return jsonify({'error': 'Integration not found'}), 404

        if integration['type'] != 'promoted':
            conn.close()
            return jsonify({'error': 'Integration is not a promoted scans connector'}), 400

        # Query promoted scans from certificates and keys inventory
        # Get unique promoted scans with their counts
        c.execute('''
            SELECT DISTINCT
                json_extract(normalised_data, '$.promoted_from_scan_name') as promoted_from_scan_name,
                MAX(json_extract(normalised_data, '$.promoted_at')) as latest_date
            FROM (
                SELECT normalised_data FROM certificates_inventory
                WHERE source_type = 'Promoted Scans' AND normalised_data IS NOT NULL
                UNION
                SELECT normalised_data FROM keys_inventory
                WHERE source_type = 'Promoted Scans' AND normalised_data IS NOT NULL
            )
            WHERE json_extract(normalised_data, '$.promoted_from_scan_name') IS NOT NULL
            GROUP BY json_extract(normalised_data, '$.promoted_from_scan_name')
            ORDER BY latest_date DESC
        ''')

        scan_names = [DatabaseService.dict_from_row(row) for row in c.fetchall()]
        scans = []

        # For each scan, get certificate and key counts
        for scan_row in scan_names:
            scan_name = scan_row['promoted_from_scan_name']
            promoted_date = scan_row['latest_date']

            # Count certificates
            c.execute('SELECT COUNT(*) FROM certificates_inventory WHERE source_type = ? AND json_extract(normalised_data, ?) = ?',
                     ('Promoted Scans', '$.promoted_from_scan_name', scan_name))
            cert_count = c.fetchone()[0] or 0

            # Count keys
            c.execute('SELECT COUNT(*) FROM keys_inventory WHERE source_type = ? AND json_extract(normalised_data, ?) = ?',
                     ('Promoted Scans', '$.promoted_from_scan_name', scan_name))
            key_count = c.fetchone()[0] or 0

            scans.append({
                'name': scan_name,
                'promoted_at': promoted_date,
                'certificate_count': cert_count,
                'key_count': key_count
            })

        conn.close()
        return jsonify({'scans': scans}), 200

    except Exception as e:
        logger.error(f"Error fetching promoted scans: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/clm/integrations/<int:integration_id>/promoted-scans/<scan_name>', methods=['DELETE'])
@login_required
@permission_required('integrations:delete')
def delete_promoted_scan(integration_id, scan_name):
    """Delete a promoted scan and its associated assets"""
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()

        # Verify integration exists and is promoted type
        c.execute('SELECT * FROM clm_integrations WHERE id = ?', (integration_id,))
        integration = DatabaseService.dict_from_row(c.fetchone())

        if not integration:
            conn.close()
            return jsonify({'error': 'Integration not found'}), 404

        if integration['type'] != 'promoted':
            conn.close()
            return jsonify({'error': 'Integration is not a promoted scans connector'}), 400

        # Delete promoted scan assets from certificates and keys inventory
        c.execute('DELETE FROM certificates_inventory WHERE source_type = ? AND json_extract(normalised_data, ?) = ?',
                 ('Promoted Scans', '$.promoted_from_scan_name', scan_name))
        c.execute('DELETE FROM keys_inventory WHERE source_type = ? AND json_extract(normalised_data, ?) = ?',
                 ('Promoted Scans', '$.promoted_from_scan_name', scan_name))

        conn.commit()
        conn.close()

        logger.info(f"Deleted promoted scan: {scan_name} from integration {integration_id}")
        return jsonify({'message': 'Promoted scan deleted successfully'}), 200

    except Exception as e:
        logger.error(f"Error deleting promoted scan: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/inventory/certificates', methods=['GET'])
@login_required
def get_all_inventory_certificates():
    """Get certificates from enriched inventory database

    Returns certificates that have been synchronized and enriched by the
    InventoryOrchestrator (via manual sync or background scheduler).

    Data includes:
    - Normalized certificate fields
    - Environmental metadata (inferred from connector type, CN, etc.)
    - Security analysis
    - PQC readiness assessment

    Query Parameters (optional):
    - connector_id: Filter to specific connector
    - expiring_within_days: Filter to certs expiring within N days

    Returns: List of certificates with enriched metadata
    """
    try:
        # Get optional filter parameters
        connector_id = request.args.get('connector_id', type=int)
        expiring_within_days = request.args.get('expiring_within_days', type=int)

        logger.info(f"Fetching certificates from inventory "
                   f"(connector_id={connector_id}, expiring_in={expiring_within_days})")

        # Get enriched certificates from database
        # This returns data that was synchronized via InventoryOrchestrator
        # (either by background scheduler or manual sync)
        from caip_service_layer.inventory_service import InventoryService

        certificates = InventoryService.get_certificates(
            connector_id=connector_id,
            expiring_within_days=expiring_within_days,
            include_inactive=False
        )

        # Merge missing DB columns (integration_name, source_type, is_promoted,
        # promoted_from_scan_name, days_until_expiry) that InventoryService omits
        if certificates:
            inventory_ids = [c['_inventory_id'] for c in certificates if c.get('_inventory_id')]
            if inventory_ids:
                placeholders = ','.join('?' * len(inventory_ids))
                conn = DatabaseService.get_connection()
                c = conn.cursor()
                c.execute(
                    f'SELECT id, integration_name, source_type, is_promoted, '
                    f'promoted_from_scan_name, days_until_expiry '
                    f'FROM certificates_inventory WHERE id IN ({placeholders})',
                    inventory_ids
                )
                db_rows = {row[0]: row for row in c.fetchall()}
                conn.close()
                for cert in certificates:
                    inv_id = cert.get('_inventory_id')
                    if inv_id and inv_id in db_rows:
                        row = db_rows[inv_id]
                        cert['integration_name'] = row[1]
                        cert['source_type'] = row[2]
                        cert['is_promoted'] = row[3]
                        cert['promoted_from_scan_name'] = row[4]
                        cert['days_until_expiry'] = row[5]

        logger.info(f"Returning {len(certificates)} enriched certificates from inventory")

        return jsonify({'certificates': certificates}), 200

    except Exception as e:
        logger.error(f"Error fetching certificates from inventory: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/kms/keys', methods=['GET'])
@login_required
def get_all_kms_keys():
    """Get keys from all enabled Luna HSM integrations"""
    try:
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM clm_integrations WHERE enabled = 1 AND type = 'Luna HSM'")
        integrations = [DatabaseService.dict_from_row(row) for row in c.fetchall()]
        conn.close()
        
        logger.info(f"Found {len(integrations)} enabled Luna HSM integrations")
        
        all_keys = []
        
        for integration in integrations:
            logger.info(f"Processing Luna HSM integration: {integration['name']}")

            try:
                config = json.loads(integration['config_json'])

                # Resolve credentials before collection
                try:
                    from caip_service_layer.secret_resolution_service import SecretResolutionService
                    from caip_service_layer.secret_store_manager import SecretStoreManager
                    secret_store_mgr = SecretStoreManager()
                    resolver = SecretResolutionService(secret_store_mgr)
                    config = resolver.resolve_config_credentials(config)
                except Exception as e:
                    logger.warning(f"Could not resolve credentials for {integration['name']}: {e}")

                # Get partition password: try resolved 'pin' first, fallback to plaintext
                partition_password = config.get('pin') or config.get('pin_plaintext')

                # Build config for ConnectorService
                hsm_config = {
                    'pkcs11_module_path': config.get('library_path'),
                    'partitions': [{
                        'name': config.get('partition_name', 'default'),
                        'partition_password': partition_password,
                        'slot_index': config.get('slot', 0)
                    }]
                }
                
                keys, _ = ConnectorService.collect_from_luna_hsm(
                    hsm_config, 
                    hsm_name=integration['name']
                )
                
                logger.info(f"Retrieved {len(keys)} keys from {integration['name']}")
                
                # Convert using centralized service
                key_dicts = ConnectorService.azure_keys_to_dict_list(keys)
                
                # Add source integration name to each key
                for key_dict in key_dicts:
                    key_dict['source_integration'] = integration['name']
                
                all_keys.extend(key_dicts)
                    
            except Exception as e:
                logger.error(f"Error collecting keys from integration {integration['id']} ({integration['name']}): {e}")
                import traceback
                logger.error(f"Traceback: {traceback.format_exc()}")
                continue
        
        logger.info(f"Total keys collected: {len(all_keys)}")
        return jsonify({'keys': all_keys}), 200
    
    except Exception as e:
        logger.error(f"Error fetching all KMS keys: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/v1/clm/compliancy/assess', methods=['POST'])
@login_required
#@permission_required('admin')
def assess_clm_compliancy():
    """
    Run compliance assessment on CLM assets against a selected policy.

    Request body:
        source_id: Integration ID (null for all enabled integrations)
        policy_id: Policy ID to assess against
        asset_type: 'certificates', 'keys', or 'all' (default: 'certificates')

    Returns:
        Assessment results with findings, summary, and rule statistics
    """
    try:
        data = request.get_json()
        source_id = data.get('source_id')  # None means all
        policy_id = data.get('policy_id')
        asset_type = data.get('asset_type', 'certificates')  # 'certificates', 'keys', or 'all'

        if not policy_id:
            return jsonify({'error': 'policy_id is required'}), 400

        # Validate asset_type
        if asset_type not in ('certificates', 'keys', 'all'):
            return jsonify({'error': 'asset_type must be certificates, keys, or all'}), 400

        # Get the policy from database (returns parsed policy_json)
        policy_record = DatabaseService.get_policy(int(policy_id))
        if not policy_record:
            return jsonify({'error': f'Policy with id {policy_id} not found'}), 404

        policy = policy_record['policy_json']  # Already parsed by DatabaseService

        # Get assets from inventory (cached from last sync)
        from caip_service_layer.inventory_service import InventoryService

        # Map source_id (CLM integration ID) to connector_id (inventory)
        # If source_id is provided, filter to that connector; otherwise get all
        connector_id = int(source_id) if source_id else None

        # Gather assets based on asset_type
        assets_to_assess = {}

        if asset_type in ('certificates', 'all'):
            certificates = InventoryService.get_certificates(connector_id=connector_id)
            assets_to_assess['certificates'] = certificates if certificates else []

        if asset_type in ('keys', 'all'):
            keys = InventoryService.get_keys(connector_id=connector_id)
            assets_to_assess['keys'] = keys if keys else []

        # Check if any assets found
        total_assets = sum(len(v) for v in assets_to_assess.values())
        if total_assets == 0:
            return jsonify({
                'summary': {
                    'certificates_assessed': 0,
                    'keys_assessed': 0,
                    'total_findings': 0
                },
                'findings': [],
                'rule_statistics': {}
            }), 200

        # Run assessment using PolicyAssessmentService
        findings, summary = PolicyAssessmentService.assess_report_data(
            assets_to_assess,
            policy
        )
        
        # Build rule statistics
        rule_statistics = {}
        for finding in findings:
            rule_id = finding.get('rule_id', 'unknown')
            if rule_id not in rule_statistics:
                rule_statistics[rule_id] = {
                    'name': finding.get('rule_name', rule_id),
                    'severity': finding.get('severity', 'low'),
                    'category': finding.get('category', 'General'),
                    'violations': 0
                }
            rule_statistics[rule_id]['violations'] += 1
        
        # Add all policy rules (even those with 0 violations) for complete picture
        for rule in policy.get('rules', []):
            rule_id = rule.get('rule_id')
            if rule_id:
                enabled = rule.get('enabled', True)
                if rule_id not in rule_statistics:
                    rule_statistics[rule_id] = {
                        'name': rule.get('metadata', {}).get('name', rule_id),
                        'severity': rule.get('metadata', {}).get('severity', 'low'),
                        'category': rule.get('metadata', {}).get('category', 'General'),
                        'violations': 0,
                        'enabled': enabled
                    }
                else:
                    # Add enabled status to existing entries
                    rule_statistics[rule_id]['enabled'] = enabled
        
        return jsonify({
            'summary': summary,
            'findings': findings,
            'rule_statistics': rule_statistics,
            'policy_name': policy_record['name'],
            'assessed_at': datetime.datetime.utcnow().isoformat(),
            'certificates': certificates
        }), 200
        
    except Exception as e:
        logger.error(f"Error in CLM compliancy assessment: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== LIFECYCLE MANAGEMENT ====================

@app.route('/api/v1/lifecycle/policies', methods=['GET'])
@login_required
def get_lifecycle_policies():
    """
    Get lifecycle policies for all connectors.

    Returns:
        List of lifecycle policies with connector names and settings
    """
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('''SELECT lp.id, lp.connector_id, cli.name as connector_name, cli.type as connector_type,
                            lp.renewal_threshold_days, lp.rotation_interval_days, lp.auto_action,
                            lp.notification_enabled, lp.created_at, lp.updated_at
                     FROM lifecycle_policies lp
                     JOIN clm_integrations cli ON lp.connector_id = cli.id
                     ORDER BY cli.name''')
        rows = c.fetchall()
        conn.close()

        policies = []
        for row in rows:
            policies.append({
                'id': row[0],
                'connector_id': row[1],
                'connector_name': row[2],
                'connector_type': row[3],
                'renewal_threshold_days': row[4],
                'rotation_interval_days': row[5],
                'auto_action': row[6],
                'notification_enabled': row[7],
                'auto_execute': row[6] == 1,
                'created_at': row[8],
                'updated_at': row[9]
            })

        return jsonify({
            'policies': policies,
            'total': len(policies)
        }), 200

    except Exception as e:
        logger.error(f"Error fetching lifecycle policies: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/lifecycle/policies/<int:connector_id>', methods=['POST'])
@login_required
def upsert_lifecycle_policy(connector_id):
    """
    Create or update lifecycle policy for a connector.

    Request body:
        renewal_threshold_days: Days until renewal reminder (default 90)
        rotation_interval_days: Days for key rotation interval
        auto_action: 0 = hold for approval, 1 = auto-execute
        notification_enabled: 1 = enable notifications, 0 = disable

    Returns:
        Updated policy or error
    """
    try:
        data = request.get_json() or {}

        # Validate connector exists
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('SELECT id FROM clm_integrations WHERE id = ?', (connector_id,))
        if not c.fetchone():
            conn.close()
            return jsonify({'error': f'Connector {connector_id} not found'}), 404

        renewal_threshold_days = data.get('renewal_threshold_days', 90)
        rotation_interval_days = data.get('rotation_interval_days')
        auto_action = data.get('auto_action', 0)
        notification_enabled = data.get('notification_enabled', 1)

        # Upsert the policy
        c.execute('''INSERT OR REPLACE INTO lifecycle_policies
                     (connector_id, renewal_threshold_days, rotation_interval_days,
                      auto_action, notification_enabled, updated_at)
                     VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)''',
                  (connector_id, renewal_threshold_days, rotation_interval_days,
                   auto_action, notification_enabled))
        conn.commit()
        conn.close()

        return jsonify({
            'message': f'Lifecycle policy updated for connector {connector_id}',
            'connector_id': connector_id,
            'renewal_threshold_days': renewal_threshold_days,
            'rotation_interval_days': rotation_interval_days,
            'auto_action': auto_action,
            'notification_enabled': notification_enabled
        }), 200

    except Exception as e:
        logger.error(f"Error upserting lifecycle policy: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/lifecycle/queue', methods=['GET'])
@login_required
def get_lifecycle_queue():
    """
    Get lifecycle action queue (assets due for renewal/rotation).

    Returns:
        Renewal and rotation queues with asset details and approval status
    """
    try:
        from caip_service_layer.inventory_service import InventoryService

        conn = get_db_connection()
        c = conn.cursor()

        renewal_queue = []
        rotation_queue = []

        # Get all lifecycle policies
        c.execute('SELECT connector_id, renewal_threshold_days, rotation_interval_days FROM lifecycle_policies')
        policies = c.fetchall()

        for policy in policies:
            connector_id, renewal_threshold, rotation_interval = policy

            # Get certificates due for renewal
            if renewal_threshold:
                c.execute('''SELECT id, fingerprint_sha256, connector_id, subject_cn, issuer_cn,
                                    not_after, days_until_expiry, key_algorithm, source_type, is_active
                             FROM certificates_inventory
                             WHERE connector_id = ? AND is_active = 1
                             AND days_until_expiry IS NOT NULL AND days_until_expiry <= ?
                             ORDER BY days_until_expiry ASC''',
                          (connector_id, renewal_threshold))
                rows = c.fetchall()

                for row in rows:
                    renewal_queue.append({
                        'id': row[0],
                        'asset_type': 'certificate',
                        'fingerprint_sha256': row[1],
                        'connector_id': row[2],
                        'subject': row[3],
                        'issuer': row[4],
                        'not_after': row[5],
                        'days_until_expiry': row[6],
                        'algorithm': row[7],
                        'source_type': row[8],
                        'status': 'Pending',  # Can be: Pending, Hold, In Progress, Renewed
                        'approval_required': True
                    })

            # Get keys due for rotation (simplified - uses days from created date)
            if rotation_interval:
                c.execute('''SELECT id, key_identifier, connector_id, key_name, key_type,
                                    key_size, source_type, expires_on, days_until_expiry, is_active
                             FROM keys_inventory
                             WHERE connector_id = ? AND is_active = 1
                             ORDER BY first_seen_at ASC''',
                          (connector_id,))
                rows = c.fetchall()

                for row in rows:
                    rotation_queue.append({
                        'id': row[0],
                        'asset_type': 'key',
                        'key_identifier': row[1],
                        'connector_id': row[2],
                        'key_name': row[3],
                        'key_type': row[4],
                        'key_size': row[5],
                        'source_type': row[6],
                        'expires_on': row[7],
                        'days_until_expiry': row[8],
                        'status': 'Pending',
                        'approval_required': True
                    })

        conn.close()

        # Calculate summary
        summary = {
            'renewal_pending': len(renewal_queue),
            'rotation_pending': len(rotation_queue),
            'awaiting_approval': len(renewal_queue) + len(rotation_queue)
        }

        return jsonify({
            'summary': summary,
            'renewal_queue': renewal_queue,
            'rotation_queue': rotation_queue
        }), 200

    except Exception as e:
        logger.error(f"Error fetching lifecycle queue: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/lifecycle/overview', methods=['GET'])
@login_required
def get_lifecycle_overview():
    """
    Get lifecycle overview dashboard data combining multiple inventory metrics.

    Returns:
        - expiry_summary: Certificate expiry buckets (expired, 7d, 30d, 90d, valid)
        - total_certificates: Total active certificates
        - total_keys: Total active keys
        - source_health: Per-connector sync status and asset counts
        - recent_changes: Recent inventory changes (last 7 days)
        - upcoming_renewals: Soonest-expiring certificates (next 90 days, top 10)
    """
    try:
        from caip_service_layer.inventory_service import InventoryService
        from datetime import datetime, timedelta

        # Get summary statistics
        summary = InventoryService.get_inventory_summary()

        # Get connector health status
        sync_status = InventoryService.get_sync_status()

        # Get recent changes (last 7 days)
        recent_changes = InventoryService.get_recent_changes(
            since=datetime.now() - timedelta(days=7),
            limit=20
        )

        # Get soonest-expiring certificates for upcoming renewals table
        expiring_certs = InventoryService.get_certificates(
            expiring_within_days=90,
            limit=10
        )

        return jsonify({
            'expiry_summary': summary['certificate_expiry'],
            'total_certificates': summary['total_certificates'],
            'total_keys': summary['total_keys'],
            'source_health': sync_status,
            'recent_changes': recent_changes,
            'upcoming_renewals': expiring_certs
        }), 200

    except Exception as e:
        logger.error(f"Error fetching lifecycle overview: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/activity/feed', methods=['GET'])
@login_required
def get_activity_feed():
    """
    Unified activity timeline for the Command Center.
    Merges inventory changes, connector sync outcomes, expiry alerts, and scan completions.
    """
    try:
        from caip_service_layer.inventory_service import InventoryService
        from database_service import DatabaseService
        from datetime import datetime, timedelta, timezone
        import json as _json

        since_days = request.args.get('since_days', 7, type=int)
        limit = request.args.get('limit', 30, type=int)
        since_dt = datetime.now(timezone.utc) - timedelta(days=since_days)
        since_iso = since_dt.isoformat()

        conn = DatabaseService.get_connection()
        c = conn.cursor()
        events = []

        # --- Block A: Inventory changes (enriched with connector + asset context) ---
        c.execute('''
            SELECT ic.id, ic.entity_type, ic.entity_id, ic.connector_id,
                   ic.change_type, ic.change_details, ic.detected_at,
                   ci.name  AS connector_name,
                   ci.type  AS connector_type,
                   cert.subject_cn,
                   cert.key_algorithm,
                   cert.key_size        AS cert_key_size,
                   cert.days_until_expiry AS cert_days_until_expiry,
                   cert.issuer_cn,
                   k.key_name,
                   k.key_type,
                   k.key_size           AS key_key_size,
                   k.days_until_expiry  AS key_days_until_expiry,
                   k.is_hsm_backed
            FROM inventory_changes ic
            LEFT JOIN clm_integrations ci ON ic.connector_id = ci.id
            LEFT JOIN certificates_inventory cert
                   ON ic.entity_type = 'certificate' AND ic.entity_id = cert.id
            LEFT JOIN keys_inventory k
                   ON ic.entity_type = 'key' AND ic.entity_id = k.id
            WHERE ic.detected_at >= ?
            ORDER BY ic.detected_at DESC
            LIMIT ?
        ''', (since_iso, limit))
        for row in c.fetchall():
            r = DatabaseService.dict_from_row(row)
            details = {}
            if r.get('change_details'):
                try:
                    details = _json.loads(r['change_details'])
                except Exception:
                    pass
            name = (r.get('subject_cn') or r.get('key_name') or
                    details.get('subject_cn') or details.get('key_name') or
                    f"{r['entity_type']} #{r['entity_id']}")
            algo = None
            if r.get('key_algorithm') and r.get('cert_key_size'):
                algo = f"{r['key_algorithm']}-{r['cert_key_size']}"
            elif r.get('key_type') and r.get('key_key_size'):
                algo = f"{r['key_type']}-{r['key_key_size']}"
            # Human diff for 'updated' rows
            human_diff = None
            if r['change_type'] == 'updated' and details.get('previous') and details.get('current'):
                try:
                    prev = _json.loads(details['previous']) if isinstance(details['previous'], str) else details['previous']
                    curr = _json.loads(details['current']) if isinstance(details['current'], str) else details['current']
                    diffs = []
                    for k2 in ('days_until_expiry', 'key_algorithm', 'key_size', 'status'):
                        if k2 in prev and k2 in curr and str(prev[k2]) != str(curr[k2]):
                            diffs.append(f"{k2}: {prev[k2]} → {curr[k2]}")
                    if diffs:
                        human_diff = ' · '.join(diffs[:2])
                except Exception:
                    pass
            expiry_days = r.get('cert_days_until_expiry') if r['entity_type'] == 'certificate' else r.get('key_days_until_expiry')
            events.append({
                'event_id': f"inv-{r['id']}",
                'event_type': 'inventory_change',
                'event_at': r['detected_at'],
                'title': name,
                'subtitle': human_diff or r['change_type'],
                'severity': 'info',
                'change_type': r['change_type'],
                'entity_type': r['entity_type'],
                'entity_id': r['entity_id'],
                'connector_name': r.get('connector_name'),
                'connector_type': r.get('connector_type'),
                'algorithm': algo,
                'days_until_expiry': expiry_days,
                'issuer_cn': r.get('issuer_cn'),
                'is_hsm_backed': bool(r.get('is_hsm_backed')),
            })

        # --- Block B: Connector sync outcomes (last sync per connector) ---
        c.execute('''
            SELECT css.connector_id, css.last_sync_completed, css.last_sync_status,
                   css.last_sync_duration_seconds, css.items_added,
                   css.items_updated, css.items_removed, css.last_sync_error,
                   ci.name AS connector_name, ci.type AS connector_type
            FROM connector_sync_status css
            JOIN clm_integrations ci ON css.connector_id = ci.id
            WHERE css.last_sync_completed >= ?
              AND css.last_sync_status IN ('success', 'failed', 'error', 'partial')
            ORDER BY css.last_sync_completed DESC
        ''', (since_iso,))
        for row in c.fetchall():
            r = DatabaseService.dict_from_row(row)
            added   = r.get('items_added') or 0
            updated = r.get('items_updated') or 0
            removed = r.get('items_removed') or 0
            dur     = r.get('last_sync_duration_seconds')
            dur_str = f" · {dur:.1f}s" if dur else ''
            parts   = []
            if added:   parts.append(f"{added} added")
            if updated: parts.append(f"{updated} updated")
            if removed: parts.append(f"{removed} removed")
            subtitle = (', '.join(parts) + dur_str) if parts else (r.get('last_sync_error') or 'no changes')
            status = r.get('last_sync_status', 'success')
            events.append({
                'event_id': f"sync-{r['connector_id']}",
                'event_type': 'connector_sync',
                'event_at': r['last_sync_completed'],
                'title': f"{r.get('connector_name', 'Connector')} synced",
                'subtitle': subtitle,
                'severity': 'success' if status == 'success' else 'error',
                'connector_name': r.get('connector_name'),
                'connector_type': r.get('connector_type'),
                'items_added': added,
                'items_updated': updated,
                'items_removed': removed,
                'sync_status': status,
            })

        # --- Block C: Live expiry alerts (certs <=30 days, synthetic event_at = today) ---
        today_iso = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        c.execute('''
            SELECT cert.id, cert.subject_cn, cert.days_until_expiry,
                   cert.key_algorithm, cert.key_size, cert.issuer_cn,
                   ci.name AS connector_name, ci.type AS connector_type
            FROM certificates_inventory cert
            JOIN clm_integrations ci ON cert.connector_id = ci.id
            WHERE cert.is_active = 1
              AND cert.days_until_expiry IS NOT NULL
              AND cert.days_until_expiry <= 30
            ORDER BY cert.days_until_expiry ASC
            LIMIT 10
        ''')
        for row in c.fetchall():
            r = DatabaseService.dict_from_row(row)
            d = r.get('days_until_expiry', 0)
            sev = 'expired' if d <= 0 else ('critical' if d <= 7 else 'warning')
            algo = f"{r['key_algorithm']}-{r['key_size']}" if r.get('key_algorithm') and r.get('key_size') else None
            parts = []
            if algo: parts.append(algo)
            if r.get('connector_name'): parts.append(r['connector_name'])
            events.append({
                'event_id': f"expiry-cert-{r['id']}",
                'event_type': 'expiry_alert',
                'event_at': today_iso,
                'title': r.get('subject_cn') or f"Certificate #{r['id']}",
                'subtitle': f"{'Expired' if d <= 0 else f'Expires in {d}d'}" + (f" · {' · '.join(parts)}" if parts else ''),
                'severity': sev,
                'days_until_expiry': d,
                'connector_name': r.get('connector_name'),
                'connector_type': r.get('connector_type'),
                'algorithm': algo,
            })

        # --- Block D: Scan run events ---
        c.execute('''
            SELECT id, name, status, last_run
            FROM scans
            WHERE last_run >= ?
              AND status NOT IN ('Never Run', 'Running')
            ORDER BY last_run DESC
            LIMIT 10
        ''', (since_iso,))
        for row in c.fetchall():
            r = DatabaseService.dict_from_row(row)
            sev = 'success' if r.get('status') in ('Successful', 'completed', 'success') else 'error'
            events.append({
                'event_id': f"scan-{r['id']}",
                'event_type': 'scan_run',
                'event_at': r['last_run'],
                'title': r.get('name', 'Scan'),
                'subtitle': r.get('status', ''),
                'severity': sev,
            })

        conn.close()

        # Sort all events by event_at descending
        events.sort(key=lambda e: e.get('event_at') or '', reverse=True)
        events = events[:limit]

        # Group into time buckets
        now_date = datetime.now(timezone.utc).date()
        grouped = {'today': [], 'yesterday': [], 'this_week': [], 'earlier': []}
        for ev in events:
            try:
                ev_date = datetime.fromisoformat(ev['event_at'].replace('Z', '+00:00')).date()
            except Exception:
                ev_date = now_date
            delta = (now_date - ev_date).days
            if delta == 0:
                grouped['today'].append(ev)
            elif delta == 1:
                grouped['yesterday'].append(ev)
            elif delta <= 7:
                grouped['this_week'].append(ev)
            else:
                grouped['earlier'].append(ev)

        return jsonify({'events': events, 'grouped': grouped}), 200

    except Exception as e:
        logger.error(f"Error fetching activity feed: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/lifecycle/renewals', methods=['GET'])
@login_required
def get_lifecycle_renewals():
    """
    Get certificate renewals data for the Renewals tab.

    Returns:
        - expiry_summary: Expiry bucket counts (expired, 7d, 30d, 90d, valid)
        - certificates: All active certificates sorted by urgency (days_until_expiry ASC)
    """
    try:
        from caip_service_layer.inventory_service import InventoryService

        # Get summary statistics
        summary = InventoryService.get_inventory_summary()

        # Get all active certificates sorted by days until expiry (expired ones first)
        certificates = InventoryService.get_certificates()

        return jsonify({
            'expiry_summary': summary['certificate_expiry'],
            'certificates': certificates
        }), 200

    except Exception as e:
        logger.error(f"Error fetching lifecycle renewals: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/lifecycle/rotations', methods=['GET'])
@login_required
def get_lifecycle_rotations():
    """
    Get key rotations data for the Rotations tab.

    Returns:
        - total_keys: Total active key count
        - keys: All active keys with rich metadata (HSM status, PQC analysis)
    """
    try:
        from caip_service_layer.inventory_service import InventoryService

        # Get total key count
        summary = InventoryService.get_inventory_summary()

        # Get all active keys
        keys = InventoryService.get_keys()

        return jsonify({
            'total_keys': summary['total_keys'],
            'keys': keys
        }), 200

    except Exception as e:
        logger.error(f"Error fetching lifecycle rotations: {e}")
        return jsonify({'error': str(e)}), 500


# ==================== HEALTH CHECK ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200

if __name__ == '__main__':
    print("=" * 60)
    print("[CAIP] CAIP Dashboard Starting")
    print("=" * 60)
    print("")
    print("CAIP Dashboard: http://localhost:5000")
    print("CAIP Documentation: http://localhost:5000/docs")
    print("")
    print("Press CTRL+C to stop")
    print("=" * 60)
    print("")
    # Start inventory sync scheduler
    SchedulerService.start(check_interval_seconds=60)
    print("[SCHEDULER] Inventory sync scheduler started (60s check interval)")
    print("")
    # NOTE: Debug mode disabled to prevent code reload errors
    # If you need hot-reload during development, use start_app.bat which sets all required environment variables
    app.run(debug=False, host='0.0.0.0', port=5000)
