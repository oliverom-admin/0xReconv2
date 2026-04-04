"""
Remote Collector Routes for CAIP

API endpoints for remote/edge collector communication:

Authentication Endpoints (Bootstrap):
- POST /api/remote/register - Register collector using bootstrap token

Collector Endpoints (API Key required):
- POST /api/remote/heartbeat - Heartbeat/status update
- POST /api/remote/report - Submit scan report
- GET  /api/remote/policy - Get assigned policy

Management Endpoints (User session required):
- GET  /api/remote/collectors - List all collectors
- GET  /api/remote/collector/<id> - Get collector details
- POST /api/remote/tokens - Generate bootstrap token
- GET  /api/remote/tokens - List bootstrap tokens
- DELETE /api/remote/tokens/<id> - Revoke bootstrap token
- POST /api/remote/collector/<id>/suspend - Suspend collector
- POST /api/remote/collector/<id>/reactivate - Reactivate collector
- DELETE /api/remote/collector/<id> - Decommission collector
- GET  /api/remote/stats - Get aggregate statistics
"""

from flask import Blueprint, request, jsonify, g, session
from functools import wraps
from typing import Optional
import logging

from database_service import DatabaseService
from caip_service_layer.remote_collector_service import RemoteCollectorService

logger = logging.getLogger('caip.operational')
security_logger = logging.getLogger('caip.security')


def _get_user_by_id(user_id: int) -> Optional[dict]:
    """Get user by ID from database."""
    with DatabaseService.get_connection_context() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        row = c.fetchone()
        return dict(row) if row else None


def _get_request_json() -> dict:
    """
    Get JSON from request body with graceful fallback.

    Handles cases where:
    - Content-Type header is missing
    - Request body is empty
    - JSON parsing fails

    Returns empty dict instead of raising exceptions.
    """
    try:
        return request.json or {}
    except Exception:
        # If JSON parsing fails, return empty dict
        return {}


remote_collector_bp = Blueprint('remote_collector', __name__)


# =============================================================================
# AUTHENTICATION DECORATORS
# =============================================================================

def require_api_key(f):
    """
    Decorator to require valid API key for collector endpoints.

    Extracts API key from X-API-Key header and validates it.
    Sets g.collector with collector data on success.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')

        if not api_key:
            security_logger.warning(f"Missing API key from {request.remote_addr}")
            return jsonify({
                'status': 'error',
                'message': 'API key required'
            }), 401

        is_valid, collector, error = RemoteCollectorService.validate_api_key(
            DatabaseService,
            api_key,
            request.remote_addr
        )

        if not is_valid:
            return jsonify({
                'status': 'error',
                'message': error
            }), 401

        g.collector = collector
        return f(*args, **kwargs)

    return decorated_function


def require_admin(f):
    """
    Decorator to require admin role for management endpoints.

    Validates user session and checks for admin role.
    Accepts: admin, system-administrator, security-admin, security-auditor
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({
                'status': 'error',
                'message': 'Authentication required'
            }), 401

        user = _get_user_by_id(session['user_id'])
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 401

        # Check for admin role (support both legacy and RBAC role names)
        admin_roles = ('admin', 'system-administrator', 'security-admin', 'security-auditor')
        if user.get('role') not in admin_roles:
            return jsonify({
                'status': 'error',
                'message': 'Admin role required'
            }), 403

        g.user = user
        return f(*args, **kwargs)

    return decorated_function


def require_login(f):
    """
    Decorator to require any authenticated user.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({
                'status': 'error',
                'message': 'Authentication required'
            }), 401

        user = _get_user_by_id(session['user_id'])
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 401

        g.user = user
        return f(*args, **kwargs)

    return decorated_function


# =============================================================================
# REGISTRATION ENDPOINTS (Bootstrap Token)
# =============================================================================

@remote_collector_bp.route('/api/remote/register', methods=['POST'])
def register_collector():
    """
    Register a new collector using a bootstrap token.

    Request Body:
        {
            "token": "abc123.def456789...",
            "collector_id": "EDGE-LONDON-01"
        }

    Returns:
        {
            "status": "success",
            "collector_id": "EDGE-LONDON-01",
            "api_key": "abcd1234.efgh5678...",  (shown once only)
            "config": { ... }
        }
    """
    try:
        data = request.json
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'Request body required'
            }), 400

        token = data.get('token')
        collector_id = data.get('collector_id')

        if not token:
            return jsonify({
                'status': 'error',
                'message': 'Bootstrap token required'
            }), 400

        if not collector_id:
            return jsonify({
                'status': 'error',
                'message': 'Collector ID required'
            }), 400

        # Validate collector_id format
        if not collector_id.replace('-', '').replace('_', '').isalnum():
            return jsonify({
                'status': 'error',
                'message': 'Collector ID must be alphanumeric with hyphens/underscores only'
            }), 400

        if len(collector_id) > 64:
            return jsonify({
                'status': 'error',
                'message': 'Collector ID must be 64 characters or less'
            }), 400

        # Register the collector
        success, registration_data, error = RemoteCollectorService.register_collector(
            DatabaseService,
            token,
            collector_id,
            request.remote_addr
        )

        if not success:
            return jsonify({
                'status': 'error',
                'message': error
            }), 400

        logger.info(f"Collector registered: {collector_id} from {request.remote_addr}")

        return jsonify({
            'status': 'success',
            **registration_data
        }), 201

    except Exception as e:
        logger.error(f"Registration error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Registration failed'
        }), 500


# =============================================================================
# COLLECTOR ENDPOINTS (API Key Required)
# =============================================================================

@remote_collector_bp.route('/api/remote/heartbeat', methods=['POST'])
@require_api_key
def heartbeat():
    """
    Process heartbeat from a collector with central orchestration.

    Request Body:
        {
            "status": "healthy",
            "version": "1.0.0",
            "config_version": 3,
            "uptime_seconds": 3600,
            "resource_usage": { ... }
        }

    Returns:
        {
            "status": "ok",
            "server_time": "2025-12-14T10:00:00Z",
            "config_changed": true,
            "config_version": 5,
            "config": { ... },  // Included if config_changed
            "pending_jobs_count": 2,
            "pending_jobs": [ ... ]  // Included if jobs pending
        }
    """
    try:
        collector = g.collector
        data = request.json or {}

        # Use enhanced heartbeat with config sync
        response = RemoteCollectorService.process_heartbeat_with_config(
            DatabaseService,
            collector['collector_id'],
            data,
            request.remote_addr
        )

        return jsonify(response), 200

    except Exception as e:
        logger.error(f"Heartbeat error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Heartbeat processing failed'
        }), 500


@remote_collector_bp.route('/api/remote/report', methods=['POST'])
@require_api_key
def submit_report():
    """
    Submit a scan report from a collector.

    Request Body:
        {
            "scan_id": "SCAN-EDGE-01-20251214-100000",
            "transmission_mode": "selective",
            "timestamp": "2025-12-14T10:00:00Z",
            "certificate_count": 150,
            "findings": [ ... ],
            "risk_score": 67.5,
            ...mode-specific data...
        }

    Returns:
        {
            "status": "success",
            "report_id": 123,
            "received_at": "2025-12-14T10:00:05Z"
        }
    """
    try:
        collector = g.collector
        data = request.json

        if not data:
            return jsonify({
                'status': 'error',
                'message': 'Report data required'
            }), 400

        scan_id = data.get('scan_id')
        if not scan_id:
            return jsonify({
                'status': 'error',
                'message': 'scan_id required'
            }), 400

        transmission_mode = data.get('transmission_mode', collector['transmission_mode'])

        # Validate transmission mode matches collector config
        if transmission_mode != collector['transmission_mode']:
            logger.warning(
                f"Collector {collector['collector_id']} sent {transmission_mode} "
                f"but configured for {collector['transmission_mode']}"
            )

        report_id = RemoteCollectorService.store_report(
            DatabaseService,
            collector['collector_id'],
            scan_id,
            transmission_mode,
            data,
            request.remote_addr
        )

        # If full report JSON is included, save it to the reports folder
        # This allows remote reports to be viewed alongside local reports
        report_json = data.get('report_json')
        if report_json:
            try:
                import json
                import os
                from pathlib import Path

                # Convert scan_id to integer if it's numeric (remote collectors send numeric scan_id)
                try:
                    scan_id_int = int(scan_id) if isinstance(scan_id, str) else scan_id
                except (ValueError, TypeError):
                    # If scan_id is not numeric, skip report upload
                    logger.warning(f"Cannot upload report: scan_id '{scan_id}' is not numeric")
                    scan_id_int = None

                if scan_id_int is not None:
                    # Check if scan exists in the scans table
                    conn = DatabaseService.get_connection()
                    c = conn.cursor()
                    c.execute('SELECT id, name FROM scans WHERE id = ?', (scan_id_int,))
                    scan_row = c.fetchone()
                    conn.close()

                    if scan_row:
                        scan_name = scan_row[1]

                        # Calculate the actual next run number from scan_logs (don't trust client)
                        conn = DatabaseService.get_connection()
                        c = conn.cursor()
                        c.execute('SELECT COALESCE(MAX(run_number), 0) FROM scan_logs WHERE scan_id = ?',
                                 (scan_id_int,))
                        row = c.fetchone()
                        run_number = (row[0] if row else 0) + 1
                        conn.close()

                        # Generate filename using standard convention
                        from datetime import datetime
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        scan_name_safe = scan_name.replace(' ', '_').replace('/', '_')
                        filename = f'{scan_name_safe}_run{run_number}_{timestamp}.json'

                        # Ensure reports folder exists
                        reports_folder = 'reports'
                        if not os.path.exists(reports_folder):
                            os.makedirs(reports_folder, exist_ok=True)

                        # Save report file
                        report_path = os.path.join(reports_folder, filename)
                        with open(report_path, 'w', encoding='utf-8') as f:
                            json.dump(report_json, f, indent=2)

                        # Update scans table with report path
                        conn = DatabaseService.get_connection()
                        try:
                            c = conn.cursor()
                            c.execute(
                                'UPDATE scans SET report_path = ? WHERE id = ?',
                                (report_path, scan_id_int)
                            )
                            conn.commit()
                            logger.info(f"Report uploaded from {collector['collector_id']}: {report_path}")
                        finally:
                            conn.close()
                    else:
                        logger.warning(f"Scan {scan_id_int} not found in scans table, cannot upload report")
                        logger.info(f"Report JSON received but not saved: scan_id={scan_id}, size: {len(json.dumps(report_json)) if isinstance(report_json, dict) else len(report_json)} bytes")

            except Exception as e:
                logger.warning(f"Could not process report_json: {e}", exc_info=True)

        from datetime import datetime
        return jsonify({
            'status': 'success',
            'report_id': report_id,
            'received_at': datetime.now().isoformat()
        }), 200

    except Exception as e:
        logger.error(f"Report submission error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Report submission failed'
        }), 500


@remote_collector_bp.route('/api/remote/policy', methods=['GET'])
@require_api_key
def get_policy():
    """
    Get the policy assigned to this collector.

    Returns:
        {
            "status": "success",
            "policy_version": 1,
            "policy": { ... }
        }
    """
    try:
        collector = g.collector

        # TODO: Implement policy assignment to collectors
        # For now, return a minimal policy
        return jsonify({
            'status': 'success',
            'policy_version': 1,
            'policy': {
                'version': '1.0',
                'rules': []
            }
        }), 200

    except Exception as e:
        logger.error(f"Policy retrieval error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Policy retrieval failed'
        }), 500


# =============================================================================
# MANAGEMENT ENDPOINTS (User Session Required)
# =============================================================================

@remote_collector_bp.route('/api/remote/tokens', methods=['POST'])
@require_admin
def generate_token():
    """
    Generate a bootstrap token for collector registration.

    Request Body:
        {
            "collector_name": "London DC Collector",
            "organization": "Acme Corp",
            "location": "London DC-1",
            "environment": "production",
            "transmission_mode": "selective",
            "ttl_hours": 24,
            "max_uses": 1,
            "ip_restriction": null,
            "engagement_ca_id": "ENG-2024-001"  (optional)
        }

    Returns:
        {
            "status": "success",
            "token": "abc123.def456...",  (shown once only)
            "token_prefix": "abc123",
            "expires_at": "2025-12-15T10:00:00Z",
            "engagement_ca_id": "ENG-2024-001",
            ...
        }
    """
    try:
        data = request.json
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'Request body required'
            }), 400

        collector_name = data.get('collector_name')
        organization = data.get('organization')

        if not collector_name:
            return jsonify({
                'status': 'error',
                'message': 'collector_name required'
            }), 400

        if not organization:
            return jsonify({
                'status': 'error',
                'message': 'organization required'
            }), 400

        token, token_metadata = RemoteCollectorService.generate_bootstrap_token(
            DatabaseService,
            collector_name=collector_name,
            organization=organization,
            created_by=g.user['username'],
            location=data.get('location'),
            environment=data.get('environment', 'production'),
            transmission_mode=data.get('transmission_mode', 'selective'),
            ttl_hours=data.get('ttl_hours', 24),
            max_uses=data.get('max_uses', 1),
            ip_restriction=data.get('ip_restriction'),
            engagement_ca_id=data.get('engagement_ca_id')
        )

        return jsonify({
            'status': 'success',
            'token': token,
            **token_metadata
        }), 201

    except Exception as e:
        logger.error(f"Token generation error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Token generation failed'
        }), 500


@remote_collector_bp.route('/api/remote/tokens', methods=['GET'])
@require_admin
def list_tokens():
    """
    List all bootstrap tokens.

    Query Params:
        include_expired: Include expired/exhausted tokens (default: false)

    Returns:
        {
            "status": "success",
            "tokens": [ ... ]
        }
    """
    try:
        include_expired = request.args.get('include_expired', 'false').lower() == 'true'

        tokens = RemoteCollectorService.list_bootstrap_tokens(
            DatabaseService,
            include_expired=include_expired
        )

        return jsonify({
            'status': 'success',
            'count': len(tokens),
            'tokens': tokens
        }), 200

    except Exception as e:
        logger.error(f"Token list error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to list tokens'
        }), 500


@remote_collector_bp.route('/api/remote/tokens/<int:token_id>', methods=['DELETE'])
@require_admin
def revoke_token(token_id):
    """
    Revoke a bootstrap token.

    Returns:
        {
            "status": "success",
            "message": "Token revoked"
        }
    """
    try:
        success = RemoteCollectorService.revoke_bootstrap_token(
            DatabaseService,
            token_id,
            g.user['username']
        )

        if success:
            return jsonify({
                'status': 'success',
                'message': 'Token revoked'
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'Token not found or already revoked'
            }), 404

    except Exception as e:
        logger.error(f"Token revocation error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Token revocation failed'
        }), 500


@remote_collector_bp.route('/api/remote/collectors', methods=['GET'])
@require_login
def list_collectors():
    """
    List all registered collectors.

    Query Params:
        status: Filter by status (optional)
        include_decommissioned: Include decommissioned (default: false)

    Returns:
        {
            "status": "success",
            "collectors": [ ... ]
        }
    """
    try:
        status_filter = request.args.get('status')
        include_decommissioned = request.args.get('include_decommissioned', 'false').lower() == 'true'

        collectors = RemoteCollectorService.list_collectors(
            DatabaseService,
            status_filter=status_filter,
            include_decommissioned=include_decommissioned
        )

        return jsonify({
            'status': 'success',
            'count': len(collectors),
            'collectors': collectors
        }), 200

    except Exception as e:
        logger.error(f"Collector list error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to list collectors'
        }), 500


@remote_collector_bp.route('/api/remote/collector/<collector_id>', methods=['GET'])
@require_login
def get_collector(collector_id):
    """
    Get details for a specific collector.

    Returns:
        {
            "status": "success",
            "collector": { ... },
            "recent_reports": [ ... ]
        }
    """
    try:
        collector = RemoteCollectorService.get_collector(DatabaseService, collector_id)

        if not collector:
            return jsonify({
                'status': 'error',
                'message': 'Collector not found'
            }), 404

        # Remove sensitive data
        collector.pop('api_key_hash', None)

        # Get recent reports
        reports = RemoteCollectorService.get_collector_reports(DatabaseService, collector_id)

        return jsonify({
            'status': 'success',
            'collector': collector,
            'recent_reports': reports
        }), 200

    except Exception as e:
        logger.error(f"Collector details error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to get collector details'
        }), 500


@remote_collector_bp.route('/api/remote/collector/<collector_id>/suspend', methods=['POST'])
@require_admin
def suspend_collector(collector_id):
    """
    Suspend a collector.

    Request Body:
        {
            "reason": "Maintenance" (optional)
        }

    Returns:
        {
            "status": "success",
            "message": "Collector suspended"
        }
    """
    try:
        data = request.json or {}
        reason = data.get('reason')

        success = RemoteCollectorService.suspend_collector(
            DatabaseService,
            collector_id,
            g.user['username'],
            reason
        )

        if success:
            return jsonify({
                'status': 'success',
                'message': 'Collector suspended'
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'Collector not found or already suspended'
            }), 404

    except Exception as e:
        logger.error(f"Collector suspend error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to suspend collector'
        }), 500


@remote_collector_bp.route('/api/remote/collector/<collector_id>/reactivate', methods=['POST'])
@require_admin
def reactivate_collector(collector_id):
    """
    Reactivate a suspended collector.

    Returns:
        {
            "status": "success",
            "message": "Collector reactivated"
        }
    """
    try:
        success = RemoteCollectorService.reactivate_collector(
            DatabaseService,
            collector_id,
            g.user['username']
        )

        if success:
            return jsonify({
                'status': 'success',
                'message': 'Collector reactivated'
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'Collector not found or not suspended'
            }), 404

    except Exception as e:
        logger.error(f"Collector reactivate error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to reactivate collector'
        }), 500


@remote_collector_bp.route('/api/remote/collector/<collector_id>', methods=['DELETE'])
@require_admin
def delete_collector(collector_id):
    """
    Permanently delete a collector and all associated data.

    Cascades delete to:
    - Reports and findings
    - Jobs and task history
    - Configurations
    - Audit logs
    - Scan associations (clears collector_id from scans)

    Request Body:
        {
            "reason": "No longer needed" (optional)
        }

    Returns:
        {
            "status": "success",
            "message": "Collector deleted",
            "details": {
                "reports_deleted": 5,
                "jobs_deleted": 2,
                "configs_deleted": 1,
                "scans_updated": 3,
                "audit_records_deleted": 15
            }
        }
    """
    try:
        # Handle JSON parsing gracefully - DELETE may not have Content-Type header
        try:
            data = request.get_json(force=True, silent=True) or {}
        except Exception:
            data = {}
        reason = data.get('reason')

        success, error = RemoteCollectorService.delete_collector(
            DatabaseService,
            collector_id,
            g.user['username'],
            reason
        )

        if success:
            return jsonify({
                'status': 'success',
                'message': f'Collector {collector_id} permanently deleted'
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': error or 'Failed to delete collector'
            }), 400

    except Exception as e:
        logger.error(f"Collector deletion error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to delete collector'
        }), 500


@remote_collector_bp.route('/api/remote/stats', methods=['GET'])
@require_login
def get_statistics():
    """
    Get aggregate statistics across all collectors.

    Returns:
        {
            "status": "success",
            "statistics": {
                "total_collectors": 10,
                "collectors_by_status": { ... },
                "collectors_by_mode": { ... },
                "total_reports": 500,
                "total_certificates": 15000,
                "total_findings": 230,
                "avg_risk_score": 45.2
            }
        }
    """
    try:
        stats = RemoteCollectorService.get_statistics(DatabaseService)

        return jsonify({
            'status': 'success',
            'statistics': stats
        }), 200

    except Exception as e:
        logger.error(f"Statistics error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to get statistics'
        }), 500


@remote_collector_bp.route('/api/remote/reports', methods=['GET'])
@require_login
def list_reports():
    """
    List reports from all collectors.

    Query Params:
        collector_id: Filter by collector (optional)
        limit: Max results (default: 50)

    Returns:
        {
            "status": "success",
            "reports": [ ... ]
        }
    """
    try:
        collector_id = request.args.get('collector_id')
        limit = int(request.args.get('limit', 50))

        if collector_id:
            reports = RemoteCollectorService.get_collector_reports(
                DatabaseService,
                collector_id,
                limit
            )
        else:
            # Get reports from all collectors
            # TODO: Add pagination
            with DatabaseService.get_connection_context() as conn:
                c = conn.cursor()
                c.execute('''
                    SELECT id, collector_id, scan_id, transmission_mode,
                           certificate_count, findings_count, risk_score, received_at
                    FROM remote_collector_reports
                    ORDER BY received_at DESC
                    LIMIT ?
                ''', (limit,))
                reports = [dict(row) for row in c.fetchall()]

        return jsonify({
            'status': 'success',
            'count': len(reports),
            'reports': reports
        }), 200

    except Exception as e:
        logger.error(f"Reports list error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to list reports'
        }), 500


@remote_collector_bp.route('/api/remote/report/<int:report_id>', methods=['GET'])
@require_login
def get_report(report_id):
    """
    Get details of a specific report.

    Returns:
        {
            "status": "success",
            "report": { ... }
        }
    """
    try:
        report = RemoteCollectorService.get_report(DatabaseService, report_id)

        if not report:
            return jsonify({
                'status': 'error',
                'message': 'Report not found'
            }), 404

        return jsonify({
            'status': 'success',
            'report': report
        }), 200

    except Exception as e:
        logger.error(f"Report details error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to get report details'
        }), 500


# =============================================================================
# COLLECTOR CONFIGURATION ENDPOINTS (Central Management)
# =============================================================================

@remote_collector_bp.route('/api/remote/collector/<collector_id>/config', methods=['GET'])
@require_login
def get_collector_config(collector_id):
    """
    Get central configuration for a collector.

    Returns:
        {
            "status": "success",
            "config": {
                "config_version": 5,
                "transmission_mode": "selective",
                "scan_targets": [...],
                "schedule": {...},
                "heartbeat_interval": 60
            }
        }
    """
    try:
        config = RemoteCollectorService.get_collector_config(DatabaseService, collector_id)

        if not config:
            return jsonify({
                'status': 'error',
                'message': 'Collector not found'
            }), 404

        return jsonify({
            'status': 'success',
            'config': config
        }), 200

    except Exception as e:
        logger.error(f"Get config error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to get configuration'
        }), 500


@remote_collector_bp.route('/api/remote/collector/<collector_id>/config', methods=['PUT'])
@require_admin
def update_collector_config(collector_id):
    """
    Update central configuration for a collector.

    Request Body:
        {
            "transmission_mode": "selective",
            "scan_targets": [...],
            "schedule": {...},
            "heartbeat_interval": 60,
            "enabled_collectors": ["tls", "ejbca", "azure_keyvault", ...]
        }

    Returns:
        {
            "status": "success",
            "config_version": 6
        }
    """
    try:
        data = request.json or {}
        logger.info(f"[update_collector_config] Request data: {data}")
        logger.info(f"[update_collector_config] enabled_collectors from request: {data.get('enabled_collectors')}")

        success, new_version = RemoteCollectorService.update_collector_config(
            DatabaseService,
            collector_id=collector_id,
            updated_by=g.user['username'],
            transmission_mode=data.get('transmission_mode'),
            scan_targets=data.get('scan_targets'),
            schedule=data.get('schedule'),
            heartbeat_interval=data.get('heartbeat_interval'),
            policy_id=data.get('policy_id'),
            enabled_collectors=data.get('enabled_collectors')
        )

        return jsonify({
            'status': 'success',
            'config_version': new_version
        }), 200

    except Exception as e:
        logger.error(f"Update config error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to update configuration'
        }), 500


@remote_collector_bp.route('/api/remote/collector/<collector_id>/scan', methods=['POST'])
@require_admin
def trigger_collector_scan(collector_id):
    """
    Trigger an ad-hoc scan on a collector.

    Request Body (optional):
        {
            "targets": [...],  // Override configured targets
            "priority": "high"
        }

    Returns:
        {
            "status": "success",
            "job_id": 123
        }
    """
    try:
        data = request.json or {}

        job_id = RemoteCollectorService.trigger_scan(
            DatabaseService,
            collector_id=collector_id,
            triggered_by=g.user['username'],
            targets=data.get('targets'),
            priority=data.get('priority', 'normal')
        )

        return jsonify({
            'status': 'success',
            'job_id': job_id,
            'message': 'Scan job created'
        }), 201

    except Exception as e:
        logger.error(f"Trigger scan error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to trigger scan'
        }), 500


# =============================================================================
# JOB QUEUE ENDPOINTS (Collector-facing)
# =============================================================================

@remote_collector_bp.route('/api/remote/jobs', methods=['GET'])
@require_api_key
def get_collector_jobs():
    """
    Get pending jobs for the authenticated collector.

    Returns:
        {
            "status": "success",
            "jobs": [
                {
                    "id": 1,
                    "job_type": "scan",
                    "priority": "high",
                    "payload": {...}
                }
            ]
        }
    """
    try:
        collector = g.collector
        jobs = RemoteCollectorService.get_pending_jobs(
            DatabaseService,
            collector['collector_id']
        )

        return jsonify({
            'status': 'success',
            'count': len(jobs),
            'jobs': jobs
        }), 200

    except Exception as e:
        logger.error(f"Get jobs error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to get jobs'
        }), 500


@remote_collector_bp.route('/api/remote/jobs/<int:job_id>/ack', methods=['POST'])
@require_api_key
def acknowledge_job(job_id):
    """
    Acknowledge a job (collector has received it).

    Returns:
        {
            "status": "success"
        }
    """
    try:
        collector = g.collector
        success = RemoteCollectorService.acknowledge_job(
            DatabaseService,
            job_id,
            collector['collector_id']
        )

        if success:
            return jsonify({'status': 'success'}), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'Job not found or already acknowledged'
            }), 404

    except Exception as e:
        logger.error(f"Ack job error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to acknowledge job'
        }), 500


@remote_collector_bp.route('/api/remote/jobs/<int:job_id>/start', methods=['POST'])
@require_api_key
def start_job(job_id):
    """
    Mark a job as started.

    Returns:
        {
            "status": "success"
        }
    """
    try:
        collector = g.collector
        success = RemoteCollectorService.start_job(
            DatabaseService,
            job_id,
            collector['collector_id']
        )

        if success:
            return jsonify({'status': 'success'}), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'Job not found or cannot be started'
            }), 404

    except Exception as e:
        logger.error(f"Start job error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to start job'
        }), 500


@remote_collector_bp.route('/api/remote/jobs/<int:job_id>/complete', methods=['POST'])
@require_api_key
def complete_job(job_id):
    """
    Mark a job as completed.

    Request Body:
        {
            "success": true,
            "result": {...},
            "error_message": null
        }

    Returns:
        {
            "status": "success"
        }
    """
    try:
        collector = g.collector
        data = request.json or {}

        # Get the job to check if it's a scan job
        job = RemoteCollectorService.get_job(DatabaseService, job_id)

        success = RemoteCollectorService.complete_job(
            DatabaseService,
            job_id,
            collector['collector_id'],
            success=data.get('success', True),
            result=data.get('result'),
            error_message=data.get('error_message')
        )

        if success:
            # If this was a scan job, update the associated scan's status
            if job and job.get('job_type') == 'scan':
                try:
                    import json
                    payload = job.get('payload')
                    if isinstance(payload, str):
                        payload = json.loads(payload) if payload else {}
                    scan_id = payload.get('scan_id')

                    if scan_id:
                        job_success = data.get('success', True)
                        result_data = data.get('result', {})
                        error_msg = data.get('error_message')

                        # Do all database operations in a single connection to avoid locking
                        with DatabaseService.get_connection_context() as conn:
                            c = conn.cursor()

                            # Get the next run number for this scan (within same connection)
                            c.execute('SELECT COALESCE(MAX(run_number), 0) FROM scan_logs WHERE scan_id = ?',
                                     (scan_id,))
                            row = c.fetchone()
                            run_number = (row[0] if row else 0) + 1

                            if job_success:
                                # Update scan to successful
                                c.execute('''UPDATE scans
                                             SET status = 'Successful',
                                             last_run = CURRENT_TIMESTAMP,
                                             updated_at = CURRENT_TIMESTAMP
                                             WHERE id = ?''', (scan_id,))

                                # Log success with correct run_number
                                c.execute('INSERT INTO scan_logs (scan_id, run_number, log_entry) VALUES (?, ?, ?)',
                                         (scan_id, run_number,
                                          f"Remote scan completed successfully (run #{run_number}). Certificates found: {result_data.get('certificates_found', 0)}, Findings: {result_data.get('findings_count', 0)}"))
                            else:
                                # Update scan to failed
                                c.execute('''UPDATE scans
                                             SET status = 'Failed',
                                             updated_at = CURRENT_TIMESTAMP
                                             WHERE id = ?''', (scan_id,))

                                # Log failure with correct run_number
                                c.execute('INSERT INTO scan_logs (scan_id, run_number, log_entry) VALUES (?, ?, ?)',
                                         (scan_id, run_number,
                                          f"Remote scan failed (run #{run_number}): {error_msg or 'Unknown error'}"))
                            conn.commit()

                        logger.info(f"Updated scan {scan_id} status after remote job {job_id} completion (run #{run_number})")
                except Exception as scan_update_error:
                    logger.error(f"Failed to update scan status after job completion: {scan_update_error}")

            return jsonify({'status': 'success'}), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'Job not found or already completed'
            }), 404

    except Exception as e:
        logger.error(f"Complete job error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to complete job'
        }), 500


# =============================================================================
# JOB MANAGEMENT ENDPOINTS (Dashboard-facing)
# =============================================================================

@remote_collector_bp.route('/api/remote/collector/<collector_id>/jobs', methods=['GET'])
@require_login
def get_collector_job_history(collector_id):
    """
    Get job history for a specific collector.

    Returns:
        {
            "status": "success",
            "jobs": [...]
        }
    """
    try:
        jobs = RemoteCollectorService.get_job_history(
            DatabaseService,
            collector_id=collector_id,
            limit=int(request.args.get('limit', 50))
        )

        return jsonify({
            'status': 'success',
            'count': len(jobs),
            'jobs': jobs
        }), 200

    except Exception as e:
        logger.error(f"Get job history error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to get job history'
        }), 500


@remote_collector_bp.route('/api/remote/collector/<collector_id>/jobs', methods=['POST'])
@require_admin
def create_collector_job(collector_id):
    """
    Create a job for a collector.

    Request Body:
        {
            "job_type": "scan",
            "priority": "normal",
            "payload": {...}
        }

    Returns:
        {
            "status": "success",
            "job_id": 123
        }
    """
    try:
        data = request.json or {}

        job_type = data.get('job_type')
        if not job_type:
            return jsonify({
                'status': 'error',
                'message': 'job_type required'
            }), 400

        job_id = RemoteCollectorService.create_job(
            DatabaseService,
            collector_id=collector_id,
            job_type=job_type,
            created_by=g.user['username'],
            payload=data.get('payload'),
            priority=data.get('priority', 'normal')
        )

        return jsonify({
            'status': 'success',
            'job_id': job_id
        }), 201

    except Exception as e:
        logger.error(f"Create job error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to create job'
        }), 500


# =============================================================================
# POLICY TEMPLATE ENDPOINTS
# =============================================================================

@remote_collector_bp.route('/api/remote/policies', methods=['GET'])
@require_login
def list_policies():
    """
    List all policy templates.

    Returns:
        {
            "status": "success",
            "policies": [...]
        }
    """
    try:
        policies = RemoteCollectorService.list_policy_templates(DatabaseService)

        return jsonify({
            'status': 'success',
            'count': len(policies),
            'policies': policies
        }), 200

    except Exception as e:
        logger.error(f"List policies error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to list policies'
        }), 500


@remote_collector_bp.route('/api/remote/policies', methods=['POST'])
@require_admin
def create_policy():
    """
    Create a new policy template.

    Request Body:
        {
            "name": "Production Standard",
            "description": "Standard policy for production collectors",
            "rules": [...]
        }

    Returns:
        {
            "status": "success",
            "policy_id": 1
        }
    """
    try:
        data = request.json or {}

        name = data.get('name')
        if not name:
            return jsonify({
                'status': 'error',
                'message': 'name required'
            }), 400

        policy_id = RemoteCollectorService.create_policy_template(
            DatabaseService,
            name=name,
            description=data.get('description', ''),
            rules=data.get('rules', []),
            created_by=g.user['username']
        )

        return jsonify({
            'status': 'success',
            'policy_id': policy_id
        }), 201

    except Exception as e:
        logger.error(f"Create policy error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to create policy'
        }), 500


@remote_collector_bp.route('/api/remote/policies/<int:policy_id>', methods=['GET'])
@require_login
def get_policy_template(policy_id):
    """
    Get a policy template by ID.

    Returns:
        {
            "status": "success",
            "policy": {...}
        }
    """
    try:
        policy = RemoteCollectorService.get_policy_template(DatabaseService, policy_id)

        if not policy:
            return jsonify({
                'status': 'error',
                'message': 'Policy not found'
            }), 404

        return jsonify({
            'status': 'success',
            'policy': policy
        }), 200

    except Exception as e:
        logger.error(f"Get policy error: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to get policy'
        }), 500


# =============================================================================
# BLUEPRINT REGISTRATION
# =============================================================================

def register_remote_collector_routes(app):
    """
    Register remote collector routes with Flask app.

    Also initializes the database tables if needed.

    Args:
        app: Flask application instance
    """
    # Initialize tables
    RemoteCollectorService.init_tables(DatabaseService)

    # Register blueprint
    app.register_blueprint(remote_collector_bp)
    logger.info("Remote collector routes registered")
