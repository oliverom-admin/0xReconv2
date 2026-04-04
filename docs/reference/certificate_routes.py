"""
Certificate Management Routes for CAIP

Provides REST API endpoints for:
- Certificate inventory and management (per-CA)
- Collector certificate registration and renewal
- Certificate revocation and status tracking
- Audit logging and reporting

URL Structure:
  /api/v1/ca/{ca_name}/certificates          - Certificate operations
  /api/v1/remote/certificate/register         - Collector registration
  /api/v1/remote/certificate/renew            - Collector renewal
  /api/v1/remote/certificate/status           - Collector status

Routes are split into:
1. Admin endpoints (requires session auth)
2. Collector endpoints (requires mTLS or bootstrap token auth)
"""

import json
import logging
from datetime import datetime
from flask import Blueprint, request, jsonify
from functools import wraps

logger = logging.getLogger('caip.operational')


def create_certificate_routes(certificate_service, database_service, auth_decorator, permission_decorator=None):
    """
    Create certificate routes blueprint.

    Args:
        certificate_service: CertificateService instance
        database_service: DatabaseService instance
        auth_decorator: Authentication decorator (e.g., login_required)
        permission_decorator: Permission decorator (e.g., permission_required)

    Returns:
        Blueprint with all certificate routes
    """
    bp = Blueprint('certificates', __name__, url_prefix='/api/v1')

    # =========================================================================
    # ADMIN ENDPOINTS - CA Certificate Management (Requires session auth)
    # =========================================================================

    @bp.route('/ca/internal', methods=['GET'])
    @auth_decorator
    def get_internal_ca():
        """
        Get internal CA details.

        Returns:
            JSON object with internal CA certificate details including algorithm, key size, and issuer
        """
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            ca = certificate_service.get_internal_ca()
            if not ca:
                return jsonify({'error': 'Internal CA not found'}), 404

            # Parse certificate to extract additional details
            cert_pem = ca['certificate_pem']
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

            # Extract key algorithm and size
            key = cert.public_key()
            key_type = type(key).__name__
            if "RSA" in key_type:
                algorithm = "RSA"
                key_size = key.key_size
            elif "EllipticCurve" in key_type:
                algorithm = "EC"
                key_size = key.curve.key_size
            else:
                algorithm = key_type
                key_size = None

            # Extract issuer (for self-signed, issuer == subject)
            issuer_cn = None
            for attr in cert.issuer:
                if attr.oid._name == "commonName":
                    issuer_cn = attr.value
                    break

            return jsonify({
                'ca': {
                    'serial_number': ca['serial_number'],
                    'subject': ca['subject'],
                    'issuer': issuer_cn or 'Self-signed',
                    'algorithm': algorithm,
                    'key_size': key_size,
                    'issued_at': ca['issued_at'],
                    'expires_at': ca['expires_at'],
                    'rotation_count': ca['rotation_count'],
                    'status': ca['status']
                }
            }), 200

        except Exception as e:
            logger.error(f"Error retrieving internal CA: {e}")
            return jsonify({'error': str(e)}), 500

    @bp.route('/ca/internal/issued-certificates', methods=['GET'])
    @auth_decorator
    def get_internal_ca_issued_certificates():
        """
        Get all certificates issued by the internal CA (dashboard + internal certificates).

        Returns:
            JSON array of certificate objects with component_id, serial, issued, expires, status
        """
        try:
            from datetime import datetime

            conn = database_service.get_connection()

            certificates = []

            # 1. Get dashboard certificates issued by internal CA
            dashboard_query = """
                SELECT
                    'dashboard' as component_id,
                    'Dashboard Server Certificate' as component_name,
                    serial_number,
                    hostname as subject,
                    issued_at,
                    expires_at,
                    status
                FROM dashboard_certificates
                WHERE status IN ('active', 'expiring')
                ORDER BY issued_at DESC
            """

            dashboard_rows = conn.execute(dashboard_query).fetchall()
            for row in dashboard_rows:
                cert_dict = {
                    'component_id': row['component_id'] if isinstance(row, dict) else row[0],
                    'component_name': row['component_name'] if isinstance(row, dict) else row[1],
                    'serial_number': row['serial_number'] if isinstance(row, dict) else row[2],
                    'subject': row['subject'] if isinstance(row, dict) else row[3],
                    'issued_at': row['issued_at'] if isinstance(row, dict) else row[4],
                    'expires_at': row['expires_at'] if isinstance(row, dict) else row[5],
                    'status': row['status'] if isinstance(row, dict) else row[6],
                }

                # Calculate days remaining
                try:
                    expires = datetime.fromisoformat(cert_dict['expires_at'])
                    now = datetime.utcnow()
                    days_remaining = (expires - now).days
                    cert_dict['days_remaining'] = days_remaining

                    # Determine status based on expiry
                    if days_remaining < 0:
                        cert_dict['status'] = 'EXPIRED'
                    elif days_remaining < 30:
                        cert_dict['status'] = 'EXPIRING'
                    else:
                        cert_dict['status'] = 'ACTIVE'
                except:
                    cert_dict['days_remaining'] = None

                certificates.append(cert_dict)

            # Note: internal_certificates table is deprecated (Phase A4) and has been removed

            conn.close()

            # Sort by issued_at descending
            certificates.sort(key=lambda x: x['issued_at'], reverse=True)

            return jsonify({'certificates': certificates}), 200

        except Exception as e:
            logger.error(f"Error retrieving internal CA issued certificates: {e}")
            return jsonify({'error': str(e)}), 500

    @bp.route('/ca/<ca_name>/certificates', methods=['GET'])
    @auth_decorator
    def list_ca_certificates(ca_name):
        """
        List all certificates issued by a CA.

        URL params:
        - ca_name: CA identifier (e.g., 'engagement-001', 'dashboard')

        Query params:
        - engagement_id (optional): Filter by engagement
        - status (optional): Filter by status (active, renewing, revoked, expired)
        - collector_id (optional): Filter by collector

        Returns:
            JSON array of certificate objects
        """
        try:
            engagement_id = request.args.get('engagement_id')
            status = request.args.get('status')

            conn = database_service.get_connection()
            query = "SELECT * FROM collector_certificates WHERE 1=1"
            params = []

            if engagement_id:
                query += " AND engagement_id = ?"
                params.append(engagement_id)

            if status:
                query += " AND status = ?"
                params.append(status)

            query += " ORDER BY expires_at ASC"

            rows = conn.execute(query, params).fetchall()
            conn.close()

            certs = []
            for row in rows:
                cert_info = certificate_service.get_collector_certificate(row['collector_id'])
                if cert_info:
                    try:
                        revoked_at = row['revoked_at']
                    except (IndexError, KeyError):
                        revoked_at = None

                    try:
                        revocation_reason = row['revocation_reason']
                    except (IndexError, KeyError):
                        revocation_reason = None

                    certs.append({
                        'collector_id': row['collector_id'],
                        'engagement_id': row['engagement_id'],
                        'serial_number': row['serial_number'],
                        'subject': row['subject'],
                        'issued_at': row['issued_at'],
                        'expires_at': row['expires_at'],
                        'days_until_expiry': cert_info.days_until_expiry,
                        'status': row['status'],
                        'thumbprint': cert_info.thumbprint,
                        'renewal_count': row['renewal_count'],
                        'revoked_at': revoked_at,
                        'revocation_reason': revocation_reason
                    })

            return jsonify({'certificates': certs}), 200

        except Exception as e:
            logger.error(f"Error listing certificates: {e}")
            return jsonify({'error': str(e)}), 500

    @bp.route('/ca/<ca_name>/certificates/<collector_id>', methods=['GET'])
    @auth_decorator
    def get_ca_certificate(ca_name, collector_id):
        """
        Get certificate details for a specific collector from a CA.

        URL params:
        - ca_name: CA identifier
        - collector_id: Collector identifier
        """
        try:
            cert_info = certificate_service.get_collector_certificate(collector_id)

            if not cert_info:
                return jsonify({'error': f'No certificate found for collector {collector_id}'}), 404

            return jsonify({
                'collector_id': collector_id,
                'serial_number': cert_info.serial_number,
                'subject': cert_info.subject,
                'issuer': cert_info.issuer,
                'issued_at': cert_info.issued_at,
                'expires_at': cert_info.expires_at,
                'days_until_expiry': cert_info.days_until_expiry,
                'status': cert_info.status,
                'thumbprint': cert_info.thumbprint,
                'pem': cert_info.pem
            }), 200

        except Exception as e:
            logger.error(f"Error getting certificate: {e}")
            return jsonify({'error': str(e)}), 500

    @bp.route('/ca/<ca_name>/certificates/<collector_id>', methods=['DELETE'])
    @auth_decorator
    def revoke_ca_certificate(ca_name, collector_id):
        """
        Revoke a collector certificate from a CA.

        URL params:
        - ca_name: CA identifier
        - collector_id: Collector identifier

        Body:
        {
            "reason": "Compromised key" (optional)
        }
        """
        try:
            data = request.get_json() or {}
            reason = data.get('reason', 'Revoked by administrator')

            success = certificate_service.revoke_collector_certificate(collector_id, reason)

            if success:
                logger.info(f"Certificate revoked for collector {collector_id}")
                return jsonify({'message': f'Certificate revoked for {collector_id}'}), 200
            else:
                return jsonify({'error': f'No active certificate found for {collector_id}'}), 404

        except Exception as e:
            logger.error(f"Error revoking certificate: {e}")
            return jsonify({'error': str(e)}), 500

    @bp.route('/ca/<ca_name>/certificates/<collector_id>/renew', methods=['POST'])
    @auth_decorator
    def force_certificate_renewal(ca_name, collector_id):
        """
        Admin-triggered certificate renewal.

        URL params:
        - ca_name: CA identifier
        - collector_id: Collector identifier

        Flags certificate for renewal; collector initiates actual renewal on next check.
        """
        try:
            conn = database_service.get_connection()
            conn.execute("""
                UPDATE collector_certificates
                SET status = 'renewing'
                WHERE collector_id = ? AND status = 'active'
            """, (collector_id,))
            conn.commit()
            conn.close()

            logger.info(f"Certificate renewal forced for collector {collector_id}")
            return jsonify({'message': f'Renewal forced for {collector_id}'}), 200

        except Exception as e:
            logger.error(f"Error forcing renewal: {e}")
            return jsonify({'error': str(e)}), 500

    @bp.route('/ca/dashboard/certificates/dashboard', methods=['GET'])
    @auth_decorator
    def get_dashboard_certificate():
        """Get dashboard TLS certificate information (from dashboard CA)."""
        try:
            cert_info = certificate_service.get_dashboard_certificate()

            return jsonify({
                'serial_number': cert_info.serial_number,
                'subject': cert_info.subject,
                'issuer': cert_info.issuer,
                'issued_at': cert_info.issued_at,
                'expires_at': cert_info.expires_at,
                'days_until_expiry': cert_info.days_until_expiry,
                'status': cert_info.status,
                'thumbprint': cert_info.thumbprint
            }), 200

        except Exception as e:
            logger.error(f"Error getting dashboard certificate: {e}")
            return jsonify({'error': str(e)}), 500

    @bp.route('/ca/<ca_name>/certificate', methods=['GET'])
    @auth_decorator
    def get_ca_certificate_info(ca_name):
        """
        Get CA certificate information.

        URL params:
        - ca_name: CA identifier (e.g., 'engagement-001', 'dashboard')
        """
        try:
            ca_pem = certificate_service.get_engagement_ca(ca_name)

            return jsonify({
                'ca_certificate': ca_pem
            }), 200

        except Exception as e:
            logger.error(f"Error getting engagement CA: {e}")
            return jsonify({'error': str(e)}), 500

    @bp.route('/ca/<ca_name>/crl', methods=['GET'])
    @auth_decorator
    def get_certificate_revocation_list(ca_name):
        """
        Get certificate revocation list for a CA.

        URL params:
        - ca_name: CA identifier (e.g., 'engagement-001')

        Returns:
            JSON array of revoked serial numbers
        """
        try:
            crl_json = certificate_service.get_certificate_revocation_list(ca_name)
            revoked_serials = json.loads(crl_json)

            return jsonify({
                'ca_name': ca_name,
                'revoked_serials': revoked_serials
            }), 200

        except Exception as e:
            logger.error(f"Error getting CRL: {e}")
            return jsonify({'error': str(e)}), 500

    @bp.route('/ca/<ca_name>/audit-log', methods=['GET'])
    @auth_decorator
    def get_certificate_audit_log(ca_name):
        """
        Get certificate audit log for a CA.

        URL params:
        - ca_name: CA identifier

        Query params:
        - event_type (optional): Filter by event (ISSUED, RENEWED, REVOKED, etc.)
        - collector_id (optional): Filter by collector
        - days (optional, default=30): Last N days

        Returns:
            JSON array of audit log entries
        """
        try:
            event_type = request.args.get('event_type')
            collector_id = request.args.get('collector_id')
            engagement_id = request.args.get('engagement_id')
            days = int(request.args.get('days', 30))

            conn = database_service.get_connection()
            query = "SELECT * FROM certificate_audit_log WHERE 1=1"
            params = []

            # Date filter
            query += f" AND datetime(timestamp) > datetime('now', '-{days} days')"

            if event_type:
                query += " AND event_type = ?"
                params.append(event_type)

            if collector_id:
                query += " AND collector_id = ?"
                params.append(collector_id)

            if engagement_id:
                query += " AND engagement_id = ?"
                params.append(engagement_id)

            query += " ORDER BY timestamp DESC"

            rows = conn.execute(query, params).fetchall()
            conn.close()

            events = []
            for row in rows:
                events.append({
                    'timestamp': row['timestamp'],
                    'event_type': row['event_type'],
                    'collector_id': row['collector_id'],
                    'engagement_id': row['engagement_id'],
                    'certificate_serial': row['certificate_serial'],
                    'admin_user_id': row['admin_user_id'],
                    'details': json.loads(row['details']) if row['details'] else {}
                })

            return jsonify({'audit_log': events}), 200

        except Exception as e:
            logger.error(f"Error getting audit log: {e}")
            return jsonify({'error': str(e)}), 500

    @bp.route('/ca/<ca_name>/statistics', methods=['GET'])
    @auth_decorator
    def get_certificate_statistics(ca_name):
        """
        Get certificate health statistics for a CA.

        URL params:
        - ca_name: CA identifier

        Returns:
            JSON object with certificate counts and alerts
        """
        try:
            conn = database_service.get_connection()

            # Total counts
            total = conn.execute(
                "SELECT COUNT(*) as count FROM collector_certificates"
            ).fetchone()['count']

            active = conn.execute(
                "SELECT COUNT(*) as count FROM collector_certificates WHERE status = 'active'"
            ).fetchone()['count']

            revoked = conn.execute(
                "SELECT COUNT(*) as count FROM collector_certificates WHERE status = 'revoked'"
            ).fetchone()['count']

            # Expiry alerts
            expiring_30 = conn.execute(
                """SELECT COUNT(*) as count FROM collector_certificates
                   WHERE status = 'active'
                   AND datetime(expires_at) < datetime('now', '+30 days')
                   AND datetime(expires_at) > datetime('now')"""
            ).fetchone()['count']

            expiring_7 = conn.execute(
                """SELECT COUNT(*) as count FROM collector_certificates
                   WHERE status = 'active'
                   AND datetime(expires_at) < datetime('now', '+7 days')
                   AND datetime(expires_at) > datetime('now')"""
            ).fetchone()['count']

            expired = conn.execute(
                "SELECT COUNT(*) as count FROM collector_certificates WHERE datetime(expires_at) < datetime('now')"
            ).fetchone()['count']

            conn.close()

            return jsonify({
                'total_certificates': total,
                'active': active,
                'revoked': revoked,
                'expired': expired,
                'expiring_30_days': expiring_30,
                'expiring_7_days': expiring_7,
                'health_status': 'good' if expiring_7 == 0 and revoked == 0 else (
                    'warning' if expiring_30 == 0 else 'alert'
                )
            }), 200

        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return jsonify({'error': str(e)}), 500

    # =========================================================================
    # REMOTE COLLECTOR ENDPOINTS (Requires bootstrap token or mTLS auth)
    # =========================================================================

    @bp.route('/remote/certificate/register', methods=['POST'])
    def register_collector():
        """
        Register new collector and issue initial certificate.

        Authentication: Bootstrap token in X-Bootstrap-Token header

        Body:
        {
            "collector_id": "collector-001",
            "engagement_id": "engagement-001",
            "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
            "collector_name": "Remote Office Scanner",
            "location": "New York, NY"
        }

        Returns:
        {
            "collector_id": "collector-001",
            "certificate": "-----BEGIN CERTIFICATE-----...",
            "ca_chain": "-----BEGIN CERTIFICATE-----...",
            "expires_at": "2025-01-20T...",
            "renewal_endpoint": "/api/v1/remote/certificate/renew"
        }
        """
        try:
            # Verify bootstrap token
            bootstrap_token = request.headers.get('X-Bootstrap-Token')
            if not bootstrap_token:
                return jsonify({'error': 'Missing X-Bootstrap-Token header'}), 401

            # Verify token is valid (check against remote_collector_tokens)
            import hashlib
            from datetime import datetime
            token_hash = hashlib.sha256(bootstrap_token.encode()).hexdigest()
            conn = database_service.get_connection()
            token_row = conn.execute(
                "SELECT * FROM remote_collector_tokens WHERE token_hash = ? AND status = 'active' AND expires_at > ?",
                (token_hash, datetime.now().isoformat())
            ).fetchone()
            conn.close()

            if not token_row:
                logger.warning(f"Invalid bootstrap token used for registration")
                return jsonify({'error': 'Invalid or expired bootstrap token'}), 401

            # Convert Row to dict for easier access with .get()
            token_row = dict(token_row)

            # Parse request
            data = request.get_json()
            engagement_code = data.get('engagement_id')  # Could be engagement code like 'ENG-2025-005'
            csr_pem = data.get('csr')

            if not all([engagement_code, csr_pem]):
                return jsonify({'error': 'Missing required fields: engagement_id, csr'}), 400

            # Use the collector_name from the token as the collector_id
            # This ensures each token is tied to a specific collector and prevents hijacking
            collector_id = token_row['collector_name']
            logger.info(f"Using collector_name from token as collector_id: {collector_id}")

            # SECURITY FIX 2: Validate engagement matches the token's engagement_ca_id (if specified)
            # This implements Option A: Token specifies which engagement the collector joins
            try:
                token_engagement_ca_id = token_row['engagement_ca_id'] if token_row['engagement_ca_id'] else None
            except (KeyError, IndexError):
                # engagement_ca_id column doesn't exist in older tokens table schema
                token_engagement_ca_id = None

            if token_engagement_ca_id:
                # Token specifies engagement - resolve TEXT engagement_id to INTEGER database ID
                if engagement_code and str(engagement_code) != str(token_engagement_ca_id):
                    logger.warning(
                        f"SECURITY VIOLATION: Token bound to engagement '{token_engagement_ca_id}' "
                        f"but collector requested '{engagement_code}'. "
                        f"Source IP: {request.remote_addr}"
                    )
                    return jsonify({'error': 'Engagement mismatch with bootstrap token'}), 403

                # Resolve token's engagement_ca_id (may be TEXT or INTEGER) to database INTEGER ID
                conn = database_service.get_connection()
                logger.info(f"Resolving token engagement_ca_id '{token_engagement_ca_id}' to database ID")
                eng_row = conn.execute(
                    "SELECT id FROM engagements WHERE engagement_id = ? OR id = ?",
                    (str(token_engagement_ca_id), str(token_engagement_ca_id))
                ).fetchone()
                conn.close()

                if not eng_row:
                    logger.warning(f"Token specifies engagement '{token_engagement_ca_id}' which does not exist")
                    return jsonify({'error': f'Engagement {token_engagement_ca_id} does not exist'}), 404

                try:
                    engagement_id = str(eng_row['id'])
                except (IndexError, KeyError, TypeError):
                    engagement_id = str(eng_row[0])

                logger.info(f"Resolved token engagement '{token_engagement_ca_id}' to database ID {engagement_id}")
            else:
                # Token doesn't specify engagement - use collector-provided value
                conn = database_service.get_connection()
                eng_row = conn.execute(
                    "SELECT id FROM engagements WHERE engagement_id = ? OR id = ?",
                    (engagement_code, engagement_code)
                ).fetchone()
                conn.close()

                if not eng_row:
                    logger.warning(f"Engagement {engagement_code} not found")
                    return jsonify({'error': f'Engagement {engagement_code} not found'}), 404

                try:
                    engagement_id = str(eng_row['id'])
                except (IndexError, KeyError, TypeError):
                    engagement_id = str(eng_row[0])

                logger.info(f"Resolved engagement code '{engagement_code}' to database ID {engagement_id}")

            # Always issue a new certificate during registration
            # This ensures the certificate matches the CSR's key pair
            # (Reusing old certs would cause key mismatch since collector generated new keys)
            logger.info(f"Issuing new certificate for collector {collector_id} during registration")

            # Issue new certificate and get CA chain (Internal CA + Engagement CA)
            cert_pem, engagement_ca = certificate_service.issue_collector_certificate(
                collector_id, engagement_id, csr_pem
            )
            ca_chain = certificate_service.get_ca_chain_for_collector(engagement_id)

            # Get expiry info
            conn = database_service.get_connection()
            cert_row = conn.execute(
                "SELECT expires_at FROM collector_certificates WHERE collector_id = ? AND status = 'active'",
                (collector_id,)
            ).fetchone()
            conn.close()
            expires_at = cert_row['expires_at'] if cert_row else None

            # SECURITY FIX 3: Track and enforce token use count
            # Validates token hasn't exceeded max_uses and increments counter
            conn = database_service.get_connection()
            try:
                # Re-fetch token to get current_uses (may have changed since initial validation)
                token_check = conn.execute(
                    "SELECT current_uses, max_uses FROM remote_collector_tokens WHERE token_hash = ?",
                    (token_hash,)
                ).fetchone()

                if not token_check:
                    logger.error(f"Token disappeared during registration: {token_row['token_prefix']}...")
                    return jsonify({'error': 'Token validation failed'}), 500

                # Check if token has exceeded max uses
                if token_check['current_uses'] >= token_check['max_uses']:
                    logger.warning(
                        f"Token {token_row['token_prefix']}... exceeded max uses "
                        f"({token_check['current_uses']} >= {token_check['max_uses']})"
                    )
                    return jsonify({'error': 'Bootstrap token has exceeded maximum uses'}), 403

                # Increment use count
                new_use_count = token_check['current_uses'] + 1
                conn.execute(
                    "UPDATE remote_collector_tokens SET current_uses = ? WHERE token_hash = ?",
                    (new_use_count, token_hash)
                )

                # If this was the last allowed use, mark token as 'used'
                if new_use_count >= token_check['max_uses']:
                    conn.execute(
                        "UPDATE remote_collector_tokens SET status = 'used' WHERE token_hash = ?",
                        (token_hash,)
                    )
                    logger.info(
                        f"Token {token_row['token_prefix']}... marked as 'used' (reached max_uses={token_check['max_uses']})"
                    )

                conn.commit()
                logger.info(
                    f"Token use count incremented: {token_row['token_prefix']}... "
                    f"({token_check['current_uses']} -> {new_use_count})"
                )
            finally:
                conn.close()

            # Create/update remote_collectors entry (do this regardless of certificate status)
            conn = database_service.get_connection()
            try:
                # Check if collector already exists in remote_collectors
                existing_collector = conn.execute(
                    "SELECT id FROM remote_collectors WHERE collector_id = ?",
                    (collector_id,)
                ).fetchone()

                # Use token values for collector metadata (token always has these from generation)
                collector_name = token_row.get('collector_name') or collector_id
                location = token_row.get('location') or data.get('location') or 'Unknown'
                organization = token_row.get('organization') or data.get('organization') or 'Default'

                if existing_collector:
                    # Update existing entry
                    conn.execute(
                        """UPDATE remote_collectors
                           SET status = 'active', updated_at = ?
                           WHERE collector_id = ?""",
                        (datetime.now().isoformat(), collector_id)
                    )
                else:
                    # Create new entry - use the bootstrap token as the API key
                    import hashlib
                    # Use the bootstrap token as the ongoing API key (no need for separate API key generation)
                    api_key_hash = hashlib.sha256(bootstrap_token.encode()).hexdigest()

                    conn.execute(
                        """INSERT INTO remote_collectors
                           (collector_id, collector_name, organization, location, status,
                            registered_at, registered_by_token, updated_at, api_key_prefix, api_key_hash)
                           VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)""",
                        (
                            collector_id,
                            collector_name,
                            organization,
                            location,
                            datetime.now().isoformat(),
                            token_row['token_prefix'],
                            datetime.now().isoformat(),
                            token_row['token_prefix'],  # Use bootstrap token prefix as API key prefix
                            api_key_hash  # Hash of the full bootstrap token
                        )
                    )

                conn.commit()
            finally:
                conn.close()

            # Return only Engagement CA - collector will trust it for both client cert validation
            # and server cert validation (port 5444 presents a cert signed by the same Engagement CA)
            logger.info(f"Sending Engagement CA chain to collector {collector_id}")

            return jsonify({
                'collector_id': collector_id,
                'collector_name': collector_name,
                'organization': organization,
                'location': location,
                'environment': token_row.get('environment', 'production'),
                'engagement_id': engagement_id,
                'certificate': cert_pem,
                'ca_chain': ca_chain,
                'expires_at': expires_at,
                'renewal_endpoint': '/api/v1/remote/certificate/renew',
                'api_key': bootstrap_token
            }), 200

        except ValueError as e:
            logger.error(f"Registration validation error: {e}")
            return jsonify({'error': str(e)}), 400

        except Exception as e:
            logger.error(f"Error registering collector: {e}")
            return jsonify({'error': 'Registration failed'}), 500

    @bp.route('/remote/certificate/renew', methods=['POST'])
    def renew_collector_certificate_endpoint():
        """
        Renew collector certificate with new CSR.

        Authentication: mTLS (existing collector certificate)

        Body:
        {
            "collector_id": "collector-001",
            "csr": "-----BEGIN CERTIFICATE REQUEST-----..."
        }

        Returns:
        {
            "collector_id": "collector-001",
            "certificate": "-----BEGIN CERTIFICATE-----...",
            "ca_chain": "-----BEGIN CERTIFICATE-----...",
            "expires_at": "2025-01-20T...",
            "grace_period_until": "2025-01-17T...",
            "renewal_count": 2
        }
        """
        try:
            # Parse request to get collector_id
            data = request.get_json()
            collector_id = data.get('collector_id')
            csr_pem = data.get('csr')

            if not all([collector_id, csr_pem]):
                return jsonify({'error': 'Missing required fields: collector_id, csr'}), 400

            # Verify mTLS client certificate
            # (In production, Flask would populate request.environ['SSL_CLIENT_CERT'])
            client_cert = request.environ.get('SSL_CLIENT_CERT')
            if not client_cert:
                return jsonify({'error': 'mTLS certificate required'}), 401

            # Verify certificate is valid for this collector
            cert_info = certificate_service.get_collector_certificate(collector_id)
            if not cert_info:
                return jsonify({'error': f'No certificate found for collector {collector_id}'}), 404

            if cert_info.status == 'revoked':
                return jsonify({'error': 'Certificate has been revoked'}), 403

            # Validate CSR
            if not certificate_service.validate_csr(csr_pem, collector_id):
                return jsonify({'error': 'Invalid CSR or CN mismatch'}), 400

            # Renew certificate
            new_cert_pem, ca_chain = certificate_service.renew_collector_certificate(
                collector_id, csr_pem
            )

            # Get new and old expiry times
            conn = database_service.get_connection()
            new_cert = conn.execute(
                "SELECT expires_at FROM collector_certificates WHERE collector_id = ? AND status = 'active'",
                (collector_id,)
            ).fetchone()

            old_cert = conn.execute(
                "SELECT previous_expires_at FROM collector_certificates WHERE collector_id = ? AND status = 'active'",
                (collector_id,)
            ).fetchone()

            renewal_count = conn.execute(
                "SELECT renewal_count FROM collector_certificates WHERE collector_id = ? AND status = 'active'",
                (collector_id,)
            ).fetchone()
            conn.close()

            return jsonify({
                'collector_id': collector_id,
                'certificate': new_cert_pem,
                'ca_chain': ca_chain,
                'expires_at': new_cert['expires_at'] if new_cert else None,
                'grace_period_until': old_cert['previous_expires_at'] if old_cert else None,
                'renewal_count': renewal_count['renewal_count'] if renewal_count else 0
            }), 200

        except ValueError as e:
            logger.error(f"Renewal validation error: {e}")
            return jsonify({'error': str(e)}), 400

        except Exception as e:
            logger.error(f"Error renewing certificate: {e}")
            return jsonify({'error': 'Renewal failed'}), 500

    @bp.route('/remote/certificate/status', methods=['GET'])
    def get_collector_certificate_status():
        """
        Get certificate status for a collector.
        Can be called by collector without mTLS for status checks.

        Query params:
        - collector_id: Collector identifier

        Returns:
        {
            "collector_id": "collector-001",
            "status": "active",
            "serial_number": "...",
            "expires_at": "...",
            "days_until_expiry": 25,
            "needs_renewal": false
        }
        """
        try:
            collector_id = request.args.get('collector_id')

            if not collector_id:
                return jsonify({'error': 'Missing collector_id query parameter'}), 400

            cert_info = certificate_service.get_collector_certificate(collector_id)

            if not cert_info:
                return jsonify({
                    'collector_id': collector_id,
                    'status': 'no_certificate',
                    'message': 'No certificate found. Register first.'
                }), 404

            return jsonify({
                'collector_id': collector_id,
                'status': cert_info.status,
                'serial_number': cert_info.serial_number,
                'expires_at': cert_info.expires_at,
                'days_until_expiry': cert_info.days_until_expiry,
                'needs_renewal': cert_info.days_until_expiry <= 7
            }), 200

        except Exception as e:
            logger.error(f"Error getting certificate status: {e}")
            return jsonify({'error': str(e)}), 500

    # =========================================================================
    # ENGAGEMENT CA MANAGEMENT ENDPOINTS
    # =========================================================================

    @bp.route('/ca/list', methods=['GET'])
    @auth_decorator
    def list_engagement_cas():
        """
        List all engagement CAs (created for collectors).

        Returns:
            JSON array of engagement CA objects with details
        """
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            conn = database_service.get_connection_context()
            with conn as connection:
                c = connection.cursor()
                # Query engagement_ca_certificates table and join with engagements for names
                c.execute('''
                    SELECT
                        ecc.id, ecc.engagement_id, e.customer_name, e.project_name,
                        ecc.subject, ecc.certificate_serial, ecc.certificate_pem,
                        ecc.issued_at, ecc.expires_at, ecc.status, ecc.rotation_count, ecc.issuer
                    FROM engagement_ca_certificates ecc
                    LEFT JOIN engagements e ON ecc.engagement_id = e.engagement_id
                    WHERE ecc.status IN ('active', 'rotating')
                    ORDER BY ecc.created_at DESC
                ''')
                rows = c.fetchall()

                cas = []
                for row in rows:
                    ca_dict = database_service.dict_from_row(row)

                    # Parse certificate to get algorithm and issuer details
                    algorithm = "Unknown"
                    key_size = "Unknown"
                    signed_by = ca_dict.get('issuer', 'Self-Signed')

                    try:
                        cert_pem = ca_dict.get('certificate_pem')
                        if cert_pem:
                            cert = x509.load_pem_x509_certificate(
                                cert_pem.encode(), default_backend()
                            )

                            # Get algorithm
                            key = cert.public_key()
                            key_type_name = type(key).__name__
                            if 'RSA' in key_type_name:
                                algorithm = "RSA"
                                key_size = str(key.key_size)
                            elif 'EllipticCurve' in key_type_name:
                                algorithm = "EC"
                                curve_name = key.curve.name
                                key_size = f"{curve_name}"

                            # Get issuer info
                            issuer = cert.issuer
                            issuer_cn = None
                            for attr in issuer:
                                if attr.oid._name == 'commonName':
                                    issuer_cn = attr.value
                                    break

                            if issuer_cn and issuer_cn != ca_dict['subject']:
                                signed_by = issuer_cn
                    except Exception as e:
                        logger.debug(f"Could not parse cert details: {e}")

                    cas.append({
                        'id': ca_dict['id'],
                        'engagement_id': ca_dict['engagement_id'],  # Now this is the text ID
                        'customer_name': ca_dict.get('customer_name'),
                        'project_name': ca_dict.get('project_name'),
                        'subject': ca_dict['subject'],
                        'serial_number': ca_dict['certificate_serial'],
                        'issued_at': ca_dict['issued_at'],
                        'expires_at': ca_dict['expires_at'],
                        'status': ca_dict['status'],
                        'rotation_count': ca_dict['rotation_count'],
                        'algorithm': algorithm,
                        'key_size': key_size,
                        'signed_by': signed_by
                    })

                return jsonify({'cas': cas}), 200

        except Exception as e:
            logger.error(f"Error listing engagement CAs: {e}")
            return jsonify({'error': str(e)}), 500

    @bp.route('/ca/create', methods=['POST'])
    @auth_decorator
    def create_engagement_ca():
        """
        Create a new engagement CA for issuing collector certificates.

        Request body:
        {
            "engagement_id": "ENG-2024-001",
            "cn": "ENG-2024-001 Collectors",
            "ou": "PKI Infrastructure",
            "o": "Customer Name",
            "c": "UK",
            "lifetime_days": 365
        }

        Returns:
            JSON object with created CA details
        """
        try:
            data = request.json
            if not data:
                return jsonify({'error': 'Request body required'}), 400

            engagement_id = data.get('engagement_id')
            if not engagement_id:
                return jsonify({'error': 'engagement_id required'}), 400

            # Get engagement details for customer/project name
            from caip_engagement_functions.engagement_service import EngagementService
            engagement = EngagementService.get_engagement(database_service, engagement_id)
            if not engagement:
                return jsonify({'error': f'Engagement {engagement_id} not found'}), 404

            # Get the database ID for the foreign key
            engagement_db_id = engagement.get('id')

            # Use DN fields from form (with defaults)
            # CN is fully editable by the admin
            cn = data.get('cn', f"CAIP-CA-{engagement_db_id}")
            # OU contains engagement ID for consistency with collector certificate pattern
            ou = data.get('organizational_unit', f'engagement-{engagement_db_id}')
            o = data.get('organization', 'CAIP')
            c = data.get('country', 'UK')
            lifetime_days = int(data.get('lifetime_days', 1825))

            # Use certificate service to create the CA with provided DN fields
            # This ensures dashboard cert generation and CA chain export are triggered
            ca_pem = certificate_service.create_engagement_ca(
                str(engagement_db_id),
                cn=cn,
                ou=ou,
                o=o,
                c=c,
                lifetime_days=lifetime_days
            )

            # Get CA details from database for response - use text engagement_id from engagement object
            text_engagement_id = engagement.get('engagement_id', engagement_id)
            from datetime import datetime
            conn = database_service.get_connection_context()
            with conn as connection:
                c = connection.cursor()
                c.execute('''
                    SELECT id, subject, certificate_serial, issued_at, expires_at
                    FROM engagement_ca_certificates
                    WHERE engagement_id = ? AND status = 'active'
                    ORDER BY issued_at DESC LIMIT 1
                ''', (text_engagement_id,))
                ca_row = c.fetchone()

            if not ca_row:
                return jsonify({'error': 'Failed to retrieve created CA'}), 500

            ca_id = ca_row[0]
            subject = ca_row[1]
            serial_number = ca_row[2]
            issued_at = ca_row[3]
            expires_at = ca_row[4]

            logger.info(f"Created engagement CA for {engagement_id} using certificate service")

            return jsonify({
                'id': ca_id,
                'engagement_id': engagement_id,
                'customer_name': engagement.get('customer_name'),
                'project_name': engagement.get('project_name'),
                'subject': subject,
                'serial_number': serial_number,
                'issued_at': issued_at,
                'expires_at': expires_at,
                'status': 'active',
                'message': f'Engagement CA created for {engagement_id}'
            }), 201

        except Exception as e:
            logger.error(f"Error creating engagement CA: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @bp.route('/ca/<engagement_id>/issued-certificates', methods=['GET'])
    @auth_decorator
    def list_issued_certificates(engagement_id):
        """
        List all certificates (collector + dashboard) issued by a specific engagement CA.

        Args:
            engagement_id: Engagement identifier (e.g., 'ENG-2024-001')

        Returns:
            List of all certificates with details, grouped by type
        """
        try:
            conn = database_service.get_connection_context()
            with conn as connection:
                c = connection.cursor()

                # Get engagement database ID
                c.execute('SELECT id FROM engagements WHERE engagement_id = ?', (engagement_id,))
                engagement = c.fetchone()
                if not engagement:
                    return jsonify({'error': f'Engagement {engagement_id} not found'}), 404

                engagement_db_id = engagement[0]

                certificates = {
                    'dashboard_certificates': [],
                    'collector_certificates': []
                }

                # Get dashboard certificates for this engagement
                c.execute('''
                    SELECT
                        id, certificate_pem, serial_number,
                        subject, issued_at, expires_at, status
                    FROM engagement_dashboard_certificates
                    WHERE engagement_id = ?
                    ORDER BY issued_at DESC
                ''', (engagement_db_id,))

                for row in c.fetchall():
                    cert_id, cert_pem, serial_num, subject, issued_at, expires_at, status = row

                    # Parse certificate to get additional info
                    try:
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        cert_obj = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                        days_until_expiry = (cert_obj.not_valid_after - datetime.utcnow()).days
                    except:
                        days_until_expiry = None

                    certificates['dashboard_certificates'].append({
                        'id': cert_id,
                        'type': 'dashboard',
                        'serial_number': serial_num,
                        'subject': subject,
                        'issued_at': issued_at,
                        'expires_at': expires_at,
                        'days_until_expiry': days_until_expiry,
                        'status': status,
                        'certificate_pem': cert_pem
                    })

                # Get all collector certificates for this engagement CA
                c.execute('''
                    SELECT
                        id, collector_id, certificate_pem, serial_number,
                        subject, issued_at, expires_at, status, revoked_at
                    FROM collector_certificates
                    WHERE engagement_id = ?
                    ORDER BY issued_at DESC
                ''', (engagement_db_id,))

                for row in c.fetchall():
                    cert_id, collector_id, cert_pem, serial_num, subject, issued_at, expires_at, status, revoked_at = row

                    # Parse certificate to get additional info
                    try:
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        cert_obj = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                        days_until_expiry = (cert_obj.not_valid_after - datetime.utcnow()).days
                    except:
                        days_until_expiry = None

                    certificates['collector_certificates'].append({
                        'id': cert_id,
                        'type': 'collector',
                        'collector_id': collector_id,
                        'serial_number': serial_num,
                        'subject': subject,
                        'issued_at': issued_at,
                        'expires_at': expires_at,
                        'days_until_expiry': days_until_expiry,
                        'status': status,
                        'revoked_at': revoked_at,
                        'certificate_pem': cert_pem
                    })

                return jsonify(certificates), 200

        except Exception as e:
            logger.error(f"Error listing issued certificates for {engagement_id}: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @bp.route('/ca/<engagement_id>/decommission', methods=['DELETE'])
    @auth_decorator
    def decommission_engagement_ca(engagement_id):
        """
        Decommission an Engagement CA and all associated data.

        This performs a complete cleanup:
        - Marks CA as 'decommissioned'
        - Revokes all active collector certificates
        - Retires all active dashboard certificates
        - Marks all collectors as inactive
        - Logs audit event

        Args:
            engagement_id: Engagement identifier (e.g., 'ENG-2024-001')

        Returns:
            JSON response with decommission confirmation
        """
        try:
            conn = database_service.get_connection()

            # Resolve text engagement ID (e.g., 'ENG-2025-004') to database ID (e.g., 4)
            engagement_db_id = engagement_id
            text_engagement_id = engagement_id
            try:
                # First try to interpret as numeric ID
                engagement_db_id = int(engagement_id)
                # If numeric, look up text ID
                eng_row = conn.execute(
                    "SELECT engagement_id FROM engagements WHERE id = ?",
                    (engagement_db_id,)
                ).fetchone()
                if eng_row:
                    text_engagement_id = eng_row['engagement_id'] if isinstance(eng_row, dict) else eng_row[0]
            except (ValueError, TypeError):
                # If not numeric, look up both numeric and text IDs
                eng_row = conn.execute(
                    "SELECT id, engagement_id FROM engagements WHERE engagement_id = ?",
                    (engagement_id,)
                ).fetchone()
                if eng_row:
                    engagement_db_id = eng_row['id'] if isinstance(eng_row, dict) else eng_row[0]
                    text_engagement_id = eng_row['engagement_id'] if isinstance(eng_row, dict) else eng_row[1]

            # Get engagement CA from engagement_ca_certificates
            ca_row = conn.execute(
                "SELECT id, status FROM engagement_ca_certificates WHERE engagement_id = ?",
                (text_engagement_id,)
            ).fetchone()

            if not ca_row:
                return jsonify({'error': 'CA not found'}), 404

            ca_id = ca_row['id'] if isinstance(ca_row, dict) else ca_row[0]
            ca_status = ca_row['status'] if isinstance(ca_row, dict) else ca_row[1]

            if ca_status == 'decommissioned':
                return jsonify({'error': 'CA already decommissioned'}), 400

            # 1. Mark CA as decommissioned in engagement_ca_certificates
            conn.execute(
                "UPDATE engagement_ca_certificates SET status = 'decommissioned', updated_at = ? WHERE engagement_id = ?",
                (datetime.now().isoformat(), text_engagement_id)
            )

            # 2. Revoke all active collector certificates
            conn.execute(
                """UPDATE collector_certificates
                   SET status = 'revoked', revoked_at = ?, revocation_reason = 'CA decommissioned'
                   WHERE engagement_id = ? AND status = 'active'""",
                (datetime.now().isoformat(), engagement_db_id)
            )

            # Count revoked certificates
            revoked_count = conn.execute(
                "SELECT COUNT(*) as count FROM collector_certificates WHERE engagement_id = ? AND status = 'revoked'",
                (engagement_db_id,)
            ).fetchone()
            revoked_cert_count = revoked_count['count'] if isinstance(revoked_count, dict) else revoked_count[0]

            # 3. Retire all active dashboard certificates
            conn.execute(
                """UPDATE engagement_dashboard_certificates
                   SET status = 'retired', updated_at = ?
                   WHERE engagement_id = ? AND status = 'active'""",
                (datetime.now().isoformat(), engagement_db_id)
            )

            # 4. Delete engagement registration tokens (no longer valid after decommission)
            conn.execute(
                """DELETE FROM remote_collector_tokens
                   WHERE engagement_ca_id = ?""",
                (engagement_db_id,)
            )

            # 5. Delete collector certificate records (since CA is decommissioned, certs are invalid)
            conn.execute(
                """DELETE FROM collector_certificates
                   WHERE engagement_id = ?""",
                (engagement_db_id,)
            )

            conn.commit()

            # After decommissioning CA, regenerate ca-chain.pem for port 5444
            # This removes the decommissioned CA from the chain used for collector validation
            try:
                certificate_service.export_ca_chain_to_file()
                logger.info(f"Regenerated CA chain after decommissioning engagement {engagement_id}")
            except Exception as e:
                logger.error(f"Failed to regenerate CA chain after decommission: {e}")
                # Don't fail the decommission operation if chain export fails

            # Log audit event
            logger.info(
                f"Decommissioned CA for engagement {engagement_id}: "
                f"revoked {revoked_cert_count} collector certificates"
            )

            return jsonify({
                'success': True,
                'engagement_id': engagement_id,
                'revoked_certificates': revoked_cert_count,
                'message': f'CA decommissioned. {revoked_cert_count} collector certificates revoked.'
            }), 200

        except Exception as e:
            logger.error(f"Error decommissioning CA {engagement_id}: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500
        finally:
            conn.close()

    @bp.route('/collector/certificates/<cert_id>/revoke', methods=['POST'])
    @auth_decorator
    def revoke_collector_certificate(cert_id):
        """
        Revoke a collector certificate.

        Args:
            cert_id: Certificate ID to revoke

        Returns:
            JSON response with revocation confirmation
        """
        try:
            conn = database_service.get_connection()

            # Get certificate details
            cert_row = conn.execute(
                "SELECT id, collector_id, engagement_id, status FROM collector_certificates WHERE id = ?",
                (cert_id,)
            ).fetchone()

            if not cert_row:
                return jsonify({'error': 'Certificate not found'}), 404

            cert_status = cert_row['status'] if isinstance(cert_row, dict) else cert_row[3]
            collector_id = cert_row['collector_id'] if isinstance(cert_row, dict) else cert_row[1]

            if cert_status == 'revoked':
                return jsonify({'error': 'Certificate already revoked'}), 400

            # Mark certificate as revoked
            conn.execute(
                """UPDATE collector_certificates
                   SET status = 'revoked', revoked_at = ?, revocation_reason = 'Manual revocation'
                   WHERE id = ?""",
                (datetime.now().isoformat(), cert_id)
            )

            conn.commit()

            logger.info(f"Revoked collector certificate {cert_id} for collector {collector_id}")

            return jsonify({
                'success': True,
                'cert_id': cert_id,
                'collector_id': collector_id,
                'message': f'Certificate for collector {collector_id} has been revoked'
            }), 200

        except Exception as e:
            logger.error(f"Error revoking certificate {cert_id}: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500
        finally:
            conn.close()

    # =========================================================================
    # USER IDENTITY CERTIFICATE ENDPOINTS (Phase 2)
    # =========================================================================

    @bp.route('/users/<int:user_id>/certificates', methods=['POST'])
    @auth_decorator
    def issue_or_rotate_user_certificate(user_id):
        """
        Issue or rotate a user's identity certificate.

        Request JSON:
        {
            "action": "issue" | "rotate",
            "engagement_id": "ENG-2026-001"  (optional)
        }

        Returns certificate info and P12 download details.
        """
        try:
            data = request.json or {}
            action = data.get('action', 'issue')
            engagement_id = data.get('engagement_id')

            if action not in ['issue', 'rotate']:
                return jsonify({'error': 'Invalid action. Must be "issue" or "rotate"'}), 400

            if action == 'issue':
                cert_result = certificate_service.issue_user_identity_certificate(
                    user_id=user_id,
                    username=None,  # Will be fetched from database
                    role='user',
                    issuing_ca_engagement_id=engagement_id
                )
            else:  # rotate
                cert_result = certificate_service.rotate_user_identity_certificate(
                    user_id=user_id,
                    issuing_ca_engagement_id=engagement_id
                )

            # Export to P12 for immediate download
            import secrets
            p12_password = secrets.token_urlsafe(12)
            p12_result = certificate_service.export_user_certificate_to_p12(
                user_id=user_id,
                p12_password=p12_password
            )

            logger.info(f"{action.capitalize()}ed certificate {cert_result['certificate_serial']} for user {user_id}")

            return jsonify({
                'certificate': {
                    'certificate_serial': cert_result['certificate_serial'],
                    'issuing_ca': cert_result['issuing_ca'],
                    'issued_at': cert_result.get('issued_at'),
                    'expires_at': cert_result.get('expires_at')
                },
                'p12_download': {
                    'download_url': p12_result['download_url'],
                    'download_token': p12_result['download_token'],
                    'p12_password': p12_result['p12_password'],
                    'expires_at': p12_result['expires_at']
                }
            }), 201

        except ValueError as e:
            logger.warning(f"Invalid request for user {user_id}: {e}")
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            logger.error(f"Error issuing/rotating certificate for user {user_id}: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @bp.route('/users/<int:user_id>/certificates/status', methods=['GET'])
    @auth_decorator
    def get_user_cert_status(user_id):
        """
        Get certificate status for a user.

        Returns current certificate status, serial, expiry, and download information.
        """
        try:
            status = certificate_service.get_user_certificate_status(user_id)

            return jsonify({
                'certificate_status': status
            }), 200

        except Exception as e:
            logger.error(f"Error getting certificate status for user {user_id}: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @bp.route('/users/<int:user_id>/certificates/revoke', methods=['POST'])
    @auth_decorator
    @permission_decorator('users:update')
    def revoke_user_certificate(user_id):
        """
        Revoke a user's identity certificate.

        Request JSON (optional):
        {
            "reason": "User requested revocation"  (optional, default provided)
        }

        Returns:
            {
                "revoked_serial": "ABC123...",
                "revoked_at": "2026-03-01T21:35:00+00:00",
                "previous_status": "active",
                "reason": "User requested revocation"
            }
        """
        try:
            data = request.json or {}
            reason = data.get('reason', 'User requested revocation')

            result = certificate_service.revoke_user_certificate(
                user_id=user_id,
                reason=reason
            )

            logger.info(f"Revoked certificate for user {user_id}: {result['revoked_serial']}")

            return jsonify({
                'certificate_revocation': result
            }), 200

        except Exception as e:
            logger.error(f"Error revoking certificate for user {user_id}: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @bp.route('/users/<int:user_id>/certificates/download-info/<download_token>', methods=['GET'])
    def get_p12_download_info(user_id, download_token):
        """
        Get P12 download info and password (within 24 hours).

        This endpoint does NOT require authentication (uses secure token instead).
        Returns password and download link if token is still valid (within 24 hours).
        Token expires after 24 hours and password is cleared from database.

        Returns:
            {
                "download_url": "/api/v1/users/{user_id}/certificates/download/{token}",
                "p12_password": "secure_password",
                "expires_at": "2026-03-02T21:35:00+00:00",
                "hours_remaining": 24,
                "file_exists": true
            }
        """
        try:
            p12_info = certificate_service.get_p12_download_info(user_id, download_token)

            if not p12_info:
                logger.warning(f"P12 download info not found or expired for user {user_id}")
                return jsonify({'error': 'Invalid, expired, or deleted download token'}), 404

            logger.info(f"Retrieved P12 download info for user {user_id}")
            return jsonify(p12_info), 200

        except Exception as e:
            logger.error(f"Error getting P12 download info for user {user_id}: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @bp.route('/users/<int:user_id>/certificates/download/<download_token>', methods=['GET'])
    def download_user_certificate(user_id, download_token):
        """
        Download user certificate in P12 format.

        This endpoint does NOT require authentication (uses secure token instead).
        Token expires after 24 hours.

        Returns PKCS#12 file with encrypted private key.
        """
        try:
            import os
            import tempfile
            from datetime import datetime, timezone

            conn = database_service.get_connection()
            try:
                # Get download record by token
                download_row = conn.execute("""
                    SELECT p12_file_path, p12_password, expires_at
                    FROM temp_p12_downloads
                    WHERE user_id = ? AND download_token = ? AND status IN ('pending', 'downloaded')
                """, (user_id, download_token)).fetchone()

                if not download_row:
                    logger.warning(f"Invalid download token for user {user_id}")
                    return jsonify({'error': 'Invalid or expired download token'}), 404

                # Check expiry
                expires_at = datetime.fromisoformat(download_row['expires_at'].replace('Z', '+00:00'))
                if expires_at < datetime.now(timezone.utc):
                    logger.warning(f"Download token expired for user {user_id}")
                    return jsonify({'error': 'Download token has expired'}), 410

                file_path = download_row['p12_file_path']

                # Verify file exists
                if not os.path.exists(file_path):
                    logger.error(f"P12 file not found: {file_path}")
                    return jsonify({'error': 'P12 file not found'}), 500

                # Mark as downloaded
                conn.execute(
                    "UPDATE temp_p12_downloads SET status = 'downloaded', downloaded_at = ? WHERE download_token = ?",
                    (datetime.now(timezone.utc).isoformat(), download_token)
                )
                conn.commit()

                logger.info(f"Downloaded P12 certificate for user {user_id}")

                # Return file
                from flask import send_file
                return send_file(
                    file_path,
                    mimetype='application/x-pkcs12',
                    as_attachment=True,
                    download_name=f'user_{user_id}_certificate.p12'
                )

            finally:
                conn.close()

        except Exception as e:
            logger.error(f"Error downloading certificate for user {user_id}: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @bp.route('/users/certificates/bulk-issue', methods=['POST'])
    @auth_decorator
    def bulk_issue_user_certificates():
        """
        Retroactively issue certificates to all users without active certificates.

        Request JSON:
        {
            "engagement_id": "ENG-2026-001"  (optional)
        }

        Returns results with success/failure per user.
        """
        try:
            data = request.json or {}
            engagement_id = data.get('engagement_id')

            conn = database_service.get_connection()
            try:
                # Find users without active certificates
                users_without_certs = conn.execute("""
                    SELECT DISTINCT u.id, u.username, u.role
                    FROM users u
                    LEFT JOIN user_digital_identities udi ON u.id = udi.user_id AND udi.status = 'active'
                    WHERE udi.user_id IS NULL
                """).fetchall()

                issued = []
                failed_count = 0

                for user_row in users_without_certs:
                    user_id = user_row['id']
                    username = user_row['username']
                    role = user_row['role']

                    try:
                        cert_result = certificate_service.issue_user_identity_certificate(
                            user_id=user_id,
                            username=username,
                            role=role,
                            issuing_ca_engagement_id=engagement_id
                        )

                        # Export to P12
                        import secrets
                        p12_password = secrets.token_urlsafe(12)
                        p12_result = certificate_service.export_user_certificate_to_p12(
                            user_id=user_id,
                            p12_password=p12_password
                        )

                        issued.append({
                            'user_id': user_id,
                            'username': username,
                            'success': True,
                            'serial': cert_result['certificate_serial'],
                            'issuing_ca': cert_result['issuing_ca'],
                            'p12_download_url': p12_result['download_url'],
                            'p12_download_token': p12_result['download_token'],
                            'p12_password': p12_result['p12_password']
                        })

                    except Exception as e:
                        logger.error(f"Failed to issue certificate for user {user_id} ({username}): {e}")
                        issued.append({
                            'user_id': user_id,
                            'username': username,
                            'success': False,
                            'error': str(e)
                        })
                        failed_count += 1

                logger.info(f"Bulk issued certificates to {len(users_without_certs) - failed_count}/{len(users_without_certs)} users")

                return jsonify({
                    'issued': issued,
                    'summary': {
                        'total_users_without_certs': len(users_without_certs),
                        'successfully_issued': len(users_without_certs) - failed_count,
                        'failed': failed_count
                    }
                }), 201

            finally:
                conn.close()

        except Exception as e:
            logger.error(f"Error in bulk certificate issuance: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @bp.route('/users/certificates/bulk-rotate', methods=['POST'])
    @auth_decorator
    def bulk_rotate_user_certificates():
        """
        Rotate all expired user identity certificates.

        Request JSON:
        {
            "engagement_id": "ENG-2026-001"  (optional)
        }

        Returns results with old/new serials per user.
        """
        try:
            data = request.json or {}
            engagement_id = data.get('engagement_id')

            result = certificate_service.bulk_rotate_expired_certificates(
                issuing_ca_engagement_id=engagement_id
            )

            # Add P12 exports for successfully rotated certs
            for rotated_cert in result['rotated']:
                if rotated_cert.get('success'):
                    try:
                        import secrets
                        p12_password = secrets.token_urlsafe(12)
                        p12_result = certificate_service.export_user_certificate_to_p12(
                            user_id=rotated_cert['user_id'],
                            p12_password=p12_password
                        )
                        rotated_cert['p12_download_url'] = p12_result['download_url']
                        rotated_cert['p12_download_token'] = p12_result['download_token']
                        rotated_cert['p12_password'] = p12_result['p12_password']
                    except Exception as e:
                        logger.warning(f"Failed to export P12 for rotated cert (user {rotated_cert['user_id']}): {e}")

            logger.info(f"Bulk rotated {result['summary']['successfully_rotated']}/{result['summary']['total_expired']} certificates")

            return jsonify(result), 201

        except Exception as e:
            logger.error(f"Error in bulk certificate rotation: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    @bp.route('/cleanup/p12-downloads', methods=['POST'])
    @auth_decorator
    @permission_decorator('users:update')
    def cleanup_expired_p12_files():
        """
        Clean up expired P12 download records and temporary files.

        This endpoint should be called periodically (e.g., hourly via cron) to:
        - Delete P12 files from /tmp that are older than 24 hours
        - Clear passwords from database records
        - Mark records as deleted

        Requires: users:update permission (admin only)

        Returns:
            {
                "status": "success|partial|failed",
                "files_deleted": 5,
                "records_deleted": 5,
                "errors": []
            }
        """
        try:
            logger.info("Starting P12 cleanup task")
            result = certificate_service.cleanup_expired_p12_files()

            status_code = 200 if result['status'] == 'success' else (206 if result['status'] == 'partial' else 500)
            logger.info(f"P12 cleanup complete: {result['files_deleted']} files, {result['records_deleted']} records")

            return jsonify(result), status_code

        except Exception as e:
            logger.error(f"Error in P12 cleanup endpoint: {e}", exc_info=True)
            return jsonify({'error': str(e), 'status': 'failed'}), 500

    @bp.route('/users/<int:user_id>/report-viewer-certificates', methods=['GET'])
    @auth_decorator
    def get_user_report_viewer_certificates(user_id):
        """
        Get all report viewer certificates for a user.

        Returns list of report viewer certs with details: serial, report_ref, expires_at, status.
        """
        try:
            conn = database_service.get_connection()
            certs = conn.execute('''
                SELECT id, certificate_serial, report_ref, expires_at, status, issued_at
                FROM user_digital_identities
                WHERE user_id = ? AND cert_purpose = 'report_viewer'
                ORDER BY issued_at DESC
            ''', (user_id,)).fetchall()
            conn.close()

            cert_list = [dict(c) for c in certs]
            return jsonify({'report_viewer_certificates': cert_list}), 200

        except Exception as e:
            logger.error(f"Error getting report viewer certificates for user {user_id}: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    return bp


def register_certificate_routes(app, certificate_service, database_service, auth_decorator, permission_decorator):
    """
    Register certificate routes with Flask app.

    Args:
        app: Flask application instance
        certificate_service: CertificateService instance
        database_service: DatabaseService instance
        auth_decorator: Authentication decorator
        permission_decorator: Permission decorator
    """
    bp = create_certificate_routes(certificate_service, database_service, auth_decorator, permission_decorator)
    app.register_blueprint(bp)
    logger.info("Certificate routes registered")
