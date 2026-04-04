"""
Secret Store Routes for CAIP

Flask blueprint providing API endpoints for system vault display and management.
Enables the dashboard to show the system vault as a read-only managed vault.

Endpoints:
- GET /api/v1/secret-stores/system-vault          - Get system vault metadata
- GET /api/v1/secret-stores/system-vault/secrets  - List secrets in system vault
"""

from flask import Blueprint, jsonify, request
from functools import wraps
import logging

logger = logging.getLogger('caip.operational')

secret_store_bp = Blueprint('secret_store', __name__, url_prefix='/api/v1/secret-stores')


def admin_required(f):
    """
    Decorator to require admin role.

    This is handled by Flask auth middleware - if user reaches here,
    they're authenticated. In the future this can be enhanced with
    proper RBAC checks.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated_function


@secret_store_bp.route('/system-vault', methods=['GET'])
@admin_required
def get_system_vault():
    """
    Get system vault information for UI display.

    Returns:
        JSON with vault metadata:
        {
            "id": 1,
            "vault_id": "system_vault",
            "name": "System Vault",
            "vault_type": "system",
            "is_system": true,
            "is_locked": false,
            "key_count": 5,
            "status": "active",
            "encryption": "AES-256-GCM",
            "created_at": "2024-03-01T00:00:00Z",
            "last_accessed_at": "2024-03-01T14:30:00Z"
        }
    """
    try:
        from database_service import DatabaseService
        from caip_service_layer.unified_vault_service import get_unified_vault_service

        # Get vault metadata from database
        with DatabaseService.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT id, vault_id, name, vault_type,
                       is_system, is_locked, key_count, status,
                       created_at, last_accessed_at
                FROM unified_vaults
                WHERE vault_id = ? AND is_system = ?
            ''', ('system_vault', 1))
            row = c.fetchone()

        if not row:
            logger.warning("System vault metadata not found in database")
            return jsonify({"error": "System vault not found"}), 404

        # Get vault status from service
        vault = get_unified_vault_service()
        vault_status = vault.get_vault_status() if vault else {}

        return jsonify({
            "id": row['id'],
            "vault_id": row['vault_id'],
            "name": row['name'],
            "vault_type": row['vault_type'],
            "is_system": bool(row['is_system']),
            "is_locked": bool(row['is_locked']),
            "key_count": vault_status.get('app_secrets_count', 0),
            "status": row['status'],
            "created_at": row['created_at'],
            "last_accessed_at": row['last_accessed_at'],
            "encryption": "AES-256-GCM",
            "pki_keys": vault_status.get('pki_keys', {})
        }), 200

    except Exception as e:
        logger.error(f"Failed to get system vault: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@secret_store_bp.route('/system-vault/secrets', methods=['GET'])
@admin_required
def list_system_vault_secrets():
    """
    List secrets in system vault (metadata only, not values).

    Returns:
        JSON with secret metadata:
        {
            "secrets": [
                {
                    "path": "app_secrets/caipflasksecretkey",
                    "name": "caipflasksecretkey",
                    "type": "app_secret",
                    "can_edit": false,
                    "can_delete": false
                },
                ...
            ],
            "count": 5
        }
    """
    try:
        from caip_service_layer.unified_vault_service import get_unified_vault_service

        vault = get_unified_vault_service()
        if not vault:
            logger.error("Unified vault service not initialized")
            return jsonify({"error": "Vault not initialized"}), 500

        secrets = vault.list_secrets()

        # Format for UI display - never show values, just metadata
        formatted_secrets = []
        seen_secrets = set()  # Track which secrets we've already added

        for secret_path in secrets:
            # Skip metadata entries - these are vault infrastructure, not actual secrets
            if secret_path.startswith('metadata/'):
                continue

            parts = secret_path.split('/')

            # For app_secrets: path is "app_secrets/secret_name" (2 parts)
            # For pki_keys: path is "pki_keys/key_name/pem" or "pki_keys/key_name/key_type" etc. (3+ parts)

            if len(parts) == 2 and parts[0] == 'app_secrets':
                # Direct app secret
                secret_type = 'app_secrets'
                secret_name = parts[1]
                unique_key = f"{secret_type}/{secret_name}"

                if unique_key not in seen_secrets:
                    seen_secrets.add(unique_key)
                    formatted_secrets.append({
                        "path": secret_path,
                        "full_path": secret_path,
                        "name": secret_name,
                        "type": secret_type,
                        "can_edit": False,
                        "can_delete": False
                    })

            elif len(parts) >= 3 and parts[0] == 'pki_keys':
                # PKI key with metadata - only include once (from /pem path)
                secret_type = 'pki_keys'
                secret_name = parts[1]

                # Only process if this is the /pem entry (the actual key content)
                if secret_path.endswith('/pem'):
                    unique_key = f"{secret_type}/{secret_name}"
                    if unique_key not in seen_secrets:
                        seen_secrets.add(unique_key)
                        formatted_secrets.append({
                            "path": secret_path,
                            "full_path": secret_path,
                            "name": secret_name,
                            "type": secret_type,
                            "can_edit": False,
                            "can_delete": False
                        })

        return jsonify({
            "secrets": formatted_secrets,
            "count": len(formatted_secrets)
        }), 200

    except Exception as e:
        logger.error(f"Failed to list system vault secrets: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@secret_store_bp.route('/system-vault/secrets', methods=['DELETE'])
@admin_required
def delete_vault_secret():
    """
    Delete a secret or PKI key from the system vault.

    Request JSON:
    {
        "path": "pki_keys/engagement_ca_keys/31/pem"  or  "app_secrets/secret_name"
    }

    Returns:
        JSON with deletion status
    """
    try:
        from caip_service_layer.unified_vault_service import get_unified_vault_service

        data = request.get_json() or {}
        secret_path = data.get('path')

        if not secret_path:
            return jsonify({"error": "Missing 'path' parameter"}), 400

        vault = get_unified_vault_service()
        if not vault:
            logger.error("Unified vault service not initialized")
            return jsonify({"error": "Vault not initialized"}), 500

        # Delete using the full path
        deleted = vault.delete_secret(secret_path)

        if deleted:
            logger.info(f"Deleted secret/key from vault: {secret_path}")
            return jsonify({"success": True, "message": f"Deleted {secret_path}"}), 200
        else:
            logger.warning(f"Secret/key not found in vault: {secret_path}")
            return jsonify({"error": "Secret not found"}), 404

    except Exception as e:
        logger.error(f"Failed to delete vault secret: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


def register_routes(app):
    """
    Register secret store blueprint with Flask application.

    Args:
        app: Flask application instance
    """
    app.register_blueprint(secret_store_bp)
    logger.info("Secret store routes registered")
