"""
Authentication and Authorization Service Layer for CAIP

Centralizes authentication and authorization logic to eliminate code duplication.
Provides standardized methods for:
- Database-backed role and permission checking (via RBACService)
- Authentication decorators for Flask routes
- Session validation utilities
- Engagement-scoped access control

Previously located in app.py lines 89-173
Updated to use database-backed RBAC system (Phase 1)
"""

import logging
from functools import wraps
from flask import session, redirect, url_for, jsonify

from database_service import DatabaseService
from caip_service_layer.rbac_service import RBACService

logger = logging.getLogger('caip.operational')


# ==================== LEGACY ROLE DEFINITIONS ====================
# NOTE: These are kept for backward compatibility with existing code
# New code should use RBACService for permission checking
# This will be removed in Phase 4 after all routes are updated

LEGACY_ROLES = {
    'admin': {
        'name': 'Administrator',
        'permissions': ['create', 'edit', 'update', 'delete', 'run', 'view', 'manage_users']
    },
    'system-administrator': {
        'name': 'System Administrator',
        'permissions': ['create', 'edit', 'update', 'delete', 'run', 'view', 'manage_users']
    },
    'report-user': {
        'name': 'Report User',
        'permissions': ['view']
    },
    'global-viewer': {
        'name': 'Global Viewer',
        'permissions': ['view']
    },
    'scan-user': {
        'name': 'Scan User',
        'permissions': ['create', 'edit', 'update', 'delete', 'run', 'view']
    },
    'engagement-manager': {
        'name': 'Engagement Manager',
        'permissions': ['create', 'edit', 'update', 'delete', 'run', 'view']
    },
    'clm-user': {
        'name': 'CLM User',
        'permissions': ['create', 'edit', 'update', 'delete', 'run', 'view']
    },
    'integration-manager': {
        'name': 'Integration Manager',
        'permissions': ['create', 'edit', 'update', 'delete', 'run', 'view']
    },
    'kms-user': {
        'name': 'KMS User',
        'permissions': ['create', 'edit', 'update', 'delete', 'run', 'view']
    },
    'assessment-coordinator': {
        'name': 'Assessment Coordinator',
        'permissions': ['create', 'edit', 'update', 'delete', 'run', 'view']
    },
    'report-analyst': {
        'name': 'Report Analyst',
        'permissions': ['view', 'create']
    },
    'security-auditor': {
        'name': 'Security Auditor',
        'permissions': ['view']
    },
    'engagement-viewer': {
        'name': 'Engagement Viewer',
        'permissions': ['view']
    }
}

# Alias for backward compatibility
ROLES = LEGACY_ROLES


# ==================== AUTHENTICATION DECORATORS ====================

def login_required(f):
    """
    Decorator to require user authentication for a route.
    
    Redirects to login page if user is not authenticated.
    
    Usage:
        @app.route('/protected')
        @login_required
        def protected_route():
            ...
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def permission_required(permission):
    """
    Decorator to require specific permission for a route.

    Returns 401 if not authenticated, 403 if authenticated but lacking permission.

    Supports both legacy permissions (e.g., 'view', 'create', 'delete') and
    new domain-specific permissions (e.g., 'users:create', 'scans:read').

    Args:
        permission: Permission string to check

    Usage:
        @app.route('/admin-only')
        @login_required
        @permission_required('manage_users')  # Legacy
        def admin_route():
            ...

        @app.route('/users')
        @login_required
        @permission_required('users:read')  # New RBAC
        def list_users():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401

            user_id = session['user_id']

            # Check if this is a new-style permission (contains ':')
            if ':' in permission:
                # Use RBAC service for new-style permissions
                if not RBACService.check_permission(user_id, permission):
                    logger.warning(
                        f"Permission denied: user_id={user_id}, permission={permission}"
                    )
                    return jsonify({'error': 'Forbidden'}), 403
            else:
                # Fall back to legacy permission checking
                user_role = get_user_role(user_id)

                if not user_role:
                    return jsonify({'error': 'Unauthorized'}), 401

                if not has_permission(user_role, permission):
                    logger.warning(
                        f"Permission denied (legacy): user={user_role}, permission={permission}"
                    )
                    return jsonify({'error': 'Forbidden'}), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ==================== PERMISSION UTILITIES ====================

def get_user_role(user_id: int) -> str:
    """
    Get the role name for a user by ID.

    NOTE: This returns the role NAME (string) for backward compatibility.
    For new code, use RBACService.get_user_role() which returns full role info.

    Args:
        user_id: Database ID of the user

    Returns:
        Role name string (e.g., 'system-administrator') or None if user not found
    """
    try:
        # Try to get from role_id first (new RBAC system)
        role_info = RBACService.get_user_role(user_id)
        if role_info:
            return role_info['name']

        # Fall back to legacy role column
        conn = DatabaseService.get_connection()
        c = conn.cursor()
        c.execute('SELECT role FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        conn.close()

        return user['role'] if user else None
    except Exception as e:
        logger.error(f"Error getting user role: {e}")
        return None


def has_permission(role: str, permission: str) -> bool:
    """
    Check if a role has a specific permission.
    
    Args:
        role: Role string (e.g., 'admin', 'scan-user')
        permission: Permission string to check
        
    Returns:
        True if role has permission, False otherwise
    """
    role_info = ROLES.get(role, {})
    return permission in role_info.get('permissions', [])


def get_role_permissions(role: str) -> list:
    """
    Get all permissions for a role.
    
    Args:
        role: Role string
        
    Returns:
        List of permission strings
    """
    return ROLES.get(role, {}).get('permissions', [])


def get_all_roles() -> list:
    """
    Get all available roles with their details.

    Uses database-backed RBAC system if available, falls back to legacy roles.

    Returns:
        List of role dictionaries with name, display_name, and permissions
    """
    try:
        # Try to get from database first
        db_roles = RBACService.get_all_roles()
        if db_roles:
            return db_roles

        # Fall back to legacy roles
        roles_list = []
        for role_key, role_info in ROLES.items():
            roles_list.append({
                'name': role_key,
                'display_name': role_info['name'],
                'permissions': role_info['permissions']
            })
        return roles_list
    except Exception as e:
        logger.error(f"Error getting all roles: {e}")
        # Fall back to legacy roles on error
        roles_list = []
        for role_key, role_info in ROLES.items():
            roles_list.append({
                'name': role_key,
                'display_name': role_info['name'],
                'permissions': role_info['permissions']
            })
        return roles_list


def is_valid_role(role: str) -> bool:
    """
    Check if a role string is valid.

    Checks both database-backed roles and legacy roles.

    Args:
        role: Role string to validate

    Returns:
        True if valid role, False otherwise
    """
    try:
        # Check database-backed roles first
        db_roles = RBACService.get_all_roles()
        if db_roles:
            valid_role_names = [r['name'] for r in db_roles]
            if role in valid_role_names:
                return True

        # Fall back to legacy roles
        return role in ROLES
    except Exception as e:
        logger.error(f"Error validating role: {e}")
        return role in ROLES


def get_role_names() -> list:
    """
    Get list of valid role names.

    Uses database-backed RBAC system if available, falls back to legacy roles.

    Returns:
        List of role name strings
    """
    try:
        # Try to get from database first
        db_roles = RBACService.get_all_roles()
        if db_roles:
            return [r['name'] for r in db_roles]

        # Fall back to legacy roles
        return list(ROLES.keys())
    except Exception as e:
        logger.error(f"Error getting role names: {e}")
        return list(ROLES.keys())


# ==================== NEW RBAC HELPER FUNCTIONS ====================

def check_user_permission(user_id: int, permission: str) -> bool:
    """
    Check if a user has a specific permission (database-backed RBAC).

    This is a convenience wrapper around RBACService.check_permission.

    Args:
        user_id: User ID
        permission: Permission name (e.g., 'users:create', 'scans:read')

    Returns:
        True if user has permission, False otherwise
    """
    return RBACService.check_permission(user_id, permission)


def get_user_permissions_list(user_id: int) -> list:
    """
    Get all permissions for a user (database-backed RBAC).

    Args:
        user_id: User ID

    Returns:
        List of permission names
    """
    return list(RBACService.get_user_permissions(user_id))


def check_engagement_access(user_id: int, engagement_id: str) -> bool:
    """
    Check if a user has access to a specific engagement.

    For engagement-scoped users, this checks if they are assigned to the engagement.
    For other users, access is always granted.

    Args:
        user_id: User ID
        engagement_id: Engagement ID

    Returns:
        True if user has access, False otherwise
    """
    if not RBACService.is_engagement_scoped(user_id):
        return True

    user_engagements = RBACService.get_user_engagements(user_id)
    return engagement_id in user_engagements
