"""
RBAC Service - Database-Backed Role and Permission Management

This service provides centralized permission checking and role management
for the CAIP platform. It replaces the hardcoded ROLES dictionary with
database-backed role and permission queries.

Key Functions:
- check_permission(user_id, permission): Check if user has a specific permission
- check_resource_access(user_id, resource_type, resource_id): Check resource-level access
- get_user_permissions(user_id): Get all permissions for a user
- get_user_role(user_id): Get user's role information
- is_engagement_scoped(user_id): Check if user has engagement-scoped access

Author: CAIP Development Team
Date: 2024-12
"""

import logging
import sqlite3
from typing import Optional, Dict, Any, List, Set
from functools import lru_cache

logger = logging.getLogger('caip.operational')


class RBACService:
    """
    Role-Based Access Control Service

    Provides permission checking and role management for the CAIP platform.
    """

    @classmethod
    def get_user_role(cls, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Get user's role information.

        Args:
            user_id: User ID

        Returns:
            Dictionary with role info (id, name, display_name, description) or None
        """
        from database_service import DatabaseService

        try:
            conn = DatabaseService.get_connection()
            c = conn.cursor()

            c.execute('''
                SELECT r.id, r.name, r.display_name, r.description, r.is_system_role
                FROM users u
                JOIN roles r ON u.role_id = r.id
                WHERE u.id = ?
            ''', (user_id,))

            row = c.fetchone()
            conn.close()

            if not row:
                logger.warning(f"No role found for user_id={user_id}")
                return None

            return DatabaseService.dict_from_row(row)

        except Exception as e:
            logger.error(f"Error getting user role for user_id={user_id}: {e}")
            return None

    @classmethod
    def get_user_permissions(cls, user_id: int) -> Set[str]:
        """
        Get all permissions for a user based on their role.

        Args:
            user_id: User ID

        Returns:
            Set of permission names (e.g., {'users:create', 'scans:read', ...})
        """
        from database_service import DatabaseService

        try:
            conn = DatabaseService.get_connection()
            c = conn.cursor()

            c.execute('''
                SELECT DISTINCT p.name
                FROM users u
                JOIN roles r ON u.role_id = r.id
                JOIN role_permissions rp ON r.id = rp.role_id
                JOIN permissions p ON rp.permission_id = p.id
                WHERE u.id = ?
            ''', (user_id,))

            permissions = {row[0] for row in c.fetchall()}
            conn.close()

            return permissions

        except Exception as e:
            logger.error(f"Error getting permissions for user_id={user_id}: {e}")
            return set()

    @classmethod
    def check_permission(cls, user_id: int, permission: str) -> bool:
        """
        Check if a user has a specific permission.

        Args:
            user_id: User ID
            permission: Permission name (e.g., 'users:create', 'scans:read')

        Returns:
            True if user has permission, False otherwise
        """
        permissions = cls.get_user_permissions(user_id)
        has_permission = permission in permissions

        if not has_permission:
            logger.warning(f"Permission denied: user_id={user_id}, permission={permission}")

        return has_permission

    @classmethod
    def has_any_permission(cls, user_id: int, permissions: List[str]) -> bool:
        """
        Check if user has ANY of the specified permissions (OR operation).

        Args:
            user_id: User ID
            permissions: List of permission names

        Returns:
            True if user has at least one permission, False otherwise
        """
        user_permissions = cls.get_user_permissions(user_id)
        return bool(user_permissions.intersection(permissions))

    @classmethod
    def has_all_permissions(cls, user_id: int, permissions: List[str]) -> bool:
        """
        Check if user has ALL of the specified permissions (AND operation).

        Args:
            user_id: User ID
            permissions: List of permission names

        Returns:
            True if user has all permissions, False otherwise
        """
        user_permissions = cls.get_user_permissions(user_id)
        return all(perm in user_permissions for perm in permissions)

    @classmethod
    def is_engagement_scoped(cls, user_id: int) -> bool:
        """
        Check if user has engagement-scoped access (engagement-viewer role).

        Users with engagement-scoped access can only view data for engagements
        they are explicitly assigned to.

        Args:
            user_id: User ID

        Returns:
            True if user is engagement-scoped, False otherwise
        """
        role = cls.get_user_role(user_id)
        return role and role.get('name') == 'engagement-viewer'

    @classmethod
    def get_user_engagements(cls, user_id: int) -> Set[str]:
        """
        Get list of engagement IDs that a user is assigned to.

        This is used for engagement-scoped access control.

        Args:
            user_id: User ID

        Returns:
            Set of engagement IDs
        """
        from database_service import DatabaseService

        try:
            conn = DatabaseService.get_connection()
            c = conn.cursor()

            c.execute('''
                SELECT engagement_id
                FROM engagement_assignments
                WHERE user_id = ?
            ''', (user_id,))

            engagement_ids = {row[0] for row in c.fetchall()}
            conn.close()

            return engagement_ids

        except Exception as e:
            logger.error(f"Error getting engagements for user_id={user_id}: {e}")
            return set()

    @classmethod
    def check_resource_access(cls, user_id: int, resource_type: str, resource_id: str) -> bool:
        """
        Check if user has access to a specific resource.

        For engagement-scoped users, this checks if they are assigned to the
        engagement associated with the resource.

        Args:
            user_id: User ID
            resource_type: Type of resource (e.g., 'certificate', 'scan', 'report')
            resource_id: Resource ID

        Returns:
            True if user has access, False otherwise
        """
        # If user is not engagement-scoped, they have access to all resources
        # (subject to their permissions)
        if not cls.is_engagement_scoped(user_id):
            return True

        # For engagement-scoped users, check if resource is in their assigned engagements
        user_engagements = cls.get_user_engagements(user_id)

        # Get engagement_id for the resource
        engagement_id = cls._get_resource_engagement(resource_type, resource_id)

        if not engagement_id:
            logger.warning(f"No engagement found for resource: {resource_type}:{resource_id}")
            return False

        has_access = engagement_id in user_engagements

        if not has_access:
            logger.warning(
                f"Resource access denied: user_id={user_id}, "
                f"resource={resource_type}:{resource_id}, engagement={engagement_id}"
            )

        return has_access

    @classmethod
    def _get_resource_engagement(cls, resource_type: str, resource_id: str) -> Optional[str]:
        """
        Get the engagement_id associated with a resource.

        This is a helper method that looks up the engagement for different resource types.

        Args:
            resource_type: Type of resource
            resource_id: Resource ID

        Returns:
            Engagement ID or None
        """
        from database_service import DatabaseService

        try:
            conn = DatabaseService.get_connection()
            c = conn.cursor()

            # Map resource types to their table and engagement column
            # This will need to be extended as new resource types are added
            resource_mappings = {
                'certificate': ('inventory', 'engagement_id'),
                'scan': ('scans', 'engagement_id'),
                'report': ('reports', 'engagement_id'),
                'assessment': ('assessments', 'engagement_id')
            }

            if resource_type not in resource_mappings:
                logger.warning(f"Unknown resource type: {resource_type}")
                conn.close()
                return None

            table, column = resource_mappings[resource_type]

            c.execute(f'SELECT {column} FROM {table} WHERE id = ?', (resource_id,))
            row = c.fetchone()
            conn.close()

            return row[0] if row else None

        except Exception as e:
            logger.error(f"Error getting engagement for resource {resource_type}:{resource_id}: {e}")
            return None

    @classmethod
    def assign_user_to_engagement(cls, user_id: int, engagement_id: str, assigned_by: int) -> bool:
        """
        Assign a user to an engagement for scoped access.

        Args:
            user_id: User ID to assign
            engagement_id: Engagement ID
            assigned_by: User ID of person making the assignment

        Returns:
            True if successful, False otherwise
        """
        from database_service import DatabaseService

        try:
            conn = DatabaseService.get_connection()
            c = conn.cursor()

            c.execute('''
                INSERT OR IGNORE INTO engagement_assignments
                (user_id, engagement_id, assigned_by)
                VALUES (?, ?, ?)
            ''', (user_id, engagement_id, assigned_by))

            conn.commit()
            conn.close()

            logger.info(
                f"User assigned to engagement: user_id={user_id}, "
                f"engagement_id={engagement_id}, assigned_by={assigned_by}"
            )

            return True

        except Exception as e:
            logger.error(
                f"Error assigning user to engagement: user_id={user_id}, "
                f"engagement_id={engagement_id}: {e}"
            )
            return False

    @classmethod
    def unassign_user_from_engagement(cls, user_id: int, engagement_id: str) -> bool:
        """
        Remove a user's assignment from an engagement.

        Args:
            user_id: User ID
            engagement_id: Engagement ID

        Returns:
            True if successful, False otherwise
        """
        from database_service import DatabaseService

        try:
            conn = DatabaseService.get_connection()
            c = conn.cursor()

            c.execute('''
                DELETE FROM engagement_assignments
                WHERE user_id = ? AND engagement_id = ?
            ''', (user_id, engagement_id))

            conn.commit()
            conn.close()

            logger.info(
                f"User unassigned from engagement: user_id={user_id}, "
                f"engagement_id={engagement_id}"
            )

            return True

        except Exception as e:
            logger.error(
                f"Error unassigning user from engagement: user_id={user_id}, "
                f"engagement_id={engagement_id}: {e}"
            )
            return False

    @classmethod
    def audit_log(cls, user_id: int, action: str, resource_type: str = None,
                  resource_id: str = None, details: Dict[str, Any] = None,
                  ip_address: str = None):
        """
        Log an action to the audit trail.

        Args:
            user_id: User ID performing the action
            action: Action description (e.g., 'create_user', 'delete_scan')
            resource_type: Type of resource affected (optional)
            resource_id: ID of resource affected (optional)
            details: Additional details as dictionary (optional)
            ip_address: IP address of request (optional)
        """
        from database_service import DatabaseService
        import json

        try:
            conn = DatabaseService.get_connection()
            c = conn.cursor()

            details_json = json.dumps(details) if details else None

            c.execute('''
                INSERT INTO audit_log
                (user_id, action, resource_type, resource_id, details_json, ip_address)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, action, resource_type, resource_id, details_json, ip_address))

            conn.commit()
            conn.close()

            logger.info(
                f"Audit log: user_id={user_id}, action={action}, "
                f"resource={resource_type}:{resource_id}"
            )

        except Exception as e:
            logger.error(f"Error writing audit log: {e}")

    @classmethod
    def get_all_roles(cls) -> List[Dict[str, Any]]:
        """
        Get all roles in the system.

        Returns:
            List of role dictionaries
        """
        from database_service import DatabaseService

        try:
            conn = DatabaseService.get_connection()
            c = conn.cursor()

            c.execute('SELECT * FROM roles ORDER BY id')
            rows = c.fetchall()
            conn.close()

            return [DatabaseService.dict_from_row(row) for row in rows]

        except Exception as e:
            logger.error(f"Error getting all roles: {e}")
            return []

    @classmethod
    def get_role_permissions(cls, role_id: int) -> List[Dict[str, Any]]:
        """
        Get all permissions for a specific role.

        Args:
            role_id: Role ID

        Returns:
            List of permission dictionaries
        """
        from database_service import DatabaseService

        try:
            conn = DatabaseService.get_connection()
            c = conn.cursor()

            c.execute('''
                SELECT p.*
                FROM permissions p
                JOIN role_permissions rp ON p.id = rp.permission_id
                WHERE rp.role_id = ?
                ORDER BY p.resource_type, p.action
            ''', (role_id,))

            rows = c.fetchall()
            conn.close()

            return [DatabaseService.dict_from_row(row) for row in rows]

        except Exception as e:
            logger.error(f"Error getting permissions for role_id={role_id}: {e}")
            return []
