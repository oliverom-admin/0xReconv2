"""
RBACService — role and permission evaluation.

Permission check flow:
  1. system_admin users bypass ALL permission checks.
  2. For other users: look up user_role_assignments, join role_permissions.
  3. Global assignments (project_id IS NULL) apply everywhere.
  4. Scoped assignments (project_id = X) apply only to project X.
  5. Permissions from global + scoped assignments are merged.
"""
from __future__ import annotations

import asyncpg
import structlog

logger = structlog.get_logger("recon.rbac")


class RBACService:
    """Role and permission evaluation."""

    def __init__(self, db: asyncpg.Connection) -> None:
        self._db = db

    async def get_user_permissions(
        self, user_id: str, project_id: str | None = None
    ) -> set[str]:
        rows = await self._db.fetch(
            """
            SELECT rp.permission
            FROM user_role_assignments ura
            JOIN role_permissions rp ON rp.role_id = ura.role_id
            WHERE ura.user_id = $1
              AND (
                ura.project_id IS NULL
                OR ($2::text IS NOT NULL AND ura.project_id = $2)
              )
            """,
            user_id,
            project_id,
        )
        return {r["permission"] for r in rows}

    async def has_permission(
        self,
        user_id: str,
        permission: str,
        project_id: str | None = None,
        is_system_admin: bool = False,
    ) -> bool:
        if is_system_admin:
            return True
        perms = await self.get_user_permissions(user_id, project_id)
        return permission in perms

    async def assign_role(
        self,
        user_id: str,
        role_name: str,
        project_id: str | None,
        assigned_by: str,
    ) -> None:
        role = await self._db.fetchrow(
            "SELECT id FROM roles WHERE name = $1", role_name
        )
        if not role:
            raise ValueError(f"Role '{role_name}' not found")
        await self._db.execute(
            """
            INSERT INTO user_role_assignments
              (user_id, role_id, project_id, assigned_by)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id, role_id, project_id) DO NOTHING
            """,
            user_id,
            role["id"],
            project_id,
            assigned_by,
        )

    async def remove_role(
        self,
        user_id: str,
        role_name: str,
        project_id: str | None,
    ) -> None:
        role = await self._db.fetchrow(
            "SELECT id FROM roles WHERE name = $1", role_name
        )
        if not role:
            return
        if project_id is None:
            await self._db.execute(
                "DELETE FROM user_role_assignments "
                "WHERE user_id=$1 AND role_id=$2 AND project_id IS NULL",
                user_id, role["id"],
            )
        else:
            await self._db.execute(
                "DELETE FROM user_role_assignments "
                "WHERE user_id=$1 AND role_id=$2 AND project_id=$3",
                user_id, role["id"], project_id,
            )

    async def list_roles(self) -> list[dict]:
        rows = await self._db.fetch(
            "SELECT id, name, description, is_system_role "
            "FROM roles ORDER BY name"
        )
        return [dict(r) for r in rows]

    async def list_role_permissions(self, role_id: str) -> list[str]:
        rows = await self._db.fetch(
            "SELECT permission FROM role_permissions "
            "WHERE role_id=$1 ORDER BY permission",
            role_id,
        )
        return [r["permission"] for r in rows]
