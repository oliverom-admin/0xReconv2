"""Rename engagement -> project throughout schema.

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-01

Renames all tables, columns, indexes, and constraints that used the
"engagement" naming convention to use "project" instead.

This is a pure rename — no data is lost and no tables are recreated.
All operations use ALTER TABLE ... RENAME which is atomic in PostgreSQL.

Changes:
  Tables:      engagements -> projects
               engagement_users -> project_users
               engagement_cas -> project_cas

  Columns:     engagement_id -> project_id  (on 11 tables)

  Indexes:     ix_engagements_status -> ix_projects_status
               ix_eu_engagement_id -> ix_pu_project_id
               ix_eca_engagement_id -> ix_pca_project_id
               ix_cc_engagement_id -> ix_cc_project_id
               ix_jq_engagement_id -> ix_jq_project_id
               ix_audit_engagement_id -> ix_audit_project_id
               ix_ura_engagement_id -> ix_ura_project_id
               ix_scan_cfg_engagement_id -> ix_scan_cfg_project_id
               ix_policies_engagement_id -> ix_policies_project_id

  Constraints: uq_engagement_users -> uq_project_users
               uq_engagement_ca_status -> uq_project_ca_status
               uq_user_role_engagement -> uq_user_role_project

  Seed data:   role name 'engagement-admin' -> 'project-admin'
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:

    # =========================================================================
    # STEP 1: Rename tables
    # Must happen before column renames so FK references resolve correctly.
    # =========================================================================

    op.rename_table("engagements", "projects")
    op.rename_table("engagement_users", "project_users")
    op.rename_table("engagement_cas", "project_cas")

    # =========================================================================
    # STEP 2: Rename engagement_id column on every table that has one
    # =========================================================================

    op.alter_column("user_role_assignments", "engagement_id",
                    new_column_name="project_id")
    op.alter_column("audit_log", "engagement_id",
                    new_column_name="project_id")
    op.alter_column("project_users", "engagement_id",
                    new_column_name="project_id")
    op.alter_column("policies", "engagement_id",
                    new_column_name="project_id")
    op.alter_column("scan_configurations", "engagement_id",
                    new_column_name="project_id")
    op.alter_column("job_queue", "engagement_id",
                    new_column_name="project_id")
    op.alter_column("project_cas", "engagement_id",
                    new_column_name="project_id")
    op.alter_column("collector_certificates", "engagement_id",
                    new_column_name="project_id")
    op.alter_column("dashboard_certificates", "engagement_id",
                    new_column_name="project_id")
    op.alter_column("secret_references", "engagement_id",
                    new_column_name="project_id")
    op.alter_column("api_keys", "engagement_id",
                    new_column_name="project_id")

    # =========================================================================
    # STEP 3: Rename indexes
    # =========================================================================

    op.execute("ALTER INDEX ix_engagements_status RENAME TO ix_projects_status")
    op.execute("ALTER INDEX ix_eu_engagement_id RENAME TO ix_pu_project_id")
    op.execute("ALTER INDEX ix_eca_engagement_id RENAME TO ix_pca_project_id")
    op.execute("ALTER INDEX ix_cc_engagement_id RENAME TO ix_cc_project_id")
    op.execute("ALTER INDEX ix_jq_engagement_id RENAME TO ix_jq_project_id")
    op.execute("ALTER INDEX ix_audit_engagement_id RENAME TO ix_audit_project_id")
    op.execute("ALTER INDEX ix_ura_engagement_id RENAME TO ix_ura_project_id")
    op.execute("ALTER INDEX ix_scan_cfg_engagement_id RENAME TO ix_scan_cfg_project_id")
    op.execute("ALTER INDEX ix_policies_engagement_id RENAME TO ix_policies_project_id")

    # =========================================================================
    # STEP 4: Rename constraints
    # =========================================================================

    op.execute("""
        ALTER TABLE project_users
        RENAME CONSTRAINT uq_engagement_users TO uq_project_users
    """)
    op.execute("""
        ALTER TABLE project_cas
        RENAME CONSTRAINT uq_engagement_ca_status TO uq_project_ca_status
    """)
    op.execute("""
        ALTER TABLE user_role_assignments
        RENAME CONSTRAINT uq_user_role_engagement TO uq_user_role_project
    """)

    # =========================================================================
    # STEP 5: Update seed data — role name
    # =========================================================================

    op.execute("""
        UPDATE roles SET name = 'project-admin'
        WHERE name = 'engagement-admin'
    """)

    # =========================================================================
    # STEP 6: Update role permission seed data
    # =========================================================================

    op.execute("""
        UPDATE role_permissions
        SET permission = REPLACE(permission, 'engagements:', 'projects:')
        WHERE permission LIKE 'engagements:%'
    """)


def downgrade() -> None:
    # Step 6 reverse
    op.execute("""
        UPDATE role_permissions
        SET permission = REPLACE(permission, 'projects:', 'engagements:')
        WHERE permission LIKE 'projects:%'
    """)

    # Step 5 reverse
    op.execute("""
        UPDATE roles SET name = 'engagement-admin'
        WHERE name = 'project-admin'
    """)

    # Step 4 reverse
    op.execute("""
        ALTER TABLE user_role_assignments
        RENAME CONSTRAINT uq_user_role_project TO uq_user_role_engagement
    """)
    op.execute("""
        ALTER TABLE project_cas
        RENAME CONSTRAINT uq_project_ca_status TO uq_engagement_ca_status
    """)
    op.execute("""
        ALTER TABLE project_users
        RENAME CONSTRAINT uq_project_users TO uq_engagement_users
    """)

    # Step 3 reverse
    op.execute("ALTER INDEX ix_projects_status RENAME TO ix_engagements_status")
    op.execute("ALTER INDEX ix_pu_project_id RENAME TO ix_eu_engagement_id")
    op.execute("ALTER INDEX ix_pca_project_id RENAME TO ix_eca_engagement_id")
    op.execute("ALTER INDEX ix_cc_project_id RENAME TO ix_cc_engagement_id")
    op.execute("ALTER INDEX ix_jq_project_id RENAME TO ix_jq_engagement_id")
    op.execute("ALTER INDEX ix_audit_project_id RENAME TO ix_audit_engagement_id")
    op.execute("ALTER INDEX ix_ura_project_id RENAME TO ix_ura_engagement_id")
    op.execute("ALTER INDEX ix_scan_cfg_project_id RENAME TO ix_scan_cfg_engagement_id")
    op.execute("ALTER INDEX ix_policies_project_id RENAME TO ix_policies_engagement_id")

    # Step 2 reverse
    op.alter_column("api_keys", "project_id", new_column_name="engagement_id")
    op.alter_column("secret_references", "project_id", new_column_name="engagement_id")
    op.alter_column("dashboard_certificates", "project_id", new_column_name="engagement_id")
    op.alter_column("collector_certificates", "project_id", new_column_name="engagement_id")
    op.alter_column("project_cas", "project_id", new_column_name="engagement_id")
    op.alter_column("job_queue", "project_id", new_column_name="engagement_id")
    op.alter_column("scan_configurations", "project_id", new_column_name="engagement_id")
    op.alter_column("policies", "project_id", new_column_name="engagement_id")
    op.alter_column("project_users", "project_id", new_column_name="engagement_id")
    op.alter_column("audit_log", "project_id", new_column_name="engagement_id")
    op.alter_column("user_role_assignments", "project_id", new_column_name="engagement_id")

    # Step 1 reverse
    op.rename_table("project_cas", "engagement_cas")
    op.rename_table("project_users", "engagement_users")
    op.rename_table("projects", "engagements")
