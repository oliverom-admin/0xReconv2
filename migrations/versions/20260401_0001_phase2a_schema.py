"""Phase 2 schema — core tables, auth, engagements, PKI, jobs, secrets.

Revision ID: 0001
Revises: 0000
Create Date: 2026-04-01

Tables created (18):
  Core system (7):    roles, users, role_permissions, user_role_assignments,
                      api_keys, auth_providers, audit_log
  Engagements (6):    engagements, engagement_users, policies, policy_versions,
                      scan_configurations, assessment_types
  Jobs (1):           job_queue
  PKI (4):            internal_ca, engagement_cas, collector_certificates,
                      dashboard_certificates
  Secrets (2):        secret_stores, secret_references
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = "0000"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:

    # =========================================================================
    # CORE SYSTEM
    # =========================================================================

    op.create_table(
        "roles",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("name", sa.Text, nullable=False, unique=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("is_system_role", sa.Boolean, nullable=False,
                  server_default="false"),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )
    op.create_index("ix_roles_name", "roles", ["name"])

    op.create_table(
        "users",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("username", sa.Text, nullable=False, unique=True),
        sa.Column("email", sa.Text, nullable=True, unique=True),
        sa.Column("password_hash", sa.Text, nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False,
                  server_default="true"),
        sa.Column("is_system_admin", sa.Boolean, nullable=False,
                  server_default="false"),
        sa.Column("oauth_provider_id", sa.Text, nullable=True),
        sa.Column("oauth_subject", sa.Text, nullable=True),
        sa.Column("mfa_enabled", sa.Boolean, nullable=False,
                  server_default="false"),
        sa.Column("mfa_secret_ref", sa.Text, nullable=True),
        sa.Column("last_login_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )
    op.create_index("ix_users_username", "users", ["username"])
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "role_permissions",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("role_id", sa.Text,
                  sa.ForeignKey("roles.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("permission", sa.Text, nullable=False),
        sa.UniqueConstraint("role_id", "permission",
                            name="uq_role_permissions"),
    )
    op.create_index("ix_rp_role_id", "role_permissions", ["role_id"])

    op.create_table(
        "user_role_assignments",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("user_id", sa.Text,
                  sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("role_id", sa.Text,
                  sa.ForeignKey("roles.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("engagement_id", sa.Text, nullable=True),
        sa.Column("assigned_by", sa.Text, nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.UniqueConstraint("user_id", "role_id", "engagement_id",
                            name="uq_user_role_engagement"),
    )
    op.create_index("ix_ura_user_id", "user_role_assignments", ["user_id"])
    op.create_index("ix_ura_engagement_id", "user_role_assignments",
                    ["engagement_id"])

    op.create_table(
        "api_keys",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("key_hash", sa.Text, nullable=False, unique=True),
        sa.Column("key_prefix", sa.Text, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("engagement_id", sa.Text, nullable=True),
        sa.Column("collector_id", sa.Text, nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False,
                  server_default="true"),
        sa.Column("last_used_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )

    op.create_table(
        "auth_providers",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("name", sa.Text, nullable=False, unique=True),
        sa.Column("provider_type", sa.Text, nullable=False),
        sa.Column("config", sa.dialects.postgresql.JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("is_enabled", sa.Boolean, nullable=False,
                  server_default="true"),
        sa.Column("auto_provision", sa.Boolean, nullable=False,
                  server_default="true"),
        sa.Column("default_role_id", sa.Text,
                  sa.ForeignKey("roles.id"), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )

    op.create_table(
        "audit_log",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("request_id", sa.Text, nullable=False),
        sa.Column("event_type", sa.Text, nullable=False),
        sa.Column("actor_id", sa.Text, nullable=True),
        sa.Column("actor_username", sa.Text, nullable=True),
        sa.Column("engagement_id", sa.Text, nullable=True),
        sa.Column("resource_type", sa.Text, nullable=True),
        sa.Column("resource_id", sa.Text, nullable=True),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("details", sa.dialects.postgresql.JSONB, nullable=True),
        sa.Column("ip_address", sa.Text, nullable=True),
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )
    op.create_index("ix_audit_actor_id", "audit_log", ["actor_id"])
    op.create_index("ix_audit_engagement_id", "audit_log", ["engagement_id"])
    op.create_index("ix_audit_event_type", "audit_log", ["event_type"])
    op.create_index("ix_audit_created_at", "audit_log", ["created_at"])

    # =========================================================================
    # ENGAGEMENT MANAGEMENT
    # =========================================================================

    op.create_table(
        "engagements",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("client_name", sa.Text, nullable=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("status", sa.Text, nullable=False,
                  server_default="'active'"),
        sa.Column("is_active", sa.Boolean, nullable=False,
                  server_default="true"),
        sa.Column("created_by", sa.Text,
                  sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("archived_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.create_index("ix_engagements_status", "engagements", ["status"])

    op.create_table(
        "engagement_users",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("engagement_id", sa.Text,
                  sa.ForeignKey("engagements.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("user_id", sa.Text,
                  sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("role", sa.Text, nullable=False,
                  server_default="'analyst'"),
        sa.Column("assigned_by", sa.Text, nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.UniqueConstraint("engagement_id", "user_id",
                            name="uq_engagement_users"),
    )
    op.create_index("ix_eu_engagement_id", "engagement_users",
                    ["engagement_id"])
    op.create_index("ix_eu_user_id", "engagement_users", ["user_id"])

    op.create_table(
        "assessment_types",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("name", sa.Text, nullable=False, unique=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False,
                  server_default="true"),
    )

    op.create_table(
        "policies",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("engagement_id", sa.Text,
                  sa.ForeignKey("engagements.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("assessment_type_id", sa.Text,
                  sa.ForeignKey("assessment_types.id"), nullable=True),
        sa.Column("rules", sa.dialects.postgresql.JSONB, nullable=False,
                  server_default=sa.text("'[]'::jsonb")),
        sa.Column("schema_version", sa.Text, nullable=False,
                  server_default="'2.0'"),
        sa.Column("is_active", sa.Boolean, nullable=False,
                  server_default="true"),
        sa.Column("created_by", sa.Text,
                  sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )
    op.create_index("ix_policies_engagement_id", "policies",
                    ["engagement_id"])

    op.create_table(
        "policy_versions",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("policy_id", sa.Text,
                  sa.ForeignKey("policies.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("version_number", sa.Integer, nullable=False),
        sa.Column("rules_snapshot", sa.dialects.postgresql.JSONB,
                  nullable=False),
        sa.Column("rules_hash", sa.Text, nullable=False),
        sa.Column("created_by", sa.Text, nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.UniqueConstraint("policy_id", "version_number",
                            name="uq_policy_versions"),
    )

    op.create_table(
        "scan_configurations",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("engagement_id", sa.Text,
                  sa.ForeignKey("engagements.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("config", sa.dialects.postgresql.JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("is_active", sa.Boolean, nullable=False,
                  server_default="true"),
        sa.Column("created_by", sa.Text,
                  sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )
    op.create_index("ix_scan_cfg_engagement_id", "scan_configurations",
                    ["engagement_id"])

    # =========================================================================
    # JOB QUEUE
    # =========================================================================

    op.create_table(
        "job_queue",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("job_type", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False,
                  server_default="'pending'"),
        sa.Column("engagement_id", sa.Text, nullable=True),
        sa.Column("payload", sa.dialects.postgresql.JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("result", sa.dialects.postgresql.JSONB, nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("priority", sa.Integer, nullable=False,
                  server_default="5"),
        sa.Column("attempts", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("max_attempts", sa.Integer, nullable=False,
                  server_default="3"),
        sa.Column("created_by", sa.Text, nullable=True),
        sa.Column("claimed_by", sa.Text, nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("started_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("completed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("scheduled_for", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.create_index("ix_jq_status", "job_queue", ["status"])
    op.create_index("ix_jq_job_type", "job_queue", ["job_type"])
    op.create_index("ix_jq_engagement_id", "job_queue", ["engagement_id"])
    op.create_index("ix_jq_pending_poll", "job_queue",
                    ["status", "priority", "created_at"])

    # =========================================================================
    # PKI
    # =========================================================================

    op.create_table(
        "internal_ca",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("certificate_pem", sa.Text, nullable=False),
        sa.Column("certificate_serial", sa.Text, nullable=False, unique=True),
        sa.Column("subject", sa.Text, nullable=False),
        sa.Column("private_key_ref", sa.Text, nullable=False),
        sa.Column("issued_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("status", sa.Text, nullable=False,
                  server_default="'active'"),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )

    op.create_table(
        "engagement_cas",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("engagement_id", sa.Text,
                  sa.ForeignKey("engagements.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("certificate_pem", sa.Text, nullable=False),
        sa.Column("certificate_serial", sa.Text, nullable=False, unique=True),
        sa.Column("subject", sa.Text, nullable=False),
        sa.Column("issuer", sa.Text, nullable=False),
        sa.Column("public_key_pem", sa.Text, nullable=False),
        sa.Column("private_key_ref", sa.Text, nullable=False),
        sa.Column("issued_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("status", sa.Text, nullable=False,
                  server_default="'active'"),
        sa.Column("rotation_count", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.UniqueConstraint("engagement_id", "status",
                            name="uq_engagement_ca_status"),
    )
    op.create_index("ix_eca_engagement_id", "engagement_cas",
                    ["engagement_id"])

    op.create_table(
        "collector_certificates",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("engagement_id", sa.Text,
                  sa.ForeignKey("engagements.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("collector_id", sa.Text, nullable=False),
        sa.Column("certificate_pem", sa.Text, nullable=False),
        sa.Column("certificate_serial", sa.Text, nullable=False, unique=True),
        sa.Column("subject", sa.Text, nullable=False),
        sa.Column("issued_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("status", sa.Text, nullable=False,
                  server_default="'active'"),
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )
    op.create_index("ix_cc_engagement_id", "collector_certificates",
                    ["engagement_id"])
    op.create_index("ix_cc_collector_id", "collector_certificates",
                    ["collector_id"])

    op.create_table(
        "dashboard_certificates",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("engagement_id", sa.Text, nullable=True),
        sa.Column("certificate_pem", sa.Text, nullable=False),
        sa.Column("certificate_serial", sa.Text, nullable=False, unique=True),
        sa.Column("subject", sa.Text, nullable=False),
        sa.Column("private_key_ref", sa.Text, nullable=False),
        sa.Column("issued_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("status", sa.Text, nullable=False,
                  server_default="'active'"),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )

    # =========================================================================
    # SECRET MANAGEMENT
    # =========================================================================

    op.create_table(
        "secret_stores",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("name", sa.Text, nullable=False, unique=True),
        sa.Column("provider_type", sa.Text, nullable=False),
        sa.Column("connection_config", sa.dialects.postgresql.JSONB,
                  nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("status", sa.Text, nullable=False,
                  server_default="'active'"),
        sa.Column("last_health_check", sa.TIMESTAMP(timezone=True),
                  nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )

    op.create_table(
        "secret_references",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("secret_id", sa.Text, nullable=False, unique=True),
        sa.Column("store_id", sa.Text,
                  sa.ForeignKey("secret_stores.id"), nullable=True),
        sa.Column("backend_type", sa.Text, nullable=False),
        sa.Column("secret_name", sa.Text, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("engagement_id", sa.Text, nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )

    # =========================================================================
    # SEED DATA
    # =========================================================================

    op.execute("""
        INSERT INTO roles (id, name, description, is_system_role) VALUES
        (gen_random_uuid()::text, 'system-admin',
         'Full system access', true),
        (gen_random_uuid()::text, 'engagement-admin',
         'Manage engagements and their members', true),
        (gen_random_uuid()::text, 'analyst',
         'Create scans, view results', true),
        (gen_random_uuid()::text, 'viewer',
         'Read-only access to engagement data', true)
    """)

    op.execute("""
        INSERT INTO role_permissions (id, role_id, permission)
        SELECT gen_random_uuid()::text, r.id, p.permission
        FROM roles r
        CROSS JOIN (VALUES
            ('users:read'),('users:create'),('users:update'),('users:delete'),
            ('engagements:read'),('engagements:create'),('engagements:update'),
            ('engagements:delete'),('engagements:assign_users'),
            ('scans:read'),('scans:create'),('scans:update'),
            ('scans:delete'),('scans:execute'),
            ('reports:read'),('reports:create'),('reports:delete'),
            ('policies:read'),('policies:create'),
            ('policies:update'),('policies:delete'),
            ('scan_configs:read'),('scan_configs:create'),
            ('scan_configs:update'),('scan_configs:delete'),
            ('inventory:read'),('inventory:sync'),
            ('scan_logs:read'),
            ('auth_providers:read'),('auth_providers:create'),
            ('auth_providers:update'),('auth_providers:delete'),
            ('secret_stores:read'),('secret_stores:create'),
            ('secret_stores:update'),('secret_stores:delete'),
            ('certificates:read'),('certificates:issue'),
            ('certificates:revoke'),
            ('audit_log:read'),('admin:bootstrap')
        ) AS p(permission)
        WHERE r.name = 'system-admin'
    """)

    op.execute("""
        INSERT INTO role_permissions (id, role_id, permission)
        SELECT gen_random_uuid()::text, r.id, p.permission
        FROM roles r
        CROSS JOIN (VALUES
            ('engagements:read'),('engagements:create'),
            ('engagements:update'),('engagements:assign_users'),
            ('scans:read'),('scans:create'),
            ('scans:update'),('scans:execute'),
            ('reports:read'),('reports:create'),
            ('policies:read'),('policies:create'),('policies:update'),
            ('scan_configs:read'),('scan_configs:create'),
            ('scan_configs:update'),
            ('inventory:read'),('scan_logs:read'),
            ('certificates:read'),('certificates:issue')
        ) AS p(permission)
        WHERE r.name = 'engagement-admin'
    """)

    op.execute("""
        INSERT INTO role_permissions (id, role_id, permission)
        SELECT gen_random_uuid()::text, r.id, p.permission
        FROM roles r
        CROSS JOIN (VALUES
            ('engagements:read'),
            ('scans:read'),('scans:create'),('scans:execute'),
            ('reports:read'),('reports:create'),
            ('policies:read'),
            ('scan_configs:read'),('scan_configs:create'),
            ('inventory:read'),('scan_logs:read')
        ) AS p(permission)
        WHERE r.name = 'analyst'
    """)

    op.execute("""
        INSERT INTO role_permissions (id, role_id, permission)
        SELECT gen_random_uuid()::text, r.id, p.permission
        FROM roles r
        CROSS JOIN (VALUES
            ('engagements:read'),('scans:read'),
            ('reports:read'),('policies:read'),
            ('scan_configs:read'),('inventory:read')
        ) AS p(permission)
        WHERE r.name = 'viewer'
    """)

    op.execute("""
        INSERT INTO assessment_types (id, name, description) VALUES
        (gen_random_uuid()::text, 'pki_assessment',
         'PKI certificate and key assessment'),
        (gen_random_uuid()::text, 'pqc_assessment',
         'Post-quantum cryptography readiness assessment')
    """)


def downgrade() -> None:
    for table in [
        "secret_references", "secret_stores",
        "dashboard_certificates", "collector_certificates",
        "engagement_cas", "internal_ca",
        "job_queue",
        "scan_configurations", "policy_versions", "policies",
        "assessment_types", "engagement_users", "engagements",
        "audit_log", "auth_providers", "api_keys",
        "user_role_assignments", "role_permissions", "users", "roles",
    ]:
        op.drop_table(table)
