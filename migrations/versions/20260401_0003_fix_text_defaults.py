"""Fix text column defaults that were double-quoted.

Revision ID: 0003
Revises: 0002
Create Date: 2026-04-01

The Phase 2A migration used server_default="'value'" for Text columns,
which produced triple-quoted defaults ('''value'''). This fixes all
affected columns to use plain string defaults, and cleans up any
existing rows that have the quoted values.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Fix column defaults
    op.execute("ALTER TABLE projects ALTER COLUMN status SET DEFAULT 'active'")
    op.execute("ALTER TABLE job_queue ALTER COLUMN status SET DEFAULT 'pending'")
    op.execute("ALTER TABLE internal_ca ALTER COLUMN status SET DEFAULT 'active'")
    op.execute("ALTER TABLE project_cas ALTER COLUMN status SET DEFAULT 'active'")
    op.execute("ALTER TABLE collector_certificates ALTER COLUMN status SET DEFAULT 'active'")
    op.execute("ALTER TABLE dashboard_certificates ALTER COLUMN status SET DEFAULT 'active'")
    op.execute("ALTER TABLE secret_stores ALTER COLUMN status SET DEFAULT 'active'")
    op.execute("ALTER TABLE project_users ALTER COLUMN role SET DEFAULT 'analyst'")
    op.execute("ALTER TABLE policies ALTER COLUMN schema_version SET DEFAULT '2.0'")

    # Clean up any existing rows with quoted defaults
    op.execute("UPDATE job_queue SET status = 'pending' WHERE status = '''pending'''")
    op.execute("UPDATE projects SET status = 'active' WHERE status = '''active'''")
    op.execute("UPDATE internal_ca SET status = 'active' WHERE status = '''active'''")
    op.execute("UPDATE project_cas SET status = 'active' WHERE status = '''active'''")
    op.execute("UPDATE collector_certificates SET status = 'active' WHERE status = '''active'''")
    op.execute("UPDATE dashboard_certificates SET status = 'active' WHERE status = '''active'''")
    op.execute("UPDATE secret_stores SET status = 'active' WHERE status = '''active'''")
    op.execute("UPDATE project_users SET role = 'analyst' WHERE role = '''analyst'''")
    op.execute("UPDATE policies SET schema_version = '2.0' WHERE schema_version = '''2.0'''")


def downgrade() -> None:
    pass
