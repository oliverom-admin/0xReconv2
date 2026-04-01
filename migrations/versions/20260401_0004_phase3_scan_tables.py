"""Phase 3 scan tables.

Revision ID: 0004
Revises: 0003
Create Date: 2026-04-01

Tables created (7):
  scans, scan_runs, scan_logs, scan_results, findings,
  remote_collectors, connector_sync_status
"""
from __future__ import annotations
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:

    op.create_table("scans",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("project_id", sa.Text,
                  sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("config_id", sa.Text,
                  sa.ForeignKey("scan_configurations.id"), nullable=True),
        sa.Column("policy_id", sa.Text,
                  sa.ForeignKey("policies.id"), nullable=True),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("assessment_type", sa.Text, nullable=False,
                  server_default=sa.text("'pki_assessment'")),
        sa.Column("status", sa.Text, nullable=False,
                  server_default=sa.text("'never_run'")),
        sa.Column("last_run_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_run_number", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("collector_results", sa.dialects.postgresql.JSONB, nullable=True),
        sa.Column("created_by", sa.Text, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )
    op.create_index("ix_scans_project_id", "scans", ["project_id"])
    op.create_index("ix_scans_status", "scans", ["status"])

    op.create_table("scan_runs",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("scan_id", sa.Text,
                  sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("run_number", sa.Integer, nullable=False),
        sa.Column("status", sa.Text, nullable=False,
                  server_default=sa.text("'running'")),
        sa.Column("job_id", sa.Text,
                  sa.ForeignKey("job_queue.id"), nullable=True),
        sa.Column("started_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("completed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("certificates_found", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("keys_found", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("findings_count", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("collector_stats", sa.dialects.postgresql.JSONB, nullable=True),
    )
    op.create_index("ix_scan_runs_scan_id", "scan_runs", ["scan_id"])

    op.create_table("scan_logs",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("scan_id", sa.Text,
                  sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("run_number", sa.Integer, nullable=False, server_default="1"),
        sa.Column("level", sa.Text, nullable=False, server_default=sa.text("'info'")),
        sa.Column("message", sa.Text, nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )
    op.create_index("ix_scan_logs_scan_id", "scan_logs", ["scan_id"])

    op.create_table("scan_results",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("scan_id", sa.Text,
                  sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("run_number", sa.Integer, nullable=False),
        sa.Column("collector_type", sa.Text, nullable=False),
        sa.Column("result_blob", sa.dialects.postgresql.JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("certificates_count", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("keys_count", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )
    op.create_index("ix_scan_results_scan_id", "scan_results", ["scan_id"])

    op.create_table("findings",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("scan_id", sa.Text,
                  sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("run_number", sa.Integer, nullable=False),
        sa.Column("rule_id", sa.Text, nullable=False),
        sa.Column("rule_name", sa.Text, nullable=False),
        sa.Column("severity", sa.Text, nullable=False),
        sa.Column("risk_score", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("remediation", sa.Text, nullable=True),
        sa.Column("evidence", sa.dialects.postgresql.JSONB, nullable=True),
        sa.Column("compliance_impact", sa.Text, nullable=True),
        sa.Column("category", sa.Text, nullable=True),
        sa.Column("affected_asset_id", sa.Text, nullable=True),
        sa.Column("affected_asset_type", sa.Text, nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_rule_id", "findings", ["rule_id"])

    op.create_table("remote_collectors",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("collector_id", sa.Text, nullable=False, unique=True),
        sa.Column("project_id", sa.Text,
                  sa.ForeignKey("projects.id"), nullable=True),
        sa.Column("name", sa.Text, nullable=True),
        sa.Column("status", sa.Text, nullable=False,
                  server_default=sa.text("'pending_registration'")),
        sa.Column("certificate_id", sa.Text,
                  sa.ForeignKey("collector_certificates.id"), nullable=True),
        sa.Column("last_heartbeat_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("agent_version", sa.Text, nullable=True),
        sa.Column("metadata", sa.dialects.postgresql.JSONB, nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )

    op.create_table("connector_sync_status",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("connector_id", sa.Text, nullable=False, unique=True),
        sa.Column("connector_type", sa.Text, nullable=False),
        sa.Column("last_sync_started", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_sync_completed", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_sync_status", sa.Text, nullable=True),
        sa.Column("last_sync_error", sa.Text, nullable=True),
        sa.Column("last_sync_duration_seconds", sa.Float, nullable=True),
        sa.Column("items_total", sa.Integer, nullable=True),
        sa.Column("items_added", sa.Integer, nullable=True),
        sa.Column("items_updated", sa.Integer, nullable=True),
        sa.Column("items_removed", sa.Integer, nullable=True),
        sa.Column("consecutive_failures", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("next_sync_due", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("sync_interval_minutes", sa.Integer, nullable=False,
                  server_default="30"),
    )


def downgrade() -> None:
    for table in [
        "connector_sync_status", "remote_collectors",
        "findings", "scan_results", "scan_logs", "scan_runs", "scans",
    ]:
        op.drop_table(table)
