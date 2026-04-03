"""Phase 5 — report infrastructure, reassessment, aggregation, CSR, CRL.

Revision ID: 0006
Revises: 0005
Create Date: 2026-04-03

Tables (6):
  reports, project_reports, report_reassessments,
  report_aggregations, certificate_signing_reqs, revocation_list
"""
from __future__ import annotations
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:

    # ── Reports ───────────────────────────────────────────────
    op.create_table("reports",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("project_id", sa.Text,
                  sa.ForeignKey("projects.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("scan_id", sa.Text,
                  sa.ForeignKey("scans.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("report_type", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False,
                  server_default=sa.text("'pending'")),
        sa.Column("format", sa.Text, nullable=True),
        sa.Column("file_path", sa.Text, nullable=True),
        sa.Column("file_size_bytes", sa.Integer, nullable=True),
        sa.Column("is_encrypted", sa.Boolean, nullable=False,
                  server_default="false"),
        sa.Column("is_signed", sa.Boolean, nullable=False,
                  server_default="false"),
        sa.Column("encryption_metadata", sa.dialects.postgresql.JSONB,
                  nullable=True, server_default=sa.text("'{}'::jsonb")),
        sa.Column("generation_metadata", sa.dialects.postgresql.JSONB,
                  nullable=True, server_default=sa.text("'{}'::jsonb")),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("created_by", sa.Text,
                  sa.ForeignKey("users.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("completed_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.create_index("ix_reports_project_id", "reports", ["project_id"])
    op.create_index("ix_reports_scan_id", "reports", ["scan_id"])
    op.create_index("ix_reports_status", "reports", ["status"])
    op.create_index("ix_reports_report_type", "reports", ["report_type"])

    # ── Project-report join ───────────────────────────────────
    op.create_table("project_reports",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("project_id", sa.Text,
                  sa.ForeignKey("projects.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("report_id", sa.Text,
                  sa.ForeignKey("reports.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("assigned_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.UniqueConstraint("project_id", "report_id",
                            name="uq_project_reports_pid_rid"),
    )
    op.create_index("ix_project_reports_project_id", "project_reports",
                    ["project_id"])
    op.create_index("ix_project_reports_report_id", "project_reports",
                    ["report_id"])

    # ── Reassessments ─────────────────────────────────────────
    op.create_table("report_reassessments",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("project_id", sa.Text,
                  sa.ForeignKey("projects.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("original_scan_id", sa.Text,
                  sa.ForeignKey("scans.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("policy_id", sa.Text,
                  sa.ForeignKey("policies.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("output_report_id", sa.Text,
                  sa.ForeignKey("reports.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("status", sa.Text, nullable=False,
                  server_default=sa.text("'pending'")),
        sa.Column("enrichment_snapshot", sa.dialects.postgresql.JSONB,
                  nullable=True, server_default=sa.text("'{}'::jsonb")),
        sa.Column("result_summary", sa.dialects.postgresql.JSONB,
                  nullable=True, server_default=sa.text("'{}'::jsonb")),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("created_by", sa.Text,
                  sa.ForeignKey("users.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("completed_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.create_index("ix_reassessments_project_id", "report_reassessments",
                    ["project_id"])
    op.create_index("ix_reassessments_status", "report_reassessments",
                    ["status"])

    # ── Aggregations ──────────────────────────────────────────
    op.create_table("report_aggregations",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("project_id", sa.Text,
                  sa.ForeignKey("projects.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("merge_strategy", sa.Text, nullable=False,
                  server_default=sa.text("'union'")),
        sa.Column("source_scan_ids", sa.dialects.postgresql.JSONB,
                  nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("output_report_id", sa.Text,
                  sa.ForeignKey("reports.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("status", sa.Text, nullable=False,
                  server_default=sa.text("'pending'")),
        sa.Column("result_summary", sa.dialects.postgresql.JSONB,
                  nullable=True, server_default=sa.text("'{}'::jsonb")),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("created_by", sa.Text,
                  sa.ForeignKey("users.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("completed_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.create_index("ix_aggregations_project_id", "report_aggregations",
                    ["project_id"])
    op.create_index("ix_aggregations_status", "report_aggregations",
                    ["status"])

    # ── Certificate signing requests ──────────────────────────
    op.create_table("certificate_signing_reqs",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("project_id", sa.Text,
                  sa.ForeignKey("projects.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("requester_id", sa.Text,
                  sa.ForeignKey("users.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("collector_id", sa.Text, nullable=True),
        sa.Column("csr_pem", sa.Text, nullable=False),
        sa.Column("subject_cn", sa.Text, nullable=False),
        sa.Column("requested_purpose", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False,
                  server_default=sa.text("'pending'")),
        sa.Column("approved_by", sa.Text,
                  sa.ForeignKey("users.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("approved_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("issued_cert_serial", sa.Text, nullable=True),
        sa.Column("rejection_reason", sa.Text, nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )
    op.create_index("ix_csr_project_id", "certificate_signing_reqs",
                    ["project_id"])
    op.create_index("ix_csr_status", "certificate_signing_reqs", ["status"])
    op.create_index("ix_csr_requester_id", "certificate_signing_reqs",
                    ["requester_id"])

    # ── Revocation list ───────────────────────────────────────
    op.create_table("revocation_list",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("project_id", sa.Text,
                  sa.ForeignKey("projects.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("serial_number", sa.Text, nullable=False),
        sa.Column("cert_purpose", sa.Text, nullable=True),
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("revocation_reason", sa.Text, nullable=True,
                  server_default=sa.text("'unspecified'")),
        sa.Column("revoked_by", sa.Text,
                  sa.ForeignKey("users.id", ondelete="SET NULL"),
                  nullable=True),
        sa.UniqueConstraint("project_id", "serial_number",
                            name="uq_revocation_project_serial"),
    )
    op.create_index("ix_revocation_project_id", "revocation_list",
                    ["project_id"])
    op.create_index("ix_revocation_serial", "revocation_list",
                    ["serial_number"])


def downgrade() -> None:
    for table in [
        "revocation_list",
        "certificate_signing_reqs",
        "report_aggregations",
        "report_reassessments",
        "project_reports",
        "reports",
    ]:
        op.drop_table(table)
