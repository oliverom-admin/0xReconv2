"""Phase 6A — report PKI tables (viewer certs, signing certs).

Revision ID: 0007
Revises: 0006
Create Date: 2026-04-03

Tables (2):
  user_digital_identities, project_signing_certs
"""
from __future__ import annotations
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:

    # ── User digital identities (viewer certs) ────────────────
    op.create_table("user_digital_identities",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("user_id", sa.Text,
                  sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("project_id", sa.Text,
                  sa.ForeignKey("projects.id", ondelete="CASCADE"),
                  nullable=True),
        sa.Column("cert_purpose", sa.Text, nullable=False,
                  server_default=sa.text("'report_viewer'")),
        sa.Column("report_ref", sa.Text, nullable=True),
        sa.Column("validity_days", sa.Integer, nullable=False,
                  server_default="30"),
        sa.Column("certificate_pem", sa.Text, nullable=False),
        sa.Column("certificate_serial", sa.Text, nullable=False, unique=True),
        sa.Column("public_key_pem", sa.Text, nullable=False),
        sa.Column("private_key_ref", sa.Text, nullable=True),
        sa.Column("issued_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("p12_generated_at", sa.TIMESTAMP(timezone=True),
                  nullable=True),
        sa.Column("p12_exported_at", sa.TIMESTAMP(timezone=True),
                  nullable=True),
        sa.Column("private_key_destroyed_at", sa.TIMESTAMP(timezone=True),
                  nullable=True),
        sa.Column("status", sa.Text, nullable=False,
                  server_default=sa.text("'pending_p12_creation'")),
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.Text, nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.UniqueConstraint("user_id", "project_id", "cert_purpose",
                            "report_ref",
                            name="uq_udi_user_project_purpose_ref"),
    )
    op.create_index("ix_udi_user_id", "user_digital_identities", ["user_id"])
    op.create_index("ix_udi_project_id", "user_digital_identities",
                    ["project_id"])
    op.create_index("ix_udi_status", "user_digital_identities", ["status"])
    op.create_index("ix_udi_expires_at", "user_digital_identities",
                    ["expires_at"])

    # ── Project signing certs ─────────────────────────────────
    op.create_table("project_signing_certs",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("project_id", sa.Text,
                  sa.ForeignKey("projects.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("certificate_pem", sa.Text, nullable=False),
        sa.Column("certificate_serial", sa.Text, nullable=False, unique=True),
        sa.Column("subject", sa.Text, nullable=False),
        sa.Column("issuer", sa.Text, nullable=False),
        sa.Column("public_key_pem", sa.Text, nullable=False),
        sa.Column("private_key_ref", sa.Text, nullable=False),
        sa.Column("issued_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("status", sa.Text, nullable=False,
                  server_default=sa.text("'active'")),
        sa.Column("rotation_count", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )
    op.create_index("ix_psc_project_id", "project_signing_certs",
                    ["project_id"])
    op.create_index("ix_psc_status", "project_signing_certs", ["status"])
    op.create_index("ix_psc_expires_at", "project_signing_certs",
                    ["expires_at"])


def downgrade() -> None:
    op.drop_table("project_signing_certs")
    op.drop_table("user_digital_identities")
