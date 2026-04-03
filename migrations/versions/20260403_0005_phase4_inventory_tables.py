"""Phase 4 — inventory, asset context, relationships, lifecycle.

Revision ID: 0005
Revises: 0004
Create Date: 2026-04-03

Tables created (9 new, 1 replaced):
  clm_integrations, certificates_inventory, keys_inventory,
  connector_sync_status (replaced), lifecycle_policies, inventory_changes,
  asset_context, asset_context_history, asset_relationships,
  enrichment_operations
"""
from __future__ import annotations
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:

    # ── CLM integration registry ─────────────────────────────
    op.create_table("clm_integrations",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("name", sa.Text, nullable=False, unique=True),
        sa.Column("type", sa.Text, nullable=False),
        sa.Column("config_json", sa.dialects.postgresql.JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("status", sa.Text, nullable=False,
                  server_default=sa.text("'active'")),
        sa.Column("enabled", sa.Boolean, nullable=False,
                  server_default="true"),
        sa.Column("cas_metadata", sa.dialects.postgresql.JSONB, nullable=True),
        sa.Column("last_sync", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )
    op.create_index("ix_clm_integrations_name", "clm_integrations", ["name"])
    op.create_index("ix_clm_integrations_type", "clm_integrations", ["type"])

    # ── Persistent certificate inventory ──────────────────────
    op.create_table("certificates_inventory",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("project_id", sa.Text,
                  sa.ForeignKey("projects.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("fingerprint_sha256", sa.Text, nullable=False),
        sa.Column("integration_id", sa.Text,
                  sa.ForeignKey("clm_integrations.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("normalised_data", sa.dialects.postgresql.JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("subject_cn", sa.Text, nullable=True),
        sa.Column("issuer_cn", sa.Text, nullable=True),
        sa.Column("not_after", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("days_until_expiry", sa.Integer, nullable=True),
        sa.Column("key_algorithm", sa.Text, nullable=True),
        sa.Column("key_size", sa.Integer, nullable=True),
        sa.Column("source_type", sa.Text, nullable=True),
        sa.Column("integration_name", sa.Text, nullable=True),
        sa.Column("is_promoted", sa.Boolean, nullable=False,
                  server_default="false"),
        sa.Column("promoted_from_scan_id", sa.Text,
                  sa.ForeignKey("scans.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("promoted_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("first_seen_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("last_seen_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("is_active", sa.Boolean, nullable=False,
                  server_default="true"),
        sa.UniqueConstraint("project_id", "fingerprint_sha256", "integration_id",
                            name="uq_cert_inv_project_fp_integration"),
    )
    op.create_index("ix_cert_inv_project_id", "certificates_inventory",
                    ["project_id"])
    op.create_index("ix_cert_inv_fingerprint", "certificates_inventory",
                    ["fingerprint_sha256"])
    op.create_index("ix_cert_inv_not_after", "certificates_inventory",
                    ["not_after"])
    op.create_index("ix_cert_inv_is_active", "certificates_inventory",
                    ["is_active"])

    # ── Persistent key inventory ──────────────────────────────
    op.create_table("keys_inventory",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("project_id", sa.Text,
                  sa.ForeignKey("projects.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("key_identifier", sa.Text, nullable=False),
        sa.Column("integration_id", sa.Text,
                  sa.ForeignKey("clm_integrations.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("normalised_data", sa.dialects.postgresql.JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("key_name", sa.Text, nullable=True),
        sa.Column("key_type", sa.Text, nullable=True),
        sa.Column("key_size", sa.Integer, nullable=True),
        sa.Column("source_type", sa.Text, nullable=True),
        sa.Column("integration_name", sa.Text, nullable=True),
        sa.Column("expires_on", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("days_until_expiry", sa.Integer, nullable=True),
        sa.Column("is_hsm_backed", sa.Boolean, nullable=False,
                  server_default="false"),
        sa.Column("is_promoted", sa.Boolean, nullable=False,
                  server_default="false"),
        sa.Column("promoted_from_scan_id", sa.Text,
                  sa.ForeignKey("scans.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("promoted_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("first_seen_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("last_seen_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("is_active", sa.Boolean, nullable=False,
                  server_default="true"),
        sa.UniqueConstraint("project_id", "key_identifier", "integration_id",
                            name="uq_key_inv_project_kid_integration"),
    )
    op.create_index("ix_key_inv_project_id", "keys_inventory", ["project_id"])
    op.create_index("ix_key_inv_key_identifier", "keys_inventory",
                    ["key_identifier"])
    op.create_index("ix_key_inv_is_active", "keys_inventory", ["is_active"])

    # ── Replace connector_sync_status with Phase 4 version ────
    # Phase 3 created this table but it was empty and lacked FK
    # to clm_integrations. Drop and recreate with proper schema.
    op.drop_table("connector_sync_status")
    op.create_table("connector_sync_status",
        sa.Column("integration_id", sa.Text,
                  sa.ForeignKey("clm_integrations.id", ondelete="CASCADE"),
                  primary_key=True),
        sa.Column("last_sync_started", sa.TIMESTAMP(timezone=True),
                  nullable=True),
        sa.Column("last_sync_completed", sa.TIMESTAMP(timezone=True),
                  nullable=True),
        sa.Column("last_sync_status", sa.Text, nullable=True),
        sa.Column("last_sync_error", sa.Text, nullable=True),
        sa.Column("last_sync_duration_s", sa.Float, nullable=True),
        sa.Column("items_total", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("items_added", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("items_updated", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("items_removed", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("next_sync_due", sa.TIMESTAMP(timezone=True),
                  nullable=True),
        sa.Column("sync_interval_minutes", sa.Integer, nullable=False,
                  server_default="30"),
        sa.Column("consecutive_failures", sa.Integer, nullable=False,
                  server_default="0"),
    )

    # ── Lifecycle policies ────────────────────────────────────
    op.create_table("lifecycle_policies",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("integration_id", sa.Text,
                  sa.ForeignKey("clm_integrations.id", ondelete="CASCADE"),
                  nullable=False, unique=True),
        sa.Column("renewal_threshold_days", sa.Integer, nullable=False,
                  server_default="90"),
        sa.Column("rotation_interval_days", sa.Integer, nullable=True),
        sa.Column("auto_action", sa.Text, nullable=True,
                  server_default=sa.text("'notify'")),
        sa.Column("notification_enabled", sa.Boolean, nullable=False,
                  server_default="true"),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )

    # ── Inventory change journal ──────────────────────────────
    op.create_table("inventory_changes",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("entity_type", sa.Text, nullable=False),
        sa.Column("entity_id", sa.Text, nullable=False),
        sa.Column("integration_id", sa.Text,
                  sa.ForeignKey("clm_integrations.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("project_id", sa.Text,
                  sa.ForeignKey("projects.id", ondelete="CASCADE"),
                  nullable=True),
        sa.Column("change_type", sa.Text, nullable=False),
        sa.Column("change_details", sa.dialects.postgresql.JSONB, nullable=True,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("detected_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )
    op.create_index("ix_inv_changes_project_id", "inventory_changes",
                    ["project_id"])
    op.create_index("ix_inv_changes_detected_at", "inventory_changes",
                    ["detected_at"])
    op.create_index("ix_inv_changes_entity_type", "inventory_changes",
                    ["entity_type"])

    # ── Asset context (business enrichment) ───────────────────
    op.create_table("asset_context",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("project_id", sa.Text,
                  sa.ForeignKey("projects.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("asset_id", sa.Text, nullable=False),
        sa.Column("asset_type", sa.Text, nullable=False),
        sa.Column("asset_name", sa.Text, nullable=True),
        sa.Column("source", sa.Text, nullable=True),
        sa.Column("business_unit", sa.Text, nullable=True),
        sa.Column("business_function", sa.Text, nullable=True),
        sa.Column("data_classification", sa.Text, nullable=True),
        sa.Column("dependencies", sa.Text, nullable=True),
        sa.Column("compliance_scope", sa.Text, nullable=True),
        sa.Column("migration_path", sa.Text, nullable=True),
        sa.Column("owner", sa.Text, nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("environment_type", sa.Text, nullable=True),
        sa.Column("service_name", sa.Text, nullable=True),
        sa.Column("application_name", sa.Text, nullable=True),
        sa.Column("discovery_method", sa.Text, nullable=True,
                  server_default=sa.text("'manual'")),
        sa.Column("discovery_confidence", sa.Float, nullable=True,
                  server_default="1.0"),
        sa.Column("override_enabled", sa.Boolean, nullable=True,
                  server_default="false"),
        sa.Column("override_score", sa.Integer, nullable=True),
        sa.Column("override_reason", sa.Text, nullable=True),
        sa.Column("changed_by", sa.Text, nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.UniqueConstraint("project_id", "asset_id",
                            name="uq_asset_context_project_asset"),
    )
    op.create_index("ix_asset_context_project_id", "asset_context",
                    ["project_id"])
    op.create_index("ix_asset_context_asset_id", "asset_context",
                    ["asset_id"])
    op.create_index("ix_asset_context_environment_type", "asset_context",
                    ["environment_type"])

    # ── Asset context history (audit trail) ───────────────────
    op.create_table("asset_context_history",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("context_id", sa.Text,
                  sa.ForeignKey("asset_context.id", ondelete="CASCADE"),
                  nullable=True),
        sa.Column("project_id", sa.Text, nullable=False),
        sa.Column("asset_id", sa.Text, nullable=False),
        sa.Column("asset_type", sa.Text, nullable=False),
        sa.Column("change_type", sa.Text, nullable=False),
        sa.Column("changed_by", sa.Text, nullable=True),
        sa.Column("changed_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.Column("previous_values", sa.dialects.postgresql.JSONB, nullable=True,
                  server_default=sa.text("'{}'::jsonb")),
    )
    op.create_index("ix_ctx_history_context_id", "asset_context_history",
                    ["context_id"])
    op.create_index("ix_ctx_history_asset_id", "asset_context_history",
                    ["asset_id"])
    op.create_index("ix_ctx_history_changed_at", "asset_context_history",
                    ["changed_at"])

    # ── Asset relationships ───────────────────────────────────
    op.create_table("asset_relationships",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("project_id", sa.Text,
                  sa.ForeignKey("projects.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("source_id", sa.Text, nullable=False),
        sa.Column("source_type", sa.Text, nullable=False),
        sa.Column("target_id", sa.Text, nullable=False),
        sa.Column("target_type", sa.Text, nullable=False),
        sa.Column("relationship_type", sa.Text, nullable=False),
        sa.Column("confidence", sa.Float, nullable=False,
                  server_default="1.0"),
        sa.Column("evidence", sa.dialects.postgresql.JSONB, nullable=True,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
        sa.UniqueConstraint("project_id", "source_id", "target_id",
                            "relationship_type",
                            name="uq_asset_rel_src_tgt_type"),
    )
    op.create_index("ix_asset_rel_project_id", "asset_relationships",
                    ["project_id"])
    op.create_index("ix_asset_rel_source_id", "asset_relationships",
                    ["source_id"])
    op.create_index("ix_asset_rel_target_id", "asset_relationships",
                    ["target_id"])

    # ── Enrichment operations ─────────────────────────────────
    op.create_table("enrichment_operations",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("project_id", sa.Text,
                  sa.ForeignKey("projects.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("operation_type", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False,
                  server_default=sa.text("'pending'")),
        sa.Column("assets_processed", sa.Integer, nullable=True,
                  server_default="0"),
        sa.Column("assets_enriched", sa.Integer, nullable=True,
                  server_default="0"),
        sa.Column("started_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("completed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("created_by", sa.Text, nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False,
                  server_default=sa.text("NOW()")),
    )


def downgrade() -> None:
    for table in [
        "enrichment_operations",
        "asset_relationships",
        "asset_context_history",
        "asset_context",
        "inventory_changes",
        "lifecycle_policies",
    ]:
        op.drop_table(table)

    # Restore Phase 3 connector_sync_status (original schema)
    op.drop_table("connector_sync_status")
    op.create_table("connector_sync_status",
        sa.Column("id", sa.Text, primary_key=True,
                  server_default=sa.text("gen_random_uuid()::text")),
        sa.Column("connector_id", sa.Text, nullable=False, unique=True),
        sa.Column("connector_type", sa.Text, nullable=False),
        sa.Column("last_sync_started", sa.TIMESTAMP(timezone=True),
                  nullable=True),
        sa.Column("last_sync_completed", sa.TIMESTAMP(timezone=True),
                  nullable=True),
        sa.Column("last_sync_status", sa.Text, nullable=True),
        sa.Column("last_sync_error", sa.Text, nullable=True),
        sa.Column("last_sync_duration_seconds", sa.Float, nullable=True),
        sa.Column("items_total", sa.Integer, nullable=True),
        sa.Column("items_added", sa.Integer, nullable=True),
        sa.Column("items_updated", sa.Integer, nullable=True),
        sa.Column("items_removed", sa.Integer, nullable=True),
        sa.Column("consecutive_failures", sa.Integer, nullable=False,
                  server_default="0"),
        sa.Column("next_sync_due", sa.TIMESTAMP(timezone=True),
                  nullable=True),
        sa.Column("sync_interval_minutes", sa.Integer, nullable=False,
                  server_default="30"),
    )

    for table in [
        "keys_inventory",
        "certificates_inventory",
        "clm_integrations",
    ]:
        op.drop_table(table)
