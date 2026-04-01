"""Initial migration — install PostgreSQL extensions.

Revision ID: 0000
Revises:
Create Date: 2026-04-01

Phase 1: installs pgcrypto and uuid-ossp.
All table schemas added in Phase 2 as a subsequent revision.
"""
from __future__ import annotations
from typing import Sequence, Union
from alembic import op

revision: str = "0000"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')


def downgrade() -> None:
    # Extensions not dropped on downgrade — safe to leave installed.
    pass
