"""
Alembic migration environment for 0xRecon.

Uses psycopg2 (sync) for migration execution.
RECON_DATABASE_URL_SYNC env var is set inside the container.

Directory is migrations/ NOT alembic/ — avoids package shadowing.
"""
from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool
from sqlalchemy.engine import Connection

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Phase 2+: import and assign table metadata here as tables are defined.
# from recon_api.db.tables import metadata
# target_metadata = metadata
target_metadata = None

# Use sync URL for Alembic
database_url = os.environ.get("RECON_DATABASE_URL_SYNC", "")
if not database_url:
    # Derive sync URL from async URL as fallback
    async_url = os.environ.get("RECON_DATABASE_URL", "")
    database_url = async_url.replace("postgresql+asyncpg://", "postgresql+psycopg2://")

config.set_main_option("sqlalchemy.url", database_url)


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = create_engine(
        config.get_main_option("sqlalchemy.url"),
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        do_run_migrations(connection)
    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
