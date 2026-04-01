#!/bin/bash
# recon-api: wait for postgres, run migrations, start uvicorn.
set -e

echo "[entrypoint] Starting 0xRecon API..."

echo "[entrypoint] Waiting for PostgreSQL..."
until python3 -c "
import asyncio, asyncpg, os, sys
async def check():
    try:
        url = os.environ['RECON_DATABASE_URL'].replace('+asyncpg', '')
        conn = await asyncpg.connect(url)
        await conn.close()
    except Exception:
        sys.exit(1)
asyncio.run(check())
" 2>/dev/null; do
    echo "[entrypoint] Not ready, retrying in 2s..."
    sleep 2
done
echo "[entrypoint] PostgreSQL ready."

echo "[entrypoint] Running Alembic migrations..."
cd /app && alembic -c migrations/alembic.ini upgrade head
echo "[entrypoint] Migrations complete."

echo "[entrypoint] Starting uvicorn..."
exec uvicorn recon_api.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 4 \
    --log-level warning \
    --no-access-log
