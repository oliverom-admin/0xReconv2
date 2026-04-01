#!/bin/bash
# recon-worker: wait for postgres and healthy API, then start worker.
# Does NOT run migrations — API container owns that.
set -e

echo "[worker] Starting 0xRecon Worker..."

echo "[worker] Waiting for PostgreSQL..."
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
    echo "[worker] Not ready, retrying in 2s..."
    sleep 2
done

echo "[worker] Waiting for API to be healthy..."
until curl -sf http://recon-api:8000/api/v1/health/ > /dev/null 2>&1; do
    echo "[worker] API not ready, retrying in 3s..."
    sleep 3
done
echo "[worker] API healthy."

exec python3 -m recon_api.worker.entrypoint
