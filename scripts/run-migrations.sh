#!/bin/bash
# Run Alembic inside the recon-api container.
# Usage: ./scripts/run-migrations.sh [upgrade head | current | history]
set -e
docker compose -p 0xrecon exec recon-api \
    alembic -c migrations/alembic.ini "${@:-upgrade head}"
