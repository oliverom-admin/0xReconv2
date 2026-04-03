#!/bin/bash
# =============================================================================
# 0xRecon — Start development stack
# Usage: ./scripts/dev-up.sh [docker compose flags]
#
# Starts: recon-postgres, recon-api, recon-worker, recon-ui
# API available at:  http://localhost:8000
# UI available at:   http://localhost:3000
#
# Note: nginx runs on the host in production. It is not part of this stack.
# =============================================================================
set -e

echo "[dev-up] Starting 0xRecon development stack..."
docker compose -p 0xrecon -f docker-compose.yml up --build "$@"
