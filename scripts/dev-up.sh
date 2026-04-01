#!/bin/bash
# Start the development stack.
set -e
if [ ! -f "nginx/certs/dev.crt" ]; then
    echo "[dev-up] Generating dev TLS certificates..."
    bash scripts/gen-dev-certs.sh
fi
echo "[dev-up] Starting 0xRecon..."
docker compose -p 0xrecon -f docker-compose.yml up --build "$@"
