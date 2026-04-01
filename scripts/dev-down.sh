#!/bin/bash
# Stop the development stack.
set -e
docker compose -p 0xrecon -f docker-compose.yml down "$@"
