#!/bin/bash
# =============================================================
# 0xRecon — Deploy Update
# =============================================================
# Pulls latest code from GitHub and rebuilds the stack.
# Run this for iterative deployments after the initial install.
#
# Usage:
#   bash install-azure/deploy-update.sh
#
# What it does:
#   1. Pull latest code from origin/main
#   2. Stop the service
#   3. Rebuild Docker images
#   4. Start the service
#   5. Wait for healthy API
#   6. Run smoke test
#
# Safe to run multiple times. Does not touch:
#   - Database volumes (data persists)
#   - Environment file (/etc/0xrecon/app.env)
#   - Nginx config
#   - Systemd unit
# =============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_section() { echo -e "\n${BLUE}== $1 ==${NC}"; }
log_ok()      { echo -e "${GREEN}  + $1${NC}"; }
log_warn()    { echo -e "${YELLOW}  ! $1${NC}"; }
log_error()   { echo -e "${RED}  x $1${NC}"; }
log_info()    { echo -e "  > $1"; }

# -- Load configuration ---------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_FILE="${SCRIPT_DIR}/deployment.conf"

if [ ! -f "$CONF_FILE" ]; then
    log_error "deployment.conf not found at $CONF_FILE"
    exit 1
fi

source "$CONF_FILE"

DOCKER_PROJECT="${DOCKER_PROJECT_NAME:-0xrecon}"
API_PORT="${RECON_API_PORT:-8000}"

echo ""
echo -e "${BLUE}+==============================================================+${NC}"
echo -e "${BLUE}|          0xRecon Deploy Update                                |${NC}"
echo -e "${BLUE}+==============================================================+${NC}"
echo ""

# -- Step 1: Pull latest code ---------------------------------
log_section "Step 1/6 — Pull latest code"

cd "${DEPLOY_PATH}"

BEFORE_SHA=$(git rev-parse --short HEAD)
sudo -u "${SERVICE_ACCOUNT}" git pull origin main
AFTER_SHA=$(git rev-parse --short HEAD)

if [ "$BEFORE_SHA" = "$AFTER_SHA" ]; then
    log_warn "No new commits — already at ${AFTER_SHA}"
    read -r -p "Continue with rebuild anyway? [y/N] " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
else
    log_ok "Updated: ${BEFORE_SHA} -> ${AFTER_SHA}"
    log_info "Commits pulled:"
    git log --oneline "${BEFORE_SHA}..${AFTER_SHA}" | head -20
fi

# -- Step 2: Stop the service ---------------------------------
log_section "Step 2/6 — Stop service"

sudo systemctl stop 0xrecon.service 2>/dev/null || true
sleep 3

# Verify containers are down
RUNNING=$(docker ps --filter "name=${DOCKER_PROJECT}" --format "{{.Names}}" | wc -l)
if [ "$RUNNING" -gt 0 ]; then
    log_warn "${RUNNING} containers still running — forcing down"
    sudo -u "${SERVICE_ACCOUNT}" docker compose \
        -p "${DOCKER_PROJECT}" \
        -f docker-compose.yml \
        -f docker-compose.prod.yml \
        down 2>/dev/null || true
fi

log_ok "Service stopped"

# -- Step 3: Rebuild images -----------------------------------
log_section "Step 3/6 — Rebuild Docker images"

sudo -u "${SERVICE_ACCOUNT}" docker compose \
    -p "${DOCKER_PROJECT}" \
    -f docker-compose.yml \
    -f docker-compose.prod.yml \
    build --no-cache

log_ok "Images rebuilt"

# -- Step 4: Start the service --------------------------------
log_section "Step 4/6 — Start service"

sudo systemctl start 0xrecon.service
log_ok "Service started"

# -- Step 5: Wait for healthy API ------------------------------
log_section "Step 5/6 — Wait for healthy API"

MAX_WAIT=180
WAITED=0
INTERVAL=10
API_HEALTHY=false

while [ $WAITED -lt $MAX_WAIT ]; do
    sleep $INTERVAL
    WAITED=$((WAITED + INTERVAL))

    HEALTH=$(curl -sf "http://127.0.0.1:${API_PORT}/api/v1/health/" 2>/dev/null || echo "")
    if echo "$HEALTH" | grep -q "db_connected"; then
        API_HEALTHY=true
        break
    fi

    log_info "Waiting for API... (${WAITED}s elapsed)"
done

if [ "$API_HEALTHY" = true ]; then
    log_ok "API healthy"
    echo "  $HEALTH"
else
    log_error "API did not become healthy within ${MAX_WAIT}s"
    log_info "Check logs: docker compose -p ${DOCKER_PROJECT} logs recon-api --tail 50"
    exit 1
fi

# Check Alembic revision
ALEMBIC_REV=$(docker compose -p "${DOCKER_PROJECT}" exec recon-api \
    alembic -c migrations/alembic.ini current 2>&1 | grep -oP '\d+' | head -1 || echo "unknown")
log_ok "Alembic revision: ${ALEMBIC_REV}"

# -- Step 6: Run smoke test -----------------------------------
log_section "Step 6/6 — Smoke test"

SMOKE_SCRIPT="${SCRIPT_DIR}/smoke-test.sh"
if [ -f "$SMOKE_SCRIPT" ]; then
    bash "$SMOKE_SCRIPT"
else
    log_warn "smoke-test.sh not found — skipping"
fi

echo ""
echo -e "${GREEN}  Deploy update complete: ${BEFORE_SHA} -> ${AFTER_SHA}${NC}"
echo ""
