#!/bin/bash
# =============================================================================
# 0xRecon — Deploy / Upgrade Script
# Version: 0.2.0 | April 2026
#
# Pulls latest code, rebuilds changed images, performs a rolling restart.
# Alembic migrations run automatically on API container startup.
#
# Reads DOCKER_PROJECT and INSTALL_DIR from .env — set by server-setup.sh.
# Safe to run from any working directory; resolves paths from script location.
#
# Usage:
#   bash scripts/deploy.sh              ← deploy latest (git pull + rebuild)
#   bash scripts/deploy.sh --skip-pull  ← rebuild without pulling
#   bash scripts/deploy.sh --build-only ← build images, do not restart
#   bash scripts/deploy.sh --branch dev ← deploy a specific branch
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${BLUE}[deploy]${NC} $*"; }
success() { echo -e "${GREEN}[ok]${NC}     $*"; }
warn()    { echo -e "${YELLOW}[warn]${NC}   $*"; }
error()   { echo -e "${RED}[error]${NC}  $*"; exit 1; }

# ── Resolve install directory from script location ────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ── Parse arguments ───────────────────────────────────────────────────────────
BRANCH="main"
SKIP_PULL=false
BUILD_ONLY=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --branch)    BRANCH="$2"; shift 2 ;;
        --skip-pull) SKIP_PULL=true; shift ;;
        --build-only) BUILD_ONLY=true; shift ;;
        -h|--help)
            echo "Usage: bash scripts/deploy.sh [--branch BRANCH] [--skip-pull] [--build-only]"
            exit 0 ;;
        *) error "Unknown argument: $1" ;;
    esac
done

# ── Load configuration from .env ─────────────────────────────────────────────
cd "$APP_DIR"

[ -f ".env" ] || error ".env not found at $APP_DIR/.env — run server-setup.sh first"

# Source .env to get DOCKER_PROJECT (and other config)
set -a
# shellcheck disable=SC1091
source .env
set +a

# Apply defaults if not set in .env (backward compat with manually created .envs)
DOCKER_PROJECT="${DOCKER_PROJECT:-0xrecon}"

# ── Preflight checks ──────────────────────────────────────────────────────────
docker info > /dev/null 2>&1 || error "Docker is not running"
[ -f "docker-compose.yml" ] || error "docker-compose.yml not found — are you in the right directory?"

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo -e "  0xRecon Deploy"
echo -e "  Directory     : $APP_DIR"
echo -e "  Docker project: $DOCKER_PROJECT"
echo -e "  Branch        : $BRANCH"
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo ""

# ── Git pull ──────────────────────────────────────────────────────────────────
if [ "$SKIP_PULL" = false ]; then
    info "Pulling latest code from origin/$BRANCH..."

    # Stash local changes if any
    if ! git diff --quiet 2>/dev/null || ! git diff --staged --quiet 2>/dev/null; then
        warn "Local uncommitted changes detected — stashing"
        git stash push -m "deploy-auto-stash-$(date +%Y%m%d%H%M%S)"
    fi

    git fetch origin
    git checkout "$BRANCH"
    git pull origin "$BRANCH"
    success "Code: $(git log -1 --format='%h — %s (%ar)')"
else
    info "Skipping git pull (--skip-pull)"
    info "Current: $(git log -1 --format='%h — %s (%ar)' 2>/dev/null || echo 'unknown')"
fi

# ── Build images ──────────────────────────────────────────────────────────────
info "Building images (only changed layers rebuild)..."
docker compose \
    -p "$DOCKER_PROJECT" \
    -f docker-compose.yml \
    -f docker-compose.prod.yml \
    build \
    --parallel \
    2>&1 | grep -v "^#" | grep -v "^$" || true
success "Images built"

if [ "$BUILD_ONLY" = true ]; then
    success "Build complete (--build-only, not restarting)"
    exit 0
fi

# ── Capture pre-deploy Alembic state ─────────────────────────────────────────
PRE_ALEMBIC=$(docker compose -p "$DOCKER_PROJECT" exec recon-api \
    alembic -c migrations/alembic.ini current 2>/dev/null \
    | awk '{print $1}' || echo "offline")

info "Pre-deploy Alembic: $PRE_ALEMBIC"

# ── Rolling restart ───────────────────────────────────────────────────────────
info "Restarting containers..."
docker compose \
    -p "$DOCKER_PROJECT" \
    -f docker-compose.yml \
    -f docker-compose.prod.yml \
    up -d \
    --remove-orphans

# ── Wait for health ───────────────────────────────────────────────────────────
info "Waiting for API health check..."
MAX_WAIT=120
ELAPSED=0
HEALTHY=false

while [ $ELAPSED -lt $MAX_WAIT ]; do
    STATUS=$(curl -sk "https://localhost/api/v1/health/" \
        | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    print('ok' if d.get('status')=='ok' and d.get('db_connected') else 'not_ready')
except Exception:
    print('not_ready')
" 2>/dev/null || echo "not_ready")

    if [ "$STATUS" = "ok" ]; then
        HEALTHY=true
        break
    fi

    sleep 5
    ELAPSED=$((ELAPSED + 5))
    echo -n "."
done
echo ""

if [ "$HEALTHY" = false ]; then
    echo ""
    warn "API did not become healthy in ${MAX_WAIT}s. Showing recent logs:"
    docker compose -p "$DOCKER_PROJECT" logs recon-api --tail=20
    echo ""
    error "Deploy incomplete. Fix errors above and re-run."
fi

# ── Post-deploy state ─────────────────────────────────────────────────────────
POST_ALEMBIC=$(docker compose -p "$DOCKER_PROJECT" exec recon-api \
    alembic -c migrations/alembic.ini current 2>/dev/null \
    | awk '{print $1}' || echo "unknown")

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}Deploy complete!${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo ""
echo "  Commit  : $(git log -1 --format='%h — %s (%ar)' 2>/dev/null || echo 'unknown')"
echo "  Alembic : $PRE_ALEMBIC → $POST_ALEMBIC"
echo ""
docker compose -p "$DOCKER_PROJECT" ps --format "table {{.Name}}\t{{.Status}}"
echo ""
success "Health: OK  |  $(date)"
echo ""
