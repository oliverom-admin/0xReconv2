#!/bin/bash
# =============================================================
# 0xRecon — Deployment Smoke Test
# =============================================================
# Runs directly on the server against the live stack.
# Tests every layer from infrastructure up to authenticated API.
#
# Usage:
#   bash install-azure/smoke-test.sh
#
# Prerequisites:
#   - install.sh has completed successfully
#   - All containers are running
#
# Tests:
#   1.  Docker — all expected containers running
#   2.  PostgreSQL — accepting connections, database present, key tables exist
#   3.  recon-api health endpoint — db_connected: true
#   4.  recon-api product config — correct product_id
#   5.  Nginx — service active, config valid, HTTPS on both subdomains
#   6.  Unauthenticated request rejected (401/403)
#   7.  Login — obtain JWT token
#   8.  Authenticated — GET /api/v1/users/ returns 200
#   9.  Authenticated — GET /api/v1/projects/ returns 200
#   10. Database — users table has admin user, roles seeded
#   11. Worker — container running, no critical errors in logs
#   12. Container log health — no CRITICAL/Traceback in recent logs
# =============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

log_section() { echo -e "\n${BLUE}== $1 ==${NC}"; }
pass()        { echo -e "${GREEN}  + $1${NC}"; PASS=$((PASS + 1)); }
fail()        { echo -e "${RED}  x $1${NC}"; FAIL=$((FAIL + 1)); }
warn()        { echo -e "${YELLOW}  ! $1${NC}"; WARN=$((WARN + 1)); }
info()        { echo -e "  > $1"; }

# -- Load deployment config ------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_FILE="${SCRIPT_DIR}/deployment.conf"

if [ ! -f "$CONF_FILE" ]; then
    echo "deployment.conf not found — run from the install-azure directory"
    exit 1
fi

source "$CONF_FILE"

DOCKER_PROJECT="${DOCKER_PROJECT_NAME:-0xrecon}"
API_PORT="${RECON_API_PORT:-8000}"
UI_PORT="${RECON_UI_PORT:-3000}"
API_URL="api.${SUBDOMAIN_PREFIX}.${BASE_DOMAIN}"
APP_URL="app.${SUBDOMAIN_PREFIX}.${BASE_DOMAIN}"

echo ""
echo -e "${BLUE}+==============================================================+${NC}"
echo -e "${BLUE}|          0xRecon Smoke Test                                   |${NC}"
echo -e "${BLUE}+==============================================================+${NC}"
echo ""
echo "  Project:  ${DOCKER_PROJECT}"
echo "  API:      http://127.0.0.1:${API_PORT}"
echo "  API URL:  https://${API_URL}"
echo "  App URL:  https://${APP_URL}"
echo ""

# =============================================================
# TEST 1 — Docker containers
# =============================================================
log_section "Test 1 — Docker containers"

EXPECTED_CONTAINERS=(
    "recon-postgres"
    "recon-api"
    "recon-worker"
    "recon-ui"
)

for CONTAINER in "${EXPECTED_CONTAINERS[@]}"; do
    STATUS=$(docker inspect --format='{{.State.Status}}' \
        "${CONTAINER}" 2>/dev/null || echo "missing")
    if [ "$STATUS" = "running" ]; then
        pass "${CONTAINER} — running"
    elif [ "$STATUS" = "missing" ]; then
        fail "${CONTAINER} — not found"
    else
        fail "${CONTAINER} — status: ${STATUS}"
    fi
done

RESTARTING=$(docker ps --filter "name=${DOCKER_PROJECT}" \
    --format "{{.Names}} {{.Status}}" | grep -i "restarting" || true)
if [ -n "$RESTARTING" ]; then
    fail "Containers in restart loop: ${RESTARTING}"
else
    pass "No containers in restart loop"
fi

# =============================================================
# TEST 2 — PostgreSQL
# =============================================================
log_section "Test 2 — PostgreSQL"

PG_CONTAINER="recon-postgres"

if docker exec "${PG_CONTAINER}" pg_isready -U recon -d recon &>/dev/null; then
    pass "PostgreSQL accepting connections"
else
    fail "PostgreSQL not ready"
fi

# Database exists
EXISTS=$(docker exec "${PG_CONTAINER}" \
    psql -U recon -d recon -tAc \
    "SELECT 1 FROM pg_database WHERE datname='recon'" 2>/dev/null || echo "")
[ "$EXISTS" = "1" ] \
    && pass "Database 'recon' exists" \
    || fail "Database 'recon' not found"

# Key tables from migrations
for TABLE in users roles projects scans findings; do
    EXISTS=$(docker exec "${PG_CONTAINER}" \
        psql -U recon -d recon -tAc \
        "SELECT 1 FROM information_schema.tables WHERE table_name='${TABLE}'" \
        2>/dev/null || echo "")
    [ "$EXISTS" = "1" ] \
        && pass "Table '${TABLE}' exists" \
        || fail "Table '${TABLE}' not found — migrations may not have run"
done

# =============================================================
# TEST 3 — recon-api health
# =============================================================
log_section "Test 3 — recon-api health"

HEALTH_RESPONSE=$(curl -sf "http://127.0.0.1:${API_PORT}/api/v1/health/" \
    2>/dev/null || echo "")

if [ -n "$HEALTH_RESPONSE" ]; then
    pass "recon-api /api/v1/health/ responding"
    DB_CONNECTED=$(echo "${HEALTH_RESPONSE}" | \
        python3 -c "import json,sys; d=json.load(sys.stdin); \
        print(d.get('db_connected','false'))" 2>/dev/null || echo "false")
    if [ "$DB_CONNECTED" = "True" ] || [ "$DB_CONNECTED" = "true" ]; then
        pass "db_connected: true"
    else
        fail "db_connected: false — database connection problem"
    fi
else
    fail "recon-api /api/v1/health/ not responding"
fi

# =============================================================
# TEST 4 — Product config
# =============================================================
log_section "Test 4 — Product config"

PRODUCT_RESPONSE=$(curl -sf \
    "http://127.0.0.1:${API_PORT}/api/v1/product/config/" \
    2>/dev/null || echo "")

if [ -n "$PRODUCT_RESPONSE" ]; then
    pass "recon-api /api/v1/product/config/ responding"
    RETURNED_ID=$(echo "${PRODUCT_RESPONSE}" | \
        python3 -c "import json,sys; d=json.load(sys.stdin); \
        print(d.get('product_id',''))" 2>/dev/null || echo "")
    if [ "$RETURNED_ID" = "${PRODUCT_ID}" ]; then
        pass "product_id matches deployment.conf: ${RETURNED_ID}"
    else
        fail "product_id mismatch — expected '${PRODUCT_ID}', got '${RETURNED_ID}'"
    fi
else
    fail "recon-api /api/v1/product/config/ not responding"
fi

# =============================================================
# TEST 5 — Nginx
# =============================================================
log_section "Test 5 — Nginx"

if systemctl is-active nginx &>/dev/null; then
    pass "Nginx service active"
else
    fail "Nginx service not active"
fi

if nginx -t 2>/dev/null; then
    pass "Nginx config valid"
else
    fail "Nginx config invalid"
fi

# HTTPS on both subdomains
for SUBDOMAIN_URL in "${API_URL}" "${APP_URL}"; do
    HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
        --resolve "${SUBDOMAIN_URL}:443:127.0.0.1" \
        "https://${SUBDOMAIN_URL}/" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "404" ] || \
       [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ]; then
        pass "Nginx https://${SUBDOMAIN_URL} -> ${HTTP_CODE}"
    elif [ "$HTTP_CODE" = "000" ]; then
        fail "Nginx https://${SUBDOMAIN_URL} -> no response"
    else
        warn "Nginx https://${SUBDOMAIN_URL} -> unexpected ${HTTP_CODE}"
    fi
done

# =============================================================
# TEST 6 — Unauthenticated request rejected
# =============================================================
log_section "Test 6 — Auth enforcement"

UNAUTH_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${API_PORT}/api/v1/users/" 2>/dev/null || echo "000")
if [ "$UNAUTH_CODE" = "401" ] || [ "$UNAUTH_CODE" = "403" ]; then
    pass "Unauthenticated GET /users/ correctly rejected (${UNAUTH_CODE})"
elif [ "$UNAUTH_CODE" = "503" ]; then
    warn "GET /users/ returned 503 — may still be starting"
else
    fail "GET /users/ returned ${UNAUTH_CODE} — expected 401 or 403"
fi

# =============================================================
# TEST 7 — Login
# =============================================================
log_section "Test 7 — Login"

LOGIN_RESPONSE=$(curl -s \
    -X POST "http://127.0.0.1:${API_PORT}/api/v1/auth/login/" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${INITIAL_ADMIN_USERNAME}\",\"password\":\"${INITIAL_ADMIN_PASSWORD}\"}" \
    2>/dev/null || echo "")

TOKEN=$(echo "${LOGIN_RESPONSE}" | \
    python3 -c "import json,sys; d=json.load(sys.stdin); \
    print(d.get('data',{}).get('access_token',''))" 2>/dev/null || echo "")

if [ -n "$TOKEN" ] && [ "$TOKEN" != "" ]; then
    pass "Login successful — JWT obtained"
else
    fail "Login failed — cannot obtain JWT"
    info "Response: ${LOGIN_RESPONSE}"
fi

# =============================================================
# TEST 8 — Authenticated GET /users/
# =============================================================
log_section "Test 8 — Authenticated API (users)"

if [ -n "$TOKEN" ]; then
    USERS_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer ${TOKEN}" \
        "http://127.0.0.1:${API_PORT}/api/v1/users/" 2>/dev/null || echo "000")
    if [ "$USERS_CODE" = "200" ]; then
        pass "GET /api/v1/users/ -> 200 (authenticated)"
    else
        fail "GET /api/v1/users/ -> ${USERS_CODE} (expected 200)"
    fi
else
    warn "Skipped — no JWT token"
fi

# =============================================================
# TEST 9 — Authenticated GET /projects/
# =============================================================
log_section "Test 9 — Authenticated API (projects)"

if [ -n "$TOKEN" ]; then
    PROJECTS_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer ${TOKEN}" \
        "http://127.0.0.1:${API_PORT}/api/v1/projects/" 2>/dev/null || echo "000")
    if [ "$PROJECTS_CODE" = "200" ]; then
        pass "GET /api/v1/projects/ -> 200 (authenticated)"
    else
        fail "GET /api/v1/projects/ -> ${PROJECTS_CODE} (expected 200)"
    fi
else
    warn "Skipped — no JWT token"
fi

# =============================================================
# TEST 10 — Database content
# =============================================================
log_section "Test 10 — Database content"

ADMIN_EXISTS=$(docker exec "${PG_CONTAINER}" \
    psql -U recon -d recon -tAc \
    "SELECT count(*) FROM users WHERE username='${INITIAL_ADMIN_USERNAME}'" \
    2>/dev/null || echo "0")
[ "$ADMIN_EXISTS" = "1" ] \
    && pass "Admin user '${INITIAL_ADMIN_USERNAME}' exists in database" \
    || fail "Admin user not found in database (count=${ADMIN_EXISTS})"

ROLE_COUNT=$(docker exec "${PG_CONTAINER}" \
    psql -U recon -d recon -tAc \
    "SELECT count(*) FROM roles" 2>/dev/null || echo "0")
if [ "$ROLE_COUNT" -ge 4 ]; then
    pass "Roles seeded: ${ROLE_COUNT} roles"
else
    fail "Roles not seeded: only ${ROLE_COUNT} found (expected >= 4)"
fi

# =============================================================
# TEST 11 — Worker
# =============================================================
log_section "Test 11 — Worker"

WORKER_STATUS=$(docker inspect --format='{{.State.Status}}' \
    "recon-worker" 2>/dev/null || echo "missing")
if [ "$WORKER_STATUS" = "running" ]; then
    pass "recon-worker container running"
else
    fail "recon-worker status: ${WORKER_STATUS}"
fi

WORKER_ERRORS=$(docker logs recon-worker --tail 50 2>&1 | \
    grep -ci "CRITICAL\|Traceback\|FATAL" || true)
if [ "$WORKER_ERRORS" -eq 0 ]; then
    pass "No critical errors in worker logs (last 50 lines)"
else
    warn "Found ${WORKER_ERRORS} critical/traceback entries in worker logs"
fi

# =============================================================
# TEST 12 — Container log health
# =============================================================
log_section "Test 12 — Container log health"

for CONTAINER in recon-api recon-worker; do
    ERRORS=$(docker logs "${CONTAINER}" --tail 100 2>&1 | \
        grep -ci "CRITICAL\|FATAL" || true)
    TRACEBACKS=$(docker logs "${CONTAINER}" --tail 100 2>&1 | \
        grep -ci "Traceback" || true)
    if [ "$ERRORS" -eq 0 ] && [ "$TRACEBACKS" -eq 0 ]; then
        pass "${CONTAINER} — no CRITICAL/FATAL/Traceback in last 100 log lines"
    else
        warn "${CONTAINER} — ${ERRORS} critical errors, ${TRACEBACKS} tracebacks"
    fi
done

# =============================================================
# SUMMARY
# =============================================================
echo ""
echo -e "${BLUE}==============================================================${NC}"
echo ""
echo -e "  ${GREEN}PASS: ${PASS}${NC}    ${RED}FAIL: ${FAIL}${NC}    ${YELLOW}WARN: ${WARN}${NC}"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}  All critical tests passed.${NC}"
    if [ "$WARN" -gt 0 ]; then
        echo -e "${YELLOW}  ${WARN} warnings — review recommended.${NC}"
    fi
    echo ""
    exit 0
else
    echo -e "${RED}  ${FAIL} test(s) failed — investigate before proceeding.${NC}"
    echo ""
    exit 1
fi
