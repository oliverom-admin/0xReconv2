#!/bin/bash
# =============================================================
# 0xRecon — Install Script
# =============================================================
# Called automatically by setup.sh after bootstrap completes.
# Can also be run standalone to re-install or repair.
#
# Usage (via setup.sh — recommended):
#   bash install-azure/setup.sh
#
# Usage (standalone — requires bootstrap already completed):
#   sudo bash install-azure/install.sh
#
# Pre-requisites when running standalone:
#   - setup.sh bootstrap phase must have completed successfully
#   - deployment.conf must contain DEPLOY_KEY_PATH
#   - Service account must exist
#   - Deploy key must exist
#   - GitHub SSH connectivity must be verified
#
# Steps:
#   1.  Validate configuration
#   2.  System update and packages
#   3.  Install Docker
#   4.  Install Nginx
#   5.  Clone repository
#   6.  Create application directories
#   7.  Write environment file
#   8.  Write .env symlink
#   9.  Configure log rotation
#   10. Configure Nginx with TLS
#   11. Create systemd service and start
#   12. Wait for healthy API
#   13. Bootstrap first admin user
# =============================================================

set -euo pipefail

# -- Must run as root ------------------------------------------
if [ "$EUID" -ne 0 ]; then
    echo "install.sh must be run as root."
    echo "Use: sudo bash install-azure/install.sh"
    echo "Or run setup.sh which handles this automatically."
    exit 1
fi

# -- Colours ---------------------------------------------------
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

# -- Step 1: Validate configuration ---------------------------
log_section "Step 1/13 — Validate configuration"

REQUIRED_VARS=(
    DEPLOY_HOST DEPLOY_USER DEPLOY_PATH SERVICE_ACCOUNT
    BASE_DOMAIN SUBDOMAIN_PREFIX TLS_TYPE
    GITHUB_USER GITHUB_REPO GIT_USER_NAME GIT_USER_EMAIL
    DEPLOY_KEY_PATH
    POSTGRES_PASSWORD
    RECON_API_PORT RECON_UI_PORT
    RECON_SECRET_KEY RECON_VAULT_MASTER_PASSWORD
    PRODUCT_ID PRODUCT_NAME PRODUCT_SHORT_NAME
    INITIAL_ADMIN_USERNAME INITIAL_ADMIN_EMAIL INITIAL_ADMIN_PASSWORD
)

MISSING=()
for VAR in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!VAR:-}" ]; then
        MISSING+=("$VAR")
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    log_error "The following required variables are not set in deployment.conf:"
    for VAR in "${MISSING[@]}"; do
        echo "    $VAR"
    done
    log_info "DEPLOY_KEY_PATH is written by setup.sh — run setup.sh if missing"
    exit 1
fi

if [ ! -f "${DEPLOY_KEY_PATH}" ]; then
    log_error "Deploy key not found at ${DEPLOY_KEY_PATH}"
    log_info  "Run setup.sh to generate the deploy key"
    exit 1
fi

if ! id "${SERVICE_ACCOUNT}" &>/dev/null; then
    log_error "Service account '${SERVICE_ACCOUNT}' does not exist"
    log_info  "Run setup.sh to create the service account"
    exit 1
fi

log_ok "Configuration valid"

# -- Derived variables -----------------------------------------
API_URL="api.${SUBDOMAIN_PREFIX}.${BASE_DOMAIN}"
APP_URL="app.${SUBDOMAIN_PREFIX}.${BASE_DOMAIN}"
GITHUB_SSH_URL="git@github.com:${GITHUB_USER}/${GITHUB_REPO}.git"
GITHUB_HTTPS_URL="https://github.com/${GITHUB_USER}/${GITHUB_REPO}"
DOCKER_PROJECT="${DOCKER_PROJECT_NAME:-0xrecon}"

# -- Deployment summary ----------------------------------------
echo ""
echo "  Server:       ${DEPLOY_HOST}"
echo "  Install path: ${DEPLOY_PATH}"
echo "  API URL:      https://${API_URL}"
echo "  App URL:      https://${APP_URL}"
echo "  TLS type:     ${TLS_TYPE}"
echo "  GitHub:       ${GITHUB_HTTPS_URL}"
echo "  Product:      ${PRODUCT_NAME} (${PRODUCT_ID})"
echo ""

if [ -z "${SETUP_SH_CALLED:-}" ]; then
    read -r -p "Proceed with installation? [y/N] " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

# -- Step 2: System update -------------------------------------
log_section "Step 2/13 — System update"
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq curl gnupg ca-certificates git openssl
log_ok "System updated"

# -- Step 3: Install Docker ------------------------------------
log_section "Step 3/13 — Install Docker"

if command -v docker &>/dev/null; then
    log_info "Docker already installed: $(docker --version)"
else
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) \
        signed-by=/etc/apt/keyrings/docker.asc] \
        https://download.docker.com/linux/ubuntu \
        $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update -qq
    apt-get install -y -qq \
        docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin
fi

usermod -aG docker "${SERVICE_ACCOUNT}"
usermod -aG docker "${DEPLOY_USER}"
log_ok "Docker installed and configured"

# -- Step 4: Install Nginx -------------------------------------
log_section "Step 4/13 — Install Nginx"

if ! command -v nginx &>/dev/null; then
    apt-get install -y -qq nginx
fi
systemctl enable nginx
log_ok "Nginx installed"

# -- Step 5: Clone repository ---------------------------------
log_section "Step 5/13 — Clone repository"

log_info "Verifying GitHub SSH connection..."
SSH_RESULT=$(sudo -u "${SERVICE_ACCOUNT}" \
    ssh -T -o ConnectTimeout=10 \
    -o StrictHostKeyChecking=accept-new \
    git@github.com 2>&1 || true)

if ! echo "${SSH_RESULT}" | grep -q "successfully authenticated"; then
    log_error "GitHub SSH authentication failed"
    log_info  "Check deploy key at: ${GITHUB_HTTPS_URL}/settings/keys"
    exit 1
fi
log_ok "GitHub SSH verified"

if [ -d "${DEPLOY_PATH}/.git" ]; then
    log_info "Repository already cloned — pulling latest main"
    sudo -u "${SERVICE_ACCOUNT}" git -C "${DEPLOY_PATH}" pull origin main
elif [ ! -d "${DEPLOY_PATH}" ] || [ -z "$(ls -A "${DEPLOY_PATH}" 2>/dev/null)" ]; then
    log_info "Cloning repository into ${DEPLOY_PATH}"
    sudo -u "${SERVICE_ACCOUNT}" git clone "${GITHUB_SSH_URL}" "${DEPLOY_PATH}"
else
    log_error "Deploy path '${DEPLOY_PATH}' exists and is non-empty but has no .git directory"
    log_info  "To perform a clean install: bash install-azure/setup.sh teardown"
    exit 1
fi

sudo -u "${SERVICE_ACCOUNT}" git -C "${DEPLOY_PATH}" config user.name "${GIT_USER_NAME}"
sudo -u "${SERVICE_ACCOUNT}" git -C "${DEPLOY_PATH}" config user.email "${GIT_USER_EMAIL}"
log_ok "Repository ready at ${DEPLOY_PATH}"

# -- Step 6: Create application directories --------------------
log_section "Step 6/13 — Application directories"

chown "${SERVICE_ACCOUNT}:${SERVICE_ACCOUNT}" "${DEPLOY_PATH}"
chmod 775 "${DEPLOY_PATH}"

mkdir -p /var/log/0xrecon
chown "${SERVICE_ACCOUNT}:${SERVICE_ACCOUNT}" /var/log/0xrecon
chmod 775 /var/log/0xrecon

mkdir -p /etc/0xrecon
chown "${SERVICE_ACCOUNT}:${SERVICE_ACCOUNT}" /etc/0xrecon
chmod 770 /etc/0xrecon

log_ok "Directories ready"

# -- Step 7: Write environment file ----------------------------
log_section "Step 7/13 — Write environment file"

tee /etc/0xrecon/app.env > /dev/null << EOF
# Generated by install.sh — re-run setup.sh to regenerate
# Do not edit manually — changes will be overwritten on re-install

# Application
RECON_ENV=production
RECON_DEBUG=false
RECON_SECRET_KEY=${RECON_SECRET_KEY}
RECON_ALLOWED_ORIGINS=https://${APP_URL},https://${API_URL}

# Database
RECON_DATABASE_URL=postgresql+asyncpg://recon:${POSTGRES_PASSWORD}@recon-postgres:5432/recon
RECON_DATABASE_URL_SYNC=postgresql+psycopg2://recon:${POSTGRES_PASSWORD}@recon-postgres:5432/recon
POSTGRES_DB=recon
POSTGRES_USER=recon
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}

# JWT
RECON_JWT_ALGORITHM=HS256
RECON_JWT_EXPIRY_HOURS=8

# Vault
RECON_VAULT_PATH=/app/data/vault.enc
RECON_VAULT_MASTER_PASSWORD=${RECON_VAULT_MASTER_PASSWORD}

# Product identity
PRODUCT_ID=${PRODUCT_ID}
PRODUCT_NAME=${PRODUCT_NAME}
PRODUCT_SHORT_NAME=${PRODUCT_SHORT_NAME}
PRODUCT_LOGO_PATH=/static/${PRODUCT_ID}/logo.svg
PRODUCT_FAVICON_PATH=/static/${PRODUCT_ID}/favicon.ico
PRODUCT_ACCENT_COLOR=#00FF41
PRODUCT_TERMINOLOGY_JSON={}
PRODUCT_FEATURE_FLAGS_JSON={"show_dpod_dashboard": true, "show_pqc_migration": true, "show_document_assessment": true}
EOF

chmod 660 /etc/0xrecon/app.env
chown "${SERVICE_ACCOUNT}:${SERVICE_ACCOUNT}" /etc/0xrecon/app.env
log_ok "Environment file written to /etc/0xrecon/app.env"

# -- Step 8: Write .env symlink --------------------------------
log_section "Step 8/13 — Write .env symlink"

ln -sf /etc/0xrecon/app.env "${DEPLOY_PATH}/.env"
chown -h "${SERVICE_ACCOUNT}:${SERVICE_ACCOUNT}" "${DEPLOY_PATH}/.env"
log_ok ".env symlink created: ${DEPLOY_PATH}/.env -> /etc/0xrecon/app.env"

# -- Step 9: Configure log rotation ----------------------------
log_section "Step 9/13 — Log rotation"

tee /etc/logrotate.d/0xrecon > /dev/null << EOF
/var/log/0xrecon/*.log {
    daily
    rotate ${LOG_RETENTION_DAYS:-14}
    compress
    delaycompress
    missingok
    notifempty
    su ${SERVICE_ACCOUNT} ${SERVICE_ACCOUNT}
    create 664 ${SERVICE_ACCOUNT} ${SERVICE_ACCOUNT}
    sharedscripts
    postrotate
        systemctl kill --kill-who=main --signal=USR1 0xrecon.service 2>/dev/null || true
    endscript
}
EOF

log_ok "Log rotation configured"

# -- Step 10: Configure Nginx with TLS ------------------------
log_section "Step 10/13 — Configure Nginx"

mkdir -p /etc/nginx/ssl

if [ "$TLS_TYPE" = "self-signed" ]; then
    openssl req -x509 -nodes \
        -days "${TLS_CERT_DAYS:-3650}" \
        -newkey rsa:4096 \
        -keyout /etc/nginx/ssl/0xrecon.key \
        -out    /etc/nginx/ssl/0xrecon.crt \
        -subj "/CN=0xrecon/O=0xRecon/C=GB" \
        -addext "subjectAltName=DNS:${API_URL},DNS:${APP_URL}"
    chmod 600 /etc/nginx/ssl/0xrecon.key
    chmod 644 /etc/nginx/ssl/0xrecon.crt
    log_ok "Self-signed certificate generated"
    openssl x509 -in /etc/nginx/ssl/0xrecon.crt -noout -subject -dates

elif [ "$TLS_TYPE" = "internal-ca" ]; then
    cp "${TLS_CERT_PATH}" /etc/nginx/ssl/0xrecon.crt
    cp "${TLS_KEY_PATH}"  /etc/nginx/ssl/0xrecon.key
    chmod 600 /etc/nginx/ssl/0xrecon.key
    chmod 644 /etc/nginx/ssl/0xrecon.crt
    log_ok "Internal CA certificate installed"
fi

rm -f /etc/nginx/sites-enabled/default

tee /etc/nginx/sites-available/0xrecon > /dev/null << NGINXEOF
# 0xRecon — Nginx reverse proxy
# Generated by install.sh — do not edit manually

# -- HTTP redirect ---------------------------------------------
server {
    listen 80;
    server_name ${API_URL} ${APP_URL};
    return 301 https://\$host\$request_uri;
}

# -- API subdomain — recon-api (port ${RECON_API_PORT}) --------
server {
    listen 443 ssl;
    server_name ${API_URL};

    ssl_certificate     /etc/nginx/ssl/0xrecon.crt;
    ssl_certificate_key /etc/nginx/ssl/0xrecon.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;

    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;

    client_max_body_size 50m;

    location /api/ {
        proxy_pass         http://127.0.0.1:${RECON_API_PORT};
        proxy_http_version 1.1;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_set_header   Connection "";
        proxy_read_timeout 300s;
    }

    location /openapi.json {
        proxy_pass http://127.0.0.1:${RECON_API_PORT};
    }

    location / {
        return 404;
    }
}

# -- App subdomain — recon-ui (port ${RECON_UI_PORT}) ----------
server {
    listen 443 ssl;
    server_name ${APP_URL};

    ssl_certificate     /etc/nginx/ssl/0xrecon.crt;
    ssl_certificate_key /etc/nginx/ssl/0xrecon.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;

    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;

    client_max_body_size 50m;

    location / {
        proxy_pass         http://127.0.0.1:${RECON_UI_PORT};
        proxy_http_version 1.1;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_intercept_errors on;
        error_page 404 = @spa_fallback;
    }

    location @spa_fallback {
        proxy_pass http://127.0.0.1:${RECON_UI_PORT};
    }
}

# -- Collector API — mTLS stub (port 8443) --------------------
# Phase 8: ssl_client_certificate and ssl_verify_client on added here
server {
    listen 8443 ssl;
    server_name ${API_URL};

    ssl_certificate     /etc/nginx/ssl/0xrecon.crt;
    ssl_certificate_key /etc/nginx/ssl/0xrecon.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location /api/v1/collector/ {
        proxy_pass         http://127.0.0.1:${RECON_API_PORT};
        proxy_http_version 1.1;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
    }

    location / { return 404; }
}
NGINXEOF

ln -sf /etc/nginx/sites-available/0xrecon \
       /etc/nginx/sites-enabled/0xrecon
nginx -t
systemctl restart nginx
systemctl is-active nginx
log_ok "Nginx configured and running"

# -- Step 11: Create systemd service and start -----------------
log_section "Step 11/13 — Create systemd service and start"

tee /etc/systemd/system/0xrecon.service > /dev/null << EOF
[Unit]
Description=0xRecon — Cryptographic Asset Discovery Platform
Documentation=${GITHUB_HTTPS_URL}
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=${SERVICE_ACCOUNT}
Group=${SERVICE_ACCOUNT}
WorkingDirectory=${DEPLOY_PATH}

Environment=COMPOSE_PROJECT_NAME=${DOCKER_PROJECT}
Environment=HOME=/home/${SERVICE_ACCOUNT}

ExecStart=/usr/bin/docker compose \\
  -p ${DOCKER_PROJECT} \\
  -f docker-compose.yml \\
  -f docker-compose.prod.yml \\
  up

ExecStop=/usr/bin/docker compose \\
  -p ${DOCKER_PROJECT} \\
  -f docker-compose.yml \\
  -f docker-compose.prod.yml \\
  down

ExecReload=/usr/bin/docker compose \\
  -p ${DOCKER_PROJECT} \\
  -f docker-compose.yml \\
  -f docker-compose.prod.yml \\
  up -d --build

Restart=on-failure
RestartSec=30
StandardOutput=append:/var/log/0xrecon/service.log
StandardError=append:/var/log/0xrecon/service-error.log
TimeoutStartSec=300
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable 0xrecon.service
log_ok "Systemd service created and enabled"

log_info "Starting service (first run builds Docker images — allow 5-10 minutes)..."
systemctl start 0xrecon.service

# -- Step 12: Wait for healthy API -----------------------------
log_section "Step 12/13 — Wait for healthy API"

API_CONTAINER="${DOCKER_PROJECT}-recon-api-1"
MAX_WAIT=300
WAITED=0
INTERVAL=10
API_HEALTHY=false

log_info "Waiting for recon-api container to be healthy..."

while [ $WAITED -lt $MAX_WAIT ]; do
    sleep $INTERVAL
    WAITED=$((WAITED + INTERVAL))

    # Check container status
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' \
        "${API_CONTAINER}" 2>/dev/null || echo "missing")

    if [ "$STATUS" = "healthy" ]; then
        API_HEALTHY=true
        break
    fi

    log_info "Waiting for API... (${WAITED}s elapsed, container status: ${STATUS})"
    docker ps --filter "name=${DOCKER_PROJECT}" \
        --format "  {{.Names}}  {{.Status}}" 2>/dev/null || true
done

if [ "$API_HEALTHY" = false ]; then
    # Try direct health check as fallback
    if curl -sf "http://127.0.0.1:${RECON_API_PORT}/api/v1/health/" 2>/dev/null | \
        grep -q "db_connected"; then
        API_HEALTHY=true
        log_warn "Container healthcheck not reporting healthy but API is responding"
    else
        log_error "recon-api did not become healthy within ${MAX_WAIT}s"
        log_info  "Check: docker logs ${API_CONTAINER} --tail 50"
        exit 1
    fi
fi

log_ok "recon-api is healthy"

# Verify db_connected
DB_CONNECTED=$(curl -sf "http://127.0.0.1:${RECON_API_PORT}/api/v1/health/" 2>/dev/null | \
    python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('db_connected','false'))" \
    2>/dev/null || echo "false")

if [ "$DB_CONNECTED" = "True" ] || [ "$DB_CONNECTED" = "true" ]; then
    log_ok "Database connected — Alembic migrations complete"
else
    log_warn "API healthy but db_connected=false — check database logs"
    log_info "Check: docker logs ${DOCKER_PROJECT}-recon-postgres-1 --tail 20"
fi

# -- Step 13: Bootstrap first admin user -----------------------
log_section "Step 13/13 — Bootstrap first admin user"

log_info "Calling bootstrap endpoint..."
BOOTSTRAP_RESPONSE=$(curl -s -w "\n%{http_code}" \
    -X POST \
    "http://127.0.0.1:${RECON_API_PORT}/api/v1/users/bootstrap/" \
    -H "Content-Type: application/json" \
    -d "{
        \"username\": \"${INITIAL_ADMIN_USERNAME}\",
        \"password\": \"${INITIAL_ADMIN_PASSWORD}\",
        \"email\": \"${INITIAL_ADMIN_EMAIL}\"
    }" 2>/dev/null || echo -e "\n000")

BOOTSTRAP_BODY=$(echo "${BOOTSTRAP_RESPONSE}" | head -n -1)
BOOTSTRAP_CODE=$(echo "${BOOTSTRAP_RESPONSE}" | tail -n 1)

if [ "$BOOTSTRAP_CODE" = "201" ]; then
    log_ok "Admin user '${INITIAL_ADMIN_USERNAME}' created successfully"
elif [ "$BOOTSTRAP_CODE" = "409" ]; then
    log_ok "Admin user already exists — bootstrap not needed (re-install)"
else
    log_warn "Bootstrap returned HTTP ${BOOTSTRAP_CODE} — manual setup may be required"
    log_info "Response: ${BOOTSTRAP_BODY}"
    log_info "To bootstrap manually: POST /api/v1/users/bootstrap/ with username/password/email"
fi

# -- Completion summary ----------------------------------------
echo ""
echo -e "${GREEN}+==============================================================+${NC}"
echo -e "${GREEN}|          0xRecon Installation Complete                        |${NC}"
echo -e "${GREEN}+==============================================================+${NC}"
echo ""
echo "  Service:      sudo systemctl status 0xrecon"
echo "  Logs:         sudo journalctl -u 0xrecon -f"
echo "  Stack logs:   docker compose -p ${DOCKER_PROJECT} logs -f"
echo ""
echo "  Health check:"
echo "    curl http://127.0.0.1:${RECON_API_PORT}/api/v1/health/"
echo ""
echo "  HTTPS endpoints (after DNS A records are created):"
echo "    https://${API_URL}/api/v1/health/"
echo "    https://${APP_URL}/"
echo ""
echo "  DNS A records to create:"
echo "    ${API_URL}  ->  ${DEPLOY_HOST}"
echo "    ${APP_URL}  ->  ${DEPLOY_HOST}"
echo ""
if [ "$TLS_TYPE" = "self-signed" ]; then
echo "  To trust the self-signed cert in your browser:"
echo "    sudo cat /etc/nginx/ssl/0xrecon.crt"
echo "    Copy to your machine and import as a trusted CA"
echo ""
fi
echo "  First login:"
echo "    URL:      https://${APP_URL}/"
echo "    Username: ${INITIAL_ADMIN_USERNAME}"
echo "    Password: (as set in deployment.conf — change immediately)"
echo ""
echo "  Environment file: /etc/0xrecon/app.env"
echo "  Deploy key:       ${DEPLOY_KEY_PATH}"
echo ""
echo "  Run smoke test:"
echo "    bash install-azure/smoke-test.sh"
echo ""
