#!/bin/bash
# =============================================================================
# 0xRecon — Server Setup Script
# Version: 0.2.0 | April 2026
#
# Installs prerequisites and interactively configures the deployment.
# Designed to be re-run as the application evolves — new phases add new
# variables, and the script version tracks what each run configures.
#
# What this script does:
#   1. Installs Docker CE, git, openssl, ufw (prerequisites only)
#   2. Creates the service account and install directory
#   3. Interactively collects deployment configuration
#   4. Writes a fully configured .env to the install directory
#   5. Configures UFW firewall
#   6. Sets up systemd auto-start
#   7. Generates JWT key pair and self-signed dev TLS certs
#
# What this script does NOT do:
#   - Build or start containers (run: bash scripts/deploy.sh after this)
#   - Install Python or any application dependencies on the host
#   - Configure Let's Encrypt (done separately — see INSTALL.md)
#
# Idempotent: safe to re-run to update configuration.
# Run as root or with sudo.
#
# Usage:
#   sudo bash scripts/server-setup.sh
#   sudo bash scripts/server-setup.sh --non-interactive  # use all defaults
#
# Version history:
#   0.1.0 — Initial: Docker, basic .env, UFW
#   0.2.0 — Configurable service account, install dir, all current variables
#           + version tracking, idempotency improvements
#   [future versions will add Phase 6 report vars, Phase 8 collector vars, etc.]
# =============================================================================

set -euo pipefail

SCRIPT_VERSION="0.2.0"
SCRIPT_PHASE_COVERAGE="Phases 1–4B"  # Update as new phases add config

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${BLUE}[setup]${NC}  $*"; }
success() { echo -e "${GREEN}[ok]${NC}     $*"; }
warn()    { echo -e "${YELLOW}[warn]${NC}   $*"; }
error()   { echo -e "${RED}[error]${NC}  $*"; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}── $* ${NC}"; }
ask()     { echo -e "${YELLOW}?${NC} $*"; }

# ── Argument parsing ──────────────────────────────────────────────────────────
NON_INTERACTIVE=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --non-interactive|-y) NON_INTERACTIVE=true; shift ;;
        -h|--help)
            echo "Usage: sudo bash scripts/server-setup.sh [--non-interactive]"
            echo "  --non-interactive  Accept all defaults without prompting"
            exit 0 ;;
        *) error "Unknown argument: $1" ;;
    esac
done

# ── Root check ────────────────────────────────────────────────────────────────
[[ "$EUID" -eq 0 ]] || error "Run as root: sudo bash scripts/server-setup.sh"

# ── Helper: prompt with default ───────────────────────────────────────────────
# Usage: prompt VAR_NAME "Question" "default_value" [secret]
prompt() {
    local var_name="$1"
    local question="$2"
    local default="$3"
    local is_secret="${4:-}"

    if [ "$NON_INTERACTIVE" = true ]; then
        eval "$var_name=\"$default\""
        return
    fi

    if [ -n "$is_secret" ]; then
        ask "$question"
        echo -n "  (leave blank for auto-generated): "
        read -rs value
        echo ""
    else
        ask "$question"
        echo -n "  [default: $default]: "
        read -r value
    fi

    if [ -z "$value" ]; then
        eval "$var_name=\"$default\""
    else
        eval "$var_name=\"$value\""
    fi
}

# ── Helper: generate secure random string ────────────────────────────────────
gen_secret() {
    local length="${1:-64}"
    python3 -c "import secrets; print(secrets.token_hex($length))"
}

gen_password() {
    # Generates a strong password without special characters that break shell quoting
    python3 -c "
import secrets, string
chars = string.ascii_letters + string.digits + '_-'
print(''.join(secrets.choice(chars) for _ in range(32)))
"
}

# =============================================================================
# HEADER
# =============================================================================

clear
echo ""
echo "  ╔═══════════════════════════════════════════════════════╗"
echo "  ║          0xRecon — Server Setup                       ║"
echo "  ║          Script version: $SCRIPT_VERSION                         ║"
echo "  ║          Covers: $SCRIPT_PHASE_COVERAGE                    ║"
echo "  ╚═══════════════════════════════════════════════════════╝"
echo ""
echo "  This script prepares the host OS and configures 0xRecon."
echo "  Run  bash scripts/deploy.sh  afterwards to start containers."
echo ""

if [ "$NON_INTERACTIVE" = false ]; then
    echo -e "  Press ${BOLD}Enter${NC} to accept defaults shown in [brackets]."
    echo -e "  Variables marked ${YELLOW}(auto)${NC} are generated if left blank."
    echo ""
    read -rp "  Press Enter to begin... " _
fi

# =============================================================================
# SECTION 1 — DEPLOYMENT IDENTITY
# These control where the application lives on the host.
# =============================================================================
section "1. Deployment Identity"

prompt SERVICE_ACCOUNT \
    "Service account name (Linux user that owns and runs the stack)" \
    "recon"

prompt INSTALL_DIR \
    "Install directory (absolute path)" \
    "/opt/0xrecon"

prompt DOCKER_PROJECT \
    "Docker Compose project name (used as prefix for all container names)" \
    "0xrecon"

# Derive the systemd service name from the docker project name
SYSTEMD_SERVICE="${DOCKER_PROJECT}"

info "Service account : $SERVICE_ACCOUNT"
info "Install dir     : $INSTALL_DIR"
info "Docker project  : $DOCKER_PROJECT"
info "Systemd service : $SYSTEMD_SERVICE"

# =============================================================================
# SECTION 2 — NETWORK AND TLS
# =============================================================================
section "2. Network and TLS"

prompt DOMAIN \
    "Domain name (e.g. recon.yourdomain.com — used in nginx and TLS cert)" \
    "localhost"

prompt HTTPS_PORT \
    "HTTPS port for dashboard and API" \
    "443"

prompt COLLECTOR_PORT \
    "Collector mTLS port (used by remote agents in Phase 8)" \
    "8443"

prompt TLS_MODE \
    "TLS certificate mode: [selfsigned] or letsencrypt" \
    "selfsigned"

if [ "$TLS_MODE" = "letsencrypt" ]; then
    prompt LE_EMAIL \
        "Email address for Let's Encrypt notifications" \
        "admin@${DOMAIN}"
fi

info "Domain          : $DOMAIN"
info "HTTPS port      : $HTTPS_PORT"
info "Collector port  : $COLLECTOR_PORT"
info "TLS mode        : $TLS_MODE"

# =============================================================================
# SECTION 3 — APPLICATION SECRETS
# Generated automatically if left blank.
# =============================================================================
section "3. Application Secrets"

info "Generating secrets (leave blank to auto-generate all)..."

prompt SECRET_KEY \
    "Application secret key (min 32 chars — used for HMAC fallback)" \
    "" \
    secret
[ -z "$SECRET_KEY" ] && SECRET_KEY=$(gen_secret 32) && info "  SECRET_KEY: (auto-generated)"

prompt VAULT_MASTER_PASSWORD \
    "Vault master password (min 32 chars — encrypts the vault.enc file)" \
    "" \
    secret
[ -z "$VAULT_MASTER_PASSWORD" ] && VAULT_MASTER_PASSWORD=$(gen_password) && info "  VAULT_MASTER_PASSWORD: (auto-generated)"

warn "IMPORTANT: Record these secrets securely now."
warn "The vault master password cannot be recovered if lost."
warn "All encrypted vault data will be unrecoverable without it."
if [ "$NON_INTERACTIVE" = false ]; then
    echo ""
    read -rp "  Press Enter to confirm you have noted the secrets... " _
fi

# =============================================================================
# SECTION 4 — DATABASE
# =============================================================================
section "4. Database"

prompt DB_NAME \
    "PostgreSQL database name" \
    "recon"

prompt DB_USER \
    "PostgreSQL username" \
    "recon"

prompt DB_PASSWORD \
    "PostgreSQL password" \
    "" \
    secret
[ -z "$DB_PASSWORD" ] && DB_PASSWORD=$(gen_password) && info "  DB_PASSWORD: (auto-generated)"

prompt DB_PORT \
    "PostgreSQL port (internal to Docker network — 5432 is standard)" \
    "5432"

# Build connection strings
DB_URL="postgresql+asyncpg://${DB_USER}:${DB_PASSWORD}@recon-postgres:${DB_PORT}/${DB_NAME}"
DB_URL_SYNC="postgresql+psycopg2://${DB_USER}:${DB_PASSWORD}@recon-postgres:${DB_PORT}/${DB_NAME}"

info "Database: ${DB_NAME} on recon-postgres:${DB_PORT} as ${DB_USER}"

# =============================================================================
# SECTION 5 — PRODUCT IDENTITY
# Supports the white-label architecture — 0xRecon or CAIP.
# =============================================================================
section "5. Product Identity"

prompt PRODUCT_ID \
    "Product ID: [0xrecon] or caip" \
    "0xrecon"

case "$PRODUCT_ID" in
    caip)
        PRODUCT_NAME_DEFAULT="CAIP"
        PRODUCT_SHORT_NAME_DEFAULT="CAIP"
        PRODUCT_ACCENT_DEFAULT="#FFB800"
        ;;
    *)
        PRODUCT_NAME_DEFAULT="0xRecon"
        PRODUCT_SHORT_NAME_DEFAULT="0xRecon"
        PRODUCT_ACCENT_DEFAULT="#00FF41"
        PRODUCT_ID="0xrecon"
        ;;
esac

prompt PRODUCT_NAME \
    "Product display name" \
    "$PRODUCT_NAME_DEFAULT"

prompt PRODUCT_SHORT_NAME \
    "Product short name (used in compact UI areas)" \
    "$PRODUCT_SHORT_NAME_DEFAULT"

prompt PRODUCT_ACCENT \
    "UI accent colour (hex)" \
    "$PRODUCT_ACCENT_DEFAULT"

info "Product: $PRODUCT_NAME ($PRODUCT_ID), accent: $PRODUCT_ACCENT"

# =============================================================================
# SECTION 6 — AUTHENTICATION
# =============================================================================
section "6. Authentication"

prompt JWT_EXPIRY_HOURS \
    "JWT token expiry in hours" \
    "8"

prompt ALLOWED_ORIGINS \
    "Allowed CORS origins (comma-separated, include your domain)" \
    "https://${DOMAIN}"

# OAuth — Phase 2B stubs, configured via UI settings panel in production
# These are left blank and can be added via the API /settings/auth-providers/ later.
# Shown here so the operator knows they exist.
info "OAuth (Azure Entra ID / Okta): configure via /api/v1/settings/ after first login"

# =============================================================================
# SECTION 7 — WORKER AND SCHEDULER
# =============================================================================
section "7. Worker and Scheduler"

prompt SCHEDULER_INTERVAL \
    "Scheduler poll interval in seconds (how often the worker checks the job queue)" \
    "10"

prompt WORKER_SCAN_TIMEOUT \
    "Maximum scan job timeout in seconds (per collector)" \
    "300"

# =============================================================================
# SECTION 8 — LOGGING
# =============================================================================
section "8. Logging"

prompt LOG_LEVEL \
    "Log level: [INFO], DEBUG, WARNING, ERROR" \
    "INFO"

prompt LOG_FORMAT \
    "Log format: [json] or text" \
    "json"

# =============================================================================
# SECTION 9 — FUTURE PHASES (stubs — collected now, used later)
# These are shown so operators can plan. Left blank or defaulted for now.
# =============================================================================
section "9. Future Phase Configuration (stubs)"

echo ""
echo "  The following will be needed in later phases."
echo "  Defaults are set now. Configure values when the phase is built."
echo ""

# Phase 6: Reports
REPORTS_DIR="${INSTALL_DIR}/reports"
prompt REPORTS_STORAGE_PATH \
    "Report file storage path (Phase 6 — report generation)" \
    "/app/reports"

prompt REPORT_RETENTION_DAYS \
    "Report retention in days (0 = keep forever, Phase 6)" \
    "365"

# Phase 8: Collector agent
prompt COLLECTOR_REGISTRATION_TOKEN_TTL \
    "Collector registration token TTL in seconds (Phase 8)" \
    "3600"

# Phase 9: UI
prompt UI_SESSION_TIMEOUT \
    "UI session timeout in minutes (Phase 9)" \
    "480"

info "Report path     : $REPORTS_STORAGE_PATH (Phase 6)"
info "Report retention: $REPORT_RETENTION_DAYS days (Phase 6)"
info "Collector TTL   : $COLLECTOR_REGISTRATION_TOKEN_TTL s (Phase 8)"

# =============================================================================
# NOW DO THE WORK
# =============================================================================

section "Installing Prerequisites"

info "Updating apt packages..."
apt-get update -qq
apt-get upgrade -y -qq
success "Packages updated"

info "Installing required packages..."
apt-get install -y -qq \
    ca-certificates curl gnupg git openssl ufw \
    python3-minimal lsb-release apt-transport-https
success "Packages installed"

# Docker CE
if ! command -v docker &>/dev/null; then
    info "Installing Docker CE..."
    apt-get remove -y -qq docker docker-engine docker.io containerd runc 2>/dev/null || true
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
        | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update -qq
    apt-get install -y -qq \
        docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin
    systemctl enable docker
    systemctl start docker
    success "Docker CE installed: $(docker --version | awk '{print $3}' | tr -d ',')"
else
    success "Docker already installed: $(docker --version | awk '{print $3}' | tr -d ',')"
fi

# =============================================================================
section "Creating Service Account: $SERVICE_ACCOUNT"

if id "$SERVICE_ACCOUNT" &>/dev/null; then
    warn "User '$SERVICE_ACCOUNT' already exists — updating group membership"
else
    useradd \
        --system \
        --no-create-home \
        --shell /usr/sbin/nologin \
        --comment "0xRecon service account" \
        "$SERVICE_ACCOUNT"
    success "User '$SERVICE_ACCOUNT' created"
fi

usermod -aG docker "$SERVICE_ACCOUNT"
success "User '$SERVICE_ACCOUNT' added to docker group"

SUDO_USER="${SUDO_USER:-}"
if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
    usermod -aG docker "$SUDO_USER"
    success "User '$SUDO_USER' added to docker group (re-login required)"
fi

# =============================================================================
section "Creating Install Directory: $INSTALL_DIR"

if [ ! -d "$INSTALL_DIR" ]; then
    mkdir -p "$INSTALL_DIR"
    success "Created $INSTALL_DIR"
else
    warn "$INSTALL_DIR already exists — leaving contents intact"
fi

mkdir -p \
    "${INSTALL_DIR}/nginx/certs" \
    "${INSTALL_DIR}/secrets" \
    "${INSTALL_DIR}/scripts"

chown -R "$SERVICE_ACCOUNT:$SERVICE_ACCOUNT" "$INSTALL_DIR" 2>/dev/null || true
success "Directory structure ready"

# =============================================================================
section "Generating JWT Key Pair"

JWT_KEY="${INSTALL_DIR}/secrets/jwt_private.pem"
JWT_PUB="${INSTALL_DIR}/secrets/jwt_public.pem"

if [ ! -f "$JWT_KEY" ]; then
    openssl genrsa -out "$JWT_KEY" 4096 2>/dev/null
    openssl rsa -in "$JWT_KEY" -pubout -out "$JWT_PUB" 2>/dev/null
    chmod 600 "$JWT_KEY"
    chmod 644 "$JWT_PUB"
    success "JWT RSA-4096 key pair generated"
else
    warn "JWT keys already exist — leaving unchanged"
fi

# =============================================================================
section "TLS Certificates"

CERT_FILE="${INSTALL_DIR}/nginx/certs/server.crt"
KEY_FILE="${INSTALL_DIR}/nginx/certs/server.key"

if [ "$TLS_MODE" = "letsencrypt" ]; then
    info "Let's Encrypt mode selected."
    if command -v certbot &>/dev/null; then
        info "Obtaining certificate for $DOMAIN..."
        certbot certonly --standalone \
            -d "$DOMAIN" \
            --agree-tos \
            --non-interactive \
            --email "$LE_EMAIL" \
            --http-01-port 80 2>/dev/null || warn "certbot failed — may need port 80 open. Run manually."
        if [ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
            cp "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$CERT_FILE"
            cp "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$KEY_FILE"
            chmod 644 "$CERT_FILE"
            chmod 600 "$KEY_FILE"

            # Auto-renewal deploy hook
            cat > /etc/letsencrypt/renewal-hooks/deploy/0xrecon.sh << HOOK
#!/bin/bash
cp /etc/letsencrypt/live/${DOMAIN}/fullchain.pem ${CERT_FILE}
cp /etc/letsencrypt/live/${DOMAIN}/privkey.pem ${KEY_FILE}
chmod 644 ${CERT_FILE}
chmod 600 ${KEY_FILE}
docker compose -p ${DOCKER_PROJECT} exec recon-nginx nginx -s reload 2>/dev/null || true
HOOK
            chmod +x /etc/letsencrypt/renewal-hooks/deploy/0xrecon.sh
            success "Let's Encrypt certificate obtained and renewal hook installed"
        fi
    else
        info "Installing certbot..."
        apt-get install -y -qq certbot
        info "Re-run this script or obtain cert manually:"
        info "  certbot certonly --standalone -d $DOMAIN --email $LE_EMAIL --agree-tos"
    fi
else
    # Self-signed
    if [ ! -f "$CERT_FILE" ]; then
        openssl req -x509 \
            -newkey rsa:4096 \
            -keyout "$KEY_FILE" \
            -out "$CERT_FILE" \
            -days 365 \
            -nodes \
            -subj "/C=GB/ST=England/L=London/O=0xRecon/CN=${DOMAIN}" \
            -addext "subjectAltName=DNS:${DOMAIN},DNS:localhost,IP:127.0.0.1" \
            2>/dev/null
        chmod 600 "$KEY_FILE"
        chmod 644 "$CERT_FILE"
        success "Self-signed TLS certificate generated (valid 365 days)"
    else
        warn "TLS certificate already exists — leaving unchanged"
    fi
fi

# =============================================================================
section "Writing Configuration: ${INSTALL_DIR}/.env"

# Back up existing .env if present
if [ -f "${INSTALL_DIR}/.env" ]; then
    BACKUP="${INSTALL_DIR}/.env.backup.$(date +%Y%m%d%H%M%S)"
    cp "${INSTALL_DIR}/.env" "$BACKUP"
    warn "Existing .env backed up to: $BACKUP"
fi

cat > "${INSTALL_DIR}/.env" << ENV
# =============================================================================
# 0xRecon — Environment Configuration
# Generated by server-setup.sh v${SCRIPT_VERSION} on $(date -Iseconds)
# Covers: ${SCRIPT_PHASE_COVERAGE}
#
# SECURITY: This file contains secrets. Do not commit to git.
# Re-run server-setup.sh to regenerate or update configuration.
# =============================================================================

# ── Deployment identity ───────────────────────────────────────────────────────
# Set by server-setup.sh — change here if you move the install
RECON_INSTALL_DIR=${INSTALL_DIR}
RECON_SERVICE_ACCOUNT=${SERVICE_ACCOUNT}
DOCKER_PROJECT=${DOCKER_PROJECT}

# ── Application ───────────────────────────────────────────────────────────────
RECON_ENV=production
RECON_DEBUG=false
RECON_SECRET_KEY=${SECRET_KEY}
RECON_ALLOWED_ORIGINS=${ALLOWED_ORIGINS}

# ── Database ──────────────────────────────────────────────────────────────────
POSTGRES_DB=${DB_NAME}
POSTGRES_USER=${DB_USER}
POSTGRES_PASSWORD=${DB_PASSWORD}
RECON_DATABASE_URL=${DB_URL}
RECON_DATABASE_URL_SYNC=${DB_URL_SYNC}
RECON_DATABASE_POOL_MIN=2
RECON_DATABASE_POOL_MAX=10

# ── JWT ───────────────────────────────────────────────────────────────────────
RECON_JWT_ALGORITHM=RS256
RECON_JWT_EXPIRY_HOURS=${JWT_EXPIRY_HOURS}
RECON_JWT_PRIVATE_KEY_PATH=/run/secrets/jwt_private_key
RECON_JWT_PUBLIC_KEY_PATH=/run/secrets/jwt_public_key
# Note: jwt_private.pem and jwt_public.pem are bind-mounted from ${INSTALL_DIR}/secrets/

# ── Vault ─────────────────────────────────────────────────────────────────────
RECON_VAULT_PATH=/app/data/vault.enc
RECON_VAULT_MASTER_PASSWORD=${VAULT_MASTER_PASSWORD}
# CRITICAL: Record this password securely. Loss = unrecoverable vault data.

# ── Network ───────────────────────────────────────────────────────────────────
RECON_DOMAIN=${DOMAIN}
RECON_HTTPS_PORT=${HTTPS_PORT}
RECON_COLLECTOR_PORT=${COLLECTOR_PORT}

# ── Worker and scheduler ──────────────────────────────────────────────────────
RECON_SCHEDULER_INTERVAL=${SCHEDULER_INTERVAL}
RECON_WORKER_SCAN_TIMEOUT=${WORKER_SCAN_TIMEOUT}

# ── Logging ───────────────────────────────────────────────────────────────────
RECON_LOG_LEVEL=${LOG_LEVEL}
RECON_LOG_FORMAT=${LOG_FORMAT}

# ── Product identity ──────────────────────────────────────────────────────────
PRODUCT_ID=${PRODUCT_ID}
PRODUCT_NAME=${PRODUCT_NAME}
PRODUCT_SHORT_NAME=${PRODUCT_SHORT_NAME}
PRODUCT_LOGO_PATH=/static/${PRODUCT_ID}/logo.svg
PRODUCT_FAVICON_PATH=/static/${PRODUCT_ID}/favicon.ico
PRODUCT_ACCENT_COLOR=${PRODUCT_ACCENT}
PRODUCT_TERMINOLOGY_JSON={}
PRODUCT_FEATURE_FLAGS_JSON={"show_dpod_dashboard":true,"show_pqc_migration":true,"show_document_assessment":true}

# ── Phase 6: Report generation (STUB — active when Phase 6 is deployed) ───────
RECON_REPORTS_PATH=${REPORTS_STORAGE_PATH}
RECON_REPORT_RETENTION_DAYS=${REPORT_RETENTION_DAYS}
# RECON_REPORT_SIGNING_KEY=        # Auto-provisioned by CertificateService on first run
# SMTP_HOST=                       # Optional — email delivery for report notifications
# SMTP_PORT=587
# SMTP_USER=
# SMTP_PASSWORD=
# SMTP_FROM=noreply@${DOMAIN}
# SMTP_TLS=true

# ── Phase 8: Remote collector agent (STUB — active when Phase 8 is deployed) ──
RECON_COLLECTOR_REGISTRATION_TTL=${COLLECTOR_REGISTRATION_TOKEN_TTL}
# RECON_COLLECTOR_CA_KEY=          # Auto-provisioned by CertificateService
# RECON_COLLECTOR_CERT_VALIDITY=30 # Days (matches ARCHITECTURE.md spec)

# ── Phase 9: UI session (STUB — active when Phase 9 is deployed) ──────────────
RECON_UI_SESSION_TIMEOUT_MINUTES=${UI_SESSION_TIMEOUT}

# ── Phase 10: Hardening (STUB — active when Phase 10 is deployed) ─────────────
# RECON_RATE_LIMIT_PER_MINUTE=60
# RECON_RATE_LIMIT_BURST=10
# RECON_HSTS_MAX_AGE=31536000

# ── OAuth providers (configure via API after first login) ─────────────────────
# These are set in the database via POST /api/v1/settings/auth-providers/
# Leave blank here — stored encrypted in the vault at runtime.
# AZURE_TENANT_ID=
# AZURE_CLIENT_ID=
# AZURE_CLIENT_SECRET=
# OKTA_DOMAIN=
# OKTA_CLIENT_ID=
# OKTA_CLIENT_SECRET=

# ── External secret stores (optional — configure via API) ─────────────────────
# AZURE_KEY_VAULT_URL=
# HASHICORP_VAULT_URL=
# HASHICORP_VAULT_TOKEN=
ENV

chmod 600 "${INSTALL_DIR}/.env"
success ".env written to ${INSTALL_DIR}/.env"

# Also write a setup record so future re-runs can show what was last configured
cat > "${INSTALL_DIR}/.setup-record" << RECORD
setup_script_version=${SCRIPT_VERSION}
setup_date=$(date -Iseconds)
phase_coverage=${SCRIPT_PHASE_COVERAGE}
service_account=${SERVICE_ACCOUNT}
install_dir=${INSTALL_DIR}
docker_project=${DOCKER_PROJECT}
domain=${DOMAIN}
tls_mode=${TLS_MODE}
RECORD
chmod 600 "${INSTALL_DIR}/.setup-record"

# =============================================================================
section "Configuring UFW Firewall"

ufw --force reset > /dev/null 2>&1
ufw default deny incoming > /dev/null
ufw default allow outgoing > /dev/null
ufw allow 22/tcp comment "SSH" > /dev/null
ufw allow 80/tcp comment "HTTP (Let's Encrypt)" > /dev/null
ufw allow "${HTTPS_PORT}/tcp" comment "HTTPS (0xRecon dashboard + API)" > /dev/null
ufw allow "${COLLECTOR_PORT}/tcp" comment "Collector mTLS (0xRecon Phase 8)" > /dev/null
ufw --force enable > /dev/null
success "UFW enabled"
info "  22/tcp              → SSH"
info "  80/tcp              → HTTP (Let's Encrypt)"
info "  ${HTTPS_PORT}/tcp             → HTTPS dashboard + API"
info "  ${COLLECTOR_PORT}/tcp          → Collector mTLS"
warn "Restrict SSH to your IP: ufw delete allow 22/tcp && ufw allow from YOUR.IP to any port 22 proto tcp"

# =============================================================================
section "Installing systemd Service: ${SYSTEMD_SERVICE}"

cat > "/etc/systemd/system/${SYSTEMD_SERVICE}.service" << UNIT
[Unit]
Description=0xRecon — Cryptographic Asset Discovery Platform
Documentation=https://github.com/oliverom-admin/0xReconv2
After=docker.service network-online.target
Requires=docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${INSTALL_DIR}
User=${SERVICE_ACCOUNT}

ExecStart=/usr/bin/docker compose \\
  -p ${DOCKER_PROJECT} \\
  -f docker-compose.yml \\
  -f docker-compose.prod.yml \\
  up -d --remove-orphans

ExecStop=/usr/bin/docker compose \\
  -p ${DOCKER_PROJECT} \\
  -f docker-compose.yml \\
  -f docker-compose.prod.yml \\
  down

ExecReload=/usr/bin/docker compose \\
  -p ${DOCKER_PROJECT} \\
  -f docker-compose.yml \\
  -f docker-compose.prod.yml \\
  up -d --remove-orphans

StandardOutput=journal
StandardError=journal
TimeoutStartSec=300
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "${SYSTEMD_SERVICE}"
success "systemd service '${SYSTEMD_SERVICE}' installed and enabled"

# =============================================================================
section "Verification"

docker info > /dev/null 2>&1 && success "Docker daemon running" \
    || warn "Docker not running — check: systemctl status docker"
docker compose version > /dev/null 2>&1 && success "Docker Compose available" \
    || warn "Docker Compose not found"
[ -f "${INSTALL_DIR}/.env" ] && success ".env exists" \
    || warn ".env missing"
[ -f "${JWT_KEY}" ] && success "JWT private key exists" \
    || warn "JWT private key missing"
[ -f "${CERT_FILE}" ] && success "TLS certificate exists" \
    || warn "TLS certificate missing — generate before starting"

# =============================================================================
# SUMMARY
# =============================================================================

echo ""
echo "  ╔═══════════════════════════════════════════════════════════╗"
echo -e "  ║  ${GREEN}Setup complete!${NC}                                        ║"
echo "  ╠═══════════════════════════════════════════════════════════╣"
printf  "  ║  %-55s║\n" "Script version : $SCRIPT_VERSION ($SCRIPT_PHASE_COVERAGE)"
printf  "  ║  %-55s║\n" "Service account: $SERVICE_ACCOUNT"
printf  "  ║  %-55s║\n" "Install dir    : $INSTALL_DIR"
printf  "  ║  %-55s║\n" "Docker project : $DOCKER_PROJECT"
printf  "  ║  %-55s║\n" "Domain         : $DOMAIN"
printf  "  ║  %-55s║\n" "TLS            : $TLS_MODE"
printf  "  ║  %-55s║\n" "Systemd svc    : $SYSTEMD_SERVICE"
echo "  ╠═══════════════════════════════════════════════════════════╣"
echo "  ║  Next steps:                                              ║"
echo "  ║                                                           ║"
echo "  ║  1. Clone repo (if not already in $INSTALL_DIR):          ║"
echo "  ║     git clone <repo-url> $INSTALL_DIR                    ║"
echo "  ║                                                           ║"
echo "  ║  2. The .env is already written. Review it:              ║"
echo "  ║     nano $INSTALL_DIR/.env                          ║"
echo "  ║                                                           ║"
echo "  ║  3. Deploy:                                               ║"
echo "  ║     bash $INSTALL_DIR/scripts/deploy.sh           ║"
echo "  ║                                                           ║"
echo "  ║  4. Create first admin account:                           ║"
echo "  ║     See INSTALL.md Step 8                                 ║"
echo "  ╚═══════════════════════════════════════════════════════════╝"
echo ""

if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
    echo -e "  ${YELLOW}Re-login as '$SUDO_USER' for docker group membership to take effect.${NC}"
    echo ""
fi
