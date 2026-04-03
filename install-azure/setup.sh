#!/bin/bash
# =============================================================
# 0xRecon — Setup Script
# =============================================================
# Orchestrates the full installation from a single command.
# Run this after filling in deployment.conf.
#
# Usage:
#   Normal installation:
#     cp install-azure/deployment.conf.example install-azure/deployment.conf
#     nano install-azure/deployment.conf
#     bash install-azure/setup.sh
#
#   Complete teardown (cleanup existing deployment):
#     bash install-azure/setup.sh teardown
#
# What this script does:
#   Phase 1 — Bootstrap
#     1. Validate deployment.conf
#     2. Create service account and group
#     3. Create application directories
#     4. Generate GitHub deploy key
#     5. Write DEPLOY_KEY_PATH into deployment.conf
#     6. Walk through adding the public key to GitHub
#     7. Verify GitHub SSH connectivity
#
#   Phase 2 — Install (calls install.sh)
#     8.  System update and packages
#     9.  Install Docker
#     10. Install Nginx
#     11. Clone repository
#     12. Create application directories
#     13. Write environment files
#     14. Write .env symlink
#     15. Configure log rotation
#     16. Configure Nginx with TLS
#     17. Create systemd service
#     18. First start and health check
#     19. Bootstrap first admin user
# =============================================================

set -euo pipefail

# -- Must not run as root --------------------------------------
if [ "$EUID" -eq 0 ]; then
    echo "Do not run setup.sh as root."
    echo "Run as your admin user — the script uses sudo where needed."
    exit 1
fi

# -- Colours ---------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_section()   { echo -e "\n${BLUE}== $1 ==${NC}"; }
log_ok()        { echo -e "${GREEN}  + $1${NC}"; }
log_warn()      { echo -e "${YELLOW}  ! $1${NC}"; }
log_error()     { echo -e "${RED}  x $1${NC}"; }
log_info()      { echo -e "  > $1"; }
log_highlight() { echo -e "${CYAN}$1${NC}"; }

# -- Teardown function -----------------------------------------
perform_teardown() {
    echo ""
    log_section "0xRecon Teardown"
    log_info "This will remove all 0xRecon deployment artifacts"
    read -r -p "Are you sure? [y/N] " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi

    log_info "Stopping service..."
    sudo systemctl stop 0xrecon 2>/dev/null || true
    sudo systemctl disable 0xrecon 2>/dev/null || true
    log_ok "Service stopped"

    log_info "Bringing down containers and volumes..."
    if [ -d "/opt/0xrecon" ]; then
        (cd /opt/0xrecon && \
            sudo -u svc-0xrecon docker compose -p 0xrecon down -v 2>/dev/null || true)
    fi
    log_ok "Containers removed"

    log_info "Removing Docker volumes..."
    docker volume rm 0xrecon_postgres_data 2>/dev/null || true
    docker volume rm 0xrecon_data 2>/dev/null || true
    docker volume rm 0xrecon_reports 2>/dev/null || true
    log_ok "Volumes removed"

    log_info "Removing application directory..."
    sudo rm -rf /opt/0xrecon
    log_ok "Application directory removed"

    log_info "Removing environment files and systemd unit..."
    sudo rm -rf /etc/0xrecon
    sudo rm -f /etc/systemd/system/0xrecon.service
    sudo systemctl daemon-reload
    log_ok "Configuration and systemd unit removed"

    log_info "Removing log directory..."
    sudo rm -rf /var/log/0xrecon
    log_ok "Log directory removed"

    log_info "Removing nginx config..."
    sudo rm -f /etc/nginx/sites-enabled/0xrecon
    sudo rm -f /etc/nginx/sites-available/0xrecon
    sudo rm -f /etc/nginx/ssl/0xrecon.crt
    sudo rm -f /etc/nginx/ssl/0xrecon.key
    sudo systemctl reload nginx 2>/dev/null || true
    log_ok "Nginx config removed"

    log_info "Verifying teardown..."
    if [ ! -d "/opt/0xrecon" ] && \
       ! docker ps | grep -q "0xrecon" && \
       ! docker volume ls | grep -q "0xrecon"; then
        echo ""
        log_ok "Teardown complete — all artifacts removed"
        echo ""
        exit 0
    else
        log_warn "Teardown may be incomplete — verify manually"
        exit 1
    fi
}

# -- Handle teardown argument ----------------------------------
if [ "${1:-}" = "teardown" ]; then
    perform_teardown
fi

CURRENT_USER="$(whoami)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_FILE="${SCRIPT_DIR}/deployment.conf"

# -- Load and validate deployment.conf ------------------------
if [ ! -f "$CONF_FILE" ]; then
    log_error "deployment.conf not found at $CONF_FILE"
    log_info  "Run: cp install-azure/deployment.conf.example install-azure/deployment.conf"
    log_info  "Then fill in all REQUIRED values and re-run setup.sh"
    exit 1
fi

source "$CONF_FILE"

log_section "Validating deployment.conf"

REQUIRED_VARS=(
    DEPLOY_HOST DEPLOY_USER DEPLOY_PATH SERVICE_ACCOUNT
    BASE_DOMAIN SUBDOMAIN_PREFIX TLS_TYPE
    GITHUB_USER GITHUB_REPO GIT_USER_NAME GIT_USER_EMAIL
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
    exit 1
fi

# Reject default/placeholder values for secrets
for SECRET_VAR in POSTGRES_PASSWORD RECON_SECRET_KEY RECON_VAULT_MASTER_PASSWORD INITIAL_ADMIN_PASSWORD; do
    VAL="${!SECRET_VAR}"
    if [[ "$VAL" == CHANGE_ME* ]] || \
       [[ "$VAL" == "changeme" ]] || \
       [[ "$VAL" == "devpassword" ]] || \
       [[ "$VAL" == "recon_dev_password" ]]; then
        log_error "${SECRET_VAR} must not be a placeholder or default value"
        log_info  "Generate POSTGRES_PASSWORD and RECON_VAULT_MASTER_PASSWORD with: openssl rand -base64 32"
        log_info  "Generate RECON_SECRET_KEY with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
        exit 1
    fi
done

# Validate vault master password length (min 32 chars)
if [ ${#RECON_VAULT_MASTER_PASSWORD} -lt 32 ]; then
    log_error "RECON_VAULT_MASTER_PASSWORD must be at least 32 characters"
    log_info  "Generate with: openssl rand -base64 32"
    exit 1
fi

if [ "$TLS_TYPE" = "internal-ca" ]; then
    if [ -z "${TLS_CERT_PATH:-}" ] || [ -z "${TLS_KEY_PATH:-}" ]; then
        log_error "TLS_TYPE=internal-ca requires TLS_CERT_PATH and TLS_KEY_PATH"
        exit 1
    fi
fi

log_ok "Configuration valid"

# -- Check sudo access -----------------------------------------
if ! sudo -n true 2>/dev/null; then
    log_info "Sudo access required — you may be prompted for your password"
    if ! sudo true; then
        log_error "Sudo access required. Ensure ${CURRENT_USER} has sudo privileges."
        exit 1
    fi
fi

# -- Derived key path ------------------------------------------
DEPLOY_KEY_DIR="/home/${SERVICE_ACCOUNT}/.ssh"
DEPLOY_KEY_PATH="${DEPLOY_KEY_DIR}/0xrecon_git_deploy"

# -- Banner ----------------------------------------------------
API_URL="api.${SUBDOMAIN_PREFIX}.${BASE_DOMAIN}"
APP_URL="app.${SUBDOMAIN_PREFIX}.${BASE_DOMAIN}"

echo ""
echo -e "${BLUE}+==============================================================+${NC}"
echo -e "${BLUE}|          0xRecon Setup                                        |${NC}"
echo -e "${BLUE}+==============================================================+${NC}"
echo ""
echo "  Server:       ${DEPLOY_HOST}"
echo "  Install path: ${DEPLOY_PATH}"
echo "  API URL:      https://${API_URL}"
echo "  App URL:      https://${APP_URL}"
echo "  GitHub repo:  https://github.com/${GITHUB_USER}/${GITHUB_REPO}"
echo "  Product:      ${PRODUCT_NAME} (${PRODUCT_ID})"
echo ""
echo "  Phase 1 — Bootstrap (this script)"
echo "  Phase 2 — Install   (calls install.sh automatically)"
echo ""
read -r -p "Proceed? [y/N] " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# =============================================================
# PHASE 1 — BOOTSTRAP
# =============================================================

# -- Step 1: Check prerequisites -------------------------------
log_section "Bootstrap 1/7 — Check prerequisites"

MISSING_TOOLS=()
for tool in sudo ssh ssh-keygen git curl openssl; do
    if ! command -v "$tool" &>/dev/null; then
        MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    log_error "Missing required tools: ${MISSING_TOOLS[*]}"
    log_info  "Install with: sudo apt-get install -y ${MISSING_TOOLS[*]}"
    exit 1
fi

log_ok "All prerequisites present"

# -- Step 2: Create service account ----------------------------
log_section "Bootstrap 2/7 — Create service account"

if ! getent group "${SERVICE_ACCOUNT}" &>/dev/null; then
    sudo groupadd "${SERVICE_ACCOUNT}"
    log_ok "Group '${SERVICE_ACCOUNT}' created"
else
    log_info "Group '${SERVICE_ACCOUNT}' already exists"
fi

if ! id "${SERVICE_ACCOUNT}" &>/dev/null; then
    sudo useradd -r -s /bin/bash \
        -d "/home/${SERVICE_ACCOUNT}" \
        -g "${SERVICE_ACCOUNT}" \
        "${SERVICE_ACCOUNT}"
    sudo mkdir -p "/home/${SERVICE_ACCOUNT}"
    sudo chown "${SERVICE_ACCOUNT}:${SERVICE_ACCOUNT}" "/home/${SERVICE_ACCOUNT}"
    log_ok "Service account '${SERVICE_ACCOUNT}' created"
else
    log_info "Service account '${SERVICE_ACCOUNT}' already exists"
fi

sudo usermod -aG "${SERVICE_ACCOUNT}" "${CURRENT_USER}"
log_ok "Added '${CURRENT_USER}' to group '${SERVICE_ACCOUNT}'"

# -- Step 3: Create directories --------------------------------
log_section "Bootstrap 3/7 — Create directories"

sudo mkdir -p "${DEPLOY_PATH}"
sudo chown "${SERVICE_ACCOUNT}:${SERVICE_ACCOUNT}" "${DEPLOY_PATH}"
sudo chmod 775 "${DEPLOY_PATH}"
log_ok "Deploy path '${DEPLOY_PATH}' ready"

sudo mkdir -p "${DEPLOY_KEY_DIR}"
sudo chown "${SERVICE_ACCOUNT}:${SERVICE_ACCOUNT}" "${DEPLOY_KEY_DIR}"
sudo chmod 700 "${DEPLOY_KEY_DIR}"
log_ok "SSH directory '${DEPLOY_KEY_DIR}' ready"

# -- Step 4: Generate deploy key -------------------------------
log_section "Bootstrap 4/7 — Generate GitHub deploy key"

if sudo test -f "${DEPLOY_KEY_PATH}"; then
    log_warn "Deploy key already exists at ${DEPLOY_KEY_PATH} — skipping generation"
    log_info  "To regenerate: sudo rm ${DEPLOY_KEY_PATH} ${DEPLOY_KEY_PATH}.pub && re-run setup.sh"
else
    sudo -u "${SERVICE_ACCOUNT}" ssh-keygen \
        -t ed25519 \
        -C "0xrecon-deploy-$(hostname)" \
        -f "${DEPLOY_KEY_PATH}" \
        -N ""
    log_ok "Deploy key generated"
fi

SSH_CONFIG_PATH="${DEPLOY_KEY_DIR}/config"
if ! sudo test -f "${SSH_CONFIG_PATH}"; then
    sudo tee "${SSH_CONFIG_PATH}" > /dev/null << EOF
Host github.com
  IdentityFile ${DEPLOY_KEY_PATH}
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new
EOF
    sudo chown "${SERVICE_ACCOUNT}:${SERVICE_ACCOUNT}" "${SSH_CONFIG_PATH}"
    sudo chmod 600 "${SSH_CONFIG_PATH}"
    log_ok "SSH config written"
else
    log_info "SSH config already exists"
fi

# -- Step 5: Write DEPLOY_KEY_PATH to deployment.conf ----------
log_section "Bootstrap 5/7 — Write DEPLOY_KEY_PATH to deployment.conf"

CONF_GENERATED_MARKER="# -- Generated by setup.sh"

if grep -q "Generated by setup.sh" "${CONF_FILE}"; then
    grep -n "Generated by setup.sh" "${CONF_FILE}" | head -1 | cut -d: -f1 | \
    xargs -I{} sh -c 'head -n $(( {} - 1 )) "$1" > "$1.tmp" && mv "$1.tmp" "$1"' \
        -- "${CONF_FILE}"
fi

tee -a "${CONF_FILE}" > /dev/null << EOF

# =============================================================
# -- Generated by setup.sh — do not edit below this line --
# =============================================================
DEPLOY_KEY_PATH=${DEPLOY_KEY_PATH}
EOF

log_ok "DEPLOY_KEY_PATH=${DEPLOY_KEY_PATH} written to deployment.conf"

# -- Step 6: Add public key to GitHub -------------------------
log_section "Bootstrap 6/7 — Add deploy key to GitHub"

GITHUB_KEYS_URL="https://github.com/${GITHUB_USER}/${GITHUB_REPO}/settings/keys"

echo ""
log_highlight "  +-------------------------------------------------------------+"
log_highlight "  |  ACTION REQUIRED — Add this key to GitHub                    |"
log_highlight "  +-------------------------------------------------------------+"
echo ""
echo "  Copy the public key below:"
echo ""
echo -e "${CYAN}"
sudo cat "${DEPLOY_KEY_PATH}.pub"
echo -e "${NC}"
echo "  Go to:"
echo -e "  ${CYAN}${GITHUB_KEYS_URL}${NC}"
echo ""
echo "  Click:  Add deploy key"
echo "  Title:  0xRecon - $(hostname)"
echo "  Key:    paste the public key above"
echo "  Allow write access: NO"
echo ""

read -r -p "  Press ENTER once you have added the key to GitHub... "

# -- Step 7: Verify GitHub connectivity -----------------------
log_section "Bootstrap 7/7 — Verify GitHub connectivity"

MAX_ATTEMPTS=3
ATTEMPT=0
VERIFIED=false

while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    ATTEMPT=$((ATTEMPT + 1))
    log_info "Testing connection (attempt ${ATTEMPT}/${MAX_ATTEMPTS})..."

    SSH_RESULT=$(sudo -u "${SERVICE_ACCOUNT}" \
        ssh -T -o ConnectTimeout=10 \
        -o StrictHostKeyChecking=accept-new \
        git@github.com 2>&1 || true)

    if echo "${SSH_RESULT}" | grep -q "successfully authenticated"; then
        VERIFIED=true
        break
    fi

    if [ $ATTEMPT -lt $MAX_ATTEMPTS ]; then
        log_warn "Connection failed — ensure the key has been saved in GitHub"
        read -r -p "  Press ENTER to retry, or Ctrl+C to abort... "
    fi
done

if [ "$VERIFIED" = false ]; then
    log_error "GitHub SSH authentication failed after ${MAX_ATTEMPTS} attempts"
    echo ""
    echo "  Troubleshooting:"
    echo "    1. Confirm the key is saved at: ${GITHUB_KEYS_URL}"
    echo "    2. Check the public key: sudo cat ${DEPLOY_KEY_PATH}.pub"
    echo "    3. Test manually: sudo -u ${SERVICE_ACCOUNT} ssh -T git@github.com"
    echo ""
    exit 1
fi

log_ok "GitHub SSH connection verified as '${SERVICE_ACCOUNT}'"

echo ""
echo -e "${GREEN}  Bootstrap complete — proceeding to install${NC}"
echo ""

# =============================================================
# PHASE 2 — INSTALL
# =============================================================

INSTALL_SCRIPT="${SCRIPT_DIR}/install.sh"

if [ ! -f "${INSTALL_SCRIPT}" ]; then
    log_error "install.sh not found at ${INSTALL_SCRIPT}"
    log_info  "Ensure install.sh is in the same directory as setup.sh"
    exit 1
fi

export SETUP_SH_CALLED=1
exec sudo bash "${INSTALL_SCRIPT}"
