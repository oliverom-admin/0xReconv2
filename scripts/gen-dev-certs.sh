#!/bin/bash
# =============================================================================
# 0xRecon — Generate self-signed TLS certificates (manual use only)
# =============================================================================
# NOTE: nginx has been removed from docker-compose.yml.
# These certificates are NOT needed to run the development stack.
#
# This script is retained for cases where a developer wants to run the
# nginx container manually outside of Docker Compose, or as a reference
# for the certificate format used by the production install script.
#
# For normal development: use scripts/dev-up.sh — no certs needed.
# =============================================================================
set -e
CERT_DIR="nginx/certs"
mkdir -p "$CERT_DIR"
echo "[gen-dev-certs] Generating self-signed certificate..."
openssl req -x509 \
    -newkey rsa:4096 \
    -keyout "$CERT_DIR/dev.key" \
    -out    "$CERT_DIR/dev.crt" \
    -days 365 \
    -nodes \
    -subj "/C=GB/ST=England/L=London/O=0xRecon Dev/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 600 "$CERT_DIR/dev.key"
chmod 644 "$CERT_DIR/dev.crt"
echo "[gen-dev-certs] Done: $CERT_DIR/dev.crt and dev.key"
