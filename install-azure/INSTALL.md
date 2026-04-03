# 0xRecon — Azure VM Deployment Guide

## Prerequisites

- **Server:** Ubuntu 24.04 LTS (Azure VM or equivalent)
- **RAM:** 4 GB minimum (8 GB recommended)
- **Disk:** 30 GB minimum
- **Admin user:** SSH access with sudo privileges
- **GitHub:** Access to the 0xReconv2 repository
- **DNS:** Ability to create A records (for HTTPS access)

## Quick Start

From your admin user's SSH session on the server:

```bash
# 1. Get the install scripts onto the server
#    (clone the repo, or scp the install-azure/ directory)
git clone https://github.com/oliverom-admin/0xReconv2.git /tmp/0xrecon-install
cd /tmp/0xrecon-install

# 2. Create and edit your deployment config
cp install-azure/deployment.conf.example install-azure/deployment.conf
nano install-azure/deployment.conf

# 3. Run setup — does everything
bash install-azure/setup.sh
```

## What Setup Does

### Phase 1 — Bootstrap (setup.sh)

1. Validates all required values in `deployment.conf`
2. Rejects placeholder/default passwords
3. Creates the `svc-0xrecon` service account
4. Creates `/opt/0xrecon` directory
5. Generates an Ed25519 SSH deploy key
6. Prompts you to add the public key to GitHub
7. Verifies GitHub SSH connectivity

### Phase 2 — Install (install.sh, called automatically)

8. Updates system packages
9. Installs Docker CE and Docker Compose plugin
10. Installs nginx (host process, managed by systemd)
11. Clones the repository via SSH
12. Creates `/etc/0xrecon/` and `/var/log/0xrecon/`
13. Writes `/etc/0xrecon/app.env` with production settings
14. Symlinks `.env` in the repo root to the env file
15. Configures log rotation (14-day default)
16. Generates self-signed TLS cert (or installs provided cert)
17. Writes nginx config with API and App subdomains
18. Creates and starts the `0xrecon.service` systemd unit
19. Waits for the API health endpoint to respond
20. Bootstraps the first admin user

## Configuration Reference

See `deployment.conf.example` for all available settings. Key values:

| Variable | Description | How to generate |
|---|---|---|
| `POSTGRES_PASSWORD` | Database password | `openssl rand -base64 32` |
| `RECON_SECRET_KEY` | JWT signing key | `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `RECON_VAULT_MASTER_PASSWORD` | Vault encryption key (min 32 chars) | `openssl rand -base64 32` |
| `INITIAL_ADMIN_PASSWORD` | First admin account password | Choose a strong password |
| `BASE_DOMAIN` | Your root domain | e.g., `stationhex.co.uk` |
| `SUBDOMAIN_PREFIX` | Prefix for api./app. subdomains | e.g., `demo.recon` |

## After Installation

### DNS Records

Create two A records pointing to your server's IP:

```
api.PREFIX.BASE_DOMAIN  ->  SERVER_IP
app.PREFIX.BASE_DOMAIN  ->  SERVER_IP
```

### Verify

```bash
# Run the smoke test
bash install-azure/smoke-test.sh

# Check service status
sudo systemctl status 0xrecon

# View container status
docker compose -p 0xrecon ps

# Check health
curl http://127.0.0.1:8000/api/v1/health/

# View logs
sudo journalctl -u 0xrecon -f
docker compose -p 0xrecon logs -f
```

### Deploy Updates

After pushing new code to GitHub:

```bash
bash install-azure/deploy-update.sh
```

This pulls the latest code, rebuilds Docker images, restarts the service,
waits for a healthy API, and runs the smoke test.

### Teardown

To completely remove the deployment:

```bash
bash install-azure/setup.sh teardown
```

This removes all containers, volumes, directories, nginx config, and the
systemd unit. The service account is not removed.

## Architecture

```
Host:
  nginx (apt, systemd) — ports 80, 443, 8443
    -> 127.0.0.1:8000 (recon-api)
    -> 127.0.0.1:3000 (recon-ui)

Docker Compose (4 containers):
  recon-postgres  — PostgreSQL 16 (internal only)
  recon-api       — FastAPI on port 8000
  recon-worker    — Background scheduler (same image)
  recon-ui        — nginx:alpine placeholder on port 3000

Volumes:
  0xrecon_postgres_data  — database
  0xrecon_data           — vault, certs
  0xrecon_reports        — generated reports

Files:
  /opt/0xrecon/          — repository clone
  /etc/0xrecon/app.env   — environment file
  /var/log/0xrecon/      — service logs
  /etc/nginx/ssl/        — TLS certificate
```

## Troubleshooting

### API not starting

```bash
# Check container logs
docker compose -p 0xrecon logs recon-api --tail 50

# Check if Alembic migrations ran
docker compose -p 0xrecon exec recon-api alembic -c migrations/alembic.ini current
```

### Database connection issues

```bash
# Check postgres container
docker compose -p 0xrecon logs recon-postgres --tail 20

# Verify credentials match
grep POSTGRES /etc/0xrecon/app.env
```

### Nginx errors

```bash
# Test config
sudo nginx -t

# Check error log
sudo tail -20 /var/log/nginx/error.log

# Verify cert
openssl x509 -in /etc/nginx/ssl/0xrecon.crt -noout -subject -dates
```

### Service won't start

```bash
# Check systemd status
sudo systemctl status 0xrecon -l

# Check service logs
sudo journalctl -u 0xrecon --no-pager -n 50
```
