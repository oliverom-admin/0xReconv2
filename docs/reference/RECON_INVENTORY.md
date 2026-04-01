# 0xRecon Codebase Inventory

**Generated:** 2026-04-01
**Purpose:** Complete read-only analysis for architecture redesign. This document provides enough detail for an architect to make every technology and design decision without needing to read the source code.

---

## Table of Contents

1. [Repository Structure](#section-1--repository-structure)
2. [Application Entry Points](#section-2--application-entry-points)
3. [Flask Application Deep Analysis](#section-3--flask-application-deep-analysis)
4. [Service Layer Analysis](#section-4--service-layer-analysis)
5. [Collector / Connector Analysis](#section-5--collector--connector-analysis)
6. [Data Models and Database](#section-6--data-models-and-database)
7. [Cryptographic Operations Inventory](#section-7--cryptographic-operations-inventory)
8. [PQC Detection and Policy Engine](#section-8--pqc-detection-and-policy-engine)
9. [Scoring and Assessment Engine](#section-9--scoring-and-assessment-engine)
10. [UI Assessment](#section-10--ui-assessment)
11. [Authentication and Authorisation](#section-11--authentication-and-authorisation)
12. [Configuration Management](#section-12--configuration-management)
13. [External Dependencies Full Audit](#section-13--external-dependencies-full-audit)
14. [Test Coverage Assessment](#section-14--test-coverage-assessment)
15. [Inter-Module Dependency Map](#section-15--inter-module-dependency-map)
16. [Known Issues, Tech Debt and Code Quality](#section-16--known-issues-tech-debt-and-code-quality)
17. [Migration Readiness Assessment](#section-17--migration-readiness-assessment)

---

## Section 1 — Repository Structure

```
0xRecon/
├── .claude/                              # Claude Code session data
├── .dist/                                # Distribution/build artifacts
├── _Archive/                             # Historical/deprecated code
├── _docs/                                # Documentation (various formats)
├── _style/                               # Styling/theme assets
│
├── caip_document_assessment_functions/   # Document assessment and evaluation
│   ├── __init__.py
│   ├── document_assessment_database.py   # DB schema for document assessments
│   ├── document_assessment_routes.py     # Flask routes for document assessment API
│   ├── document_assessment_service.py    # Business logic for document handling
│   ├── document_templates.py             # Document template definitions
│   └── document_templates_Enhanced.py    # Enhanced template variations
│
├── caip_engagement_functions/            # Customer engagement & reporting management
│   ├── engagement_routes.py              # Flask routes for engagement CRUD/reporting
│   ├── engagement_service.py             # Engagement business logic
│   └── email_functions/                  # Email delivery and notifications
│
├── caip_logging_functions/               # Enterprise logging system
│   ├── logging_config.py                 # Audit logging setup
│   ├── logging_config_1.py               # Alternate config variant
│   ├── logging_config_2.py               # Another config variant
│   ├── logging_helpers.py                # Logging utility functions
│   ├── logging_helpers_1.py              # Helper variation
│   ├── logging_helpers_2.py              # More helper functions
│   ├── LOGGING_ARCHITECTURE.txt          # Architecture documentation
│   ├── LOGGING_OVERVIEW.txt              # Overview documentation
│   ├── FLASK_INTEGRATION.txt             # Flask integration guide
│   └── INTEGRATION_EXAMPLES.txt          # Integration examples
│
├── caip_policy_functions/                # Policy definition and evaluation
│   ├── policy_assessment_service.py      # Policy assessment logic
│   └── rule_assessment.py                # Rule evaluation engine
│
├── caip_pqc_functions/                   # Post-Quantum Cryptography detection
│   └── pqc_detector.py                   # PQC algorithm detection service
│
├── caip_reporting_functions/             # Report generation and export
│   ├── cbom_export_service.py            # Cryptographic Bill of Materials export
│   ├── engagement_chart_builder.py       # Chart generation
│   ├── engagement_chart_builder_pil.py   # PIL-based chart builder
│   ├── engagement_docx_builder.py        # Word document generation
│   ├── engagement_docx_charts.py         # Chart embedding in Word
│   ├── engagement_financial_calculator.py # Financial impact calculations
│   ├── engagement_financial_section.py   # Financial report sections
│   ├── executive_report_docx_service.py  # Executive summary Word doc
│   ├── executive_report_redesigned.py    # Redesigned executive report
│   ├── executive_report_service.py       # Executive report service
│   ├── reporting.py                      # Core reporting functionality
│   ├── reporting_service.py              # Report service layer
│   ├── report_docx_sections.py           # Document section builders
│   ├── report_docx_styles.py             # Word document styling
│   ├── report_docx_template.py           # Template-based doc generation
│   └── test_docx_phase1.py              # Phase 1 testing
│
├── caip_scanning_functions/              # PKI data collection and scanning
│   ├── __init__.py
│   ├── assessment.py                     # Assessment model definitions
│   ├── config.py                         # Scanner configuration defaults
│   ├── health_check.py                   # Health check operations
│   ├── main.py                           # Entry point for scanning module
│   ├── models.py                         # Data models (Cert, Key, TLS, CRL, etc.)
│   ├── models_1.py                       # Model variants
│   ├── reporting.py                      # Scanning result reporting
│   ├── verify_refactoring.py             # Refactoring verification
│   ├── _scan_orchestrator.py             # Orchestration engine for scan execution
│   ├── _scan_orchestrator copy.py        # Backup variant
│   ├── _Archive/                         # Archived scanner implementations
│   └── collectors/                       # Specialized collectors
│       ├── __init__.py
│       ├── azure_keyvault.py             # Azure Key Vault collector
│       ├── crl_collector.py              # CRL retrieval collector
│       ├── ejbca_collector.py            # EJBCA PKI system collector
│       ├── file_share.py                 # Network file share scanner
│       ├── luna_hsm.py                   # Thales Luna HSM collector
│       ├── luna_hsm_2.py                 # Luna HSM variant
│       └── tls_scanner.py               # TLS/SSL scanner
│
├── caip_service_layer/                   # Core business logic and integrations
│   ├── assessment_routes.py              # Domain 1-3 assessment API routes
│   ├── assessment_service.py             # Assessment questionnaire service
│   ├── asset_context_routes.py           # Asset relationship/context API
│   ├── asset_context_service.py          # Asset context business logic
│   ├── auth_service.py                   # Authentication/authorization core
│   ├── certificate_routes.py             # PKI certificate management routes
│   ├── certificate_service.py            # Certificate lifecycle management
│   ├── encryption_utils.py               # AES-256-GCM encryption utilities
│   ├── enrichment_routes.py              # Data enrichment API routes
│   ├── enrichment_service.py             # Enrichment business logic
│   ├── environment_inference_service.py  # Environment type detection
│   ├── inventory_orchestrator.py         # Multi-phase inventory orchestration
│   ├── inventory_service.py              # Inventory management
│   ├── key_normalisation_service.py      # Cryptographic key normalization
│   ├── metadata_enrichment_service.py    # Metadata enrichment
│   ├── mtls_validator.py                 # mTLS certificate validation
│   ├── oauth_service.py                  # OAuth 2.0 integration
│   ├── oauth_providers/                  # OAuth provider implementations
│   │   ├── __init__.py
│   │   ├── azure_entra_id.py             # Azure Entra ID provider
│   │   └── okta.py                       # Okta provider
│   ├── pki_terminology.py                # PKI domain terminology database
│   ├── pqc_reporting_service.py          # PQC reporting
│   ├── rbac_service.py                   # Role-Based Access Control
│   ├── relationship_routes.py            # Relationship API routes
│   ├── relationship_service.py           # Relationship business logic
│   ├── remote_collector_service.py       # Edge/remote collector management
│   ├── scheduler_service.py              # Background job scheduling
│   ├── scoring_service.py                # Assessment scoring logic
│   ├── secret_resolution_service.py      # Multi-backend secret resolution
│   ├── secret_service.py                 # Legacy secret management
│   ├── secret_store_manager.py           # Secret store provider management
│   ├── secret_store_providers/           # Secret store backend implementations
│   ├── secrets_cli.py                    # Secret management CLI
│   ├── unified_vault_service.py          # Modern AES-256-GCM vault
│   └── secret_store_routes.py            # Secret store management API
│
├── caip_route_layer/                     # Additional blueprint route files
│   ├── cbom_routes.py                    # Cryptographic BOM routes
│   ├── inventory_routes.py               # Continuous inventory monitoring
│   ├── remote_collector_routes.py        # Remote collector API endpoints
│   └── secret_store_routes.py            # Secret store management routes
│
├── caip_workflow_functions/              # Workflow automation
│   └── email_functions/                  # Email workflows
│
├── database_migrations/                  # Database migration scripts
├── docs/                                 # Application documentation
├── logs/                                 # Runtime logs directory
├── policies/                             # Policy definition files (YAML/JSON)
│
├── remote_collector/                     # Standalone remote collector application
│   ├── __main__.py                       # Entry point (register, run commands)
│   ├── app.py                            # Flask app (mirrors main structure)
│   ├── daemon.py                         # Daemon mode, local decryption endpoint
│   ├── client.py                         # Server communication client
│   ├── scanner.py                        # Scanning orchestration
│   ├── connector_service.py              # Connector implementations
│   ├── database_service.py               # Local SQLite database
│   ├── config.py                         # Collector configuration
│   ├── models.py                         # Data models
│   ├── reporting_service.py              # Local report generation
│   ├── assessment.py                     # Assessment logic
│   ├── adapters/                         # Collector-specific adapters
│   ├── caip_policy_functions/            # DUPLICATED from main
│   ├── caip_pqc_functions/               # DUPLICATED from main
│   ├── caip_reporting_functions/         # DUPLICATED from main
│   ├── caip_scanning_functions/          # DUPLICATED from main
│   ├── caip_service_layer/               # DUPLICATED from main
│   ├── QUICK_START.sh                    # Installation script
│   ├── install.sh                        # Systemd service installation
│   └── requirements.txt                  # Python dependencies (subset)
│
├── reports/                              # Generated reports directory
├── scripts/                              # Utility scripts
├── static/                               # Static web assets
│   ├── css/dashboard/                    # 15 CSS files (custom theme system)
│   ├── js/dashboard/                     # 19+ JS files (vanilla JS, fetch API)
│   └── images/                           # Image assets
├── templates/                            # Jinja2 HTML templates (6 files)
├── uploads/                              # User file uploads
│   └── documents/                        # Document uploads
│
├── app.py                                # MAIN FLASK APP (5,915 lines — GOD OBJECT)
├── caip_vault_cli.py                     # Vault management CLI tool
├── collector_client.py                   # Remote collector test client
├── connector_service.py                  # System connector orchestration
├── database_constraint_removal.py        # Migration utility
├── database_migrations.py                # Migration runner
├── database_service.py                   # SQLite database layer (~110KB)
├── diagnose_luna_hsm.py                  # Luna HSM diagnostics
├── diagnose_running_dashboard.sh         # Dashboard diagnostics script
├── manage_users.py                       # User management CLI tool
├── pki_integration.py                    # PKI system integration
├── production_config_collectors.py       # Gunicorn config (collectors port 5444)
├── production_config.py                  # Gunicorn config (dashboard port 5443)
├── setup_caip_vault.py                   # Vault initialization utility
├── start_app.bat                         # Windows startup script
├── start_app.sh                          # Linux/Mac startup script (gunicorn dual-endpoint)
└── requirements.txt                      # Python dependencies
```

---

## Section 2 — Application Entry Points

### 2.1 Flask Instantiation

**Single instance at module level** — no application factory pattern.

- **File:** `app.py:151`
- **Code:** `app = Flask(__name__)`
- **Config applied:** Upload folder, reports folder, database path, 16MB max upload, session security (HTTP-only, SameSite=Lax, 8-hour lifetime)

### 2.2 Main Entry Point

**File:** `app.py:5898-5915`
```python
if __name__ == '__main__':
    SchedulerService.start(check_interval_seconds=60)
    app.run(debug=False, host='0.0.0.0', port=5000)
```

Actions on startup:
1. Loads .env via python-dotenv
2. Initializes UnifiedVaultService (AES-256-GCM, system_vault.enc)
3. Initializes Legacy SecretService (AUTO: Azure KV → file → memory)
4. Loads Flask secret key from vault (fallback: random temporary key)
5. Configures DatabaseService (SQLite with WAL mode)
6. Runs `DatabaseService.init_db()` (creates all tables, runs migrations)
7. Auto-provisions Internal CA and Dashboard TLS certificate
8. Registers 12 blueprint route modules
9. Loads SecretStoreManager (registered stores from DB)
10. Starts SchedulerService (60-second inventory sync interval)
11. Launches Flask dev server on 0.0.0.0:5000

### 2.3 CLI Entry Points

| Script | Purpose | Framework | Subcommands |
|--------|---------|-----------|-------------|
| `caip_vault_cli.py` | Vault management | argparse | init, set, get, list, delete, unlock |
| `manage_users.py` | User account management | argparse | reset-password, create admin/user, list, set-role, disable, enable |
| `collector_client.py` | Remote collector test | argparse | register, heartbeat, report, daemon |
| `setup_caip_vault.py` | Vault initialization | direct | Single command |
| `diagnose_luna_hsm.py` | HSM diagnostics | direct | Single command |
| `secrets_cli.py` | Secret management | argparse | Various secret operations |

### 2.4 Shell Scripts

**start_app.sh** (Production — Linux):
```bash
# Sets environment variables:
CAIP_VAULT_FILE=system_vault.enc
CAIP_SECRET_BACKEND=AUTO
CAIP_MASTER_PASSWORD=test-master-password-12345
# Azure KV credentials (development values)
AZURE_KEY_VAULT_URL=https://thalescrypto-kv01.vault.azure.net/
AZURE_TENANT_ID=a330a4b0-a516-470c-8f43-b227229864c2
AZURE_CLIENT_ID=fd61fb32-89c8-4cf0-9636-2b26b5d8860a
AZURE_CLIENT_SECRET=REDACTED_FOR_PUSH_PROTECTION

# Launches TWO gunicorn endpoints:
# Port 5443 — Dashboard (session auth, TLS + optional mTLS)
# Port 5444 — Collectors (required mTLS, client cert validation)
```

**start_app.bat** (Development — Windows):
```batch
# Sets same env vars, launches Flask dev server on 0.0.0.0:5000
python -X utf8 -m flask run --host=0.0.0.0 --port=5000
```

### 2.5 Scheduled Tasks

| Task | Module | Interval | Purpose |
|------|--------|----------|---------|
| SchedulerService | `caip_service_layer/scheduler_service.py` | 60 seconds | Inventory synchronization |

### 2.6 Containerisation

**No Dockerfile exists.** No docker-compose.yml. No container configuration of any kind.

### 2.7 Requirements (Full)

```
# requirements.txt — reproduced in full

# CORE WEB FRAMEWORK
Flask==2.3.3
Werkzeug==2.3.7
Jinja2==3.1.2

# CONFIGURATION & ENVIRONMENT
python-dotenv==1.0.0

# CRYPTOGRAPHY & SECURITY
cryptography==41.0.3
PyJWT==2.8.0
bcrypt==4.0.1

# CERTIFICATE HANDLING
pyOpenSSL==23.2.0
certifi==2023.7.22

# REPORT GENERATION
reportlab==4.0.4
Pillow==10.0.0

# DATA FORMATS & SERIALIZATION
PyYAML==6.0.1
jsonschema==4.19.0

# HTTP & NETWORKING
requests==2.31.0
urllib3==2.0.4

# AZURE INTEGRATION (Optional — commented out)
# azure-identity==1.14.0
# azure-keyvault-secrets==4.7.0
# azure-keyvault-keys==4.7.0

# DATABASE: SQLite3 (built-in, WAL mode configured in app.py)

# MONITORING
psutil==5.9.5

# PRODUCTION SERVER
gunicorn==21.2.0
gevent==23.9.1

# OPTIONAL (not in requirements.txt but imported with try/except):
# PyKCS11 — Luna HSM support
# python-docx — DOCX report generation
# matplotlib — Chart generation
```

### 2.8 Environment Variables

```
# .env — reproduced in full
CAIP_SECRET_BACKEND=ENCRYPTED_FILE
CAIP_SECRETS_FILE=secrets.enc
CAIP_MASTER_PASSWORD=test-master-password-12345
# CAIP_MASTER_KEYFILE=/etc/caip/master.key
# AZURE_KEY_VAULT_URL=https://thalescrypto-kv01.vault.azure.net/
# AZURE_TENANT_ID=a330a4b0-a516-470c-8f43-b227229864c2
# AZURE_CLIENT_ID=fd61fb32-89c8-4cf0-9636-2b26b5d8860a
# AZURE_CLIENT_SECRET=REDACTED_FOR_PUSH_PROTECTION
FLASK_APP=app.py
FLASK_ENV=development
```

**Complete Environment Variable Map:**

| Variable | Purpose | Required | Default |
|----------|---------|----------|---------|
| `CAIP_SECRET_BACKEND` | Secret backend mode | Yes | `ENCRYPTED_FILE` |
| `CAIP_VAULT_FILE` | Encrypted vault file path | No | `system_vault.enc` |
| `CAIP_MASTER_PASSWORD` | Master password for vault | Yes (if file backend) | None |
| `CAIP_MASTER_KEYFILE` | Alternative to password | No | None |
| `CAIP_SECRETS_FILE` | Legacy secrets file | No | `secrets.enc` |
| `AZURE_KEY_VAULT_URL` | Azure KV endpoint | No | None |
| `AZURE_TENANT_ID` | Azure AD tenant | No | None |
| `AZURE_CLIENT_ID` | Azure service principal | No | None |
| `AZURE_CLIENT_SECRET` | Azure SP secret | No | None |
| `COLLECTOR_API_TOKEN` | Remote collector auth | No | `default-collector-token` |
| `FLASK_APP` | Flask application module | No | `app.py` |
| `FLASK_ENV` | Flask environment | No | `development` |

---

## Section 3 — Flask Application Deep Analysis

### 3.1 Blueprint Registrations (12 Total)

| # | Module | Registration Function | Purpose |
|---|--------|----------------------|---------|
| 1 | `caip_document_assessment_functions/document_assessment_routes.py` | `register_document_assessment_routes()` | Document assessment CRUD, evaluation, scoring |
| 2 | `caip_service_layer/certificate_routes.py` | `register_certificate_routes()` | User identity certs, CA management, cert lifecycle |
| 3 | `caip_engagement_functions/engagement_routes.py` | `register_engagement_routes()` | Engagement CRUD, customer management |
| 4 | `caip_service_layer/assessment_routes.py` | `register_assessment_routes()` | Assessment schema, questionnaire responses |
| 5 | `caip_service_layer/asset_context_routes.py` | `register_context_routes()` | Asset relationship management |
| 6 | `caip_service_layer/relationship_routes.py` | `register_relationship_routes()` | Certificate/key relationship mapping |
| 7 | `caip_service_layer/enrichment_routes.py` | `register_enrichment_routes()` | Data enrichment operations |
| 8 | `caip_route_layer/cbom_routes.py` | `register_cbom_routes()` | Cryptographic Bill of Materials export |
| 9 | `caip_route_layer/inventory_routes.py` | `register_inventory_routes()` | Continuous inventory monitoring |
| 10 | `caip_route_layer/remote_collector_routes.py` | `register_remote_collector_routes()` | Edge collector API |
| 11 | `caip_route_layer/secret_store_routes.py` | `register_secret_store_routes()` | Secret store provider management |
| 12 | `caip_service_layer/secret_store_routes.py` | `register_routes()` | System vault display (read-only) |

### 3.2 All Routes (89 in app.py + blueprint routes)

#### Authentication & Session (6 routes)
| Method | Path | Function | Auth | Permission |
|--------|------|----------|------|------------|
| GET/POST | `/login` | `login()` | — | — |
| GET | `/logout` | `logout()` | — | — |
| GET | `/` | `index()` | — | — |
| GET | `/dashboard` | `dashboard()` | `@login_required` | — |
| GET | `/api/session` | `get_session()` | `@login_required` | — |
| GET | `/api/v1/auth/mode` | `get_auth_mode()` | — | — |

#### RBAC & User Management (16 routes)
| Method | Path | Function | Auth | Permission |
|--------|------|----------|------|------------|
| GET | `/api/v1/users` | `get_users()` | `@login_required` | — |
| POST | `/api/v1/users` | `create_user()` | `@login_required` | `users:create` |
| PUT | `/api/v1/users/<id>` | `update_user()` | `@login_required` | `users:update` |
| DELETE | `/api/v1/users/<id>` | `delete_user()` | `@login_required` | `users:delete` |
| GET | `/api/v1/users/roles` | `get_roles()` | `@login_required` | — |
| GET | `/api/v1/rbac/roles` | `get_rbac_roles()` | `@login_required` | `users:read` |
| GET | `/api/v1/rbac/roles/<id>/permissions` | `get_role_permissions()` | `@login_required` | `users:read` |
| GET | `/api/v1/rbac/permissions` | `get_rbac_permissions()` | `@login_required` | `users:read` |
| GET | `/api/v1/rbac/users/<id>/permissions` | `get_user_permissions()` | `@login_required` | — |
| GET | `/api/v1/rbac/engagements/<id>/users` | `get_engagement_users()` | `@login_required` | `engagements:read` |
| POST | `/api/v1/rbac/engagements/<id>/assign` | `assign_user_to_engagement()` | `@login_required` | `engagements:assign_users` |
| DELETE | `/api/v1/rbac/engagements/<eid>/unassign/<uid>` | `unassign_user_from_engagement()` | `@login_required` | `engagements:assign_users` |
| GET | `/api/v1/auth/providers` | `get_auth_providers()` | — | — |
| GET | `/api/v1/auth/oauth/login/<id>` | `oauth_login()` | — | — |
| GET | `/api/v1/auth/oauth/callback` | `oauth_callback()` | — | — |
| GET | `/admin/certificates` | `certificate_management()` | `@login_required` | `users:read` |

#### Auth Provider Settings (5 routes)
| Method | Path | Function | Auth | Permission |
|--------|------|----------|------|------------|
| GET | `/api/v1/settings/auth-providers` | `get_all_auth_providers()` | `@login_required` | `auth_providers:read` |
| POST | `/api/v1/settings/auth-providers` | `create_auth_provider()` | `@login_required` | `auth_providers:create` |
| GET | `/api/v1/settings/auth-providers/<id>` | `get_auth_provider()` | `@login_required` | `auth_providers:read` |
| PUT | `/api/v1/settings/auth-providers/<id>` | `update_auth_provider()` | `@login_required` | `auth_providers:update` |
| DELETE | `/api/v1/settings/auth-providers/<id>` | `delete_auth_provider()` | `@login_required` | `auth_providers:delete` |

#### Scan Configuration (5 routes)
| Method | Path | Function | Auth | Permission |
|--------|------|----------|------|------------|
| GET | `/api/v1/scans/configurations` | `get_configurations()` | `@login_required` | `scan_configs:read` |
| POST | `/api/v1/scans/configurations` | `create_configuration()` | `@login_required` | `scan_configs:create` |
| PUT | `/api/v1/scans/configurations/<id>` | `update_configuration()` | `@login_required` | `scan_configs:update` |
| DELETE | `/api/v1/scans/configurations/<id>` | `delete_configuration()` | `@login_required` | `scan_configs:delete` |
| GET | `/api/v1/scans/configurations/<id>/export` | `export_configuration()` | `@login_required` | `scan_configs:read` |

#### Policy Management (8 routes)
| Method | Path | Function | Auth | Permission |
|--------|------|----------|------|------------|
| POST | `/api/v1/policies/upload` | `upload_policy_v2()` | `@login_required` | — |
| GET | `/api/v1/policies` | `list_policies()` | `@login_required` | — |
| POST | `/api/v1/policies` | `create_policy()` | `@login_required` | — |
| GET | `/api/v1/policies/<id>` | `get_policy()` | `@login_required` | — |
| PUT | `/api/v1/policies/<id>` | `update_policy()` | `@login_required` | — |
| DELETE | `/api/v1/policies/<id>` | `delete_policy()` | `@login_required` | — |
| GET | `/api/v1/policies/by-assessment-type/<type>` | `get_policies_by_assessment_type()` | `@login_required` | `view` |
| GET | `/api/v1/assessment-types` | `get_assessment_types()` | `@login_required` | — |

#### Scan Execution (7 routes)
| Method | Path | Function | Auth | Permission |
|--------|------|----------|------|------------|
| GET | `/api/v1/scans` | `get_scans()` | `@login_required` | `scans:read` |
| POST | `/api/v1/scans` | `create_scan()` | `@login_required` | `scans:create` |
| PUT | `/api/v1/scans/<id>` | `update_scan()` | `@login_required` | `scans:update` |
| DELETE | `/api/v1/scans/<id>` | `delete_scan()` | `@login_required` | `scans:delete` |
| POST | `/api/v1/scans/<id>/run` | `run_scan()` | `@login_required` | `scans:execute` |
| GET | `/api/v1/scans/<id>/status` | `get_scan_status()` | `@login_required` | `scans:read` |
| POST | `/api/v1/scans/<id>/cancel` | `cancel_scan()` | `@login_required` | `scans:execute` |

#### Scan Logs & Results (4 routes)
| Method | Path | Function | Auth | Permission |
|--------|------|----------|------|------------|
| GET | `/api/v1/scans/<id>/logs` | `get_scan_logs()` | `@login_required` | `scan_logs:read` |
| POST | `/api/remote/logs` | `add_remote_scan_log()` | — | — |
| GET | `/api/v1/scans/<id>/runs` | `get_scan_runs()` | `@login_required` | `scans:read` |
| POST | `/api/v1/scans/<id>/promote` | `promote_scan_to_inventory()` | `@login_required` | `inventory:update_context` |

#### Report Generation & Management (14 routes)
| Method | Path | Function | Auth | Permission |
|--------|------|----------|------|------------|
| GET | `/api/v1/reports/scans/<id>` | `get_scan_report()` | `@login_required` | `reports:read` |
| GET | `/api/v1/reports/scans/<id>/view` | `view_scan_report()` | `@login_required` | `reports:read` |
| POST | `/api/v1/reports/scans/<id>/upload` | `upload_scan_report()` | `@login_required` | `reports:write` |
| GET | `/api/v1/reports/<filename>` | `serve_report()` | `@login_required` | `reports:read` |
| GET | `/api/v1/reports/reassessments` | `get_reassessments()` | `@login_required` | `reports:read` |
| POST | `/api/v1/reports/reassessments` | `create_reassessment()` | `@login_required` | `reports:generate` |
| GET | `/api/v1/reports/reassessments/<id>/report/view` | `view_reassessment_report()` | `@login_required` | `reports:read` |
| POST | `/api/v1/reports/embed/config` | `get_embed_config()` | `@login_required` | `reports:generate` |
| POST | `/api/v1/reports/embed` | `generate_unified_embed_dashboard()` | `@login_required` | `reports:generate` |
| POST | `/api/v1/reports/executive-summary` | `generate_executive_summary()` | `@login_required` | `reports:executive_summary` |
| GET | `/api/v1/reports/aggregations` | `get_aggregations()` | `@login_required` | `reports:read` |
| POST | `/api/v1/reports/aggregations` | `create_aggregation()` | `@login_required` | `reports:aggregate` |
| GET | `/api/v1/reports/aggregations/<id>/report/view` | `view_aggregation_report()` | `@login_required` | `reports:read` |
| GET | `/api/v1/engagements/<id>/summary` | `get_engagement_summary()` | `@login_required` | `engagements:read` |

#### Inventory & Integration (14 routes)
| Method | Path | Function | Auth | Permission |
|--------|------|----------|------|------------|
| GET | `/api/v1/inventory/integrations` | `get_inventory_integrations()` | `@login_required` | `integrations:read` |
| POST | `/api/v1/inventory/integrations` | `create_inventory_integration()` | `@login_required` | `integrations:create` |
| POST | `/api/v1/inventory/integrations/<id>/sync` | `sync_inventory_integration()` | `@login_required` | `integrations:sync` |
| DELETE | `/api/v1/inventory/integrations/<id>` | `delete_inventory_integration()` | `@login_required` | `integrations:delete` |
| PUT | `/api/v1/inventory/integrations/<id>` | `update_inventory_integration()` | `@login_required` | `integrations:update` |
| PUT | `/api/v1/inventory/integrations/<id>/toggle` | `toggle_inventory_integration()` | `@login_required` | `integrations:enable_disable` |
| GET | `/api/v1/inventory/integrations/<id>/certificates` | `get_integration_certificates()` | `@login_required` | `inventory:read_certificates` |
| GET | `/api/v1/inventory/integrations/<id>/cas` | `get_integration_cas()` | `@login_required` | `integrations:read` |
| GET | `/api/v1/clm/integrations/<id>/promoted-scans` | `get_promoted_scans()` | `@login_required` | — |
| DELETE | `/api/v1/clm/integrations/<id>/promoted-scans/<name>` | `delete_promoted_scan()` | `@login_required` | — |
| GET | `/api/v1/inventory/certificates` | `get_inventory_certificates()` | `@login_required` | — |
| GET | `/api/v1/kms/keys` | `get_kms_keys()` | `@login_required` | — |
| POST | `/api/v1/clm/compliancy/assess` | `assess_clm_compliancy()` | `@login_required` | — |
| GET | `/api/v1/lifecycle/policies` | `get_lifecycle_policies()` | `@login_required` | — |

#### Lifecycle Management (6 routes)
| Method | Path | Function | Auth | Permission |
|--------|------|----------|------|------------|
| POST | `/api/v1/lifecycle/policies/<id>` | `set_lifecycle_policy()` | `@login_required` | — |
| GET | `/api/v1/lifecycle/queue` | `get_lifecycle_queue()` | `@login_required` | — |
| GET | `/api/v1/lifecycle/overview` | `get_lifecycle_overview()` | `@login_required` | — |
| GET | `/api/v1/activity/feed` | `get_activity_feed()` | `@login_required` | — |
| GET | `/api/v1/lifecycle/renewals` | `get_lifecycle_renewals()` | `@login_required` | — |
| GET | `/api/v1/lifecycle/rotations` | `get_lifecycle_rotations()` | `@login_required` | — |

#### Utility (3 routes)
| Method | Path | Function | Auth | Permission |
|--------|------|----------|------|------------|
| GET | `/dpod` | `dpod_dashboard()` | `@login_required` | — |
| GET | `/api/admin/bootstrap-verify` | `verify_bootstrap()` | `@login_required` | — |
| GET | `/api/health` | `health_check()` | — | — |

### 3.3 Middleware & Request Hooks

**@app.before_request** (Lines 243-339):
1. Generates 8-character request ID (UUID) for audit tracking
2. Sets audit context with request_id and username (if authenticated)
3. On port 5444: extracts SSL_CLIENT_CERT from WSGI environment, validates via `MTLSCertificateValidator`, returns 403 if invalid

**No @app.after_request, @app.errorhandler, or @app.teardown_appcontext handlers defined.**

### 3.4 Flask Extensions

| Extension | Status | Purpose |
|-----------|--------|---------|
| Flask-CORS | **Not used** | — |
| Flask-SQLAlchemy | **Not used** | Raw sqlite3 instead |
| Flask-Login | **Not used** | Custom `@login_required` decorator |
| Flask-JWT-Extended | **Not used** | Session-based auth instead |
| Flask-Migrate | **Not used** | Custom migration scripts |

**No Flask extensions are used.** All functionality is implemented with custom code.

---

## Section 4 — Service Layer Analysis

### 4.1 Core Services

| Service | File | Purpose |
|---------|------|---------|
| **DatabaseService** | `database_service.py` (~110KB) | SQLite connection, schema, migrations, all CRUD operations |
| **AuthService** | `caip_service_layer/auth_service.py` | Authentication decorators, RBAC, role/permission checking |
| **CertificateService** | `caip_service_layer/certificate_service.py` | CA management, cert issuance, mTLS validation |
| **ScoringEngine** | `caip_service_layer/scoring_service.py` | Risk scoring, weight factors, effort estimation |
| **AggregationEngine** | `caip_service_layer/scoring_service.py` | Score aggregation, health index, grading |
| **InventoryService** | `caip_service_layer/inventory_service.py` | CLM inventory sync, promotion to persistent storage |
| **InventoryOrchestrator** | `caip_service_layer/inventory_orchestrator.py` | Multi-phase inventory orchestration |
| **AssetContextService** | `caip_service_layer/asset_context_service.py` | Asset enrichment, override management, history |
| **EnrichmentService** | `caip_service_layer/enrichment_service.py` | Bulk enrichment operations |
| **RelationshipService** | `caip_service_layer/relationship_service.py` | Certificate/key relationship mapping |
| **EnvironmentInferenceService** | `caip_service_layer/environment_inference_service.py` | Auto-detect prod/staging/dev from metadata |
| **KeyNormalisationService** | `caip_service_layer/key_normalisation_service.py` | Normalize key data across collector formats |
| **UnifiedVaultService** | `caip_service_layer/unified_vault_service.py` | AES-256-GCM encrypted secret storage |
| **SecretService** | `caip_service_layer/secret_service.py` | Legacy secret management (Azure KV + file) |
| **SecretStoreManager** | `caip_service_layer/secret_store_manager.py` | Multi-backend secret store orchestration |
| **SecretResolutionService** | `caip_service_layer/secret_resolution_service.py` | Resolve secrets from registered stores |
| **OAuthService** | `caip_service_layer/oauth_service.py` | OAuth 2.0 provider integration |
| **RBACService** | `caip_service_layer/rbac_service.py` | Role-based access control |
| **SchedulerService** | `caip_service_layer/scheduler_service.py` | Background job scheduling (60s interval) |
| **RemoteCollectorService** | `caip_service_layer/remote_collector_service.py` | Edge collector lifecycle management |
| **MTLSValidator** | `caip_service_layer/mtls_validator.py` | mTLS certificate validation |
| **EncryptionUtils** | `caip_service_layer/encryption_utils.py` | AES-256-GCM with PBKDF2 |

### 4.2 Key Service Methods

**CertificateService Workflow:**
```
ensure_internal_ca() → Check DB → Generate RSA 4096 CA cert → Store in vault + DB
ensure_dashboard_certificate() → Check DB → Generate cert signed by internal CA → Store in vault + DB
issue_certificate_for_collector(collector_id, engagement_id) → Sign with engagement CA → Store
validate_collector_certificate(cert_pem) → Parse → Extract CN/OU → Validate against DB
```

**Scoring Pipeline:**
```
ScoringEngine.score_finding(rule_result, asset_context, asset_data) → ScoredFinding
  → base_risk_score × weight_factors.combined = weighted_score
  → priority_score = weighted_score / effort_estimate

AggregationEngine.aggregate(scored_findings, total_assets, assets_with_context) → AssessmentScore
  → Count by severity → Sum exposure → Calculate health_index → Assign grade (A+ to F)
  → Generate priority_queue (top 10)
```

**Policy Assessment Pipeline:**
```
PolicyAssessmentService.assess_scan_results(scan_results, policy)
  → Convert models to assessment dicts
  → UnifiedAssessor evaluates against v2.0 policy rules
  → Returns: List[RuleResult], summary
```

**Inventory Sync:**
```
InventoryService.sync_connector(connector_id, results) → {items_total, added, updated, removed}
InventoryService.promote_scan_to_inventory(scan_id, connector_id) → count
```

### 4.3 Patterns

- **No dependency injection** — services instantiate their own dependencies
- **No async/await** — all synchronous blocking calls
- **No connection pooling** — SQLite connections created per-operation
- **No caching layer** — some in-memory caches per collector instance
- **No retry logic** — single-attempt operations with exception handling

---

## Section 5 — Collector / Connector Analysis

### 5.1 Luna HSM Collector (CRITICAL)

**File:** `caip_scanning_functions/collectors/luna_hsm.py`
**Class:** `LunaHSMCollector`
**External System:** Thales Luna HSM via PKCS#11
**Library:** PyKCS11 (NOT python-pkcs11)
**Mode:** Read-only discovery — no cryptographic operations performed

**Imports:**
```python
from PyKCS11 import PyKCS11Lib, PyKCS11, PyKCS11Error
from PyKCS11.LowLevel import (
    CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_CERTIFICATE, CKO_SECRET_KEY,
    CKA_LABEL, CKA_ID, CKA_KEY_TYPE, CKA_MODULUS_BITS, CKA_EC_PARAMS, CKA_VALUE,
    CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_MODIFIABLE,
    CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE, CKA_LOCAL,
    CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY, CKA_WRAP, CKA_UNWRAP, CKA_DERIVE,
    CKA_START_DATE, CKA_END_DATE
)
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
```

**Connection:** Constructor takes `pkcs11_module_path` (DLL/SO path) and `hsm_name`. Partition password passed to `collect_keys_from_partition()`.

**Methods:**
| Method | Purpose |
|--------|---------|
| `__init__(pkcs11_module_path, hsm_name)` | Load PKCS#11 module |
| `_safe_get(session, obj, attr)` | Safe attribute retrieval with exception handling |
| `_open_session_and_login(slot, password)` | Open session, authenticate with partition password |
| `collect_keys_from_partition(password, slot_index, partition_label)` | Main collection — enumerate all keys |

**PKCS#11 Attributes Read:**
- **Identity:** CKA_LABEL, CKA_ID, CKA_TOKEN, CKA_PRIVATE
- **Security:** CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_MODIFIABLE, CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE, CKA_LOCAL
- **Operations:** CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY, CKA_WRAP, CKA_UNWRAP, CKA_DERIVE
- **Key Type:** CKA_KEY_TYPE → CKK_RSA, CKK_EC, CKK_AES, CKK_DES3, CKK_DES
- **Key Size:** CKA_MODULUS_BITS (RSA), CKA_EC_PARAMS (EC), CKA_VALUE_LEN (symmetric)
- **Lifecycle:** CKA_START_DATE, CKA_END_DATE
- **Certificate:** CKA_VALUE (DER-encoded cert, matched by CKA_ID)

**Hardcoded Values:**
- EC key size default: 256 bits (should derive from CKA_EC_PARAMS)
- 3DES: 168 bits
- DES: 56 bits

**Thread Safety:** Session per slot, no shared state, session closed in finally block.

### 5.2 Azure Key Vault Collector

**File:** `caip_scanning_functions/collectors/azure_keyvault.py`
**Class:** `AzureKeyVaultCollector`
**Library:** `azure-keyvault-certificates`, `azure-keyvault-keys`, `azure-identity`
**Mode:** Read-only metadata extraction

**Connection:** Service Principal auth (`ClientSecretCredential`) or `DefaultAzureCredential` fallback.

**Methods:**
| Method | Purpose |
|--------|---------|
| `collect_all_certificates()` | List and parse all certificates |
| `collect_specific_certificate(name)` | Fetch single certificate |
| `collect_all_keys()` | List and extract all key metadata |
| `collect_specific_key(name)` | Fetch single key |
| `_parse_certificate(cert_bytes, ...)` | Parse X.509 cert with full extension extraction |
| `_extract_key_metadata(key)` | Extract key properties from JsonWebKey |

**Data Captured:** Full X.509 extensions, Azure tags, subscription ID, vault location, HSM-backed flag, managed status, version, recovery level.

### 5.3 EJBCA Collector

**File:** `caip_scanning_functions/collectors/ejbca_collector.py`
**Class:** `EJBCACollector`
**Library:** `requests`, `cryptography` (PKCS#12 parsing)
**Mode:** Read-only — fetches CA info and certificates

**Connection:** P12 client certificate mutual TLS via `requests.Session.cert`.

**API Endpoint:** `{base_url}/ejbca/ejbca-rest-api/v1/ca`

**Methods:**
| Method | Purpose |
|--------|---------|
| `_create_session()` | Create requests session with P12 mTLS |
| `get_cas()` | List all Certificate Authorities |
| `_fetch_ca_certificate_chain(ca_name)` | Download CA cert chain (cached) |

### 5.4 TLS/SSL Scanner

**File:** `caip_scanning_functions/collectors/tls_scanner.py`
**Class:** `TLSScanner`
**Library:** `ssl`, `socket`, `OpenSSL` (pyOpenSSL), `cryptography`
**Mode:** Read-only — connects and extracts certificate chain

**Methods:**
| Method | Purpose |
|--------|---------|
| `scan_host(host, port)` | Scan TLS endpoint, extract certificates |
| `_extract_certificate_chain(sock)` | Extract full cert chain from socket |
| `_extract_chain_pyopenssl(host, port)` | Fallback extraction using pyOpenSSL |
| `_detect_tls_library(context)` | Identify OpenSSL/LibreSSL/BoringSSL |
| `_enumerate_tls_versions()` | Check all supported TLS versions |

**Data Captured:** Certificate chain, TLS version, cipher suite, forward secrecy, handshake timing, CT SCTs, OCSP, CRL DPs.

**Timeout:** 1 second per host (configurable).

### 5.5 CRL Collector

**File:** `caip_scanning_functions/collectors/crl_collector.py`
**Class:** `CRLCollector`
**Library:** `requests`, `cryptography`
**Mode:** Download and parse CRLs

**Data Captured:** Issuer, this_update, next_update, revoked certificates (serial + reason), CRL number, staleness detection.

**Timeout:** 30 seconds per HTTP request.

### 5.6 File Share Scanner

**File:** `caip_scanning_functions/collectors/file_share.py`
**Class:** `FileShareScanner`
**Library:** `os`, `pathlib`, `cryptography`
**Mode:** Filesystem discovery only

**Detected Extensions:** .pem, .crt, .cer, .p12, .pfx, .key, .pub, .der, .p7b, .jks, .keystore, .pkcs8, .pks, .pvk, .pssc

**Content Detection:** Regex patterns for PEM headers, Base64 DER, encrypted key indicators.

**Limits:** Max recursion depth 20, max file size 100MB, content read limit 10KB.

### 5.7 Connector Summary

| Collector | External System | Library | Read/Write | Auth Method |
|-----------|----------------|---------|------------|-------------|
| Luna HSM | Thales Luna HSM | PyKCS11 | Read-only | Partition password |
| Azure KV | Azure Key Vault | azure-keyvault-* | Read-only | Service Principal / DefaultAzureCredential |
| EJBCA | EJBCA PKI | requests (P12 mTLS) | Read-only | Client certificate (P12) |
| TLS Scanner | Any TLS endpoint | ssl, pyOpenSSL | Read-only | None (public endpoint) |
| CRL Collector | CRL Distribution Points | requests | Read-only | None (HTTP GET) |
| File Share | Local/network filesystem | os, pathlib | Read-only | OS-level permissions |

---

## Section 6 — Data Models and Database

### 6.1 Database Type & Configuration

- **Type:** SQLite (file-based)
- **File:** `pki_dashboard.db`
- **ORM:** None — raw `sqlite3` module with parameterized queries
- **Connection Timeout:** 10.0 seconds
- **WAL Mode:** Enabled (`PRAGMA journal_mode = WAL`)
- **Foreign Keys:** Enabled (`PRAGMA foreign_keys = ON`)
- **Row Factory:** `sqlite3.Row` (dict-like access)
- **Connection Pattern:** Per-operation connection (no pooling)

### 6.2 Complete Schema (30+ tables)

#### Core System Tables

**users**
| Column | Type | Constraints |
|--------|------|------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| username | TEXT | UNIQUE NOT NULL |
| password | TEXT | NOT NULL (hash) |
| role | TEXT | DEFAULT 'scan-user' |
| mfa_enabled | INTEGER | DEFAULT 0 |
| mfa_secret_ref | TEXT | Vault reference |
| password_algorithm | TEXT | DEFAULT 'pbkdf2' |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP |
| updated_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP |

**configurations**
| Column | Type | Constraints |
|--------|------|------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| name | TEXT | UNIQUE NOT NULL |
| config_json | TEXT | NOT NULL (JSON) |
| engagement_id | TEXT | FK → engagements(engagement_id) |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP |
| updated_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP |

**policies**
| Column | Type | Constraints |
|--------|------|------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| name | TEXT | UNIQUE NOT NULL |
| policy_json | TEXT | NOT NULL (v2.0 format) |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP |
| updated_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP |

**scans**
| Column | Type | Constraints |
|--------|------|------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| scan_uid | TEXT | UNIQUE ("SCN-{uuid}") |
| name | TEXT | UNIQUE NOT NULL |
| config_id | INTEGER | NOT NULL FK → configurations(id) |
| policy_id | INTEGER | NOT NULL FK → policies(id) |
| status | TEXT | DEFAULT 'Never Run' |
| assessment_type | TEXT | DEFAULT 'pki_health_check' |
| engagement_id | TEXT | FK → engagements(engagement_id) |
| collector_id | TEXT | FK → remote_collectors(collector_id) |
| collector_results | TEXT | JSON tracking partial success |
| last_run | TIMESTAMP | |
| report_path | TEXT | |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP |
| updated_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP |

**scan_logs**
| Column | Type | Constraints |
|--------|------|------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| scan_id | INTEGER | NOT NULL FK → scans(id) |
| run_number | INTEGER | DEFAULT 1 |
| log_entry | TEXT | NOT NULL |
| timestamp | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP |

#### Engagement & Reporting Tables

**engagements**
| Column | Type | Constraints |
|--------|------|------------|
| id | INTEGER | PRIMARY KEY AUTOINCREMENT |
| engagement_id | TEXT | UNIQUE NOT NULL ("ENG-{uuid}") |
| customer_name | TEXT | NOT NULL |
| project_name | TEXT | NOT NULL |
| description | TEXT | |
| status | TEXT | DEFAULT 'Active' |
| start_date | TEXT | |
| end_date | TEXT | |
| lead_consultant | TEXT | |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP |
| updated_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP |

**engagement_reports** — Links reports to engagements (id, engagement_id, report_type, report_reference_id, report_name, report_path, include_in_executive, display_order, added_at)

**engagement_executive_summaries** — Executive summary documents (id, engagement_id, version, report_name, report_path, included_reports_json, generated_at, generated_by)

**reassessments** — Policy reassessment results (id, name, original_report_filename, policy_id, engagement_id, report_data JSON, reassessed_report_path, status, version, enrichment_snapshot, created_by, created_at)

**report_aggregations** — Aggregated reports (id, name, policy_id, engagement_id, merge_strategy, source_reports JSON, aggregated_report_path, report_data JSON, status, created_at)

#### Inventory Management Tables

**certificates_inventory** — Persistent certificate inventory (id, fingerprint_sha256, connector_id FK, normalised_data JSON, subject_cn, issuer_cn, not_after, days_until_expiry, key_algorithm, key_size, source_type, integration_name, is_promoted, promoted_from_scan_name, promoted_at, first_seen_at, last_seen_at, is_active)

**keys_inventory** — Persistent key inventory (id, key_identifier, connector_id FK, normalised_data JSON, key_name, key_type, key_size, source_type, integration_name, expires_on, days_until_expiry, is_hsm_backed, is_promoted, promoted_from_scan_name, promoted_at, first_seen_at, last_seen_at, is_active)

**connector_sync_status** — Sync tracking per connector (connector_id PK, last_sync_started, last_sync_completed, last_sync_status, last_sync_error, last_sync_duration_seconds, items_total/added/updated/removed, next_sync_due, sync_interval_minutes DEFAULT 30, consecutive_failures)

**lifecycle_policies** — Per-connector lifecycle rules (id, connector_id FK UNIQUE, renewal_threshold_days DEFAULT 90, rotation_interval_days, auto_action, notification_enabled)

**inventory_changes** — Change tracking (id, entity_type, entity_id, connector_id, change_type, change_details, detected_at)

**clm_integrations** — Integration configurations (id, name UNIQUE, type, config_json, status, enabled, cas_metadata JSON, last_sync, created_at, updated_at)

#### Asset Context & Enrichment Tables

**asset_context** — Business context per asset (id, engagement_id, asset_id, asset_type, business_unit, business_function, data_classification, compliance_scope, dependencies, migration_path, owner, notes, override_enabled, override_score, override_phase, override_reason, excluded, exclusion_reason, environment_type CHECK IN ('production','staging','development','testing','unknown'), service_name, application_name, discovery_method, discovery_confidence CHECK 0.0-1.0, last_modified_by, last_modified_at, created_at, updated_at)

**asset_context_history** — Full audit trail (mirrors asset_context fields + change_type, changed_by, changed_at, previous_values JSON)

**asset_relationships** — Certificate/key relationships (id, parent_asset_id, parent_asset_type CHECK IN ('certificate','key'), child_asset_id, child_asset_type, relationship_type, confidence 0.0-1.0, discovered_at, source, metadata JSON; UNIQUE(parent, child, type))

**enrichment_operations** — Bulk operation tracking (id, operation_id UNIQUE, engagement_id, operation_type, affected_count, asset_ids JSON, changed_by, created_at)

#### Certificate Management Tables

**collector_certificates** — Per-collector client certs (id, collector_id UNIQUE, engagement_id FK, certificate_pem, public_key_pem, private_key_encrypted (deprecated), serial_number UNIQUE, subject, issuer, issued_at, expires_at, status, revoked_at, revocation_reason, renewal_count, previous_serial_number, previous_expires_at)

**engagement_cas** — Per-engagement CA certificates (id, engagement_id FK UNIQUE, ca_certificate_pem, ca_private_key_encrypted (deprecated), serial_number UNIQUE, subject, issued_at, expires_at, rotation_count, status)

**dashboard_certificates** — Dashboard mTLS server cert (id, certificate_pem, private_key_ref (vault), serial_number UNIQUE, issued_at, expires_at, hostname DEFAULT 'caip-dashboard', status)

**engagement_dashboard_certificates** — Per-engagement SNI server certs (id, engagement_id FK, certificate_pem, private_key_ref, public_key_pem, serial_number UNIQUE, subject, issued_at, expires_at, status; UNIQUE(engagement_id, status))

**internal_ca** — Auto-provisioned root CA (id, ca_certificate_pem, serial_number UNIQUE, subject, issued_at, expires_at, rotation_count, status)

**engagement_ca_certificates** — Phase 3 engagement CAs (id, engagement_id FK, certificate_pem, certificate_serial UNIQUE, subject, issuer, public_key_pem, private_key_ref, issued_at, expires_at, status, rotation_count; UNIQUE(engagement_id, status))

**report_signing_certificates** — Phase 3 report signing (id, engagement_id FK, certificate_pem, certificate_serial UNIQUE, subject, issuer, public_key_pem, private_key_ref, issued_at, expires_at, status, rotation_count; UNIQUE(engagement_id, status))

**certificate_audit_log** — Certificate lifecycle events (id, event_type, collector_id, engagement_id FK, certificate_serial, admin_user_id, details JSON, timestamp)

**certificate_registration_requests** — CSR tracking (id, collector_id, engagement_id FK, api_key_id, csr_pem, status, requested_at, approved_at, approved_by, certificate_serial, rejection_reason)

**certificate_revocation_list** — CRL cache (id, engagement_id FK UNIQUE, serial_numbers JSON, updated_at)

#### Secret Management Tables

**secret_references** — Secret pointer storage (id, secret_id UNIQUE, backend_type, kv_secret_name, description, created_at, updated_at)

**secret_stores** — Registered secret store providers (id, name UNIQUE, provider_type, connection_config JSON, status, last_health_check, created_at, updated_at)

#### Authentication Provider Tables

**auth_providers** — OAuth/SSO configuration (id, name UNIQUE, provider_type, config_json, enabled, auto_provision, default_role, created_at, updated_at)

### 6.3 Data Model Classes (Python)

**File:** `caip_scanning_functions/models.py`

| Model | Purpose | Key Fields |
|-------|---------|------------|
| `CertificateInfo` | Certificate metadata | serial_number, subject, issuer, validity, algorithms, extensions, fingerprint, TLS info, PQC analysis, Azure metadata |
| `AzureKeyVaultKeyInfo` | Azure key metadata | key_type, key_size, key_curve, operations, lifecycle dates, vault info, tags, HSM-backed flag |
| `KeyInfo` | PKCS#11 key metadata | label, object_id, key_type, key_size, security attributes (sensitive, extractable, etc.), operations (encrypt, sign, wrap, etc.), associated_certificate |
| `TLSScanResult` | TLS scan result | host, port, supported_protocols, cipher_suites, certificate_chain, security_metadata |
| `CRLInfo` | CRL data | issuer, update dates, revoked certs, CRL number, staleness |
| `Finding` | Assessment finding | id, severity, title, description, affected_entities, remediation, risk_score, category |
| `ScanResults` | Container | certificates, keys, azure_keys, tls_results, findings, crls, file_scan_results, normalised_keys/certificates |

---

## Section 7 — Cryptographic Operations Inventory

### 7.1 Operations Performed

| Operation | Algorithm | Library | HSM/Software | File |
|-----------|-----------|---------|-------------|------|
| Cert parsing (DER) | X.509 | cryptography | Software | All collectors |
| Cert parsing (PEM) | X.509 | cryptography | Software | All collectors |
| CRL parsing | X.509 CRL | cryptography | Software | crl_collector.py |
| Fingerprint hash | SHA-256 | hashlib | Software | All collectors |
| ID hash | MD5 | hashlib | Software | assessment.py (legacy) |
| Key generation | RSA 4096 | cryptography | Software | certificate_service.py |
| Key serialization | PKCS#8/PEM | cryptography | Software | certificate_service.py |
| P12 loading | PKCS#12 | cryptography | Software | ejbca_collector.py |
| Vault encryption | AES-256-GCM + PBKDF2 | cryptography (AESGCM) | Software | encryption_utils.py, unified_vault_service.py |
| Password hashing | PBKDF2 | werkzeug | Software | app.py (user auth) |
| PKCS#11 key read | Various (RSA, EC, AES, 3DES, DES) | PyKCS11 | Luna HSM | luna_hsm.py |
| TLS handshake | TLS 1.0-1.3 | ssl, pyOpenSSL | Software | tls_scanner.py |

### 7.2 Key Generation Parameters

- **Internal CA:** RSA 4096-bit, SHA-256, 5-year validity
- **Dashboard Cert:** RSA 4096-bit, SHA-256, 365-day validity
- **Collector Cert:** RSA 4096-bit, SHA-256, 30-day validity, 3-day renewal grace
- **Public Exponent:** 65537 (all RSA keys)

### 7.3 Encryption Details

**Unified Vault (AES-256-GCM + PBKDF2):**
- Key derivation: PBKDF2-HMAC-SHA256, 480,000 iterations, 16-byte salt
- Encryption: AES-256-GCM with 12-byte nonce
- Storage: salt + nonce + ciphertext in single file

### 7.4 What Happens on HSM vs Software

| Location | Operations |
|----------|-----------|
| **Luna HSM (via PKCS#11)** | Read-only: enumerate slots, list objects, read attributes. No sign/encrypt/wrap/derive operations. |
| **Software (cryptography lib)** | All key generation, cert signing, vault encryption, password hashing, cert parsing |

**Critical Note:** The Luna HSM collector is discovery-only. No cryptographic operations (sign, encrypt, wrap, derive) are performed on the HSM. All such operations happen in software.

---

## Section 8 — PQC Detection and Policy Engine

### 8.1 PQC Detector

**File:** `caip_pqc_functions/pqc_detector.py` (~687 lines)
**Class:** `PQCDetector`
**Pattern:** Singleton via `get_detector()`

**Detection Method:** OID matching (highest confidence) → name pattern matching → classical fallback

**Algorithms Detected:**

| Category | Algorithms | OID Range |
|----------|-----------|-----------|
| ML-DSA (Dilithium) Signatures | ML-DSA-44, ML-DSA-65, ML-DSA-87 | 2.16.840.1.101.3.4.3.17-19 |
| ML-KEM (Kyber) Key Encapsulation | ML-KEM-512, ML-KEM-768, ML-KEM-1024 | 2.16.840.1.101.3.4.4.1-3 |
| SLH-DSA (SPHINCS+) Signatures | 12 variants (SHA2/SHAKE, Levels 1/3/5) | 2.16.840.1.101.3.4.3.20-31 |
| Hybrid Composites | ECDSA-P*/RSA-PSS/Ed* with ML-DSA | 2.16.840.1.114027.80.8.1.1-8 |

**Name Patterns:** ML-DSA, ML-KEM, SLH-DSA, SPHINCS, Dilithium, Kyber, FALCON, BIKE, HQC, Classic McEliece

**Migration Status Classification:**
| Status | Meaning |
|--------|---------|
| `PQC_READY` | Using PQC or strong symmetric (AES-256) |
| `HYBRID_TRANSITION` | Using hybrid classical+PQC |
| `NEEDS_MIGRATION` | Classical, quantum-vulnerable |
| `UNKNOWN` | Cannot determine |

**Vulnerability Assessment:**
- RSA/EC/DSA/DH: quantum-vulnerable (Shor's algorithm)
- AES-128: 64-bit post-quantum security (Grover's halves effective key length)
- AES-256: 128-bit post-quantum security (quantum-safe)
- 3DES/DES: vulnerable regardless

### 8.2 Policy Engine

**Files:** `caip_policy_functions/rule_assessment.py`, `caip_policy_functions/policy_assessment_service.py`

**Rule Schema (v2.0 policy format):**
```json
{
  "version": "2.0",
  "rules": [
    {
      "id": "string",
      "name": "string",
      "description": "string",
      "collector_type": "tls|azure|luna_hsm|ejbca|crl|file_scan",
      "asset_type": "certificate|key|tls_endpoint|crl",
      "severity": "critical|high|medium|low|info",
      "condition": {
        "type": "simple|expression|temporal",
        "field": "string",
        "operator": "eq|ne|gt|lt|gte|lte|in|not_in|contains|not_contains|regex",
        "value": "any"
      },
      "finding_template": {
        "title": "string",
        "description": "string (with {field} placeholders)",
        "remediation": "string",
        "category": "string"
      }
    }
  ]
}
```

**Loading:** Policies stored in `policies` table as JSON. Loaded via `RuleRegistry.load_policy(policy_dict)`.

**Evaluation:** `RuleEvaluator.evaluate_rule(rule, asset_dict)` → `RuleResult` (triggered/not_triggered, finding if triggered).

**Condition Types:**
- **Simple:** Single field comparison
- **Expression:** Complex boolean expressions
- **Temporal:** Date-based conditions (expiry within X days)

---

## Section 9 — Scoring and Assessment Engine

**File:** `caip_service_layer/scoring_service.py`

### 9.1 Scoring Engine

**Input:** RuleResult + AssetContext + AssetData
**Output:** ScoredFinding with weighted_score and priority_score

**Weight Factors (from asset_context):**
| Factor | Source | Range |
|--------|--------|-------|
| business_function | Critical=1.5, Important=1.2, Standard=1.0, Unknown=0.8 | 0.8-1.5 |
| data_classification | Restricted=1.5, Confidential=1.3, Internal=1.0, Public=0.8 | 0.8-1.5 |
| compliance_scope | Multiplier per compliance framework present | Additive |
| dependencies | High=1.3, Medium=1.1, Low=1.0, None=0.9 | 0.9-1.3 |
| environment_type | production=1.5, staging=1.0, development=0.7, testing=0.5 | 0.5-1.5 |

**Formula:**
```
weighted_score = base_risk_score × weight_factors.combined
priority_score = weighted_score / effort_estimate
```

### 9.2 Aggregation Engine

**Input:** List[ScoredFinding], total_assets, assets_with_context
**Output:** AssessmentScore

**Health Index:** Blended severity + compliance score
**Grade Scale:** A+ (95+), A (90+), B+ (85+), B (80+), C+ (75+), C (70+), D+ (65+), D (60+), F (<60)
**Priority Queue:** Top 10 findings by priority_score

### 9.3 CBOM Export

**File:** `caip_reporting_functions/cbom_export_service.py`
**Format:** CycloneDX 1.6+ CBOM (JSON)

**Structure:**
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:<uuid>",
  "version": 1,
  "metadata": {},
  "components": [
    {"type": "crypto-asset", "assetType": "certificate|related-crypto-material|algorithm|protocol"}
  ],
  "dependencies": []
}
```

---

## Section 10 — UI Assessment

### 10.1 Framework

- **Template Engine:** Jinja2 (Flask built-in)
- **CSS:** Custom CSS with CSS variables (no Bootstrap, Tailwind, or external framework)
- **JavaScript:** Vanilla JS with native `fetch()` API (no React, Vue, jQuery, or axios)
- **Charts:** Chart.js v4.4.0 (via CDN)
- **Theme:** "Station Hex" dark theme (green #00FF41, amber #FFB800, dark bg #0a1520/#0D1B2A)
- **Fonts:** Orbitron, Share Tech Mono

### 10.2 Pages/Views

| Template | Purpose | Key Data Displayed |
|----------|---------|-------------------|
| `dashboard.html` | Primary dashboard | Multi-tab: Engagements, Scans, Document Scans, Certificate Management, Reports, Settings, Admin. Sidebar navigation. |
| `login.html` | Authentication | Username/password form, OAuth provider buttons (Azure, Okta, Auth0, Google), offline mode fallback |
| `certificate_management.html` | Cert lifecycle | Bulk actions, status badges (no-cert, pending-p12, active, expired, revoked), engagement CA filtering |
| `dpod_dashboard.html` | DPOD dashboard | Code signing, HSM management, partitions, key inventory, client hosts |
| `pki_report.html` | PKI report viewer | Assessment results, findings, scoring. Phase 5 decryption hooks (TODO) |
| `pqc_report.html` | PQC report viewer | PQC assessment, migration status. Phase 5 decryption hooks (TODO) |

### 10.3 JavaScript Modules (19+ files)

| File | Purpose |
|------|---------|
| `dashboard.js` | Core: engagement context, scan CRUD, configuration management, policy management |
| `certificate-management.js` | CA/cert fetching, revocation, bulk operations |
| `collectors_management.js` | Collector config CRUD, health checks, sync status |
| `credential_field_helper.js` | Dynamic credential field rendering by connector type |
| `rbac_init.js` | RBAC initialization on page load |
| `rbac_management.js` | Role/permission/user management |
| `enrichment-page.js` | Enrichment data tab logic |
| `enrichment-table.js` | Table rendering, pagination |
| `enrichment-filters.js` | Filter UI for enrichment |
| `environment_ui.js` | Environment classification UI |
| `dpod_dashboard.js` | DPOD-specific functionality |
| `p12-parser.js` | In-browser PKCS#12 parsing |
| `report-decryptor.js` | Report decryption UI |
| `report-state-manager.js` | Report state across pages |
| `report_verifier.js` | Report signature verification |
| `secret_picker.js` | Reusable secret selection modal |
| `secret_stores_management.js` | Secret store CRUD |
| `settings_management.js` | Application settings |
| `ui-controller.js` | Global UI state, modal coordination |
| `vault_manager.js` | Vault configuration and key management |
| `signature-verifier.js` | Certificate/report signature verification |

### 10.4 CSS Files (15 files)

variables.css, base.css, forms.css, utilities.css, layout.css, components.css, modals.css, landing.css, modules.css, assessment.css, certificate-management.css, secret_stores.css, secret_picker.css, vault_manager.css, dpod_dashboard.css

### 10.5 Assessment

**Worth porting or rewriting?** Rewrite from scratch. The UI is tightly coupled to Flask template rendering with inline Jinja2 logic. The custom CSS theme system and vanilla JS approach would not survive a migration to a modern frontend framework. The data it displays is valuable; the rendering layer is not.

---

## Section 11 — Authentication and Authorisation

### 11.1 Authentication Methods

1. **Local credentials:** Username + password (PBKDF2 hash via Werkzeug)
2. **OAuth 2.0:** Azure Entra ID, Okta (pluggable provider system)
3. **mTLS client certificates:** For remote collectors on port 5444 (CN=collector_id, OU=engagement_id)

### 11.2 Session Management

- **Cookie name:** `caip_session`
- **HTTP-only:** Yes
- **SameSite:** Lax
- **Secure flag:** False (TODO: set True for HTTPS)
- **Lifetime:** 8 hours
- **Data stored:** user_id, username, role, oauth_provider_id

### 11.3 Role-Based Access Control

**Roles:** admin, scan-user, reviewer (and potentially others)

**Permission Categories:**
- `users:*` — User management
- `auth_providers:*` — Auth provider configuration
- `engagements:*` — Engagement management
- `scan_configs:*` — Scan configuration
- `scans:*` — Scan execution
- `reports:*` — Report access and generation
- `integrations:*` — Inventory integration management
- `assessments:*` — Assessment data
- `inventory:*` — Inventory management
- `scan_logs:*` — Scan log access

### 11.4 Multi-Tenancy

Engagement-based multi-tenancy:
- Engagement ID scopes all data (scans, configs, reports, certificates, asset context)
- Users can be assigned to specific engagements
- Engagement CAs issue per-engagement collector certificates
- No cross-engagement data leakage (enforced at query level)

### 11.5 OAuth Provider Configuration (DB-stored)

| Provider | Module | Capabilities |
|----------|--------|-------------|
| Azure Entra ID | `caip_service_layer/oauth_providers/azure_entra_id.py` | Authorization code flow, auto-provisioning |
| Okta | `caip_service_layer/oauth_providers/okta.py` | Authorization code flow, auto-provisioning |

---

## Section 12 — Configuration Management

### 12.1 Configuration Files

| File | Format | Purpose |
|------|--------|---------|
| `.env` | Dotenv | Environment variables (secret backend, Azure creds, Flask config) |
| `caip_scanning_functions/config.py` | Python dict | Default scan settings, policy defaults |
| `production_config.py` | Python | Gunicorn config for dashboard (port 5443) |
| `production_config_collectors.py` | Python | Gunicorn config for collectors (port 5444) |

### 12.2 Default Scan Configuration

```python
{
    "version": "1.0",
    "scan_settings": {"timeout": 30, "retries": 3, "thread_pool_size": 10, "buffer_size": 4096},
    "logging": {"level": "INFO"},
    "tls_scan": {"enabled": True, "timeout": 1, "endpoints": [{"host": "example.com", "port": 443}]},
    "azure": {"enabled": False, "vaults": []},
    "luna_hsm": {"enabled": False, "partitions": []},
    "ejbca": {"enabled": False, "servers": []},
    # ... other collectors
}
```

### 12.3 Secrets Management Hierarchy

1. **Unified Vault** (`system_vault.enc`) — AES-256-GCM encrypted file, master password protected
2. **Azure Key Vault** — Cloud secret management (if configured)
3. **HashiCorp Vault** — If registered as secret store
4. **AWS Secrets Manager** — If registered as secret store
5. **Encrypted File Provider** — Fallback

**Startup Secret Resolution:**
```
Flask secret key: unified_vault → legacy SecretService → random temporary key (warning logged)
```

### 12.4 Hardcoded Secrets (SECURITY ISSUE)

| Location | Value | Risk |
|----------|-------|------|
| `.env` | `CAIP_MASTER_PASSWORD=test-master-password-12345` | CRITICAL — weak test password in source |
| `app.py:353` | `generate_password_hash('Willows83')` | HIGH — default admin password |
| `.env.example` | Azure tenant/client IDs and secret (commented) | MEDIUM — real credentials in sample file |
| `collector_client.py` | `DEFAULT_SERVER = "http://localhost:5000"` | LOW — test default |
| `start_app.sh` | Full Azure credentials | HIGH — real credentials in shell script |

---

## Section 13 — External Dependencies Full Audit

### 13.1 Direct Dependencies

| Package | Version | Purpose | Migration Notes |
|---------|---------|---------|-----------------|
| Flask | 2.3.3 | Web framework | **REPLACE** with FastAPI |
| Werkzeug | 2.3.7 | WSGI toolkit (Flask dep) | Removed with Flask |
| Jinja2 | 3.1.2 | Template engine | Only needed if keeping server-side templates |
| python-dotenv | 1.0.0 | .env loading | Compatible with FastAPI |
| cryptography | 41.0.3 | Crypto operations | **UPGRADE** to latest; keep |
| PyJWT | 2.8.0 | JWT tokens | Keep for JWT auth |
| bcrypt | 4.0.1 | Password hashing | Keep |
| pyOpenSSL | 23.2.0 | TLS scanning fallback | Keep for TLS scanner |
| certifi | 2023.7.22 | CA bundle | Keep |
| reportlab | 4.0.4 | PDF generation | Keep |
| Pillow | 10.0.0 | Image processing | Keep |
| PyYAML | 6.0.1 | YAML parsing | Keep |
| jsonschema | 4.19.0 | JSON validation | Keep (or use Pydantic) |
| requests | 2.31.0 | HTTP client | Keep (or switch to httpx for async) |
| urllib3 | 2.0.4 | HTTP low-level | Transitive dep of requests |
| psutil | 5.9.5 | System monitoring | Keep |
| gunicorn | 21.2.0 | WSGI server | **REPLACE** with uvicorn |
| gevent | 23.9.1 | Async worker | **REMOVE** — FastAPI uses native async |

### 13.2 Optional Dependencies (imported with try/except)

| Package | Purpose | Migration Notes |
|---------|---------|-----------------|
| PyKCS11 | Luna HSM PKCS#11 | **EVALUATE** vs python-pkcs11 |
| azure-identity | Azure auth | Keep |
| azure-keyvault-secrets | Azure KV secrets | Keep |
| azure-keyvault-keys | Azure KV keys | Keep |
| python-docx | DOCX generation | Keep |
| matplotlib | Chart generation | Keep or replace |

### 13.3 Flags

| Issue | Packages |
|-------|----------|
| **Duplicate crypto libraries** | PyKCS11 (0xRecon) vs python-pkcs11 (0xConductor) — need to standardise |
| **Duplicate HTTP clients** | requests + urllib3 — could consolidate to httpx for async support |
| **No async HTTP** | requests is synchronous — blocks during HSM/Azure/EJBCA calls |
| **Outdated versions** | cryptography 41.0.3 (current is 44+), pyOpenSSL 23.2.0 (outdated) |

---

## Section 14 — Test Coverage Assessment

### 14.1 Test Files (33 total, ~9,800 lines)

| File | Tests | Lines |
|------|-------|-------|
| `test_engagement_api.py` | Engagement API endpoints | ~165 |
| `test_engagement_charts.py` | Chart generation | ~163 |
| `test_engagement_docx.py` | DOCX report generation | ~167 |
| `test_enrichment_data_flow.py` | Metadata enrichment pipeline | ~358 |
| `test_environment_ui.py` | Environment classification | ~479 |
| `test_financial_integration.py` | Financial calculator | ~187 |
| `test_inventory_orchestrator_phase_1.py` | Phase 1: Certificate discovery | ~137 |
| `test_inventory_orchestrator_phase_2_registry.py` | Phase 2: Certificate attributes | ~134 |
| `test_inventory_orchestrator_phase_3.py` | Phase 3: Relationships | ~142 |
| `test_inventory_orchestrator_phase_4.py` | Phase 4: Encryption/scoring | ~204 |
| `test_inventory_orchestrator_phase_5.py` | Phase 5: Advanced analysis | ~228 |
| `test_inventory_orchestrator_phase_5_6.py` | Phase 5-6: Combined | ~224 |
| `test_inventory_orchestrator_phase_6.py` | Phase 6: Finalization | ~184 |
| `test_inventory_orchestrator_integration_phase_1_4.py` | Integration phases 1-4 | ~161 |
| `test_inventory_service_backward_compat.py` | Backward compatibility | ~178 |
| `test_inventory_service_orchestrator_integration.py` | Service integration | ~146 |
| `test_metadata_signals_phase3.py` | Signal processing | ~524 |
| `test_phase2_serialization.py` | Certificate serialization | ~239 |
| `test_phase2_user_certs.py` | User certificate handling | ~388 |
| `test_phase4_encryption.py` | Encryption/key analysis | ~325 |
| `test_phase4_scoring.py` | Risk scoring | ~208 |
| `test_phase5_ejbca_profile_integration.py` | EJBCA integration | ~282 |
| `test_phase_5_staging_validation.py` | Staging validation | ~316 |
| `test_relationship_api.py` | Relationship APIs | ~485 |
| `test_relationship_integration.py` | Relationship service | ~220 |
| `test_relationship_service.py` | Relationship logic | ~344 |
| `test_relationship_signal_integration.py` | Signal relationships | ~175 |
| `test_relationship_signal_phase1.py` | Signal phase 1 | ~376 |
| `test_remote_financial_deployment.py` | Remote deployment | ~106 |
| `test_standardized_normalization.py` | Data normalization | ~190 |
| `test_vault_creation.py` | Vault initialization | ~85 |
| `caip_reporting_functions/test_docx_phase1.py` | DOCX phase 1 | Unknown |

### 14.2 Modules with NO Test Coverage

| Module | Files | Risk |
|--------|-------|------|
| `caip_document_assessment_functions/` | 6 Python files | Medium |
| `caip_logging_functions/` | 5+ Python files | Low |
| `caip_policy_functions/` | 3 Python files | **HIGH** — policy engine untested |
| `caip_pqc_functions/` | 1 Python file | **HIGH** — PQC detection untested |
| `caip_workflow_functions/email_functions/` | Unknown | Low |
| `caip_vault_cli.py` | 1 file | Medium |
| All collectors individually | 7 files | **HIGH** — mocked in integration tests only |

### 14.3 External System Mocking

All external systems mocked via `unittest.mock.patch()`:
- Azure Key Vault, EJBCA, Luna HSM, File Share, TLS connections
- No centralized fixture file — fixtures defined inline per test module
- No integration tests requiring live infrastructure

### 14.4 Test Portability

The test suite is **not easily portable** to a new stack:
- Tests are tightly coupled to Flask request context
- Database tests depend on SQLite-specific behavior
- Mock patterns would need rewriting for async FastAPI
- **Recommendation:** Rewrite tests alongside the migration

---

## Section 15 — Inter-Module Dependency Map

### 15.1 High Fan-In (Many things depend on these)

| Module | Dependents | Migration Risk |
|--------|-----------|---------------|
| `database_service.py` | app.py, all route modules, all service layer | **CRITICAL** — everything touches the DB through this |
| `caip_service_layer/auth_service.py` | app.py, all route handlers | HIGH — auth decorators everywhere |
| `caip_service_layer/certificate_service.py` | app.py, scanning modules, reporting | HIGH |
| `caip_service_layer/secret_service.py` | app.py, connector_service, collectors | HIGH |
| `caip_logging_functions/logging_config.py` | app.py, remote_collector, services | MEDIUM |

### 15.2 High Fan-Out (Depend on many things)

| Module | Dependencies | Issue |
|--------|-------------|-------|
| `app.py` (5,915 lines) | ~40 modules | **GOD OBJECT** — routing + init + business logic |
| `remote_collector/app.py` (153KB) | Similar to main app | Duplicated god object |
| `database_service.py` (110KB) | sqlite3, logging, doc assessment DB | Monolithic data access layer |

### 15.3 Circular Dependencies

Potential chains:
- `app.py` → `database_service.py` → `caip_document_assessment_functions/document_assessment_database.py`
- `caip_service_layer/auth_service.py` → `database_service.py` → `app.py`
- `connector_service.py` → collectors → `certificate_service.py` → `database_service.py`

Mitigated by module-level imports, but fragile.

### 15.4 Code Duplication

**Critical:** The entire `remote_collector/` directory duplicates 5 `caip_*` module directories from the main codebase. No shared package — pure copy-paste.

### 15.5 Cryptolib Status

**No `packages/cryptolib/` directory exists.** No `EXTRACTION_SUMMARY.md` found. All cryptographic operations are implemented directly in the codebase using the `cryptography` library and `PyKCS11`. There is no shared cryptolib between 0xRecon and 0xConductor — they are completely independent codebases with independent crypto implementations.

---

## Section 16 — Known Issues, Tech Debt and Code Quality

### 16.1 TODO/FIXME Comments (28 instances)

| File | Line | Comment |
|------|------|---------|
| `logs/caip_route_layer/secret_store_routes.py` | 179 | TODO: Get from authenticated user (created_by field) |
| `logs/caip_route_layer/secret_store_routes.py` | 698 | TODO: Check authorization — only connectors/scanners should resolve secrets |
| `logs/caip_route_layer/remote_collector_routes.py` | 471 | TODO: Implement policy assignment to collectors |
| `logs/caip_route_layer/remote_collector_routes.py` | 945 | TODO: Add pagination |
| `caip_service_layer/remote_collector_service.py` | 740 | TODO: Implement policy sync |
| `caip_service_layer/metadata_enrichment_service.py` | 196 | TODO: Extract cipher details, compression, protocol range |
| `caip_service_layer/metadata_enrichment_service.py` | 201 | TODO: Extract Server header, CDN detection, HTTP/2 support |
| `caip_service_layer/metadata_enrichment_service.py` | 206 | TODO: Detect CRIME, DROWN, weak ciphers |
| `caip_service_layer/environment_inference_service.py` | 40 | TODO: Phase 2 (activity history sync detection) |
| `caip_service_layer/environment_inference_service.py` | 41 | TODO: Phase 2 (requires activity history) |
| `caip_scanning_functions/_scan_orchestrator.py` | 1140 | TODO: Load from DB if engagement_id available |
| `caip_scanning_functions/collectors/tls_scanner.py` | 651 | TODO: Proper OCSP detection (hardcoded to True) |
| `remote_collector/daemon.py` | 680 | TODO: Queue for retry |
| `templates/pqc_report.html` | 4919 | TODO: Call Phase 5 decryption UI here |
| `templates/pki_report.html` | 3975 | TODO: Call Phase 5 decryption UI here |

### 16.2 Hardcoded Credentials

| Severity | Location | Value |
|----------|----------|-------|
| CRITICAL | `.env` | `CAIP_MASTER_PASSWORD=test-master-password-12345` |
| HIGH | `app.py:353` | Default admin password `Willows83` |
| HIGH | `start_app.sh` | Azure tenant ID, client ID, client secret in plaintext |
| MEDIUM | `.env.example` | Real Azure credentials (commented out) |
| LOW | `collector_client.py` | `default-collector-token` |

### 16.3 Silent Error Swallowing (73+ instances)

**Bare `except:` blocks (worst offenders):**
- `app.py` — 7 instances
- `caip_engagement_functions/engagement_service.py` — 4 instances
- `caip_reporting_functions/executive_report_service.py` — 15+ instances
- `caip_policy_functions/rule_assessment.py` — 4 instances
- `caip_scanning_functions/collectors/azure_keyvault.py` — 7 instances
- `caip_scanning_functions/collectors/luna_hsm.py` — 4 instances
- `caip_scanning_functions/collectors/ejbca_collector.py` — 6 instances

**`except Exception: pass` blocks:**
- `app.py` — 5 instances
- `connector_service.py` — 1 instance

### 16.4 Security Issues

1. **No CSRF protection** — SameSite=Lax only, no CSRF tokens in forms
2. **SESSION_COOKIE_SECURE=False** — Cookies sent over HTTP
3. **No rate limiting** — No middleware for brute-force protection
4. **No input sanitization middleware** — Only manual validation in routes
5. **No error handler decorators** — No @app.errorhandler for 404, 500, etc.
6. **Unfiltered error messages** — Raw exception messages returned to clients

### 16.5 Code Quality Assessment

| Aspect | Rating | Notes |
|--------|--------|-------|
| **Architecture** | Poor | God object (app.py = 5,915 lines), no separation of concerns |
| **Consistency** | Mixed | Service layer well-structured; app.py is chaotic |
| **Documentation** | Moderate | Extensive external docs; minimal inline documentation |
| **Error handling** | Poor | 73+ silent exception swallowing |
| **Security** | Mixed | Good vault system; poor at HTTP security basics |
| **Testing** | Moderate | Good inventory test coverage; major gaps in collectors/policies/PQC |
| **Code duplication** | Severe | Entire remote_collector duplicates 5 main packages |
| **Modularity** | Mixed | Good service separation; terrible route separation |

---

## Section 17 — Migration Readiness Assessment

### 17.1 Module Migration Matrix

| Module | Keep As-Is | Refactor | Rewrite | Complexity | Notes |
|--------|-----------|----------|---------|------------|-------|
| **Luna HSM Collector** | | X | | MEDIUM | Swap PyKCS11 → python-pkcs11, add async |
| **Azure KV Collector** | | X | | LOW | Add async (azure SDK supports it natively) |
| **EJBCA Collector** | | X | | LOW | Swap requests → httpx for async |
| **TLS Scanner** | | X | | LOW | Mostly stdlib, add async wrapper |
| **CRL Collector** | | X | | LOW | Swap requests → httpx |
| **File Share Scanner** | X | | | LOW | Filesystem-only, works as-is |
| **PQC Detector** | X | | | LOW | Pure logic, no framework deps |
| **Policy Engine** | | X | | MEDIUM | Add proper schema validation, need tests |
| **Scoring Engine** | X | | | LOW | Pure logic, no framework deps |
| **Database Layer** | | | X | HIGH | SQLite → PostgreSQL, raw SQL → ORM |
| **Auth System** | | | X | HIGH | Session → JWT, add OAuth/OIDC properly |
| **Certificate Service** | | X | | MEDIUM | Decouple from Flask, add async |
| **Secret Management** | | X | | MEDIUM | Good architecture, needs async wrapper |
| **Inventory Service** | | X | | MEDIUM | Decouple from SQLite |
| **Reporting** | | X | | MEDIUM | Large codebase, decouple from Flask |
| **Flask Routes (app.py)** | | | X | HIGH | 5,915-line god object must be decomposed |
| **Remote Collector** | | | X | HIGH | Duplicated codebase, needs shared package |
| **UI (templates + JS)** | | | X | HIGH | Replace with modern frontend framework |
| **CBOM Export** | X | | | LOW | Pure data transformation |

### 17.2 Key Migration Questions

**Is Flask usage shallow or deep?**
Deep. Business logic is embedded in view functions throughout the 5,915-line `app.py`. The `@login_required` and `@permission_required` decorators are Flask-specific. Session management is Flask-native. However, the service layer is reasonably decoupled — the deeper services (scoring, PQC, policy) don't import Flask.

**Is the Luna HSM connector using PyKCS11 or python-pkcs11?**
**PyKCS11.** Switching to python-pkcs11 would require rewriting the attribute access pattern (PyKCS11 uses `session.getAttributeValue()` with CKA constants; python-pkcs11 uses a higher-level object API). The connector is ~300 lines and read-only, so the rewrite cost is moderate — maybe 2-3 days including testing.

**Is there a database that needs migrating?**
Yes. SQLite with 30+ tables, WAL mode, raw SQL queries (no ORM). Migration to PostgreSQL requires:
1. Schema translation (mostly straightforward, except CHECK constraints and AUTOINCREMENT)
2. Rewriting all raw SQL queries (or introducing an ORM)
3. Connection pooling (SQLite has none; PostgreSQL needs it)
4. Migration framework (Alembic recommended)

**Is the existing test suite portable?**
No. Tests are coupled to Flask request context and SQLite behavior. They use `unittest.mock.patch()` patterns that would need restructuring for async FastAPI. **Recommendation:** Rewrite tests in parallel with migration, using pytest-asyncio and httpx test client.

**What is the single highest-risk element of this migration?**
The **database_service.py** monolith (110KB). Every module depends on it. It contains raw SQL for 30+ tables with no abstraction layer. Migrating this to PostgreSQL + async ORM without breaking all consumers is the critical path.

**What could be lifted and shifted with minimal changes?**
- PQC Detector (pure logic, no deps)
- Scoring Engine (pure logic, no deps)
- CBOM Export Service (pure data transformation)
- File Share Scanner (stdlib only)
- Data models (`caip_scanning_functions/models.py`)

**What should be completely rewritten?**
- `app.py` — decompose into proper FastAPI routers
- `database_service.py` — replace with async ORM (SQLAlchemy async or Tortoise)
- `remote_collector/` — eliminate duplication, use shared packages
- UI — modern frontend framework (React/Vue/Svelte)
- Auth system — proper JWT + OAuth2 with library support (fastapi-users or similar)

### 17.3 Data Flow Summary

```
External Systems (Luna HSM, Azure KV, EJBCA, TLS endpoints, CRLs, File shares)
        ↓
Collectors (7 specialized collectors — all read-only)
        ↓
ScanOrchestrator (multi-collector orchestration)
        ↓
ScanResults (certificates, keys, TLS, CRLs, findings)
        ↓
KeyNormalisationService (standardize formats)
        ↓
PolicyAssessmentService (evaluate against v2.0 rules)
        ↓
ScoringEngine (weight by business context)
        ↓
AggregationEngine (health index, grading, priority queue)
        ↓
ReportingService (PDF/DOCX/CBOM generation)
        ↓
InventoryService (persistent CLM inventory)
        ↓
Dashboard (Jinja2 templates + vanilla JS)
```

### 17.4 Port Architecture

```
Current:
  Port 5000  — Flask dev server (HTTP, all traffic)
  Port 5443  — Gunicorn dashboard (HTTPS, session auth)
  Port 5444  — Gunicorn collectors (HTTPS, mTLS required)

Recommended:
  Separate services behind API gateway
  Dashboard API  — FastAPI + uvicorn (JWT auth)
  Collector API  — FastAPI + uvicorn (mTLS auth)
  Worker service — Background scanning/reporting
  Frontend       — Static SPA served separately
```

---

## Appendix A — Files Unable to Read

No files were inaccessible during this analysis. All Python source files, templates, configuration files, and scripts were successfully read.

## Appendix B — File Size Highlights

| File | Size | Concern |
|------|------|---------|
| `app.py` | ~254KB / 5,915 lines | God object — must be decomposed |
| `database_service.py` | ~110KB | Monolithic data access — must be split |
| `remote_collector/app.py` | ~153KB | Duplicated god object |
| `caip_reporting_functions/executive_report_service.py` | Large | Complex report generation |
| `caip_scanning_functions/collectors/ejbca_collector.py` | Large | Full EJBCA REST API integration |
