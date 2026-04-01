# 0xRecon — Master Architecture Document
# Version 1.1 | April 2026
#
# Status: UPDATED — Engagement construct renamed to Project (2026-04-01)
#
# This document is the single source of truth for the 0xRecon rebuild.
# It is maintained by the architect (Claude Chat — 0xRecon project) and
# updated at the end of every significant session.
# Claude Code reads this document at the start of every session.
#
# ================================================================================

---

# PART 1 — SYSTEM OVERVIEW

## 1.1 What 0xRecon Is

0xRecon is an enterprise cryptographic discovery, assessment, and advisory platform.
It discovers cryptographic assets across an organisation's estate, assesses posture
against configurable policy, produces prioritised findings, and generates signed and
encrypted deliverable reports for client engagement.

0xRecon is one product in the Station Hex 0x suite:

  0xRecon      — Cryptographic discovery, assessment, CBOM, reporting (this product)
  0xConductor  — Cryptographic operations gateway and policy enforcement
  0xVector     — PQC migration advisory (planned)
  0xMesh       — Federated trust mesh (planned)

## 1.2 Multi-Product Identity (White-Label Architecture)

0xRecon ships as two branded products from a single codebase:

  0xRecon  — Station Hex brand. Enterprise security architects.
  CAIP     — Cryptographic Asset Intelligence Platform. Consulting engagement brand.

The backend, database, API, workers, and all business logic are completely brand-agnostic.
Product identity is injected exclusively at the UI layer via a product configuration
block served from the API. No product-specific string, logo, or terminology ever appears
in backend source code.

See Part 9 for the full multi-product architecture.

## 1.3 Design Principles

  1.  Brand identity lives only in the UI. The backend has no product name.
  2.  Project context scopes all data. Cross-project leakage is impossible.
  3.  Every report is a cryptographically signed and optionally encrypted deliverable.
  4.  Collectors are read-only. No cryptographic operations are performed during discovery.
  5.  Policy is versioned, stored in the database, and evaluated server-side.
  6.  All secrets are vault-managed. No credentials in source code or environment files.
  7.  Container-first. Dev and production use identical images.
  8.  PostgreSQL only. No SQLite anywhere.
  9.  FastAPI throughout. No Flask.
  10. python-pkcs11 is the sole PKCS#11 library. No PyKCS11.
  11. Async throughout. No synchronous blocking calls in the API or worker.
  12. Fail closed on all security decisions.
  13. The remote collector is a packaged agent, not a copy of the main codebase.
  14. API-driven UI. The frontend renders what the API returns. Zero business logic in UI.

## 1.4 What Is Being Rebuilt and Why

0xRecon is rebuilt from its existing CAIP codebase. The rebuild addresses:

  - Monolithic god object (app.py — 5,915 lines, database_service.py — 110KB)
  - SQLite with no ORM replaced by PostgreSQL + SQLAlchemy Core + Alembic
  - Flask replaced by FastAPI (async, Pydantic, OpenAPI)
  - Session auth replaced by JWT
  - PyKCS11 replaced by python-pkcs11 (align with 0xConductor)
  - Remote collector duplication eliminated (shared package, proper agent)
  - All CAIP naming removed from backend source
  - Multi-product identity architecture introduced
  - Signed/encrypted report gaps closed (signature verification, chain validation)
  - Container-first deployment from day one

All existing capability is carried forward. Nothing is dropped. See Part 6 for
the complete capability register and migration strategy.

---

# PART 2 — CONTAINER TOPOLOGY

## 2.1 Production Stack

```
+-------------------------------------------------------------+
|  nginx                                                       |
|  TLS termination, reverse proxy, mTLS for collector API     |
|  Ports: 443 (dashboard), 8443 (collector API)               |
+----------+----------+----------+----------------------------+
           |          |          |
    +------+--+  +----+----+  +-+----------+
    |recon-api|  |recon-ui |  |recon-worker|
    |FastAPI  |  |React /  |  |Background  |
    |uvicorn  |  |Vite /   |  |jobs, scan  |
    |Port 8000|  |Nginx    |  |execution,  |
    |         |  |Port 3000|  |report gen  |
    +------+--+  +---------+  +-----+------+
           |                        |
           +----------+-------------+
                      |
               +------+------+
               |recon-postgres|
               |PostgreSQL 16 |
               |Port 5432     |
               +-------------+
```

## 2.2 Container Responsibilities

**recon-postgres**
  PostgreSQL 16. Dedicated container. Owns all persistent state.
  Named volume: recon-postgres-data
  No direct external access. Internal network only.

**recon-api**
  FastAPI application server (uvicorn, 4 workers).
  Handles all HTTP API requests.
  JWT auth for user-facing routes.
  mTLS validation for collector-facing routes.
  Reads/writes database. Reads vault. Dispatches jobs to worker via DB job table.
  Does NOT execute scans or generate reports directly.
  Subdomains: api.{domain}

**recon-worker**
  Same Docker image as recon-api, different entrypoint (CMD).
  Runs the SchedulerService loop (configurable interval, default 60s).
  Executes scan jobs: collector orchestration, policy evaluation, scoring.
  Generates reports: HTML, DOCX, PDF, CBOM.
  Issues certificates (report viewer certs, P12 generation).
  Signs and encrypts reports.
  Writes results to database. Stores reports to named volume.

**recon-ui**
  React 18 + TypeScript + Vite, served by nginx.
  Single-page application. Fetches product config on startup.
  Renders 0xRecon or CAIP identity based on product config.
  No business logic. Renders what the API returns.
  Port: 3000 (internal), served via nginx on 443.

**nginx**
  TLS termination (self-signed dev, Let's Encrypt prod).
  Routes: / to recon-ui, /api/ to recon-api.
  mTLS enforcement on /api/v1/collector/ routes (port 8443).
  Collector API port (8443) accepts client certificates from registered collectors.

## 2.3 Remote Collector Agent

The remote collector is NOT a container in the main stack. It is a separately
packaged Python agent deployed to edge nodes:

  - Distributed as a Python package (pip-installable or standalone zip)
  - Registers with the main API over HTTPS (receives mTLS client certificate)
  - Runs scans locally using the shared collector package
  - Reports results to the main API over mTLS
  - Runs as a systemd service on the edge node
  - Has its own local SQLite DB for buffering (not shared with main)

See Part 8 for the full remote collector architecture.

## 2.4 Docker Compose Project Name

  Development:   docker compose -p 0xrecon -f docker-compose.yml up
  Production:    docker compose -p 0xrecon -f docker-compose.yml -f docker-compose.prod.yml up

Always use -p 0xrecon. Never omit the project name.

## 2.5 Port Assignments

  5432   recon-postgres (internal only)
  8000   recon-api (internal, proxied by nginx)
  3000   recon-ui (internal, proxied by nginx)
  443    nginx (dashboard — HTTPS)
  8443   nginx (collector API — mTLS)

## 2.6 Subdomains (Production)

  api.recon.{domain}   — recon-api (user-facing API)
  app.recon.{domain}   — recon-ui (dashboard)

  For CAIP deployments, domain and subdomains are configured per deployment.
  The backend is identical. Only nginx config and product config differ.

---

# PART 3 — TECHNOLOGY STACK

## 3.1 Backend

  Language:         Python 3.11+
  Web framework:    FastAPI (replaces Flask)
  ASGI server:      uvicorn (replaces gunicorn + gevent)
  DB driver:        asyncpg (async PostgreSQL)
  ORM/query:        SQLAlchemy Core async (no ORM, no Flask-SQLAlchemy)
  Migrations:       Alembic — directory: migrations/ (NOT alembic/)
  Validation:       Pydantic v2
  Auth JWT:         python-jose[cryptography]
  Password:         bcrypt cost 12
  HTTP client:      httpx (replaces requests — async support)
  PKCS#11:          python-pkcs11 v0.9.x (replaces PyKCS11 everywhere)
  Crypto:           cryptography library (cert parsing, key gen, vault, signing)
  Azure KV:         azure-keyvault-keys, azure-keyvault-secrets, azure-identity
  TLS scanning:     ssl, pyOpenSSL (kept for TLS scanner fallback)
  Report gen:       python-docx (DOCX), reportlab (PDF)
  Scheduling:       Custom SchedulerService (DB-backed job table, no Celery)
  Env config:       python-dotenv

## 3.2 Frontend

  Framework:        React 18 + TypeScript (strict)
  Build:            Vite
  Styling:          Tailwind CSS (extending Station Hex design tokens)
  Components:       shadcn/ui (Radix UI primitives)
  State (server):   TanStack Query
  State (client):   Zustand
  Forms:            React Hook Form + Zod
  Auth:             IAuthProvider abstraction (LocalAuthProvider + MsalAuthProvider)
  API clients:      openapi-typescript-codegen from /openapi.json
  Charts:           Recharts (replaces vanilla Chart.js)
  Report viewer:    Standalone React components (PKI report, PQC report)
  P12/crypto:       forge.js (bundled, for offline report decryption)

## 3.3 Design System (Station Hex)

  Primary font:     Orbitron (headings)
  Body font:        Share Tech Mono
  Background:       #0D1B2A (dark navy)
  Card bg:          #1f2937
  Accent:           #00FF41 (terminal green)
  Secondary:        #FFB800 (amber)
  Border:           rgba(0, 255, 65, 0.25)

  CSS variables map to Tailwind theme.extend.
  CAIP may override accent colour via product config if brand requires.
  Component library: shadcn/ui (same as 0xConductor).

## 3.4 Infrastructure

  Database:         PostgreSQL 16
  Container:        Docker, Docker Compose
  Proxy:            nginx (TLS + mTLS)
  Dev OS:           Windows (VSCode + Claude Code + Docker Desktop)
  Deploy OS:        Ubuntu Server 24.04 LTS

## 3.5 Library Decisions — Rationale

  Flask to FastAPI:
    Flask usage was deep (5,915-line app.py). Since app.py is a full rewrite
    regardless, writing in FastAPI costs nothing extra. Gains: native async,
    Pydantic validation, automatic OpenAPI docs, consistency with 0xConductor.

  PyKCS11 to python-pkcs11:
    0xConductor uses python-pkcs11. Unifying eliminates a dual-library situation
    across the product suite. The Luna collector (300 lines, read-only) is
    rewritten using python-pkcs11 with patterns ported from the existing connector.

  requests to httpx:
    Async HTTP required for EJBCA, CRL, and TLS collectors in an async FastAPI
    context. httpx is a drop-in replacement with async support.

  SQLite to PostgreSQL:
    Container-first architecture requires a proper database. PostgreSQL provides
    connection pooling, concurrent writes, and aligns with 0xConductor.

  gunicorn/gevent to uvicorn:
    FastAPI is ASGI. uvicorn is the correct ASGI server. gevent is removed.

---

# PART 4 — DATABASE DESIGN

## 4.1 Database Configuration

  Engine:     PostgreSQL 16
  Driver:     asyncpg (async), psycopg2-binary (Alembic sync migrations only)
  Query:      SQLAlchemy Core (no ORM — same pattern as 0xConductor)
  Migrations: Alembic, directory: migrations/ (NOT alembic/)
  Pooling:    asyncpg connection pool, min=2, max=10

## 4.2 Schema Domain Groups

The 30+ SQLite tables from the existing codebase are reorganised into
logical domain groups. All tables use PostgreSQL native types (no AUTOINCREMENT,
no TEXT for booleans, no JSON stored as TEXT).

### Core System

  users                     — All accounts (local + OAuth provisioned)
  roles                     — Role definitions (admin, analyst, reviewer, viewer)
  role_permissions          — Permission assignments per role
  user_role_assignments     — User-to-role mappings (scoped to project or global)
  api_keys                  — Machine-to-machine API keys (collector registration)
  auth_providers            — OAuth provider config (Azure Entra ID, Okta)
  audit_log                 — Immutable event log (all API mutations)

### Project Management

  projects                  — Customer project records
  project_users             — User assignments to projects
  scan_configurations       — Scan config per project (collector targets, options)
  policies                  — Policy definitions (v2.0 JSON rule format)
  policy_versions           — Policy version history (SHA256-hash-based)
  assessment_types          — Assessment type catalogue

### Scan Execution

  scans                     — Scan records (config, status, project, policy)
  scan_runs                 — Individual run records per scan execution
  scan_logs                 — Per-run log entries
  scan_results              — Raw scan result blobs (JSONB, per collector)
  findings                  — Normalised findings from policy evaluation
  job_queue                 — Worker job dispatch table

### Asset Inventory (CLM)

  certificates_inventory    — Persistent certificate inventory
  keys_inventory            — Persistent key inventory
  connector_sync_status     — Sync health tracking per connector
  lifecycle_policies        — Per-connector lifecycle rules
  inventory_changes         — Change tracking journal

### Asset Context and Enrichment

  asset_context             — Business context per asset (environment, classification,
                              compliance scope, dependencies, owner, service name)
  asset_context_history     — Full audit trail of context changes
  asset_relationships       — Certificate/key relationship graph (with confidence scores)
  enrichment_operations     — Bulk enrichment operation tracking

### Reporting

  reports                   — Report records (type, status, path, encryption status)
  report_reassessments      — Policy reassessment records
  report_aggregations       — Multi-report aggregation records
  project_reports           — Report-to-project assignments

### Per-Project PKI

  internal_ca               — Root CA for the deployment (auto-provisioned)
  project_cas               — Per-project intermediate CA
  project_signing_certs     — Per-project report signing certificates
  user_digital_identities   — Per-user report viewer certificates
  collector_certificates    — Per-collector mTLS client certificates
  dashboard_certificates    — Dashboard TLS server certificate
  certificate_audit_log     — Certificate lifecycle event log
  certificate_signing_reqs  — CSR tracking and approval workflow
  revocation_list           — CRL cache per project

### Secret Management

  secret_references         — Vault reference pointers
  secret_stores             — Registered external secret store providers

### Document Assessment

  document_assessments      — Uploaded document assessment records
  document_findings         — Findings from document assessment
  document_templates        — Assessment template definitions

### Remote Collector

  remote_collectors         — Registered remote collector agents
  collector_heartbeats      — Heartbeat tracking
  collector_scan_reports    — Results reported from remote collectors

## 4.3 Key Schema Decisions

  - All IDs: BIGSERIAL primary keys (not AUTOINCREMENT)
  - UUIDs: Generated in Python (uuid4), stored as TEXT where display-facing
  - Timestamps: TIMESTAMPTZ (not naive TIMESTAMP) — always UTC
  - JSON columns: PostgreSQL JSONB (not TEXT) — enables indexing
  - Booleans: BOOLEAN (not INTEGER 0/1)
  - Project scoping: project_id FOREIGN KEY on all data tables
  - No AUTOINCREMENT keyword (PostgreSQL uses SERIAL/BIGSERIAL)
  - Foreign keys enabled by default in PostgreSQL (no PRAGMA required)

## 4.4 Alembic Convention

  Directory:    migrations/ (NOT alembic/ — avoids package shadowing)
  Run inside:   recon-api container with DATABASE_URL env var
  Pattern:      Same as 0xConductor — script-based, not autogenerate

---

# PART 5 — API DESIGN

## 5.1 API Structure

Two logical API surfaces, served from a single FastAPI application:

  User API       — Authenticated user operations. JWT required.
  Collector API  — Machine-to-machine. mTLS client certificate required.
                   Served on a separate nginx port (8443) with mTLS enforcement.

Both surfaces are implemented in the same recon-api container. The distinction
is enforced at nginx (mTLS vs JWT) and at the FastAPI dependency layer.

## 5.2 Route Groups

All routes under /api/v1/ with trailing slash standard enforced throughout.

  /api/v1/auth/              — Login, logout, OAuth flow, session info, auth mode
  /api/v1/users/             — User CRUD, role assignment, project assignment
  /api/v1/rbac/              — Role definitions, permission catalogue
  /api/v1/projects/          — Project CRUD, user assignment
  /api/v1/configurations/    — Scan configuration CRUD and export
  /api/v1/policies/          — Policy CRUD, upload, version history
  /api/v1/scans/             — Scan CRUD, execution, status, logs, runs
  /api/v1/reports/           — Report generation, retrieval, reassessments, aggregations
  /api/v1/inventory/         — CLM inventory, integrations, sync
  /api/v1/assets/            — Asset context, enrichment, relationships
  /api/v1/certificates/      — Per-project CA, collector certs, user certs, P12
  /api/v1/connectors/        — Connector CRUD, health check, credential management
  /api/v1/cbom/              — CBOM export
  /api/v1/lifecycle/         — Lifecycle policies, renewal queue, rotation queue
  /api/v1/documents/         — Document assessment CRUD and evaluation
  /api/v1/secret-stores/     — Secret store provider management
  /api/v1/settings/          — Auth provider config, platform settings
  /api/v1/product/config     — Product identity config (public, no auth)
  /api/v1/health             — Health check (public, no auth)
  /api/v1/admin/             — Bootstrap verify, audit log (admin only)

  Collector surface (mTLS, port 8443):
  /api/v1/collector/register/    — Agent registration
  /api/v1/collector/heartbeat/   — Heartbeat reporting
  /api/v1/collector/results/     — Scan result submission
  /api/v1/collector/logs/        — Log submission
  /api/v1/collector/config/      — Config and policy pull

## 5.3 Authentication

  User sessions:    JWT (python-jose), RS256, 8-hour expiry
  Token storage:    Memory (LocalAuthProvider) or sessionStorage (MsalAuthProvider)
  OAuth flow:       Authorization code, Azure Entra ID + Okta
  Collectors:       mTLS client certificate (CN=collector_id, OU=project_id)
  Machine API:      API key (hashed, stored in api_keys table)

## 5.4 Middleware Stack (FastAPI)

  1. Request ID generation (UUID, injected into audit context)
  2. Audit context setup (request_id, username if authenticated)
  3. CORS (origins from environment variable)
  4. JWT validation (dependency, not middleware — applied per-router)
  5. mTLS validation (nginx injects SSL_CLIENT_CERT header, FastAPI dependency reads it)
  6. Project context injection (from JWT claims + DB validation)
  7. RBAC permission check (dependency per route)

## 5.5 Response Envelope

All API responses use a consistent envelope:

  Success:  { "data": {...}, "meta": {...} }
  Error:    { "error": { "code": "...", "message": "...", "details": {...} } }

## 5.6 OpenAPI

  FastAPI generates OpenAPI 3.1 spec automatically.
  Spec served at /openapi.json.
  TypeScript client generated from spec via openapi-typescript-codegen.
  Frontend never hardcodes API paths or request shapes.

---

# PART 6 — CAPABILITY REGISTER

Complete inventory of all capabilities from the existing codebase, with
migration strategy and target phase.

## 6.1 Collectors (Discovery)

| Capability | Strategy | Phase | Notes |
|---|---|---|---|
| Luna HSM collector | Port | 3 | PyKCS11 to python-pkcs11. _safe_get, slot resolution, session lifecycle patterns preserved. Read-only enumeration. |
| Azure Key Vault collector | Refactor | 3 | Add async (azure SDK supports it natively). |
| EJBCA collector | Refactor | 3 | requests to httpx. mTLS session pattern preserved. |
| TLS scanner | Refactor | 3 | Async wrapper. ssl + pyOpenSSL kept. |
| CRL collector | Refactor | 3 | requests to httpx. |
| File share scanner | Lift | 3 | Stdlib only. Wrap in async thread executor. |
| Scan orchestrator | Refactor | 3 | Decouple from Flask. Async. DB-backed job dispatch. |

## 6.2 Analysis Pipeline

| Capability | Strategy | Phase | Notes |
|---|---|---|---|
| PQC detector | Lift | 2 | Pure logic, no framework deps. All OIDs, name patterns, migration status classifications preserved. |
| Policy engine (v2.0) | Refactor | 2 | Add Pydantic schema validation. Fix 4x bare except. Add tests. Rule schema format preserved. |
| Scoring engine | Lift | 2 | Pure logic. Weight factors, formula, grade scale preserved. |
| Aggregation engine | Lift | 2 | Pure logic. Health index, grade scale, priority queue preserved. |
| Key normalisation service | Refactor | 3 | Decouple from SQLite. Add async. |
| Environment inference | Lift | 3 | Pure logic. No framework deps. |
| Asset enrichment | Refactor | 4 | Decouple from SQLite. Add async. Business context model preserved. |
| Relationship mapping | Refactor | 4 | Decouple from SQLite. Relationship graph model preserved. |

## 6.3 Inventory and Lifecycle

| Capability | Strategy | Phase | Notes |
|---|---|---|---|
| CLM inventory service | Refactor | 4 | SQLite to PostgreSQL. Async. Sync logic preserved. |
| Inventory orchestrator | Refactor | 4 | Decouple from Flask. DB-backed. |
| Scheduler service | Refactor | 2 | Worker container entrypoint. DB job table replaces in-process threading. |
| Lifecycle policies | Refactor | 4 | Renewal thresholds, rotation intervals, auto-action. |
| Connector sync status | Refactor | 4 | Health tracking, failure counting. |

## 6.4 Project Management

| Capability | Strategy | Phase | Notes |
|---|---|---|---|
| Project CRUD | Rewrite | 2 | FastAPI router. Same data model. |
| Per-project user assignment | Rewrite | 2 | RBAC scoping. Same model. |
| Scan configuration CRUD | Rewrite | 2 | FastAPI router. Config JSON format preserved. |
| Policy CRUD + upload | Rewrite | 2 | FastAPI router. Policy JSON v2.0 format preserved. |
| Scan reassessments | Rewrite | 5 | Historical report + new policy = reassessed output. |
| Scan aggregations | Rewrite | 5 | Multi-report merge strategies. |

## 6.5 Per-Project PKI Sub-System

| Capability | Strategy | Phase | Notes |
|---|---|---|---|
| Internal CA (auto-provision) | Refactor | 2 | RSA-4096, 5yr, SHA-256. Same parameters. |
| Per-project CA issuance | Refactor | 2 | RSA-4096, SHA-256. |
| Collector certificate issuance | Refactor | 2 | 30-day, CN=collector_id, OU=project_id. mTLS. |
| User report viewer certificates | Refactor | 6 | 7-90 day validity. P12 generation with random password. |
| Report signing certificates | Refactor | 6 | RSA-4096, 2yr, digitalSignature + contentCommitment. Vault-stored private key. |
| Certificate lifecycle (revoke, renew) | Refactor | 5 | 3-day renewal grace. Revocation list. |
| CSR tracking and approval | Refactor | 5 | CSR state machine. |

## 6.6 Report Generation

| Capability | Strategy | Phase | Notes |
|---|---|---|---|
| Interactive HTML report — PKI | Rewrite | 6 | React component. Same data schema. Standalone exportable HTML. |
| Interactive HTML report — PQC | Rewrite | 6 | React component. Same data schema. Standalone exportable HTML. |
| Signed + encrypted HTML report | Refactor | 6 | AES-256-GCM + RSA-OAEP + RSA-PSS preserved. DOM element IDs and JSON structures preserved for backward compat. Gaps closed: sig verification before decrypt, chain validation, cert expiry check. |
| DOCX executive reports | Refactor | 6 | Decouple from Flask. python-docx. |
| PDF reports | Refactor | 6 | Decouple from Flask. reportlab. |
| Financial impact calculator | Lift | 6 | Pure calculation logic. No framework deps. |
| CBOM export (CycloneDX 1.6+) | Lift | 5 | Pure data transformation. Format preserved. |

## 6.7 Authentication and Authorisation

| Capability | Strategy | Phase | Notes |
|---|---|---|---|
| Local credential auth | Rewrite | 2 | bcrypt. JWT. No session cookies. |
| OAuth — Azure Entra ID | Rewrite | 2 | Authorization code flow. Auto-provisioning. |
| OAuth — Okta | Rewrite | 2 | Authorization code flow. Auto-provisioning. |
| mTLS (collector API) | Rewrite | 2 | nginx enforcement. FastAPI dependency validates cert. |
| RBAC (roles + permissions) | Rewrite | 2 | Same role model. Project-scoped. |
| Auth provider management | Rewrite | 2 | DB-stored config. FastAPI CRUD. |

## 6.8 Secret Management

| Capability | Strategy | Phase | Notes |
|---|---|---|---|
| Unified vault (AES-256-GCM file) | Refactor | 2 | Master password bootstrap. Same crypto params (PBKDF2-SHA256, 480k iterations, AES-256-GCM). |
| Azure Key Vault backend | Refactor | 2 | Async. Same SecretService pattern. |
| Multi-backend secret resolution | Refactor | 2 | SecretResolutionService. Priority order preserved. |
| Secret store provider management | Refactor | 2 | DB-stored stores. FastAPI CRUD. |
| HashiCorp Vault backend | Refactor | 2 | Carry forward if implemented; stub if not. Confirm in Phase 2. |
| AWS Secrets Manager backend | Refactor | 2 | Carry forward if implemented; stub if not. Confirm in Phase 2. |

## 6.9 Document Assessment

| Capability | Strategy | Phase | Notes |
|---|---|---|---|
| Document upload and storage | Rewrite | 7 | FastAPI. File storage to named volume. |
| Document assessment engine | Refactor | 7 | Decouple from Flask/SQLite. Async. |
| Assessment templates | Lift | 7 | Template definitions preserved. |
| Document findings | Refactor | 7 | Findings model aligned with scan findings model. |
| Document scoring | Refactor | 7 | Reuse scoring engine. |

## 6.10 Remote Collector Agent

| Capability | Strategy | Phase | Notes |
|---|---|---|---|
| Agent registration | Rewrite | 8 | Proper package. REST registration. CA-issued mTLS cert. |
| Agent heartbeat | Rewrite | 8 | |
| Agent scan execution | Rewrite | 8 | Uses shared collector package. No code duplication. |
| Agent result reporting | Rewrite | 8 | mTLS to collector API. |
| Agent daemon mode | Rewrite | 8 | systemd service. Local SQLite buffer. |
| Agent config and policy pull | Rewrite | 8 | Config fetched from server at run time. |

## 6.11 User Interface

| Capability | Strategy | Phase | Notes |
|---|---|---|---|
| Login / OAuth UI | Rewrite | 2 | Auth flow is phase 2. |
| Dashboard (all tabs) | Rewrite | 9 | React 18 + TypeScript + shadcn/ui. |
| Project management UI    | Rewrite | 9 | |
| Scan management UI | Rewrite | 9 | |
| Report viewer UI (PKI + PQC) | Rewrite | 6 | React components. Standalone export. |
| Certificate management UI | Rewrite | 9 | |
| Enrichment UI | Rewrite | 9 | |
| RBAC / user management UI | Rewrite | 9 | |
| Policy management UI | Rewrite | 9 | |
| Secret store management UI | Rewrite | 9 | |
| DPOD dashboard UI | Rewrite | 9 | |
| Document assessment UI | Rewrite | 9 | |
| Settings UI | Rewrite | 9 | |

## 6.12 Supporting Capabilities

| Capability | Strategy | Phase | Notes |
|---|---|---|---|
| PKI terminology database | Lift | 3 | Domain knowledge module. No framework deps. |
| Audit logging | Rewrite | 2 | Immutable audit_log table. All mutations logged. |
| Structured application logging | Rewrite | 2 | Python logging with JSON formatter. No print statements. |
| Health check endpoint | Rewrite | 1 | /api/v1/health — DB ping, version. |

---

# PART 7 — SERVICE LAYER ARCHITECTURE

## 7.1 Layered Architecture

```
HTTP Layer (FastAPI routers)
  |  validates request shape (Pydantic), extracts auth context
Service Layer (Python classes)
  |  all business logic, orchestration, DB access
Repository Layer (SQLAlchemy Core async)
  |  parameterised SQL, connection pool
PostgreSQL
```

The service layer owns all business logic. Routers contain zero business logic.
"If it's a business decision — backend. If it's a rendering decision — frontend."

## 7.2 Core Services

  ScanService              — Scan lifecycle, job dispatch, status management
  CollectorOrchestrator    — Multi-collector execution, result aggregation
  PolicyService            — Policy CRUD, version management, evaluation dispatch
  ScoringService           — Scoring engine, aggregation engine, priority queue
  PQCService               — PQC detection, migration status classification
  InventoryService         — CLM sync, promotion, lifecycle tracking
  AssetContextService      — Enrichment, override, history
  RelationshipService      — Asset relationship graph
  ReportService            — Report generation dispatch, retrieval
  ReportCryptoService      — Signing, encryption, P12 generation (worker only)
  CertificateService       — Internal CA, per-project PKI, mTLS issuance
  AuthService              — JWT, OAuth, mTLS validation
  RBACService              — Role and permission evaluation
  VaultService             — Secret read/write, master password bootstrap
  SecretResolutionService  — Multi-backend secret resolution
  SchedulerService         — Job queue polling, worker loop
  DocumentService          — Document assessment pipeline
  ProductConfigService     — Product identity config resolution

## 7.3 Dependency Pattern

Services instantiate their dependencies explicitly.
FastAPI Depends() is used for request-scoped dependencies (DB connection, current user).
No IoC container. No global singletons except for the DB connection pool.

## 7.4 Async Pattern

All service methods are async. Database calls use await.
CPU-bound operations (PKCS#11, crypto) run in asyncio.to_thread().
No synchronous blocking in the async event loop.

---

# PART 8 — COLLECTOR AND CONNECTOR ARCHITECTURE

## 8.1 Collector Package Structure

All collectors live in a shared Python package: packages/recon-collectors/
This package is installed in both recon-api/recon-worker containers AND
the remote collector agent. Single source, no duplication.

```
packages/recon-collectors/
  collectors/
    __init__.py
    base.py              — BaseCollector abstract class
    luna_hsm.py          — Thales Luna HSM (python-pkcs11, read-only)
    azure_keyvault.py    — Azure Key Vault (async azure SDK)
    ejbca.py             — EJBCA (httpx, mTLS)
    tls_scanner.py       — TLS/SSL scanner (ssl, pyOpenSSL)
    crl_collector.py     — CRL retrieval (httpx)
    file_share.py        — Filesystem scanner (stdlib)
  models.py              — CertificateInfo, KeyInfo, TLSScanResult, etc.
  orchestrator.py        — ScanOrchestrator (multi-collector coordination)
  normalisation.py       — KeyNormalisationService
  config.py              — Default scan config schema
```

## 8.2 BaseCollector Interface

```python
class BaseCollector(ABC):
    @abstractmethod
    async def collect(self, config: dict) -> ScanResults:
        """Execute collection. Return structured results."""

    @abstractmethod
    async def health_check(self) -> dict:
        """Return health status dict."""

    @property
    @abstractmethod
    def collector_type(self) -> str:
        """Identifier: luna_hsm | azure_keyvault | ejbca | tls | crl | file"""
```

## 8.3 Luna HSM Collector — Key Design Decisions

  Library:      python-pkcs11 v0.9.x (same as 0xConductor Luna backend)
  Mode:         Read-only. No sign/encrypt/wrap/derive on HSM.
  Session:      lib.get_token(token_label=...) — NOT slot index
  Concurrency:  asyncio.to_thread() — PKCS#11 calls are blocking
  Attributes:   All CKA_ attributes from existing connector preserved

  Patterns preserved from existing connector:
    - Slot resolution logic (handles DPoD slot number vs index distinction)
    - _safe_get() defensive attribute reading (try/except per attribute)
    - EC key size derivation from CKA_EC_PARAMS (not hardcoded 256)
    - Session lifecycle: logout() then closeSession() in finally block,
      each wrapped in independent try/except (avoids Luna log noise)

## 8.4 Remote Collector Agent

```
packages/recon-agent/
  __main__.py       — CLI entry (register, run, daemon, status)
  agent.py          — Agent lifecycle management
  client.py         — HTTPS/mTLS client to main API
  scanner.py        — Local scan orchestration (uses recon-collectors package)
  config.py         — Agent configuration
  local_store.py    — Local SQLite buffer for offline operation
  daemon.py         — Daemon mode, systemd integration
  install.sh        — systemd service installation
```

The agent imports recon-collectors (same package as server).
The agent does NOT contain copies of any server-side service layer code.
Communication: mTLS to /api/v1/collector/* endpoints on port 8443.
Registration: Agent generates CSR, server signs with project CA, returns cert.

---

# PART 9 — MULTI-PRODUCT IDENTITY ARCHITECTURE

## 9.1 Principle

The entire backend is brand-agnostic. No product name, logo path, or
terminology string appears anywhere in backend Python code.

Product identity is a deployment-time configuration, not a code-time decision.

## 9.2 Product Configuration Environment Variables

  PRODUCT_ID=0xrecon
  PRODUCT_NAME=0xRecon
  PRODUCT_SHORT_NAME=0xRecon
  PRODUCT_LOGO_PATH=/static/0xrecon/logo.svg
  PRODUCT_FAVICON_PATH=/static/0xrecon/favicon.ico
  PRODUCT_ACCENT_COLOR=#00FF41
  PRODUCT_TERMINOLOGY_JSON={}
  PRODUCT_FEATURE_FLAGS_JSON={}

  For CAIP deployment, the same variables are set with CAIP values.
  No code changes required to switch products.

## 9.3 Product Config API Endpoint

  GET /api/v1/product/config  — Public. No auth. Returns product identity block.

  Response structure:
  {
    "product_id": "0xrecon",
    "product_name": "0xRecon",
    "product_short_name": "0xRecon",
    "logo_url": "/static/0xrecon/logo.svg",
    "favicon_url": "/static/0xrecon/favicon.ico",
    "accent_colour": "#00FF41",
    "terminology": {
      "engagement": "Engagement",
      "collector": "Collector",
      "finding": "Finding",
      "scan": "Scan",
      "assessment": "Assessment"
    },
    "feature_flags": {
      "show_dpod_dashboard": true,
      "show_pqc_migration": true,
      "show_document_assessment": true
    }
  }

## 9.4 Frontend Product Context

  ProductContext      React context. Fetched once on app startup.
  useTerm(key)        Returns terminology string for current product.
                      useTerm('engagement') = "Engagement" (0xRecon) or "Project" (CAIP)
  useFeatureFlag(key) Returns boolean for current product.
  useProductConfig()  Returns full product config object.

  All product-specific strings in the UI go through useTerm().
  No hardcoded product name in any React component.

## 9.5 Report Branding

  Signed/encrypted HTML reports include a brand block at generation time:
  product_name, product_logo_base64, accent_colour are embedded in the HTML.
  The standalone report reflects the correct brand with no server connection.

## 9.6 Static Assets

  /static/0xrecon/logo.svg
  /static/0xrecon/favicon.ico
  /static/caip/logo.svg
  /static/caip/favicon.ico

  Both asset sets ship in the same Docker image.
  PRODUCT_LOGO_PATH selects which is served.

## 9.7 Deployment Models

  Single instance:
    One deployment. PRODUCT_ID env var determines brand.
    Use when customers share one database instance.

  Separate deployments (recommended for MSSP/consulting):
    Two deployed instances. Each has its own database and config.
    Same Docker image. Different .env files.
    CAIP customers point at CAIP deployment.
    0xRecon customers point at 0xRecon deployment.

---

# PART 10 — REPORT CRYPTO ARCHITECTURE

## 10.1 Overview

The signed and encrypted HTML report is the primary commercial deliverable.
It works fully offline at the recipient's browser. No server connection
required at decryption time.

## 10.2 Cryptographic Parameters (Preserved from Existing)

  Report payload encryption:  AES-256-GCM, 12-byte nonce, no AAD
  AES key wrapping:           RSA-OAEP, SHA-256, MGF1-SHA-256, 4096-bit recipient key
  Report signing:             RSA-PSS, SHA-256, 32-byte salt, 4096-bit signing key
  Signing certificate:        RSA-4096, 2yr validity, digitalSignature + contentCommitment
  Viewer certificate:         RSA-4096, 7-90 day validity, digitalSignature + keyEncipherment
  P12 password:               secrets.token_urlsafe(20)
  P12 parsing:                forge.js (inlined in report HTML at generation time)
  Client decryption:          Web Crypto API (SubtleCrypto)

## 10.3 Generation Flow (Worker)

  Trigger:    POST /api/v1/reports/embed/ dispatches job to worker via job_queue table.

  Worker executes:
    1. Issue report_viewer certificate for each recipient (CertificateService)
    2. Generate P12 for each recipient (random password, reference stored in vault)
    3. Encrypt report JSON: single random AES-256-GCM key, 12-byte nonce
    4. Wrap AES key for each recipient with their RSA public key (RSA-OAEP)
    5. Sign entire encrypted_blobs dict with project signing cert (RSA-PSS)
    6. Render HTML template with embedded blobs, metadata, signing result, forge.js
    7. Write HTML file to reports volume
    8. Update report record in DB (status: complete, path: report file path)

## 10.4 HTML Payload Structure (Preserved for Backward Compatibility)

  DOM element IDs are preserved exactly from the existing system.
  Any report generated by the old CAIP system remains openable by the new viewer.

  #pkiReportDataJson / #pqcReportDataJson  — Plaintext report (if not encrypted)
  #caip-encrypted-blobs                    — Per-recipient encrypted data
  #caip-encryption-metadata                — Recipient list, algorithm, timestamp
  #caip-signing-result                     — Signature, cert PEM, serial, timestamp

  Encrypted blob per recipient:
  {
    "username": {
      "encrypted_aes_key": "<base64: RSA-OAEP wrapped 32-byte AES key>",
      "encrypted_report":  "<base64: AES-256-GCM ciphertext + 16-byte auth tag>",
      "iv":                "<base64: 12-byte GCM nonce>",
      "tag":               "aes-256-gcm"
    }
  }

## 10.5 Client-Side Decryption Flow (New Build — All Gaps Closed)

  1. On load: detect presence of #caip-encrypted-blobs
  2. If encrypted: show decryption modal with recipient info and signing metadata
  3. MANDATORY: verify signature before any decryption
       - Extract public key from embedded certificate_pem using forge.js
       - crypto.subtle.verify(RSA-PSS, publicKey, signature, encrypted_blobs_bytes)
       - Signature failure: show tamper warning, block decryption entirely
  4. Prompt user for P12 file
  5. Parse P12 with forge.js (inlined, offline capable)
  6. Match username in encrypted_blobs to find this recipient's encrypted_aes_key
  7. Import private key: crypto.subtle.importKey (RSA-OAEP, decrypt usage)
  8. Unwrap AES key: crypto.subtle.decrypt(RSA-OAEP, privateKey, encrypted_aes_key)
  9. Import AES key: crypto.subtle.importKey (AES-GCM, decrypt usage)
  10. Decrypt report: crypto.subtle.decrypt(AES-GCM, aesKey, encrypted_report)
  11. Parse JSON and render report dashboard
  12. Check viewer cert expiry: warn if expired, do not block
  13. Validate cert chains to project CA: warn if chain invalid, do not block

## 10.6 Gaps Closed vs Existing Codebase

  Signature verification    Existing: never called. New: mandatory step 3.
  Certificate chain check   Existing: missing. New: forge.js chain verification.
  Cert expiry check         Existing: missing. New: warn at decrypt time.
  Single JS library         Existing: forge.js + jsrsasign. New: forge.js only.
  Dead code removed         Existing: ReportDecryptor, P12Parser (stubs). New: removed.
  State machine             Existing: ReportStateManager unused. New: React state.

---

# PART 11 — PHASE PLAN

## Phase Overview

  Phase 1   — Repository scaffold and container stack
  Phase 2   — Core data layer, auth, vault, API skeleton
  Phase 3   — Collector package and scan pipeline
  Phase 4   — Asset management and inventory (CLM)
  Phase 5   — CBOM, reassessments, aggregations, PKI lifecycle
  Phase 6   — Report generation and signed/encrypted HTML reports
  Phase 7   — Document assessment
  Phase 8   — Remote collector agent
  Phase 9   — Full UI (React, all pages)
  Phase 10  — Hardening

Each phase has a dedicated prompt file (PHASE_N.md) with numbered prompts,
hard stops, and explicit shell-command verification gates.
No phase starts until the prior phase gate is explicitly passed.
This architecture document is updated at the end of every significant session.

## Phase 1 — Repository Scaffold and Container Stack

Deliverables:
  - Monorepo structure:
      packages/recon-api/
      packages/recon-worker/
      packages/recon-collectors/
      packages/recon-ui/
      packages/recon-agent/
  - docker-compose.yml (postgres, api, worker, ui, nginx)
  - docker-compose.prod.yml (production overrides)
  - Dockerfile for recon-api and recon-worker (shared image, different CMD)
  - Dockerfile for recon-ui
  - nginx.conf (TLS, reverse proxy, mTLS port 8443)
  - .env.example (all required variables documented, no real values)
  - Alembic initialised (migrations/ directory, env.py, initial empty migration)
  - PostgreSQL container healthy
  - recon-api container starts, /api/v1/health returns 200 with DB connected

Gate: curl http://localhost:8000/api/v1/health returns 200 with db_connected: true

## Phase 2 — Core Data Layer, Auth, Vault, API Skeleton

Deliverables:
  - SQLAlchemy Core async setup (connection pool, base metadata)
  - Alembic migration: users, roles, role_permissions, user_role_assignments,
    api_keys, auth_providers, audit_log, projects, project_users,
    scan_configurations, policies, policy_versions, internal_ca, project_cas,
    collector_certificates, dashboard_certificates, job_queue,
    secret_references, secret_stores
  - VaultService (AES-256-GCM file, PBKDF2 master password bootstrap)
  - SecretResolutionService (vault, Azure KV, file, memory backends)
  - AuthService (local JWT, OAuth Azure Entra ID + Okta, mTLS dependency)
  - RBACService (role/permission evaluation, project scoping)
  - CertificateService (internal CA auto-provision, project CA, collector certs)
  - ProductConfigService (reads PRODUCT_* env vars, serves /api/v1/product/config)
  - SchedulerService (job queue polling loop — worker entrypoint)
  - Login UI (React, IAuthProvider, LocalAuthProvider + MsalAuthProvider)
  - ProductContext + useTerm + useFeatureFlag in React (from day one)
  - PQCService and ScoringService lifted (pure logic, no DB dependency)

Gate: POST /api/v1/auth/login/ returns JWT.
      Protected route rejects without JWT.
      GET /api/v1/product/config returns correct product identity block.
      Worker container starts and polls job_queue without error.

## Phase 3 — Collector Package and Scan Pipeline

Deliverables:
  - packages/recon-collectors (all 6 collectors, BaseCollector, orchestrator, models)
  - Luna HSM collector (python-pkcs11, read-only, all CKA attributes)
  - Azure KV collector (async azure SDK)
  - EJBCA collector (httpx, mTLS)
  - TLS scanner (async wrapper, ssl + pyOpenSSL)
  - CRL collector (httpx)
  - File share scanner (asyncio.to_thread wrapper)
  - Alembic migration: scans, scan_runs, scan_logs, scan_results, findings,
    remote_collectors, connector_sync_status
  - ScanService (CRUD, job dispatch, status management)
  - PolicyService (CRUD, version management, evaluation)
  - All scan and policy API routes functional

Gate: POST /api/v1/scans/{id}/run/ creates a job entry.
      Worker picks it up and executes at least one collector.
      Scan status transitions to complete. Findings written to DB.

## Phase 4 — Asset Management and Inventory

Deliverables:
  - Alembic migration: certificates_inventory, keys_inventory, asset_context,
    asset_context_history, asset_relationships, enrichment_operations,
    lifecycle_policies, inventory_changes
  - InventoryService (sync, promotion, lifecycle tracking)
  - AssetContextService (enrichment, overrides, history)
  - RelationshipService (relationship graph, confidence scoring)
  - EnvironmentInferenceService (environment type detection)
  - KeyNormalisationService (cross-collector format normalisation)
  - All inventory and asset context API routes functional

Gate: Scan result promoted to inventory.
      Asset context written and retrievable.
      Asset relationship created.
      Lifecycle queue populated for expiring certificates.

## Phase 5 — CBOM, Reassessments, Aggregations, PKI Lifecycle

Deliverables:
  - Alembic migration: reports, report_reassessments, report_aggregations,
    project_reports, certificate_signing_reqs, revocation_list
  - CBOMExportService (CycloneDX 1.6+ — lifted from existing)
  - ReportFinancialCalculator (lifted from existing)
  - Reassessment service (historical scan + new policy)
  - Aggregation service (multi-report merge strategies)
  - Certificate lifecycle routes (CSR, revoke, renew)
  - All relevant API routes functional

Gate: GET /api/v1/cbom/scans/{id}/ returns valid CycloneDX 1.6 JSON.
      Reassessment route creates reassessed report record.
      Aggregation route creates aggregated report record.

## Phase 6 — Report Generation and Signed/Encrypted HTML Reports

Deliverables:
  - Alembic migration: user_digital_identities, project_signing_certs
  - ReportService (generation dispatch, retrieval, status tracking)
  - ReportCryptoService (encrypt_report_data, sign_encrypted_blob)
  - Viewer cert issuance and P12 generation in CertificateService
  - HTML report templates (PKI, PQC) — Jinja2, server-side rendered by worker
  - forge.js inlined at generation time
  - POST /api/v1/reports/embed/ route with worker dispatch
  - React report viewer component (with full client-side crypto pipeline)
  - All 6 gaps from existing system closed (see Part 10.6)
  - DOCX executive reports (python-docx)
  - PDF reports (reportlab)
  - DOM element IDs and JSON structures preserved for backward compat

Gate: POST /api/v1/reports/embed/ generates signed + encrypted HTML report.
      Report opens in browser with no server connection.
      Signature verification passes before decryption is permitted.
      Correct P12 decrypts report successfully.
      Incorrect P12 is rejected cleanly.

## Phase 7 — Document Assessment

Deliverables:
  - Alembic migration: document_assessments, document_findings, document_templates
  - DocumentService (upload, pipeline, findings, scoring)
  - Assessment templates (lifted from existing)
  - All document assessment API routes functional

Gate: Document uploaded via API.
      Assessment runs against at least one template.
      Findings returned with scores.

## Phase 8 — Remote Collector Agent

Deliverables:
  - packages/recon-agent (agent, client, scanner, daemon, install.sh)
  - Agent uses recon-collectors package (no code duplication)
  - Registration flow (CSR to signed cert to mTLS credential)
  - Heartbeat, result reporting, config pull
  - All collector API routes (/api/v1/collector/*)
  - collector_heartbeats Alembic migration
  - collector_scan_reports Alembic migration

Gate: Agent registers on a test node and receives mTLS certificate.
      Agent executes a scan and results appear in server DB.
      Heartbeat received and tracked.

## Phase 9 — Full UI

Deliverables:
  - All remaining React pages: Dashboard, Projects, Scans, Reports,
    Inventory, Assets, Certificates, Collectors, Policies, RBAC,
    Secret Stores, DPOD Dashboard, Document Assessment, Settings, Audit
  - All pages wired to API (TanStack Query, generated TypeScript client)
  - ProductContext active throughout — useTerm() on all label strings
  - Report viewer components integrated (PKI, PQC with full crypto pipeline)
  - Auth flow end-to-end (local + OAuth)
  - Responsive layout, Station Hex design system throughout

Gate: All pages render with real data from API.
      useTerm('project') returns "Project" for 0xRecon product config.
      Auth flow completes end-to-end for both local and OAuth.
      Report viewer decrypts a Phase 6 test report successfully.

## Phase 10 — Hardening

Deliverables:
  - Docker Secrets API integration (closes docker inspect credential exposure)
  - Rate limiting per user/project (nginx or FastAPI middleware)
  - Input sanitisation middleware
  - Structured JSON logging throughout
  - Prometheus metrics endpoint
  - OpenTelemetry tracing
  - Let's Encrypt TLS (replaces self-signed)
  - Security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
  - SESSION_COOKIE_SECURE enforced (where applicable)
  - No bare except blocks anywhere (audit pass)
  - Penetration test checklist executed and findings resolved

---

# PART 12 — NAMING CONVENTIONS

## 12.1 Backend Naming

  Python package prefix:    recon_ (not caip_)
  Log namespace:            recon.{module} (not caip.{module})
  Environment variables:    RECON_{NAME} for application config
                            PRODUCT_{NAME} for product identity config
  Docker project:           0xrecon
  Docker image names:       0xrecon-api, 0xrecon-worker, 0xrecon-ui
  DB table prefix:          None — tables named by domain
  Vault key prefix:         recon-{purpose} (e.g., recon-signing-key-{id})
  API route prefix:         /api/v1/

## 12.2 Frontend Naming

  Product name in UI:   From useTerm() and useProductConfig() — never hardcoded
  CSS class prefix:     recon- for custom classes not from shadcn or Tailwind
  Component naming:     PascalCase, no product prefix

## 12.3 The String "caip" in the New Codebase

  "caip" does NOT appear in:
    Python module names, class names, function names, log messages,
    DB table names, environment variable names, Docker image names,
    API routes, or configuration keys.

  "caip" ONLY appears in:
    PRODUCT_ID=caip environment variable (deployment config)
    /static/caip/logo.svg and /static/caip/favicon.ico (static assets)
    PRODUCT_TERMINOLOGY_JSON if CAIP uses different label strings
    DOM element IDs in report HTML (#caip-encrypted-blobs etc.) —
      preserved for backward compatibility with existing reports only.

---

# PART 13 — CRITICAL PATTERNS

## Docker Compose

  Always: docker compose -p 0xrecon -f docker-compose.yml up
  Production: docker compose -p 0xrecon -f docker-compose.yml -f docker-compose.prod.yml up
  Never omit -p 0xrecon.

## Alembic

  Directory: migrations/ NOT alembic/ (avoids package shadowing)
  Run inside container with DATABASE_URL env var.
  Never run Alembic on the host against a remote DB.

## Async Discipline

  All DB calls:       await async_session.execute(...)
  All HTTP calls:     await httpx_client.get(...)
  All PKCS#11 calls:  await asyncio.to_thread(blocking_pkcs11_call)
  No requests library. No blocking I/O in async context. No gevent.

## Error Handling

  No bare except: or except Exception: pass anywhere.
  All exceptions caught with specific exception type.
  All exceptions logged with full traceback (logger.exception not logger.error).
  API errors return structured error envelope — never raw exception messages to client.

## Secret Discipline

  No credentials in source code.
  No credentials in committed environment files.
  .env.example contains structure only — all values are documented placeholders.
  All secrets resolved through VaultService or SecretResolutionService at runtime.

## Collector Safety

  Collectors are read-only. No key generation, signing, encryption, wrapping,
  or any destructive operation on the HSM during collection. Discovery only.

## Report Backward Compatibility

  DOM element IDs in HTML reports are preserved exactly.
  JSON structures inside those elements are preserved exactly.
  Any report generated by the old CAIP system must open correctly
  in the new report viewer without modification.

## Worker Job Pattern

  API receives request, validates, writes job to job_queue table, returns 202 Accepted.
  Worker polls job_queue, picks up pending jobs, executes, updates status.
  API status endpoint reads job/report status from DB.
  No direct API-to-worker communication. DB is the coordination point.

---

# PART 14 — DECISIONS LOG

  2026-04 v1.0: Initial architecture produced from full codebase inventory
                (RECON_INVENTORY.md, REPORT_CRYPTO_INVENTORY.md).

  2026-04 v1.0: Flask replaced by FastAPI.
                Flask usage was deep (5,915-line god object). Full rewrite
                required regardless. FastAPI chosen for async, Pydantic,
                OpenAPI, and consistency with 0xConductor.

  2026-04 v1.0: PyKCS11 replaced by python-pkcs11.
                Eliminates dual-library situation across product suite.
                Luna collector rewritten (300 lines, moderate effort).
                Slot resolution, _safe_get, and session lifecycle patterns
                preserved from existing production-tested connector.

  2026-04 v1.0: SQLite replaced by PostgreSQL.
                Container-first requires a proper database. database_service.py
                (110KB) replaced by SQLAlchemy Core + asyncpg + Alembic.

  2026-04 v1.0: Multi-product identity via ProductContext.
                Backend is brand-agnostic. Product identity in UI only.
                PRODUCT_ID env var at deployment time. useTerm() hook in React.
                DOM element IDs in report HTML preserved for CAIP backward compat.

  2026-04 v1.0: Remote collector rebuilt as proper packaged agent.
                remote_collector/ directory (duplicated 153KB god object)
                eliminated. Replaced by packages/recon-agent which imports
                packages/recon-collectors (shared, no duplication).

  2026-04 v1.0: Report signature verification gap closed.
                SignatureVerifier was implemented but never called in existing
                codebase. New build: verify-then-decrypt is mandatory.
                Signature failure blocks decryption entirely.

  2026-04 v1.0: Document assessment retained as Phase 7.
                Confirmed as product differentiator. Full capability carried forward.

  2026-04 v1.0: CAIP naming removed from all backend source.
                "caip" only appears in PRODUCT_ID env var, static assets,
                and report DOM element IDs (backward compat only).

  2026-04 v1.0: forge.js as sole client-side crypto library.
                Replaces forge.js + jsrsasign dual-library situation.
                forge.js handles both P12 parsing and certificate DER parsing.
                Inlined in report HTML at generation time for offline operation.

  2026-04 v1.0: Worker container pattern for heavyweight operations.
                Scan execution, report generation, certificate issuance, and
                signing all run in recon-worker. API dispatches via job_queue
                table. No long-running operations in the API process.

  2026-04 v1.1: Engagement construct renamed to Project.
                The top-level scoping construct previously named "engagement"
                is renamed to "project" throughout the new codebase.
                DB tables: engagements → projects, engagement_users → project_users,
                engagement_cas → project_cas.
                Role: engagement-admin → project-admin.
                Permission strings: engagements:* → projects:*.
                Vault key: engagement-ca-key-{id} → project-ca-key-{id}.
                API route: /api/v1/engagements/ → /api/v1/projects/.
                Legacy reference files (docs/reference/*) document the old CAIP
                codebase and are intentionally unchanged.
                The terminology system (PRODUCT_TERMINOLOGY_JSON) allows
                deployments to display this construct as "Engagement" in the UI
                if preferred — the backend key is always "project".

---

# PART 15 — OPEN QUESTIONS

  OQ-001: Document assessment — does CAIP use different template definitions
          to 0xRecon, or are templates shared? Affects whether templates are
          product-config-driven. Resolve before Phase 7.

  OQ-002: HashiCorp Vault and AWS Secrets Manager backends — fully implemented
          in existing codebase or stubs? Confirm in Phase 2 before implementing.

  OQ-003: Financial impact calculator — surfaced in UI or reports only?
          Affects Phase 9 UI scope. Resolve before Phase 9.

  OQ-004: CAIP terminology overrides — which specific labels does CAIP use
          that differ from 0xRecon? Required before Phase 9 to populate
          PRODUCT_TERMINOLOGY_JSON for CAIP deployment config.

  OQ-005: Report HTML backward compatibility — are there existing encrypted
          reports in customer hands? If yes, DOM element ID preservation is
          mandatory (already planned). If no live customers yet, we have
          freedom to revise the format if needed.
