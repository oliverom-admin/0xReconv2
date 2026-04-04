# 0xRecon — Phase Status Tracker

**READ THIS FILE FIRST AT THE START OF EVERY SESSION.**
**UPDATE THIS FILE BEFORE ENDING EVERY SESSION.**

This is the single source of truth for build progress.
If this file and a phase document disagree, this file takes precedence.

---

## Current State

```
Current phase:    Phase 6 — Report Generation and Signed/Encrypted HTML
Current prompt:   6B complete — begin at Prompt 6C.1
Overall status:   Phases 1–5 complete. Phases 6A–6B complete. 242 tests passing.
                  Alembic at 0007. ReportCryptoService working.
                  Encrypt/sign/verify/decrypt round-trip verified.
Last session:     2026-04-04
Last verified:    2026-04-04T11:00Z — Phase 6B full gate PASS
```

---

## Naming Convention (Project, not Engagement)

All new code uses **project** throughout. The rename from "engagement" is complete
in all code, schema, and documentation. Do not use "engagement" in new code.

| Use | Not |
|---|---|
| `projects`, `project_users`, `project_cas` | `engagements`, `engagement_users` |
| `project_id` | `engagement_id` |
| `project-admin` | `engagement-admin` |
| `projects:*` | `engagements:*` |
| `/api/v1/projects/` | `/api/v1/engagements/` |
| `project-ca-key-{8char}` | `engagement-ca-key-{8char}` |

---

## Phase Completion Overview

| Phase | Description | Status | Gate | Alembic | Tests |
|---|---|---|---|---|---|
| 1 | Scaffold — containers, FastAPI, nginx, Alembic | ✅ COMPLETE | PASS | 0000 | 17 |
| 2A | Data foundation — DB pool, 20-table schema, vault | ✅ COMPLETE | PASS | 0002 | 45 |
| 2B | Auth, services, API skeleton | ✅ COMPLETE | PASS | 0003 | 75 |
| 3 | Collector package and scan pipeline | ✅ COMPLETE | PASS | 0004 | 88 |
| 4A | Inventory foundation (migration, service, routes) | ✅ COMPLETE | PASS | 0005 | 107 |
| 4B | Context, relationships, environment inference | ✅ COMPLETE | PASS | 0005 | 135 |
| 5A | Report infrastructure + CBOM export | ✅ COMPLETE | PASS | 0006 | 170 |
| 5B | Reassessments and aggregations | ✅ COMPLETE | PASS | 0006 | 191 |
| 5C | PKI certificate lifecycle | ✅ COMPLETE | PASS | 0006 | 207 |
| 6A | Report PKI schema + cert provisioning | ✅ COMPLETE | PASS | 0007 | 224 |
| 6B | ReportCryptoService (encrypt/sign/verify) | ✅ COMPLETE | PASS | 0007 | 242 |
| 6C | HTML templates, worker pipeline, embed route | ⏳ | — | — | — |
| 7 | Document assessment | ⏳ | — | — | — |
| 8 | Remote collector agent | ⏳ | — | — | — |
| 9 | Full UI — React, all pages | ⏳ | — | — | — |
| 10 | Hardening | ⏳ | — | — | — |

---

## What Is Built (Phases 1–2B)

### Infrastructure
- 4 Docker containers: recon-postgres (healthy), recon-api (healthy),
  recon-worker (polling), recon-ui (placeholder)
- PostgreSQL 16 with pgcrypto + uuid-ossp
- nginx runs on host in production (removed from Docker Compose)
- Ports 443/8443 free for host nginx binding

### Database (Alembic 0003, 20 domain tables)
```
Core system:     users, roles, role_permissions, user_role_assignments,
                 api_keys, auth_providers, audit_log
Project mgmt:    projects, project_users, scan_configurations,
                 policies, policy_versions, assessment_types
Scan execution:  job_queue   (scans/findings tables added in Phase 3)
PKI:             internal_ca, project_cas, collector_certificates,
                 dashboard_certificates
Secret mgmt:     secret_stores, secret_references
```

### Services and Routes
- VaultService (AES-256-GCM, PBKDF2-600k) — vault.enc at /app/data/
- SecretResolutionService (vault → Azure KV stub → memory)
- AuthService — JWT (HS256 dev fallback), bcrypt-12
- RBACService — permission evaluation, project-scoped roles
- CertificateService — internal CA (RSA-4096, 10yr), project CA (RSA-4096, 5yr),
  collector certs (RSA-4096, 30-day)
- SchedulerService — job_queue polling (FOR UPDATE SKIP LOCKED), 10s interval
- PQCService — OID + name-pattern detection (in recon-core)
- ScoringService — weight tables, grade boundaries A+→F (in recon-core)

### API Routes Working
```
POST /api/v1/auth/login/          ← JWT returned
GET  /api/v1/auth/me/             ← current user
GET  /api/v1/auth/providers/      ← OAuth providers list
POST /api/v1/users/bootstrap/     ← seed first admin (idempotent)
GET  /api/v1/users/               ← list users (admin only)
POST /api/v1/users/               ← create user
GET  /api/v1/users/{id}/          ← get user
PUT  /api/v1/users/{id}/          ← update user
GET  /api/v1/rbac/roles/          ← list roles
GET  /api/v1/rbac/roles/{id}/permissions/
GET  /api/v1/rbac/users/{id}/permissions/
POST /api/v1/rbac/users/{id}/roles/
GET  /api/v1/projects/            ← list projects
POST /api/v1/projects/            ← create project (provisions project CA)
GET  /api/v1/projects/{id}/
PUT  /api/v1/projects/{id}/
DELETE /api/v1/projects/{id}/
POST /api/v1/projects/{id}/users/
GET  /api/v1/health/              ← db_connected: true
GET  /api/v1/product/config/      ← product identity block
```

### Not Yet Built (Phase 3+)
- Collectors (Luna HSM, Azure KV, EJBCA, TLS, CRL, File Share)
- Scan execution pipeline (ScanService, PolicyService, scan/findings tables)
- Inventory and asset management (CLM)
- Reports (HTML signed/encrypted, DOCX, PDF, CBOM)
- Document assessment
- Remote collector agent (mTLS registration)
- React UI (all pages — placeholder only)
- OAuth flow (Azure Entra ID, Okta — routes stubbed)
- mTLS enforcement on port 8443

---

## Phase 1 — Complete ✅

| Prompt | Description | Status |
|---|---|---|
| 1.1 | Directory structure | ✅ |
| 1.2 | Environment configuration | ✅ |
| 1.3 | Python package manifests | ✅ |
| 1.4 | FastAPI application skeleton | ✅ |
| 1.5 | Dockerfile and entrypoints | ✅ |
| 1.6 | Alembic configuration | ✅ |
| 1.7 | Docker Compose files | ✅ |
| 1.8 | nginx and helper scripts | ✅ |
| 1.9 | Test suite (17 tests) | ✅ |
| 1.10 | Stack startup + gate | ✅ |

Fixes: env.py sync engine · config.py allowed_origins field_validator ·
logging_config.py removed add_logger_name · test_conventions.py source-only scope

---

## Phase 2A — Complete ✅ (Alembic 0001→0002, 45 tests)

| Prompt | Description | Status |
|---|---|---|
| 2A.1 | DB pool + health `db_connected: true` | ✅ |
| 2A.2 | Alembic 0001 — 20 tables + seed roles/types | ✅ |
| 2A.3 | VaultService + SecretResolutionService | ✅ |
| 2A.4 | Test suite (45 tests) + gate | ✅ |
| 2A.5 | Schema rename remediation 0002 (engagement→project) | ✅ |

Fixes: JSONB server_defaults triple-quoting → sa.text("'{}':jsonb")

---

## Phase 2B — Complete ✅ (Alembic 0003, 75 tests)

| Prompt | Description | Status |
|---|---|---|
| 2B.1 | AuthService + JWT deps + auth routes | ✅ |
| 2B.2 | RBACService + bootstrap + user/RBAC routes | ✅ |
| 2B.3 | CertificateService + internal CA on startup | ✅ |
| 2B.4 | SchedulerService + real job_queue polling | ✅ |
| 2B.5 | Project routes + CA provisioning on create | ✅ |
| 2B.6 | PQCService + ScoringService + full test suite + gate | ✅ |

Fixes: migration 0003 fixes text column server_defaults · PQC classify_name
checks transitioning before safe · auth tests accept 503 alongside 401/403 ·
cleaned 3 duplicate internal_ca rows

---

## Phase 3 — Complete ✅ (Alembic 0004, 88 tests)

| Prompt | Description | Status |
|---|---|---|
| 3.1 | Models + BaseCollector | ✅ |
| 3.2 | Luna HSM collector (python-pkcs11) | ✅ |
| 3.3 | Azure Key Vault collector (async SDK) | ✅ |
| 3.4 | EJBCA collector (httpx, mTLS P12) | ✅ |
| 3.5 | TLS scanner (ssl + pyOpenSSL) | ✅ |
| 3.6 | CRL + File Share collectors | ✅ |
| 3.7 | CollectorOrchestrator | ✅ |
| 3.8 | Alembic migration 0004 + ScanService | ✅ |
| 3.9 | PolicyService + policy engine v2.0 | ✅ |
| 3.10 | Routes + worker handler + gate | ✅ |

Fixes: ScanService.dispatch_scan config_payload dict() → isinstance check ·
product.py terminology key "engagement"→"project" ·
PQC classify_name transitioning before safe (from 2B)

---

## 2026-04-03 — nginx moved to host (pre-deployment change)

- Removed recon-nginx container from docker-compose.yml and docker-compose.prod.yml
- Stack now runs 4 containers: recon-postgres, recon-api, recon-worker, recon-ui
- nginx/nginx.conf retained as routing reference for install script authoring
- scripts/dev-up.sh updated — cert check removed
- ARCHITECTURE.md sections 2.1, 2.2, 2.5, 3.4 updated to reflect host nginx
- Gate: 4 containers healthy, health=200, db_connected=true, 88/88 tests pass
- Ports 443/8443 are now free — will be bound by host nginx on production server

---

## 2026-04-03 — install-azure/ deployment tooling created

- Created install-azure/ directory with 6 files:
  - deployment.conf.example — operator configuration template
  - setup.sh — Phase 1 bootstrap (service account, deploy key, GitHub)
  - install.sh — Phase 2 install (Docker, nginx, clone, env, systemd, bootstrap)
  - smoke-test.sh — 12-test post-install validation
  - deploy-update.sh — git pull + rebuild + health check for updates
  - INSTALL.md — operator guide
- Added install-azure/deployment.conf to .gitignore
- All 4 scripts pass bash syntax check
- Stack health verified: 4 containers, health=200, db_connected=true

---

## Phase 3 — Architecture (Collector Package and Scan Pipeline)

**Gate:** `POST /api/v1/scans/{id}/run/` creates a job. Worker picks it up,
executes at least one collector, scan transitions to complete, findings written.

### What Phase 3 delivers (from ARCHITECTURE.md):
- `packages/recon-collectors/` — all 6 collectors fully implemented:
  - Luna HSM (python-pkcs11, read-only, full CKA attribute list)
  - Azure Key Vault (async azure SDK)
  - EJBCA (httpx, mTLS P12 session)
  - TLS scanner (ssl + pyOpenSSL, asyncio.to_thread wrapper)
  - CRL collector (httpx)
  - File share scanner (asyncio.to_thread, stdlib only)
- Alembic migration: `scans`, `scan_runs`, `scan_logs`, `scan_results`,
  `findings`, `remote_collectors`, `connector_sync_status`
- ScanService (CRUD, job dispatch, status management)
- PolicyService (CRUD, version management, evaluation — policy engine v2.0)
- CollectorOrchestrator (multi-collector execution, result aggregation,
  partial failure handling)
- KeyNormalisationService (cross-collector format normalisation)
- EnvironmentInferenceService (hostname heuristics, confidence scoring)
- All scan and policy API routes functional

### Reference files for Phase 3:
- `docs/reference/legacy_luna_hsm.py` — _safe_get pattern, slot resolution,
  session lifecycle. Rewrite using python-pkcs11 not PyKCS11.
- `docs/reference/legacy_azure_keyvault.py` — field extraction, Azure metadata
- `docs/reference/legacy_ejbca_collector.py` — REST endpoint structure, mTLS
- `docs/reference/legacy_tls_scanner.py` — TLS metadata captured
- `docs/reference/legacy_crl_collector.py` — CRL parsing
- `docs/reference/legacy_file_share.py` — extension list, content detection
- `docs/reference/legacy_scan_orchestrator.py` — partial failure handling,
  collector result combination, per-collector timeouts
- `docs/reference/legacy_rule_assessment.py` — RuleRegistry, RuleEvaluator,
  condition types (simple/expression/temporal)
- `docs/reference/legacy_policy_assessment_service.py` — assess_scan_results()

---

## Phase 4 — Asset Management and Inventory (CLM)

**Gate:** Scan result promoted to inventory. Asset context written and
retrievable. Asset relationship created. Lifecycle queue populated.

### What Phase 4 delivers:
- Alembic migration: `certificates_inventory`, `keys_inventory`,
  `asset_context`, `asset_context_history`, `asset_relationships`,
  `enrichment_operations`, `lifecycle_policies`, `inventory_changes`,
  `clm_integrations`, `connector_sync_status`
- InventoryService (sync, promotion, lifecycle tracking)
- AssetContextService (enrichment, overrides, history)
- RelationshipService (relationship graph, confidence scoring)
- All inventory and asset context API routes

### Reference files for Phase 4:
- `docs/reference/legacy_inventory_service.py`
- `docs/reference/legacy_asset_context_service.py`
- `docs/reference/legacy_environment_inference_service.py`
- `docs/reference/legacy_key_normalisation_service.py`

---

## Phase 5 — CBOM, Reassessments, Aggregations, PKI Lifecycle

**Gate:** `GET /api/v1/cbom/scans/{id}/` returns valid CycloneDX 1.6 JSON.
Reassessment route creates record. Aggregation route creates record.

### What Phase 5 delivers:
- Alembic migration: `reports`, `report_reassessments`, `report_aggregations`,
  `project_reports`, `certificate_signing_reqs`, `revocation_list`
- CBOMExportService (CycloneDX 1.6+ — lifted from legacy)
- ReassessmentService (historical scan + new policy)
- AggregationService (multi-report merge strategies)
- ReportFinancialCalculator (lifted from legacy)
- Certificate lifecycle routes (CSR, revoke, renew, 3-day grace)
- All relevant API routes

### Reference files for Phase 5:
- `docs/reference/legacy_cbom_export_service.py`
- `docs/reference/legacy_financial_calculator.py`

---

## Phase 6 — Report Generation and Signed/Encrypted HTML Reports

**Gate:** `POST /api/v1/reports/embed/` generates signed + encrypted HTML.
Report opens offline. Signature verification passes before decrypt.
Correct P12 decrypts. Wrong P12 rejected cleanly.

### What Phase 6 delivers:
- Alembic migration: `user_digital_identities`, `project_signing_certs`
- ReportService (generation dispatch, retrieval, status)
- ReportCryptoService (encrypt_report_data, sign_encrypted_blob)
- Viewer cert issuance + P12 generation in CertificateService
- HTML report templates (PKI, PQC) — Jinja2, worker-rendered
- forge.js inlined at generation time
- React report viewer (full client-side crypto pipeline)
- DOCX executive reports (python-docx)
- PDF reports (reportlab)
- All 6 gaps from legacy closed (see ARCHITECTURE.md Part 10.6)
- DOM element IDs preserved for backward compat with existing reports

### Reference files for Phase 6:
- `docs/reference/legacy_certificate_service.py` — encrypt_report_data(),
  sign_encrypted_blob() — must be byte-for-byte compatible
- `docs/reference/legacy_engagement_docx_builder.py`
- `docs/reference/legacy_executive_report_service.py`
- `docs/reference/REPORT_CRYPTO_INVENTORY.md`

---

## Phase 7 — Document Assessment

**Gate:** Document uploaded. Assessment runs against at least one template.
Findings returned with scores.

### What Phase 7 delivers:
- Alembic migration: `document_assessments`, `document_findings`,
  `document_templates`
- DocumentService (upload, pipeline, findings, scoring)
- Assessment templates (lifted from legacy)
- All document assessment API routes

### Reference files for Phase 7:
- `docs/reference/legacy_document_assessment_service.py`
- `docs/reference/legacy_document_templates.py`

---

## Phase 8 — Remote Collector Agent

**Gate:** Agent registers, receives mTLS certificate. Agent executes scan,
results in server DB. Heartbeat received and tracked.

### What Phase 8 delivers:
- `packages/recon-agent/` — proper packaged agent (no code duplication)
- Agent uses `packages/recon-collectors/` shared package
- Registration flow (CSR → signed cert → mTLS credential)
- Heartbeat, result reporting, config pull
- All collector API routes (`/api/v1/collector/*`)
- Alembic migration: `collector_heartbeats`, `collector_scan_reports`
- mTLS enforcement on nginx port 8443 (ssl_verify_client on)

### Reference files for Phase 8:
- `docs/reference/legacy_remote_collector_daemon.py`
- `docs/reference/legacy_remote_collector_client.py`

---

## Phase 9 — Full UI (React, all pages)

**Gate:** All pages render with real API data. `useTerm('project')` returns
"Project". Auth flow (local + OAuth) works end-to-end.

### What Phase 9 delivers:
- Full React 18 + TypeScript + Vite + Tailwind + shadcn/ui frontend
- All pages: Dashboard, Projects, Scans, Reports, Inventory, Assets,
  Certificates, Collectors, Policies, RBAC, Secret Stores, DPOD Dashboard,
  Document Assessment, Settings, Audit
- TanStack Query + generated TypeScript client from /openapi.json
- ProductContext + useTerm() + useFeatureFlag() throughout
- IAuthProvider (LocalAuthProvider + MsalAuthProvider for OAuth)
- Report viewer components (PKI, PQC with full client-side crypto)
- Station Hex design system throughout
- Replaces nginx placeholder currently serving on port 3000

---

## Phase 10 — Hardening

**Gate:** Penetration test checklist executed. All findings resolved.

### What Phase 10 delivers:
- Docker Secrets API (closes docker inspect credential exposure)
- Rate limiting (nginx or FastAPI middleware)
- Input sanitisation middleware
- Prometheus metrics endpoint
- OpenTelemetry tracing
- Let's Encrypt TLS (replaces self-signed)
- Security headers (HSTS, CSP, X-Frame-Options)
- No bare except blocks anywhere (final audit pass)
- SESSION_COOKIE_SECURE enforced

---

## Architectural Questions Pending

None.

---

## Known Tech Debt

1. **`test_product_config.py` terminology key** — Phase 1 test still checks for
   terminology key `"engagement"`. Update to `"project"` in Phase 3 alongside
   updating `routers/product.py` default terminology dict.

2. **OAuth routes stubbed** — `GET /api/v1/auth/oauth/login/` returns 404.
   Full OAuth flow (Azure Entra ID, Okta) implemented in Phase 9.

3. **mTLS not enforced** — nginx port 8443 accepts connections without client
   cert verification. `ssl_verify_client on` added in Phase 8.

4. **Worker job handlers are stubs** — SchedulerService dispatches correctly
   but all job_type handlers raise ValueError("Unknown job type").
   Real handlers added in Phase 3 (scan_execute) and Phase 6 (report_generate).

5. **HS256 JWT fallback** — No RSA key files configured; auth uses HS256
   with RECON_SECRET_KEY. Generate RS256 key pair and configure paths before
   production deployment.

---

## Session Notes

### 2026-04-01 — Architecture + planning
- ARCHITECTURE.md v1.0, CLAUDE.md, phase prompt files produced
- Full codebase inventory analysed

### 2026-04-01 — Phase 1 execution (commit 3cbe419)
- All 10 prompts, 17 tests passing, stack healthy

### 2026-04-01 — Naming decision
- Construct "engagement" renamed to "project" throughout
- ARCHITECTURE.md v1.1 patch applied, CLAUDE.md v1.1 replaced

### 2026-04-01 — Phase 2A execution
- Prompts 2A.1–2A.4 complete. Alembic 0001. 45 tests.
- Schema rename migration 0002 (2A.5). All project_* names live in DB.

### 2026-04-01 — Phase 2B execution (commit 240e8f0)
- Prompts 2B.1–2B.6 complete. Alembic 0003. 75 tests.
- JWT auth, bootstrap, RBAC, CertificateService, SchedulerService,
  project routes, PQCService, ScoringService all working.
- Gate: login=200, no-token=403, with-token=200, db_connected=true,
  internal CA active, worker clean, 75/75 tests.
