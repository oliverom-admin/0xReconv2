# 0xRecon — Claude Code Session Opener
# Read this file at the start of every Claude Code session.
# ================================================================================

## What This Project Is

0xRecon is a cryptographic asset discovery, assessment, and reporting platform.
It is one product in the Station Hex 0x suite. The same codebase can present
as a separately branded product (CAIP) by changing the PRODUCT_ID environment
variable. The backend knows nothing about product identity.

This project is being **rebuilt from scratch** using a containerised architecture.
The original 0xRecon codebase (Flask, SQLite, no containers) exists as reference
only. Do not copy code from the original without explicit instruction.

## Architect / Developer Separation

**Claude Chat (separate session) = Architect.**
All technology decisions, schema design, API design, phase sequencing, and
architectural changes are made in Claude Chat and recorded in ARCHITECTURE.md.

**Claude Code (this session) = Developer.**
Claude Code implements what the architecture specifies. If something in the
architecture is ambiguous or appears incorrect, stop and flag it — do not
resolve architectural questions autonomously.

## Document Locations

```
ARCHITECTURE.md              Master architecture document — read first, always
CLAUDE.md                    This file — session opener
docs/phases/                 Phase prompt files (PHASE_1.md, PHASE_2.md, etc.)
docs/decisions/              Architectural decision records
PHASE_STATUS.md              Current phase, prompt status, last verified state
```

## Current State

```
Current phase:    Phase 1 — Scaffold
Current prompt:   Not started
Overall status:   Project initialised. No code written yet.
Last session:     2026-04-01
```

Update PHASE_STATUS.md before ending every session.

## Repository Structure (Target)

```
packages/
├── recon-api/          FastAPI application (port 8000)
├── recon-worker/       Background worker (no port)
├── recon-core/         Shared library (API + worker dependency)
└── recon-ui/           React 18 + Vite (port 3000)
docker-compose.yml
docker-compose.prod.yml
nginx/
migrations/             Alembic migrations (inside recon-api)
docs/
ARCHITECTURE.md
CLAUDE.md
PHASE_STATUS.md
```

## Technology Stack (Non-Negotiable)

```
Web framework:    FastAPI (not Flask)
Database:         PostgreSQL 16 (not SQLite)
DB driver:        asyncpg (async)
Query layer:      SQLAlchemy Core async (no ORM)
Migrations:       Alembic — directory: migrations/ (not alembic/)
PKCS#11:          python-pkcs11 (not PyKCS11)
HTTP client:      httpx (not requests)
Validation:       Pydantic v2
Auth:             python-jose[cryptography] for JWT, bcrypt for passwords
Frontend:         React 18 + TypeScript strict + Vite + Tailwind + shadcn/ui
Logging:          structlog (structured JSON)
```

## Naming Conventions

```
Python packages:  recon_* (no caip anywhere)
DB tables:        snake_case, no prefix
API routes:       /api/v1/{resource}/ — trailing slash, lowercase, plural
Environment vars: RECON_* prefix
Docker services:  recon-* prefix
Log namespace:    recon.*
```

The word "caip" must not appear in source code, configuration, database
values, log output, variable names, class names, or comments.
The only exception: three DOM element IDs in HTML report output
(caip-encrypted-blobs, caip-encryption-metadata, caip-signing-result)
which are retained for backward compatibility with distributed reports.

## Critical Patterns

**Docker Compose:**
Always: docker compose -p 0xrecon -f docker-compose.yml -f docker-compose.prod.yml
Never omit -p 0xrecon.

**Alembic:**
Directory: migrations/ not alembic/ (avoids package shadowing).
Run inside recon-api container, not on host.
Auto-runs on API container startup via entrypoint.

**Trailing slash:**
All API routes end with /. FastAPI router: redirect_slashes=False.

**Async throughout:**
All service methods are async def.
All PKCS#11 calls wrapped in asyncio.to_thread().
All external HTTP calls use httpx.AsyncClient.

**API-driven UI:**
Frontend renders API responses. Zero business logic in frontend.
No hardcoded role checks in React components.

**Engagement scoping:**
Every DB query for engagement data includes engagement_id filter.
Middleware validates engagement access before any service call.

**Vault references:**
Private keys never in database. DB stores vault key name strings only.

**UUID primary keys:**
All tables use UUID PKs generated server-side (gen_random_uuid()).
No AUTOINCREMENT integer IDs exposed via API.

## Phase Execution Rules

1. Read the phase prompt file before writing any code
2. Work through prompts in order — no skipping
3. After each prompt, run the verification gate commands before proceeding
4. If a gate fails, fix it before moving to the next prompt
5. Update PHASE_STATUS.md before ending the session
6. If an architectural decision is required, stop and document the question
   in PHASE_STATUS.md — do not resolve it autonomously

## What the Original 0xRecon Codebase Contains (Reference Only)

The following capabilities must all be implemented in the new codebase.
They are reference for logic, not for code copying:

- Scan pipeline: collectors → policy engine → scoring → report
- Collectors: Luna HSM, Azure KV, EJBCA, TLS, CRL, File Share
- PQC detection (OID matching + name patterns)
- Policy engine (v2.0 rule schema, simple/expression/temporal conditions)
- Scoring and aggregation engine (weighted scores, health index, A+–F grade)
- CBOM export (CycloneDX 1.6+ JSON)
- Asset enrichment and context (business context per asset)
- Environment inference (production/staging/dev classification)
- Relationship mapping (cert-to-key, cert-to-cert)
- Inventory service (CLM, sync, promote to inventory)
- Lifecycle management (renewal thresholds, rotation intervals)
- Engagement model (multi-engagement, all data scoped)
- Per-engagement PKI (internal CA, engagement CA, signing certs, viewer certs)
- Signed and encrypted HTML reports (AES-256-GCM + RSA-OAEP + RSA-PSS)
- Interactive HTML report viewer with client-side decryption
- DOCX executive reports (python-docx)
- PDF reports (reportlab)
- Financial impact calculator
- Scan reassessments (re-run historical scan through new policy)
- Scan aggregations (merge multiple scan results)
- Secret management (UnifiedVault + multi-backend resolution)
- Auth: local credentials, OAuth (Azure Entra, Okta), mTLS for collectors
- RBAC (system-admin, engagement-admin, analyst, viewer)
- Remote collector agent (edge deployment, heartbeat, mTLS)
- Background scheduler (inventory sync, lifecycle checks)
- Document assessment (upload + evaluate against templates)
- DPOD dashboard (Luna HSM partition/key/host view)
- Product identity layer (white-label via PRODUCT_ID env var)

## Design System

```
Background:    #0D1B2A
Card bg:       #1f2937
Accent:        #00FF41 (terminal green)
Border:        rgba(0, 255, 65, 0.25)
Secondary:     #FFB800 (amber)
Font heading:  Orbitron
Font body:     Share Tech Mono
```
