# 0xRecon — Phase 1: Repository Scaffold and Container Stack
# Phase Prompt File for Claude Code
# Version: 1.0 | April 2026
#
# READ BEFORE STARTING:
#   1. Read ARCHITECTURE.md in full
#   2. Read CLAUDE.md in full
#   3. Read PHASE_STATUS.md
#   4. Work through prompts in strict order — no skipping
#   5. After each prompt, run ALL verification commands before proceeding
#   6. On any gate failure: fix before advancing, never bypass
#   7. Update PHASE_STATUS.md before ending every session
#
# CONTEXT CONTINUITY:
#   If resuming from a previous session, read PHASE_STATUS.md first.
#   It records exactly where you stopped and the last verified state.
#   Never assume — verify. Run the relevant gate commands to confirm
#   current state matches the recorded state before continuing.
#
# ================================================================================

---

## Phase 1 Objective

Produce a fully working, containerised repository scaffold. At the end of this
phase, the repository structure is in place, all containers start cleanly, and
the health endpoint returns 200 with a confirmed database connection.

No business logic is implemented in this phase. This phase is purely
infrastructure: directories, Docker, nginx, Alembic bootstrap, and a minimal
FastAPI application that proves the stack is wired together correctly.

**Phase 1 gate (must pass before Phase 2 begins):**
```
curl -s http://localhost:8000/api/v1/health | python3 -m json.tool
```
Must return HTTP 200 with body containing `"db_connected": true`.

---

## Context Survival Rules

These rules ensure Claude Code can resume correctly across session boundaries,
context compaction events, and chat restarts.

**Rule 1 — Always read before writing.**
At the start of every session (or after any context compaction), read:
- ARCHITECTURE.md
- CLAUDE.md
- PHASE_STATUS.md
Do not rely on conversation history. These files are ground truth.

**Rule 2 — PHASE_STATUS.md is the session ledger.**
Every time a prompt is completed and its gate passes, update PHASE_STATUS.md:
- Set `Current prompt` to the just-completed prompt number
- Set `Last verified` to the current datetime
- Record the exact gate commands run and their output summary
- Record any decisions made or deviations from the plan

**Rule 3 — Verify state, never assume it.**
When resuming, always run the gate command for the last recorded completed
prompt before continuing to the next prompt. Container state, filesystem state,
and database state can all drift between sessions.

**Rule 4 — Flag, do not resolve, architectural questions.**
If you encounter something ambiguous in this phase document or in
ARCHITECTURE.md, write it to the "Architectural Questions Pending" section of
PHASE_STATUS.md and stop. Do not invent a resolution. The architect resolves
it in the next Claude Chat session.

**Rule 5 — Never modify ARCHITECTURE.md or CLAUDE.md.**
These are read-only reference documents for Claude Code. Only the architect
(Claude Chat) updates them.

---

## Pre-Phase Checklist

Before writing a single line of code, confirm all of the following:

- [ ] You have read ARCHITECTURE.md Parts 1–4, 11 (Phase 1), 12, 13 in full
- [ ] You have read CLAUDE.md in full
- [ ] PHASE_STATUS.md shows "Phase 1 — Not started" (or the last completed prompt if resuming)
- [ ] Docker Desktop is running (Windows host — confirm with `docker info`)
- [ ] No existing containers named recon-* are running (`docker ps --filter name=recon`)
- [ ] The working directory is the project root (contains ARCHITECTURE.md)

---

## Prompt 1.1 — Repository Directory Structure

### Objective
Create the complete directory skeleton for the monorepo. No files contain any
real code yet — only the directories and required stub files to make the
structure valid.

### Instructions

Create the following directory structure exactly. Do not deviate from these
names — they are referenced in ARCHITECTURE.md and must be consistent
throughout the entire build.

```
0xrecon/                          ← project root
├── packages/
│   ├── recon-api/                ← FastAPI application
│   │   ├── recon_api/            ← Python package
│   │   │   └── __init__.py
│   │   ├── tests/
│   │   │   └── __init__.py
│   │   ├── Dockerfile
│   │   └── pyproject.toml
│   ├── recon-worker/             ← Worker entrypoint (uses recon-api image)
│   │   └── README.md
│   ├── recon-core/               ← Shared library (API + worker dependency)
│   │   ├── recon_core/
│   │   │   └── __init__.py
│   │   └── pyproject.toml
│   ├── recon-collectors/         ← Collector package (all 6 collectors)
│   │   ├── recon_collectors/
│   │   │   └── __init__.py
│   │   └── pyproject.toml
│   ├── recon-agent/              ← Remote collector agent
│   │   ├── recon_agent/
│   │   │   └── __init__.py
│   │   └── pyproject.toml
│   └── recon-ui/                 ← React 18 + Vite frontend
│       └── README.md
├── migrations/                   ← Alembic migrations (run from recon-api container)
│   ├── versions/
│   ├── env.py
│   ├── script.py.mako
│   └── alembic.ini
├── nginx/
│   ├── nginx.conf
│   └── certs/
│       └── .gitkeep
├── docs/
│   ├── phases/                   ← Phase prompt files live here
│   │   └── PHASE_1.md            ← Copy this file here
│   └── decisions/                ← ADR files
├── scripts/
│   ├── dev-up.sh
│   ├── dev-down.sh
│   └── run-migrations.sh
├── docker-compose.yml
├── docker-compose.prod.yml
├── .env.example
├── .env                          ← DO NOT COMMIT — copy of .env.example with dev values
├── .gitignore
├── ARCHITECTURE.md
├── CLAUDE.md
└── PHASE_STATUS.md
```

### File Contents

**`.gitignore`**
```
# Environment
.env
.env.local
*.env

# Python
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
*.egg-info/
dist/
build/
.venv/
venv/
*.egg

# Node
node_modules/
dist/
.next/

# Docker
*.log

# Certs (never commit real certs)
nginx/certs/*.pem
nginx/certs/*.crt
nginx/certs/*.key
nginx/certs/*.p12
!nginx/certs/.gitkeep

# Reports volume
reports/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Alembic (never commit auto-generated versions without review)
# versions/ is NOT ignored — migrations are committed
```

**`packages/recon-worker/README.md`**
```markdown
# recon-worker

The worker runs using the same Docker image as recon-api.
It uses a different CMD entrypoint that starts the SchedulerService loop.

There is no separate Dockerfile for the worker — see the recon-api Dockerfile
and the worker service definition in docker-compose.yml.

The worker is defined as a separate service in docker-compose.yml:
  command: python -m recon_api.worker.entrypoint
```

**`packages/recon-ui/README.md`**
```markdown
# recon-ui

React 18 + TypeScript + Vite frontend.
Bootstrapped in Phase 9. This directory is a placeholder in Phase 1.

The recon-ui container serves the compiled React app via nginx.
Product identity is fetched from GET /api/v1/product/config at startup.
No business logic lives in the frontend.
```

### Verification Gate 1.1

```bash
# Verify directory structure exists
find . -type d | sort | head -60

# Verify key stub files exist
test -f packages/recon-api/recon_api/__init__.py && echo "PASS: recon_api package"
test -f packages/recon-core/recon_core/__init__.py && echo "PASS: recon_core package"
test -f packages/recon-collectors/recon_collectors/__init__.py && echo "PASS: recon_collectors package"
test -f packages/recon-agent/recon_agent/__init__.py && echo "PASS: recon_agent package"
test -f migrations/env.py && echo "PASS: alembic env.py"
test -f .gitignore && echo "PASS: .gitignore"
```

All checks must output PASS before proceeding.

**Update PHASE_STATUS.md: Set `Current prompt: 1.1 complete`**

---

## Prompt 1.2 — Environment Configuration

### Objective
Create the `.env.example` file documenting all required environment variables,
and a `.env` file with safe development values. No real credentials anywhere.

### Instructions

**`.env.example`**
```bash
# =============================================================================
# 0xRecon — Environment Configuration
# Copy to .env and fill in values for your environment.
# NEVER commit .env to version control.
# =============================================================================

# --- Application ---
RECON_ENV=development
RECON_DEBUG=true
RECON_SECRET_KEY=CHANGE_ME_generate_with_secrets.token_hex_32
RECON_ALLOWED_ORIGINS=http://localhost:3000,https://app.recon.example.com

# --- Database ---
RECON_DATABASE_URL=postgresql+asyncpg://recon:recon_dev_password@recon-postgres:5432/recon
RECON_DATABASE_URL_SYNC=postgresql+psycopg2://recon:recon_dev_password@recon-postgres:5432/recon

# --- PostgreSQL Container ---
POSTGRES_DB=recon
POSTGRES_USER=recon
POSTGRES_PASSWORD=recon_dev_password

# --- JWT ---
# Generate with: openssl genrsa -out jwt_private.pem 2048
# and: openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem
RECON_JWT_PRIVATE_KEY_PATH=/run/secrets/jwt_private_key
RECON_JWT_PUBLIC_KEY_PATH=/run/secrets/jwt_public_key
RECON_JWT_ALGORITHM=RS256
RECON_JWT_EXPIRY_HOURS=8

# --- Vault ---
# Master password for the local AES-256-GCM vault file
RECON_VAULT_PATH=/app/data/vault.enc
RECON_VAULT_MASTER_PASSWORD=CHANGE_ME_min_32_chars_dev_only

# --- Product Identity ---
PRODUCT_ID=0xrecon
PRODUCT_NAME=0xRecon
PRODUCT_SHORT_NAME=0xRecon
PRODUCT_LOGO_PATH=/static/0xrecon/logo.svg
PRODUCT_FAVICON_PATH=/static/0xrecon/favicon.ico
PRODUCT_ACCENT_COLOR=#00FF41
PRODUCT_TERMINOLOGY_JSON={}
PRODUCT_FEATURE_FLAGS_JSON={"show_dpod_dashboard": true, "show_pqc_migration": true, "show_document_assessment": true}

# --- Azure Key Vault (optional — leave blank if not used) ---
AZURE_TENANT_ID=
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=
AZURE_KEY_VAULT_URL=

# --- EJBCA (optional — leave blank if not used) ---
EJBCA_BASE_URL=
EJBCA_CLIENT_CERT_PATH=
EJBCA_CLIENT_KEY_PATH=

# --- Collector API (mTLS port) ---
RECON_COLLECTOR_API_PORT=8443
```

**`.env`** (development values — never commit)
```bash
RECON_ENV=development
RECON_DEBUG=true
RECON_SECRET_KEY=dev_secret_key_not_for_production_use_only
RECON_ALLOWED_ORIGINS=http://localhost:3000

RECON_DATABASE_URL=postgresql+asyncpg://recon:recon_dev_password@recon-postgres:5432/recon
RECON_DATABASE_URL_SYNC=postgresql+psycopg2://recon:recon_dev_password@recon-postgres:5432/recon

POSTGRES_DB=recon
POSTGRES_USER=recon
POSTGRES_PASSWORD=recon_dev_password

RECON_JWT_ALGORITHM=RS256
RECON_JWT_EXPIRY_HOURS=8

RECON_VAULT_PATH=/app/data/vault.enc
RECON_VAULT_MASTER_PASSWORD=dev_vault_password_min_32_chars_here

PRODUCT_ID=0xrecon
PRODUCT_NAME=0xRecon
PRODUCT_SHORT_NAME=0xRecon
PRODUCT_LOGO_PATH=/static/0xrecon/logo.svg
PRODUCT_FAVICON_PATH=/static/0xrecon/favicon.ico
PRODUCT_ACCENT_COLOR=#00FF41
PRODUCT_TERMINOLOGY_JSON={}
PRODUCT_FEATURE_FLAGS_JSON={"show_dpod_dashboard": true, "show_pqc_migration": true, "show_document_assessment": true}
```

### Verification Gate 1.2

```bash
# Both files exist
test -f .env.example && echo "PASS: .env.example"
test -f .env && echo "PASS: .env"

# .env is in .gitignore
grep -q "^\.env$" .gitignore && echo "PASS: .env in .gitignore"

# .env.example is NOT in .gitignore (it should be committed)
grep -q "^\.env\.example$" .gitignore && echo "FAIL: .env.example is in .gitignore" || echo "PASS: .env.example not in .gitignore"

# No real secrets in .env.example (check for placeholder pattern)
grep -q "CHANGE_ME" .env.example && echo "PASS: .env.example uses placeholders"
```

**Update PHASE_STATUS.md: Set `Current prompt: 1.2 complete`**

---

## Prompt 1.3 — Python Package Manifests

### Objective
Create `pyproject.toml` files for all Python packages. These define
dependencies, package metadata, and build configuration. No installation
or virtual environments yet — just the manifest files.

### Instructions

**`packages/recon-api/pyproject.toml`**
```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "recon-api"
version = "1.0.0"
description = "0xRecon API server"
requires-python = ">=3.11"
dependencies = [
    # Web framework
    "fastapi==0.115.6",
    "uvicorn[standard]==0.32.1",
    "pydantic==2.10.3",
    "pydantic-settings==2.6.1",

    # Database
    "sqlalchemy[asyncio]==2.0.36",
    "asyncpg==0.30.0",
    "alembic==1.14.0",
    "psycopg2-binary==2.9.10",   # Alembic sync runner only

    # Auth
    "python-jose[cryptography]==3.3.0",
    "bcrypt==4.2.1",
    "passlib[bcrypt]==1.7.4",

    # HTTP client
    "httpx==0.28.1",

    # Crypto
    "cryptography==43.0.3",

    # Azure (optional connectors)
    "azure-keyvault-keys==4.9.0",
    "azure-keyvault-secrets==4.8.0",
    "azure-identity==1.19.0",

    # Report generation
    "python-docx==1.1.2",
    "reportlab==4.2.5",
    "jinja2==3.1.4",

    # Utilities
    "python-dotenv==1.0.1",
    "python-multipart==0.0.20",
    "structlog==24.4.0",

    # Shared packages (installed as local editable)
    "recon-core",
    "recon-collectors",
]

[project.optional-dependencies]
dev = [
    "pytest==8.3.4",
    "pytest-asyncio==0.24.0",
    "pytest-cov==6.0.0",
    "httpx==0.28.1",
    "anyio==4.7.0",
]

[tool.hatch.build.targets.wheel]
packages = ["recon_api"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]

[tool.ruff]
line-length = 100
target-version = "py311"
```

**`packages/recon-core/pyproject.toml`**
```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "recon-core"
version = "1.0.0"
description = "0xRecon shared core library"
requires-python = ">=3.11"
dependencies = [
    "pydantic==2.10.3",
    "cryptography==43.0.3",
    "structlog==24.4.0",
]

[tool.hatch.build.targets.wheel]
packages = ["recon_core"]
```

**`packages/recon-collectors/pyproject.toml`**
```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "recon-collectors"
version = "1.0.0"
description = "0xRecon collector package (all discovery collectors)"
requires-python = ">=3.11"
dependencies = [
    "pydantic==2.10.3",
    "httpx==0.28.1",
    "cryptography==43.0.3",
    "pyOpenSSL==24.3.0",
    "structlog==24.4.0",
    "recon-core",
    # python-pkcs11 is optional — required only on nodes with HSM
    # "python-pkcs11==0.9.0",
]

[tool.hatch.build.targets.wheel]
packages = ["recon_collectors"]
```

**`packages/recon-agent/pyproject.toml`**
```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "recon-agent"
version = "1.0.0"
description = "0xRecon remote collector agent"
requires-python = ">=3.11"
dependencies = [
    "httpx==0.28.1",
    "cryptography==43.0.3",
    "structlog==24.4.0",
    "recon-collectors",
    "recon-core",
]

[tool.hatch.build.targets.wheel]
packages = ["recon_agent"]
```

### Verification Gate 1.3

```bash
# All pyproject.toml files exist
test -f packages/recon-api/pyproject.toml && echo "PASS: recon-api pyproject.toml"
test -f packages/recon-core/pyproject.toml && echo "PASS: recon-core pyproject.toml"
test -f packages/recon-collectors/pyproject.toml && echo "PASS: recon-collectors pyproject.toml"
test -f packages/recon-agent/pyproject.toml && echo "PASS: recon-agent pyproject.toml"

# FastAPI version pinned correctly
grep -q "fastapi==0.115.6" packages/recon-api/pyproject.toml && echo "PASS: fastapi pinned"

# No PyKCS11 anywhere — only python-pkcs11 is permitted
grep -r "PyKCS11" packages/ && echo "FAIL: PyKCS11 found" || echo "PASS: no PyKCS11"

# No Flask anywhere
grep -r "flask" packages/ && echo "FAIL: flask found" || echo "PASS: no flask"

# No requests library anywhere (httpx only)
grep -r '"requests"' packages/ && echo "FAIL: requests found" || echo "PASS: no requests"
```

**Update PHASE_STATUS.md: Set `Current prompt: 1.3 complete`**

---

## Prompt 1.4 — FastAPI Application Skeleton

### Objective
Create a minimal but structurally complete FastAPI application. This implements:
- Application factory with correct middleware registration order
- The `/api/v1/health` endpoint (no auth required)
- The `/api/v1/product/config` endpoint (no auth required)  
- Application settings via Pydantic Settings
- Structured logging setup
- A lifespan context manager (startup/shutdown hooks — for DB pool in Phase 2)

No database connection yet. The health endpoint returns `db_connected: false`
until Phase 2 wires up the connection pool.

### Instructions

**`packages/recon-api/recon_api/__init__.py`**
```python
"""0xRecon API package."""
__version__ = "1.0.0"
```

**`packages/recon-api/recon_api/config.py`**
```python
"""Application configuration via Pydantic Settings."""
from __future__ import annotations

import json
from functools import lru_cache
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All application configuration. Loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="RECON_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    env: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    secret_key: str = "change_me"
    allowed_origins: list[str] = ["http://localhost:3000"]

    # Database
    database_url: str = ""
    database_url_sync: str = ""
    database_pool_min: int = 2
    database_pool_max: int = 10

    # JWT
    jwt_algorithm: str = "RS256"
    jwt_expiry_hours: int = 8
    jwt_private_key_path: str = ""
    jwt_public_key_path: str = ""

    # Vault
    vault_path: str = "/app/data/vault.enc"
    vault_master_password: str = ""

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_origins(cls, v: str | list) -> list[str]:
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v


class ProductConfig(BaseSettings):
    """Product identity configuration. Never contains business logic."""

    model_config = SettingsConfigDict(
        env_prefix="PRODUCT_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    id: str = "0xrecon"
    name: str = "0xRecon"
    short_name: str = "0xRecon"
    logo_path: str = "/static/0xrecon/logo.svg"
    favicon_path: str = "/static/0xrecon/favicon.ico"
    accent_color: str = "#00FF41"
    terminology_json: str = "{}"
    feature_flags_json: str = (
        '{"show_dpod_dashboard": true, "show_pqc_migration": true, "show_document_assessment": true}'
    )

    @property
    def terminology(self) -> dict:
        try:
            return json.loads(self.terminology_json)
        except (json.JSONDecodeError, TypeError):
            return {}

    @property
    def feature_flags(self) -> dict:
        try:
            return json.loads(self.feature_flags_json)
        except (json.JSONDecodeError, TypeError):
            return {}


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()


@lru_cache
def get_product_config() -> ProductConfig:
    """Return cached product config instance."""
    return ProductConfig()
```

**`packages/recon-api/recon_api/logging_config.py`**
```python
"""Structured logging configuration using structlog."""
from __future__ import annotations

import logging
import sys

import structlog


def configure_logging(debug: bool = False) -> None:
    """Configure structlog for JSON output in production, console in dev."""
    log_level = logging.DEBUG if debug else logging.INFO

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    if debug:
        # Human-readable console output for development
        processors = shared_processors + [
            structlog.dev.ConsoleRenderer(),
        ]
    else:
        # JSON output for production
        processors = shared_processors + [
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )

    # Suppress noisy third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("asyncpg").setLevel(logging.WARNING)
```

**`packages/recon-api/recon_api/main.py`**
```python
"""FastAPI application factory for 0xRecon."""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from recon_api.config import get_settings
from recon_api.logging_config import configure_logging
from recon_api.routers import health, product

logger = structlog.get_logger("recon.main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan manager.
    
    Startup: initialise DB pool, warm caches.
    Shutdown: close DB pool, flush buffers.
    
    Phase 1: No DB pool yet. Logs startup/shutdown only.
    Phase 2: DB pool initialisation added here.
    """
    settings = get_settings()
    configure_logging(debug=settings.debug)

    logger.info(
        "recon_api_starting",
        env=settings.env,
        debug=settings.debug,
        version="1.0.0",
    )

    # Phase 2: await init_db_pool(settings.database_url)
    yield

    logger.info("recon_api_stopping")
    # Phase 2: await close_db_pool()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="0xRecon API",
        version="1.0.0",
        docs_url="/api/docs" if settings.debug else None,
        redoc_url="/api/redoc" if settings.debug else None,
        openapi_url="/openapi.json" if settings.debug else None,
        redirect_slashes=False,
        lifespan=lifespan,
    )

    # CORS — must be first middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Routers
    app.include_router(health.router, prefix="/api/v1")
    app.include_router(product.router, prefix="/api/v1")

    return app


# Application instance (used by uvicorn)
app = create_app()
```

**`packages/recon-api/recon_api/routers/__init__.py`**
```python
"""FastAPI routers package."""
```

**`packages/recon-api/recon_api/routers/health.py`**
```python
"""Health check endpoint. No auth required. Used by nginx, load balancers, and gate checks."""
from __future__ import annotations

import structlog
from fastapi import APIRouter

logger = structlog.get_logger("recon.health")

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check() -> dict:
    """
    Returns API health status.

    Phase 1: db_connected is always false (no DB pool yet).
    Phase 2: db_connected reflects actual asyncpg pool health.
    """
    # Phase 2: Replace with real DB ping via dependency injection
    db_connected = False

    status = "ok" if db_connected else "degraded"

    logger.debug("health_check", db_connected=db_connected, status=status)

    return {
        "status": status,
        "version": "1.0.0",
        "db_connected": db_connected,
    }
```

**`packages/recon-api/recon_api/routers/product.py`**
```python
"""Product identity configuration endpoint. No auth required. Public."""
from __future__ import annotations

from fastapi import APIRouter

from recon_api.config import get_product_config

router = APIRouter(tags=["product"])


@router.get("/product/config")
async def get_product_config_endpoint() -> dict:
    """
    Returns product identity configuration block.

    Public endpoint — no authentication required.
    The frontend fetches this once on startup to determine
    which brand (0xRecon or CAIP) to render.

    The backend is completely brand-agnostic. This endpoint
    returns what PRODUCT_* env vars dictate.
    """
    config = get_product_config()

    # Default terminology if none configured
    terminology = config.terminology or {
        "engagement": "Engagement",
        "collector": "Collector",
        "finding": "Finding",
        "scan": "Scan",
        "assessment": "Assessment",
    }

    return {
        "product_id": config.id,
        "product_name": config.name,
        "product_short_name": config.short_name,
        "logo_url": config.logo_path,
        "favicon_url": config.favicon_path,
        "accent_colour": config.accent_color,
        "terminology": terminology,
        "feature_flags": config.feature_flags,
    }
```

### Verification Gate 1.4

```bash
# All files exist
test -f packages/recon-api/recon_api/main.py && echo "PASS: main.py"
test -f packages/recon-api/recon_api/config.py && echo "PASS: config.py"
test -f packages/recon-api/recon_api/logging_config.py && echo "PASS: logging_config.py"
test -f packages/recon-api/recon_api/routers/health.py && echo "PASS: health router"
test -f packages/recon-api/recon_api/routers/product.py && echo "PASS: product router"

# No Flask imports anywhere in the new code
grep -r "from flask" packages/recon-api/recon_api/ && echo "FAIL: flask import found" || echo "PASS: no flask"

# No synchronous database calls (no psycopg2 in main application code — sync driver is for Alembic only)
grep -r "psycopg2" packages/recon-api/recon_api/ && echo "WARN: psycopg2 in application code — should only be in Alembic env.py" || echo "PASS: no psycopg2 in app code"

# redirect_slashes=False is set
grep -q "redirect_slashes=False" packages/recon-api/recon_api/main.py && echo "PASS: redirect_slashes=False"

# CAIP string does not appear in source (except allowed exceptions)
grep -rn "caip" packages/recon-api/recon_api/ | grep -v "caip-encrypted-blobs\|caip-encryption-metadata\|caip-signing-result" && echo "FAIL: caip string in source" || echo "PASS: no caip in source"
```

**Update PHASE_STATUS.md: Set `Current prompt: 1.4 complete`**

---

## Prompt 1.5 — Dockerfile (recon-api / recon-worker)

### Objective
Create the Dockerfile for the recon-api image. This same image is used for
both recon-api and recon-worker containers — they differ only by their CMD.

The Dockerfile must:
- Use Python 3.11 slim base
- Install all packages from pyproject.toml
- Install recon-core and recon-collectors as local editable packages
- Set a non-root user
- Copy the migrations directory
- Use a shell entrypoint script that auto-runs Alembic migrations on API startup

### Instructions

**`packages/recon-api/Dockerfile`**
```dockerfile
# =============================================================================
# 0xRecon — recon-api / recon-worker image
# Both services use this image. CMD in docker-compose.yml determines role.
# =============================================================================
FROM python:3.11-slim AS base

# Build-time metadata
LABEL org.opencontainers.image.title="0xRecon API"
LABEL org.opencontainers.image.version="1.0.0"

# System dependencies
# libpq-dev: required for psycopg2-binary (Alembic sync runner)
# build-essential: required for cryptography wheel build
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd --gid 1001 recon \
    && useradd --uid 1001 --gid recon --shell /bin/bash --create-home recon

# Working directory
WORKDIR /app

# =============================================================================
# Dependencies stage
# =============================================================================
FROM base AS deps

# Install shared packages first (recon-core, recon-collectors)
COPY packages/recon-core /app/packages/recon-core
COPY packages/recon-collectors /app/packages/recon-collectors

RUN pip install --no-cache-dir /app/packages/recon-core
RUN pip install --no-cache-dir /app/packages/recon-collectors

# Install recon-api dependencies
COPY packages/recon-api/pyproject.toml /app/packages/recon-api/pyproject.toml

# Install dependencies only (not the package itself yet)
RUN pip install --no-cache-dir \
    fastapi==0.115.6 \
    "uvicorn[standard]==0.32.1" \
    pydantic==2.10.3 \
    pydantic-settings==2.6.1 \
    "sqlalchemy[asyncio]==2.0.36" \
    asyncpg==0.30.0 \
    alembic==1.14.0 \
    psycopg2-binary==2.9.10 \
    "python-jose[cryptography]==3.3.0" \
    bcrypt==4.2.1 \
    "passlib[bcrypt]==1.7.4" \
    httpx==0.28.1 \
    cryptography==43.0.3 \
    python-docx==1.1.2 \
    "reportlab==4.2.5" \
    jinja2==3.1.4 \
    python-dotenv==1.0.1 \
    python-multipart==0.0.20 \
    structlog==24.4.0

# =============================================================================
# Application stage
# =============================================================================
FROM deps AS app

# Copy application code
COPY packages/recon-api/recon_api /app/recon_api

# Copy migrations (Alembic runs from /app)
COPY migrations /app/migrations

# Copy entrypoint scripts
COPY packages/recon-api/entrypoint.sh /app/entrypoint.sh
COPY packages/recon-api/entrypoint-worker.sh /app/entrypoint-worker.sh
RUN chmod +x /app/entrypoint.sh /app/entrypoint-worker.sh

# Data directory (vault, reports) — owned by recon user
RUN mkdir -p /app/data /app/reports && chown -R recon:recon /app/data /app/reports

# Switch to non-root user
USER recon

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Default CMD: API server
# Worker overrides this in docker-compose.yml
CMD ["/app/entrypoint.sh"]
```

**`packages/recon-api/entrypoint.sh`**
```bash
#!/bin/bash
# =============================================================================
# recon-api entrypoint
# Runs Alembic migrations then starts the API server.
# =============================================================================
set -e

echo "[entrypoint] Starting 0xRecon API..."

# Wait for PostgreSQL to be ready
echo "[entrypoint] Waiting for PostgreSQL..."
until python3 -c "
import asyncio, asyncpg, os, sys
async def check():
    try:
        conn = await asyncpg.connect(os.environ['RECON_DATABASE_URL'].replace('+asyncpg', ''))
        await conn.close()
        print('[entrypoint] PostgreSQL ready.')
    except Exception as e:
        sys.exit(1)
asyncio.run(check())
" 2>/dev/null; do
    echo "[entrypoint] PostgreSQL not ready, retrying in 2s..."
    sleep 2
done

# Run Alembic migrations
echo "[entrypoint] Running Alembic migrations..."
cd /app
alembic -c migrations/alembic.ini upgrade head
echo "[entrypoint] Migrations complete."

# Start API server
echo "[entrypoint] Starting uvicorn..."
exec uvicorn recon_api.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 4 \
    --log-level warning \
    --no-access-log
```

**`packages/recon-api/entrypoint-worker.sh`**
```bash
#!/bin/bash
# =============================================================================
# recon-worker entrypoint
# Waits for DB then starts the SchedulerService polling loop.
# Does NOT run migrations (API container owns that).
# =============================================================================
set -e

echo "[worker] Starting 0xRecon Worker..."

# Wait for PostgreSQL to be ready
echo "[worker] Waiting for PostgreSQL..."
until python3 -c "
import asyncio, asyncpg, os, sys
async def check():
    try:
        conn = await asyncpg.connect(os.environ['RECON_DATABASE_URL'].replace('+asyncpg', ''))
        await conn.close()
    except Exception:
        sys.exit(1)
asyncio.run(check())
" 2>/dev/null; do
    echo "[worker] PostgreSQL not ready, retrying in 2s..."
    sleep 2
done

# Wait for API to have completed migrations (poll health endpoint)
echo "[worker] Waiting for API to be healthy..."
until curl -sf http://recon-api:8000/api/v1/health > /dev/null 2>&1; do
    echo "[worker] API not healthy yet, retrying in 3s..."
    sleep 3
done
echo "[worker] API healthy."

# Start worker
echo "[worker] Starting scheduler loop..."
exec python3 -m recon_api.worker.entrypoint
```

**`packages/recon-api/recon_api/worker/__init__.py`**
```python
"""Worker package. Runs as the recon-worker container entrypoint."""
```

**`packages/recon-api/recon_api/worker/entrypoint.py`**
```python
"""
Worker entrypoint. Polls job_queue and executes jobs.

Phase 1: Minimal stub that confirms the worker starts and loops cleanly.
Phase 2: SchedulerService with real job_queue polling added here.
"""
from __future__ import annotations

import asyncio
import signal

import structlog

from recon_api.config import get_settings
from recon_api.logging_config import configure_logging

logger = structlog.get_logger("recon.worker")


async def main() -> None:
    settings = get_settings()
    configure_logging(debug=settings.debug)

    logger.info("recon_worker_starting", version="1.0.0", env=settings.env)

    # Graceful shutdown
    shutdown_event = asyncio.Event()

    def _handle_signal(sig: int, frame: object) -> None:
        logger.info("recon_worker_shutdown_signal", signal=sig)
        shutdown_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    # Phase 2: Replace with SchedulerService.run(shutdown_event)
    logger.info("recon_worker_polling_loop_start")
    poll_count = 0
    while not shutdown_event.is_set():
        poll_count += 1
        logger.debug("recon_worker_poll", poll_count=poll_count)
        # Phase 2: job = await job_queue.next_pending()
        # Phase 2: if job: await executor.execute(job)
        await asyncio.sleep(60)  # 60-second poll interval

    logger.info("recon_worker_stopped")


if __name__ == "__main__":
    asyncio.run(main())
```

### Verification Gate 1.5

```bash
# Entrypoint scripts are executable
test -x packages/recon-api/entrypoint.sh && echo "PASS: entrypoint.sh executable"
test -x packages/recon-api/entrypoint-worker.sh && echo "PASS: entrypoint-worker.sh executable"

# Dockerfile exists
test -f packages/recon-api/Dockerfile && echo "PASS: Dockerfile"

# Worker stub exists
test -f packages/recon-api/recon_api/worker/entrypoint.py && echo "PASS: worker entrypoint"

# Non-root user is set
grep -q "USER recon" packages/recon-api/Dockerfile && echo "PASS: non-root user"

# Healthcheck is defined
grep -q "HEALTHCHECK" packages/recon-api/Dockerfile && echo "PASS: healthcheck defined"

# No Flask in Dockerfile
grep -q "flask" packages/recon-api/Dockerfile && echo "FAIL: flask in Dockerfile" || echo "PASS: no flask"
```

**Update PHASE_STATUS.md: Set `Current prompt: 1.5 complete`**

---

## Prompt 1.6 — Alembic Configuration

### Objective
Configure Alembic for async PostgreSQL. Create the `migrations/` directory
structure with a working `env.py` that uses asyncpg and SQLAlchemy Core async.
Create an empty initial migration.

### Instructions

**`migrations/alembic.ini`**
```ini
# Alembic configuration for 0xRecon
# Run with: alembic -c migrations/alembic.ini upgrade head
# Always run inside the recon-api container, never on the host.

[alembic]
script_location = migrations
prepend_sys_path = .

# Version filename format
file_template = %%(year)d%%(month).2d%%(day).2d_%%(hour).2d%%(minute).2d_%%(rev)s_%%(slug)s

# Truncate long slug
truncate_slug_length = 40

# Do not use the default alembic/ directory (avoids package shadowing)
# Configured in docker-compose.yml via ALEMBIC_CONFIG env var

[post_write_hooks]
# No post-write hooks in Phase 1

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
```

**`migrations/env.py`**
```python
"""
Alembic migration environment for 0xRecon.

Uses asyncpg (async) for migrations. This file is run by Alembic
inside the recon-api container where DATABASE_URL is set.

IMPORTANT: The directory is migrations/ NOT alembic/ — this avoids
shadowing the alembic package itself.
"""
from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

# Alembic config object
config = context.config

# Configure logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import all table metadata here (added per phase as tables are defined)
# Phase 2+: from recon_api.db.tables import metadata
# Phase 1: No tables yet
target_metadata = None

# Override sqlalchemy.url with RECON_DATABASE_URL_SYNC env var
# We use the sync psycopg2 URL for Alembic (it runs sync migration scripts)
# Note: Alembic migration runner is synchronous even in an async app
database_url = os.environ.get("RECON_DATABASE_URL_SYNC", "")
if not database_url:
    # Fallback: derive sync URL from async URL
    async_url = os.environ.get("RECON_DATABASE_URL", "")
    database_url = async_url.replace("postgresql+asyncpg://", "postgresql+psycopg2://")

config.set_main_option("sqlalchemy.url", database_url)


def run_migrations_offline() -> None:
    """Run migrations in offline mode (no DB connection — SQL script output)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Execute migration with active DB connection."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations using async engine (for future async migration support)."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in online mode (standard Alembic operation)."""
    # Use asyncio runner for async engine
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
```

**`migrations/script.py.mako`**
```mako
"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

# revision identifiers, used by Alembic.
revision: str = ${repr(up_revision)}
down_revision: Union[str, None] = ${repr(down_revision)}
branch_labels: Union[str, Sequence[str], None] = ${repr(branch_labels)}
depends_on: Union[str, Sequence[str], None] = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
```

Now create the initial empty migration file. Use the Alembic naming convention:

**`migrations/versions/20260401_0001_initial.py`**
```python
"""Initial migration — empty baseline.

Revision ID: 0001
Revises: 
Create Date: 2026-04-01 00:00:00.000000

Phase 1: No tables. Establishes the Alembic version baseline.
Phase 2: Real schema migrations added as new revision files.
"""
from __future__ import annotations

from typing import Sequence, Union

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Phase 1: Empty baseline migration.
    # PostgreSQL UUID extension — required by all future tables.
    from alembic import op
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')


def downgrade() -> None:
    # Note: We do NOT drop pgcrypto/uuid-ossp on downgrade — they may be
    # used by other schemas and are safe to leave.
    pass
```

### Verification Gate 1.6

```bash
# All Alembic files exist
test -f migrations/alembic.ini && echo "PASS: alembic.ini"
test -f migrations/env.py && echo "PASS: env.py"
test -f migrations/script.py.mako && echo "PASS: script.py.mako"
test -f migrations/versions/20260401_0001_initial.py && echo "PASS: initial migration"

# Directory is named migrations/ not alembic/
test -d migrations && echo "PASS: directory named migrations/"
test -d alembic && echo "FAIL: alembic/ directory should not exist" || echo "PASS: no alembic/ directory"

# env.py uses asyncpg URL handling
grep -q "asyncpg" migrations/env.py && echo "PASS: asyncpg in env.py"

# env.py uses RECON_DATABASE_URL_SYNC
grep -q "RECON_DATABASE_URL_SYNC" migrations/env.py && echo "PASS: sync URL env var"
```

**Update PHASE_STATUS.md: Set `Current prompt: 1.6 complete`**

---

## Prompt 1.7 — Docker Compose

### Objective
Create `docker-compose.yml` (development) and `docker-compose.prod.yml`
(production overrides). The development compose file must start all services,
with correct networking, named volumes, and health dependencies.

### Instructions

**`docker-compose.yml`**
```yaml
# =============================================================================
# 0xRecon — Development Docker Compose
# Usage: docker compose -p 0xrecon -f docker-compose.yml up
# ALWAYS use -p 0xrecon. Never omit the project name.
# =============================================================================

name: 0xrecon

services:

  recon-postgres:
    image: postgres:16-alpine
    container_name: recon-postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: ${POSTGRES_DB:-recon}
      POSTGRES_USER: ${POSTGRES_USER:-recon}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-recon_dev_password}
      PGDATA: /var/lib/postgresql/data/pgdata
    volumes:
      - recon-postgres-data:/var/lib/postgresql/data
    ports:
      - "5432:5432"   # Exposed in dev for direct access. Closed in prod overlay.
    networks:
      - recon-internal
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-recon} -d ${POSTGRES_DB:-recon}"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s

  recon-api:
    build:
      context: .
      dockerfile: packages/recon-api/Dockerfile
    container_name: recon-api
    restart: unless-stopped
    command: /app/entrypoint.sh
    environment:
      RECON_ENV: ${RECON_ENV:-development}
      RECON_DEBUG: ${RECON_DEBUG:-true}
      RECON_SECRET_KEY: ${RECON_SECRET_KEY}
      RECON_ALLOWED_ORIGINS: ${RECON_ALLOWED_ORIGINS:-http://localhost:3000}
      RECON_DATABASE_URL: ${RECON_DATABASE_URL}
      RECON_DATABASE_URL_SYNC: ${RECON_DATABASE_URL_SYNC}
      RECON_JWT_ALGORITHM: ${RECON_JWT_ALGORITHM:-RS256}
      RECON_JWT_EXPIRY_HOURS: ${RECON_JWT_EXPIRY_HOURS:-8}
      RECON_VAULT_PATH: ${RECON_VAULT_PATH:-/app/data/vault.enc}
      RECON_VAULT_MASTER_PASSWORD: ${RECON_VAULT_MASTER_PASSWORD}
      PRODUCT_ID: ${PRODUCT_ID:-0xrecon}
      PRODUCT_NAME: ${PRODUCT_NAME:-0xRecon}
      PRODUCT_SHORT_NAME: ${PRODUCT_SHORT_NAME:-0xRecon}
      PRODUCT_LOGO_PATH: ${PRODUCT_LOGO_PATH:-/static/0xrecon/logo.svg}
      PRODUCT_FAVICON_PATH: ${PRODUCT_FAVICON_PATH:-/static/0xrecon/favicon.ico}
      PRODUCT_ACCENT_COLOR: ${PRODUCT_ACCENT_COLOR:-#00FF41}
      PRODUCT_TERMINOLOGY_JSON: ${PRODUCT_TERMINOLOGY_JSON:-{}}
      PRODUCT_FEATURE_FLAGS_JSON: ${PRODUCT_FEATURE_FLAGS_JSON:-{"show_dpod_dashboard":true,"show_pqc_migration":true,"show_document_assessment":true}}
    volumes:
      - recon-data:/app/data
      - recon-reports:/app/reports
    ports:
      - "8000:8000"
    networks:
      - recon-internal
    depends_on:
      recon-postgres:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/v1/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s

  recon-worker:
    build:
      context: .
      dockerfile: packages/recon-api/Dockerfile
    container_name: recon-worker
    restart: unless-stopped
    command: /app/entrypoint-worker.sh
    environment:
      RECON_ENV: ${RECON_ENV:-development}
      RECON_DEBUG: ${RECON_DEBUG:-true}
      RECON_DATABASE_URL: ${RECON_DATABASE_URL}
      RECON_DATABASE_URL_SYNC: ${RECON_DATABASE_URL_SYNC}
      RECON_VAULT_PATH: ${RECON_VAULT_PATH:-/app/data/vault.enc}
      RECON_VAULT_MASTER_PASSWORD: ${RECON_VAULT_MASTER_PASSWORD}
      PRODUCT_ID: ${PRODUCT_ID:-0xrecon}
    volumes:
      - recon-data:/app/data
      - recon-reports:/app/reports
    networks:
      - recon-internal
    depends_on:
      recon-postgres:
        condition: service_healthy
      recon-api:
        condition: service_healthy

  recon-ui:
    # Phase 1: Nginx placeholder — React app built in Phase 9
    image: nginx:alpine
    container_name: recon-ui
    restart: unless-stopped
    volumes:
      - ./nginx/ui-placeholder:/usr/share/nginx/html:ro
    ports:
      - "3000:80"
    networks:
      - recon-internal

  nginx:
    image: nginx:alpine
    container_name: recon-nginx
    restart: unless-stopped
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/certs:/etc/nginx/certs:ro
    ports:
      - "443:443"
      - "8443:8443"
    networks:
      - recon-internal
    depends_on:
      - recon-api
      - recon-ui

volumes:
  recon-postgres-data:
    name: 0xrecon_postgres_data
  recon-data:
    name: 0xrecon_data
  recon-reports:
    name: 0xrecon_reports

networks:
  recon-internal:
    name: 0xrecon_internal
    driver: bridge
```

**`docker-compose.prod.yml`**
```yaml
# =============================================================================
# 0xRecon — Production Overrides
# Usage: docker compose -p 0xrecon -f docker-compose.yml -f docker-compose.prod.yml up
# =============================================================================

services:

  recon-postgres:
    ports: []   # No external port exposure in production

  recon-api:
    environment:
      RECON_ENV: production
      RECON_DEBUG: "false"
    # In production: use Docker Secrets or external secret injection
    # environment entries for secrets are omitted here — injected externally

  recon-worker:
    environment:
      RECON_ENV: production
      RECON_DEBUG: "false"

  nginx:
    volumes:
      - ./nginx/nginx.prod.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/certs:/etc/nginx/certs:ro   # Let's Encrypt certs mounted here
```

### Verification Gate 1.7

```bash
# Files exist
test -f docker-compose.yml && echo "PASS: docker-compose.yml"
test -f docker-compose.prod.yml && echo "PASS: docker-compose.prod.yml"

# Validate compose file syntax (requires Docker)
docker compose -p 0xrecon -f docker-compose.yml config --quiet && echo "PASS: docker-compose.yml valid"

# Project name is set in compose file
grep -q "^name: 0xrecon" docker-compose.yml && echo "PASS: project name set"

# postgres port is closed in prod overlay
grep -A5 "recon-postgres:" docker-compose.prod.yml | grep -q "ports: \[\]" && echo "PASS: postgres port closed in prod"

# All 5 services defined
grep -c "^  recon-" docker-compose.yml | grep -q "^5$" && echo "PASS: 5 services defined" || echo "INFO: check service count"
```

**Update PHASE_STATUS.md: Set `Current prompt: 1.7 complete`**

---

## Prompt 1.8 — nginx Configuration

### Objective
Create the nginx configuration for development. In Phase 1, nginx provides:
- Reverse proxy from port 443 to recon-api:8000 for /api/ routes
- Reverse proxy from port 443 to recon-ui:80 for all other routes
- Port 8443 stub for mTLS (not enforced in Phase 1 — mTLS in Phase 2)
- Self-signed TLS certificate generation script

No real mTLS enforcement yet. The collector port (8443) is stubbed.

### Instructions

Create a self-signed certificate generation script first:

**`scripts/gen-dev-certs.sh`**
```bash
#!/bin/bash
# =============================================================================
# Generate self-signed TLS certificates for development.
# Run ONCE before first docker compose up.
# DO NOT run in production — use Let's Encrypt or your PKI.
# =============================================================================
set -e

CERT_DIR="nginx/certs"
mkdir -p "$CERT_DIR"

echo "[gen-dev-certs] Generating self-signed dev TLS certificate..."

openssl req -x509 \
    -newkey rsa:4096 \
    -keyout "$CERT_DIR/dev.key" \
    -out "$CERT_DIR/dev.crt" \
    -days 365 \
    -nodes \
    -subj "/C=GB/ST=England/L=London/O=0xRecon Dev/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 "$CERT_DIR/dev.key"
chmod 644 "$CERT_DIR/dev.crt"

echo "[gen-dev-certs] Certificates written to $CERT_DIR/"
echo "[gen-dev-certs] dev.key (private — not committed)"
echo "[gen-dev-certs] dev.crt (self-signed)"
```

**`nginx/nginx.conf`**
```nginx
# =============================================================================
# 0xRecon — nginx development configuration
# TLS termination, reverse proxy, mTLS stub for collector port
# =============================================================================

worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /tmp/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent"';

    access_log /var/log/nginx/access.log main;
    sendfile on;
    keepalive_timeout 65;

    # Security headers (applied to all responses)
    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Upstream: recon-api
    upstream recon_api {
        server recon-api:8000;
        keepalive 32;
    }

    # Upstream: recon-ui
    upstream recon_ui {
        server recon-ui:80;
        keepalive 16;
    }

    # ==========================================================================
    # HTTPS — Dashboard and API (port 443)
    # ==========================================================================
    server {
        listen 443 ssl;
        server_name localhost;

        ssl_certificate     /etc/nginx/certs/dev.crt;
        ssl_certificate_key /etc/nginx/certs/dev.key;
        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_ciphers         HIGH:!aNULL:!MD5;
        ssl_session_cache   shared:SSL:10m;
        ssl_session_timeout 10m;

        client_max_body_size 50m;

        # API routes — proxy to FastAPI
        location /api/ {
            proxy_pass http://recon_api;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header Connection "";
            proxy_read_timeout 300;
            proxy_connect_timeout 10;
        }

        # OpenAPI docs (dev only)
        location /openapi.json {
            proxy_pass http://recon_api;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
        }

        # All other routes — proxy to React UI
        location / {
            proxy_pass http://recon_ui;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;

            # SPA fallback — serve index.html for client-side routes
            proxy_intercept_errors on;
            error_page 404 = @fallback;
        }

        location @fallback {
            proxy_pass http://recon_ui;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
        }
    }

    # ==========================================================================
    # Collector API — mTLS (port 8443)
    # Phase 1: SSL only, no client certificate verification yet
    # Phase 2: ssl_verify_client on with engagement CA chain
    # ==========================================================================
    server {
        listen 8443 ssl;
        server_name localhost;

        ssl_certificate     /etc/nginx/certs/dev.crt;
        ssl_certificate_key /etc/nginx/certs/dev.key;
        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_ciphers         HIGH:!aNULL:!MD5;

        # Phase 2: Enable mTLS
        # ssl_client_certificate /etc/nginx/certs/engagement-ca.crt;
        # ssl_verify_client on;
        # ssl_verify_depth 2;

        location /api/v1/collector/ {
            # Phase 2: proxy_set_header SSL-Client-Cert $ssl_client_cert;
            proxy_pass http://recon_api;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Reject all other routes on the collector port
        location / {
            return 404;
        }
    }

    # HTTP → HTTPS redirect
    server {
        listen 80;
        server_name localhost;
        return 301 https://$host$request_uri;
    }
}
```

Create the UI placeholder directory:

**`nginx/ui-placeholder/index.html`**
```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>0xRecon</title>
<style>
  body {
    background: #0D1B2A;
    color: #00FF41;
    font-family: 'Share Tech Mono', 'Courier New', monospace;
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100vh;
    margin: 0;
    text-align: center;
  }
  h1 { font-size: 2rem; margin-bottom: 0.5rem; }
  p  { color: #FFB800; }
</style>
</head>
<body>
  <div>
    <h1>0xRecon</h1>
    <p>UI placeholder — Phase 9</p>
    <p style="color:#00FF41;opacity:0.5;font-size:0.8rem">API: <a style="color:#00FF41" href="/api/v1/health">/api/v1/health</a></p>
  </div>
</body>
</html>
```

**`scripts/dev-up.sh`**
```bash
#!/bin/bash
# Start the development stack.
# Usage: ./scripts/dev-up.sh
set -e

# Generate dev certs if they don't exist
if [ ! -f "nginx/certs/dev.crt" ]; then
    echo "[dev-up] Generating dev TLS certificates..."
    bash scripts/gen-dev-certs.sh
fi

echo "[dev-up] Starting 0xRecon development stack..."
docker compose -p 0xrecon -f docker-compose.yml up --build "$@"
```

**`scripts/dev-down.sh`**
```bash
#!/bin/bash
# Stop the development stack.
# Usage: ./scripts/dev-down.sh [--volumes]
set -e

echo "[dev-down] Stopping 0xRecon development stack..."
docker compose -p 0xrecon -f docker-compose.yml down "$@"
```

**`scripts/run-migrations.sh`**
```bash
#!/bin/bash
# Run Alembic migrations inside the recon-api container.
# Usage: ./scripts/run-migrations.sh [alembic args]
# Example: ./scripts/run-migrations.sh upgrade head
# Example: ./scripts/run-migrations.sh current
set -e

docker compose -p 0xrecon exec recon-api \
    alembic -c migrations/alembic.ini "${@:-upgrade head}"
```

```bash
chmod +x scripts/dev-up.sh scripts/dev-down.sh scripts/run-migrations.sh scripts/gen-dev-certs.sh
```

### Verification Gate 1.8

```bash
# All files exist
test -f nginx/nginx.conf && echo "PASS: nginx.conf"
test -f nginx/ui-placeholder/index.html && echo "PASS: ui placeholder"
test -f scripts/dev-up.sh && echo "PASS: dev-up.sh"
test -f scripts/dev-down.sh && echo "PASS: dev-down.sh"
test -f scripts/run-migrations.sh && echo "PASS: run-migrations.sh"
test -f scripts/gen-dev-certs.sh && echo "PASS: gen-dev-certs.sh"

# Scripts are executable
test -x scripts/dev-up.sh && echo "PASS: dev-up.sh executable"
test -x scripts/gen-dev-certs.sh && echo "PASS: gen-dev-certs.sh executable"

# nginx.conf mentions mTLS phase 2 comment
grep -q "Phase 2" nginx/nginx.conf && echo "PASS: Phase 2 mTLS note in nginx.conf"

# Port 8443 defined
grep -q "8443" nginx/nginx.conf && echo "PASS: port 8443 defined"
```

**Update PHASE_STATUS.md: Set `Current prompt: 1.8 complete`**

---

## Prompt 1.9 — Minimal Tests

### Objective
Create the minimal test suite for Phase 1. Tests must pass before the phase
gate is considered complete. This establishes the testing pattern used in all
subsequent phases.

Tests for Phase 1:
- Health endpoint returns 200 with expected shape
- Product config endpoint returns 200 with expected shape
- Product config contains no hardcoded product name (reads from env)
- The word "caip" does not appear in source code (except allowed DOM IDs)

### Instructions

**`packages/recon-api/tests/conftest.py`**
```python
"""
Pytest configuration and shared fixtures for recon-api tests.

Provides:
- async_client: an AsyncClient hitting the FastAPI test app
- monkeypatched environment for test isolation
"""
from __future__ import annotations

import os

import pytest
from httpx import ASGITransport, AsyncClient

# Set test environment before importing app
os.environ.setdefault("RECON_ENV", "development")
os.environ.setdefault("RECON_DEBUG", "true")
os.environ.setdefault("RECON_SECRET_KEY", "test_secret_key")
os.environ.setdefault("RECON_DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RECON_DATABASE_URL_SYNC", "postgresql+psycopg2://test:test@localhost:5432/test")
os.environ.setdefault("RECON_VAULT_MASTER_PASSWORD", "test_vault_password_min_32_chars_ok")
os.environ.setdefault("PRODUCT_ID", "0xrecon")
os.environ.setdefault("PRODUCT_NAME", "0xRecon")
os.environ.setdefault("PRODUCT_SHORT_NAME", "0xRecon")


@pytest.fixture
async def async_client():
    """AsyncClient wired to the FastAPI test app. No real DB required."""
    # Import here to ensure env vars are set before app is created
    from recon_api.config import get_settings, get_product_config
    from recon_api.main import create_app

    # Clear lru_cache to pick up test env vars
    get_settings.cache_clear()
    get_product_config.cache_clear()

    app = create_app()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client

    # Clean up cache after test
    get_settings.cache_clear()
    get_product_config.cache_clear()
```

**`packages/recon-api/tests/test_health.py`**
```python
"""Tests for the /api/v1/health endpoint."""
from __future__ import annotations

import pytest


class TestHealthEndpoint:
    """Health check endpoint tests."""

    async def test_health_returns_200(self, async_client):
        """Health endpoint must return 200 regardless of DB state."""
        response = await async_client.get("/api/v1/health")
        assert response.status_code == 200

    async def test_health_response_shape(self, async_client):
        """Health response must contain required fields."""
        response = await async_client.get("/api/v1/health")
        data = response.json()

        assert "status" in data, "Missing 'status' field"
        assert "version" in data, "Missing 'version' field"
        assert "db_connected" in data, "Missing 'db_connected' field"

    async def test_health_status_values(self, async_client):
        """Status field must be one of the allowed values."""
        response = await async_client.get("/api/v1/health")
        data = response.json()
        assert data["status"] in ("ok", "degraded"), f"Unexpected status: {data['status']}"

    async def test_health_db_connected_is_bool(self, async_client):
        """db_connected must be a boolean, not a string."""
        response = await async_client.get("/api/v1/health")
        data = response.json()
        assert isinstance(data["db_connected"], bool), "db_connected must be bool"

    async def test_health_phase1_db_not_connected(self, async_client):
        """Phase 1: DB is not connected. Expect db_connected: false."""
        response = await async_client.get("/api/v1/health")
        data = response.json()
        assert data["db_connected"] is False, "Phase 1: db_connected should be False"
        assert data["status"] == "degraded", "Phase 1: status should be 'degraded' when DB not connected"

    async def test_health_no_auth_required(self, async_client):
        """Health endpoint must not require authentication."""
        # No Authorization header — must still return 200
        response = await async_client.get("/api/v1/health")
        assert response.status_code != 401, "Health endpoint must not require auth"
        assert response.status_code != 403, "Health endpoint must not require auth"
```

**`packages/recon-api/tests/test_product_config.py`**
```python
"""Tests for the /api/v1/product/config endpoint."""
from __future__ import annotations

import os

import pytest


class TestProductConfigEndpoint:
    """Product config endpoint tests."""

    async def test_product_config_returns_200(self, async_client):
        """Product config endpoint must return 200."""
        response = await async_client.get("/api/v1/product/config")
        assert response.status_code == 200

    async def test_product_config_shape(self, async_client):
        """Product config response must contain all required fields."""
        response = await async_client.get("/api/v1/product/config")
        data = response.json()

        required_fields = [
            "product_id",
            "product_name",
            "product_short_name",
            "logo_url",
            "favicon_url",
            "accent_colour",
            "terminology",
            "feature_flags",
        ]
        for field in required_fields:
            assert field in data, f"Missing required field: {field}"

    async def test_product_config_terminology_has_required_keys(self, async_client):
        """Terminology block must contain the 5 required keys."""
        response = await async_client.get("/api/v1/product/config")
        data = response.json()
        terminology = data["terminology"]

        required_keys = ["engagement", "collector", "finding", "scan", "assessment"]
        for key in required_keys:
            assert key in terminology, f"Missing terminology key: {key}"

    async def test_product_config_feature_flags_are_booleans(self, async_client):
        """All feature flags must be booleans."""
        response = await async_client.get("/api/v1/product/config")
        data = response.json()
        for key, value in data["feature_flags"].items():
            assert isinstance(value, bool), f"Feature flag '{key}' must be bool, got {type(value)}"

    async def test_product_config_no_auth_required(self, async_client):
        """Product config must be public — no auth required."""
        response = await async_client.get("/api/v1/product/config")
        assert response.status_code not in (401, 403), "Product config must be public"

    async def test_product_config_reads_from_env(self, async_client, monkeypatch):
        """Product config must reflect PRODUCT_* env vars, not hardcoded values."""
        from recon_api.config import get_product_config

        monkeypatch.setenv("PRODUCT_ID", "caip")
        monkeypatch.setenv("PRODUCT_NAME", "CAIP Test")
        get_product_config.cache_clear()

        response = await async_client.get("/api/v1/product/config")
        data = response.json()

        # With CAIP product config, product_id must be caip
        assert data["product_id"] == "caip", "Product config must read from env"
        assert data["product_name"] == "CAIP Test"

        # Cleanup
        get_product_config.cache_clear()

    async def test_accent_colour_is_hex(self, async_client):
        """Accent colour must be a valid hex colour string."""
        response = await async_client.get("/api/v1/product/config")
        data = response.json()
        colour = data["accent_colour"]
        assert colour.startswith("#"), f"accent_colour must start with #, got: {colour}"
        assert len(colour) in (4, 7), f"accent_colour must be 3 or 6 hex digits, got: {colour}"
```

**`packages/recon-api/tests/test_naming_conventions.py`**
```python
"""
Architecture convention tests.

These tests enforce naming and structural conventions defined in ARCHITECTURE.md
and CLAUDE.md. They scan source files and fail if prohibited patterns are found.

Run these tests in CI to catch convention violations early.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

# Source root — all Python source files are checked
PACKAGES_ROOT = Path(__file__).parent.parent.parent  # packages/


def get_python_files(package_dir: str) -> list[Path]:
    """Return all .py files in a package directory."""
    root = PACKAGES_ROOT / package_dir
    return list(root.rglob("*.py"))


class TestNamingConventions:
    """Source code convention enforcement tests."""

    def test_no_caip_in_recon_api_source(self):
        """
        The word 'caip' must not appear in recon_api source code.
        Exception: DOM element IDs in HTML templates are exempt.
        """
        allowed_substrings = [
            "caip-encrypted-blobs",
            "caip-encryption-metadata",
            "caip-signing-result",
        ]

        violations = []
        for py_file in get_python_files("recon-api/recon_api"):
            content = py_file.read_text(encoding="utf-8")
            lines = content.splitlines()
            for lineno, line in enumerate(lines, 1):
                line_lower = line.lower()
                if "caip" in line_lower:
                    # Check if this is an allowed exception
                    if not any(allowed in line_lower for allowed in allowed_substrings):
                        violations.append(f"{py_file}:{lineno}: {line.strip()}")

        assert not violations, (
            "CAIP string found in source (not in allowed DOM ID list):\n"
            + "\n".join(violations)
        )

    def test_no_flask_imports(self):
        """Flask must not be imported anywhere in the new codebase."""
        violations = []
        for package in ["recon-api", "recon-core", "recon-collectors", "recon-agent"]:
            for py_file in get_python_files(package):
                content = py_file.read_text(encoding="utf-8")
                if "from flask" in content or "import flask" in content:
                    violations.append(str(py_file))

        assert not violations, f"Flask import found in: {violations}"

    def test_no_pykcs11_imports(self):
        """PyKCS11 must not be imported. Only python-pkcs11 is permitted."""
        violations = []
        for package in ["recon-api", "recon-core", "recon-collectors", "recon-agent"]:
            for py_file in get_python_files(package):
                content = py_file.read_text(encoding="utf-8")
                if "PyKCS11" in content or "import pkcs11" in content.replace("from pkcs11", ""):
                    # python-pkcs11 uses 'import pkcs11', PyKCS11 uses 'import PyKCS11'
                    if "PyKCS11" in content:
                        violations.append(str(py_file))

        assert not violations, f"PyKCS11 import found in: {violations}"

    def test_no_requests_library(self):
        """The requests library must not be used. httpx is required."""
        violations = []
        for package in ["recon-api", "recon-core", "recon-collectors", "recon-agent"]:
            for py_file in get_python_files(package):
                content = py_file.read_text(encoding="utf-8")
                if "import requests" in content or "from requests" in content:
                    violations.append(str(py_file))

        assert not violations, f"requests library import found in: {violations}"

    def test_no_bare_except_clauses(self):
        """
        Bare 'except:' or 'except Exception: pass' clauses must not appear.
        All exceptions must be caught by specific type and logged.
        """
        violations = []
        for package in ["recon-api", "recon-core", "recon-collectors", "recon-agent"]:
            for py_file in get_python_files(package):
                content = py_file.read_text(encoding="utf-8")
                lines = content.splitlines()
                for lineno, line in enumerate(lines, 1):
                    stripped = line.strip()
                    if stripped in ("except:", "except Exception: pass", "except BaseException:"):
                        violations.append(f"{py_file}:{lineno}: {stripped}")

        assert not violations, (
            "Bare except clause found:\n" + "\n".join(violations)
        )

    def test_api_routes_use_trailing_slash(self):
        """All API route definitions must use trailing slashes."""
        violations = []
        for py_file in get_python_files("recon-api/recon_api/routers"):
            content = py_file.read_text(encoding="utf-8")
            lines = content.splitlines()
            for lineno, line in enumerate(lines, 1):
                # Find router decorator lines that define paths
                if "@router." in line and '"/api' in line:
                    # Check for missing trailing slash
                    import re
                    match = re.search(r'"/api[^"]*"', line)
                    if match:
                        path = match.group(0)
                        if not path.endswith('/"'):
                            violations.append(f"{py_file}:{lineno}: {line.strip()}")

        assert not violations, (
            "API route missing trailing slash:\n" + "\n".join(violations)
        )
```

### Verification Gate 1.9

Run the tests. They must all pass before proceeding:

```bash
cd packages/recon-api

# Install dependencies in a temporary venv for testing
python3 -m venv /tmp/recon-test-venv
source /tmp/recon-test-venv/bin/activate

# Install recon-core and recon-collectors first
pip install -q /tmp/../packages/recon-core  # adjust path as needed
# Actually install from the packages directory:
pip install -q ../../packages/recon-core
pip install -q ../../packages/recon-collectors

# Install test dependencies
pip install -q \
    fastapi==0.115.6 \
    "uvicorn[standard]==0.32.1" \
    pydantic==2.10.3 \
    pydantic-settings==2.6.1 \
    httpx==0.28.1 \
    structlog==24.4.0 \
    python-dotenv==1.0.1 \
    pytest==8.3.4 \
    pytest-asyncio==0.24.0 \
    anyio==4.7.0

# Install the package itself
pip install -q -e .

# Run tests
pytest tests/ -v --tb=short

deactivate
```

Expected output: all tests pass. Naming convention tests will have some
warnings about missing files that will be populated in later phases — that
is acceptable. Zero failures.

```bash
# Also verify test file count
find packages/recon-api/tests -name "test_*.py" | wc -l
# Should show at least 3
```

**Update PHASE_STATUS.md: Set `Current prompt: 1.9 complete`**

---

## Prompt 1.10 — Integration: Stack Startup

### Objective
Bring the full container stack up and verify the Phase 1 gate condition:
`/api/v1/health` returns 200 with `db_connected: true`.

This is the definitive Phase 1 gate. Everything before this prompt was
preparation. This prompt proves the stack works end-to-end.

### ⛔ HARD STOP — Pre-flight Checklist

Do not execute this prompt until ALL of the following are confirmed:

- [ ] Prompts 1.1 through 1.9 complete and their gates passed
- [ ] PHASE_STATUS.md reflects all previous prompts as complete
- [ ] Docker Desktop is running
- [ ] No conflicting containers on ports 5432, 8000, 3000, 443, 8443
- [ ] `.env` file exists with RECON_DATABASE_URL set
- [ ] `nginx/certs/dev.crt` exists (run `scripts/gen-dev-certs.sh` if not)

Pre-flight commands:
```bash
# Check for port conflicts
lsof -i :5432 -i :8000 -i :3000 2>/dev/null | grep LISTEN || echo "No conflicts"

# Verify .env
test -f .env && echo "PASS: .env exists"
grep -q "RECON_DATABASE_URL" .env && echo "PASS: DATABASE_URL in .env"

# Generate certs if needed
test -f nginx/certs/dev.crt || bash scripts/gen-dev-certs.sh
```

### Instructions

**Step 1: Build and start the stack**
```bash
docker compose -p 0xrecon -f docker-compose.yml up --build -d
```

Wait for containers to be healthy (allow up to 60 seconds):
```bash
docker compose -p 0xrecon ps
```

All of these must show "healthy" or "running":
- recon-postgres: healthy
- recon-api: healthy  
- recon-worker: running
- recon-ui: running

**Step 2: Verify health endpoint**
```bash
# Direct to API container
curl -s http://localhost:8000/api/v1/health | python3 -m json.tool
```

Phase 1 expected response:
```json
{
    "status": "degraded",
    "version": "1.0.0",
    "db_connected": false
}
```

Note: `db_connected: false` is correct in Phase 1. The health endpoint
stub returns false until Phase 2 adds the DB pool. What matters is:
- HTTP 200 returned
- Response is valid JSON with all three fields
- Container is running and reachable

**Step 3: Verify product config endpoint**
```bash
curl -s http://localhost:8000/api/v1/product/config | python3 -m json.tool
```

Expected response:
```json
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
```

**Step 4: Verify Alembic ran successfully**
```bash
./scripts/run-migrations.sh current
```
Expected: Shows revision `0001 (head)`.

**Step 5: Verify pgcrypto extension was installed**
```bash
docker compose -p 0xrecon exec recon-postgres \
    psql -U recon -d recon -c "SELECT extname FROM pg_extension WHERE extname IN ('pgcrypto', 'uuid-ossp');"
```
Expected: 2 rows returned (pgcrypto, uuid-ossp).

**Step 6: Verify worker is running**
```bash
docker compose -p 0xrecon logs recon-worker --tail=20
```
Expected: Logs show `recon_worker_starting` and `recon_worker_polling_loop_start`.
No error lines.

**Step 7: Verify nginx proxy**
```bash
# This will fail TLS cert validation (self-signed) but should return 200 with -k
curl -sk https://localhost/api/v1/health | python3 -m json.tool
```

### ⛔ HARD STOP — Phase 1 Gate

The following command is the official Phase 1 gate.

```bash
# PHASE 1 GATE — must pass before Phase 2 begins
curl -s http://localhost:8000/api/v1/health | python3 -m json.tool
```

**Gate passes if:**
- HTTP status code is 200
- Response body contains `"status"` field
- Response body contains `"version"` field  
- Response body contains `"db_connected"` field

**Gate fails if:**
- Connection refused (container not running)
- HTTP 500 or any non-200 response
- Response is not valid JSON
- Any required field is missing

If the gate fails, troubleshoot before proceeding:
```bash
# Check container logs for errors
docker compose -p 0xrecon logs recon-api --tail=50
docker compose -p 0xrecon logs recon-postgres --tail=20

# Check container status
docker compose -p 0xrecon ps

# Check if port 8000 is listening
curl -v http://localhost:8000/api/v1/health
```

Only when the gate passes, update PHASE_STATUS.md.

### Verification Gate 1.10 — Full Gate

```bash
# 1. HTTP 200 from health endpoint
STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api/v1/health)
[ "$STATUS" = "200" ] && echo "PASS: HTTP 200" || echo "FAIL: HTTP $STATUS"

# 2. Response contains db_connected field
curl -s http://localhost:8000/api/v1/health | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert 'db_connected' in d, 'FAIL: missing db_connected'
assert 'status' in d, 'FAIL: missing status'
assert 'version' in d, 'FAIL: missing version'
print('PASS: all fields present')
"

# 3. Product config returns 200
STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api/v1/product/config)
[ "$STATUS" = "200" ] && echo "PASS: product/config HTTP 200" || echo "FAIL: product/config HTTP $STATUS"

# 4. Alembic at head
docker compose -p 0xrecon exec recon-api alembic -c migrations/alembic.ini current 2>&1 | grep -q "head" && echo "PASS: alembic at head" || echo "FAIL: alembic not at head"

# 5. Worker running without errors
WORKER_ERRORS=$(docker compose -p 0xrecon logs recon-worker 2>&1 | grep -i "error\|exception\|traceback" | wc -l)
[ "$WORKER_ERRORS" = "0" ] && echo "PASS: worker no errors" || echo "WARN: worker has $WORKER_ERRORS error lines — check logs"

# 6. PostgreSQL healthy
docker compose -p 0xrecon exec recon-postgres pg_isready -U recon -d recon && echo "PASS: postgres healthy"
```

**When all gates pass:**

Update PHASE_STATUS.md with:
```
Current phase:    Phase 1 — Scaffold
Current prompt:   1.10 complete — PHASE COMPLETE
Overall status:   Phase 1 gate passed. Stack running. Ready for Phase 2.
Last session:     [current date]
Last verified:    [current datetime]
```

And update the Phase Completion Overview table:
```
| 1 | Scaffold | ✅ COMPLETE | PASS |
```

---

## Phase 1 Completion Summary

When Phase 1 is complete, the following is true:

**Infrastructure**
- Monorepo structure: `packages/recon-api`, `recon-worker`, `recon-core`, `recon-collectors`, `recon-agent`, `recon-ui`
- Docker Compose stack with 5 services, all named `recon-*`
- PostgreSQL 16 with pgcrypto and uuid-ossp extensions
- nginx reverse proxy on 443 (dashboard) and 8443 (collector API stub)
- Self-signed dev TLS certificates

**Application**
- FastAPI application with correct middleware stack order
- `/api/v1/health` — HTTP 200, JSON response with db_connected field
- `/api/v1/product/config` — HTTP 200, full product identity block
- Product identity reads from PRODUCT_* env vars (no hardcoded names)
- Worker container starts and enters poll loop

**Alembic**
- `migrations/` directory (not `alembic/`)
- Initial migration installs pgcrypto + uuid-ossp
- Alembic runs on API container startup via entrypoint.sh

**Tests**
- Unit tests for health endpoint
- Unit tests for product config endpoint
- Convention enforcement tests (no Flask, no CAIP, no bare except, no requests)
- All tests pass

**Conventions**
- No "caip" in any source file (except allowed DOM IDs — none exist yet in Phase 1)
- No Flask, PyKCS11, or requests imports
- Trailing slashes on all API routes
- `redirect_slashes=False` on FastAPI app
- Structured logging via structlog

**What is NOT in Phase 1 (deferred to later phases)**
- Real database connection pool (Phase 2)
- JWT authentication (Phase 2)
- Any business logic (Phase 2+)
- React frontend (Phase 9)
- mTLS enforcement (Phase 2)

---

## Troubleshooting Guide

### Container won't start — dependency error
```bash
# Check which package is missing
docker compose -p 0xrecon logs recon-api | grep "ModuleNotFoundError"
# Fix: ensure the failing package is in the Dockerfile RUN pip install ... block
```

### Alembic fails — can't connect to DB
```bash
# Check the DATABASE_URL_SYNC value
docker compose -p 0xrecon exec recon-api env | grep DATABASE_URL
# Ensure it uses postgresql+psycopg2:// not postgresql+asyncpg://
```

### Health endpoint returns 500
```bash
# Check for import errors in main.py
docker compose -p 0xrecon logs recon-api | tail -50
# Most common cause: missing dependency or syntax error
```

### Port conflict
```bash
# Find what's using the port
lsof -i :8000
# Kill the process or change the port mapping in docker-compose.yml
```

### nginx fails to start — cert not found
```bash
# Generate dev certs
bash scripts/gen-dev-certs.sh
# Then restart nginx
docker compose -p 0xrecon restart nginx
```

### Worker keeps restarting
```bash
# Check worker logs
docker compose -p 0xrecon logs recon-worker --tail=30
# Common cause: API health check timing — worker waits for API to be healthy
# If API is healthy and worker still fails, check the worker entrypoint script
```

---

## Session End Checklist

Before ending any session during Phase 1:

- [ ] Run the gate command for the last completed prompt and record output
- [ ] Update PHASE_STATUS.md `Current prompt` field
- [ ] Update PHASE_STATUS.md `Last session` field with today's date
- [ ] Update PHASE_STATUS.md `Last verified` field with datetime and gate output summary
- [ ] If containers are running, note it in PHASE_STATUS.md session notes
- [ ] Commit all files (never commit .env)
- [ ] If any architectural questions arose, record them in PHASE_STATUS.md "Architectural Questions Pending"

---

*End of PHASE_1.md*
*Phase prompt file version: 1.0 | April 2026*
*Next: docs/phases/PHASE_2.md — Core Data Layer, Auth, Vault, API Skeleton*
