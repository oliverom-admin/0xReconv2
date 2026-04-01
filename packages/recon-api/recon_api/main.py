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
    Application lifespan.

    Phase 2A: DB pool init/close.
    Phase 2B: Vault init + internal CA provisioning uncommented here.
    """
    settings = get_settings()
    configure_logging(debug=settings.debug)
    logger.info("recon_api_starting", env=settings.env, debug=settings.debug)

    from recon_api.db.pool import init_pool, close_pool
    pool = await init_pool(
        settings.database_url,
        min_size=settings.database_pool_min,
        max_size=settings.database_pool_max,
    )
    app.state.db_pool = pool
    logger.info("recon_api_db_pool_ready")

    # Phase 2B: uncomment after Prompt 2B.3 is complete
    # from recon_api.services.vault import VaultService
    # vault = VaultService(settings.vault_path, settings.vault_master_password)
    # await vault.initialize()
    # app.state.vault = vault
    # logger.info("recon_api_vault_ready")
    #
    # from recon_api.services.certificate import CertificateService
    # async with pool.acquire() as conn:
    #     await CertificateService(conn, vault).ensure_internal_ca()
    # logger.info("recon_api_internal_ca_ready")

    yield

    await close_pool()
    logger.info("recon_api_stopping")


def create_app() -> FastAPI:
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

    # CORS must be first middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router, prefix="/api/v1")
    app.include_router(product.router, prefix="/api/v1")

    # Phase 2B routers — stub files created in Phase 2B prompts
    # Uncomment as each prompt is completed:
    # from recon_api.routers import auth as auth_router
    # from recon_api.routers import users as users_router
    # from recon_api.routers import rbac as rbac_router
    # from recon_api.routers import engagements as engagements_router
    # app.include_router(auth_router.router, prefix="/api/v1")
    # app.include_router(users_router.router, prefix="/api/v1")
    # app.include_router(rbac_router.router, prefix="/api/v1")
    # app.include_router(engagements_router.router, prefix="/api/v1")

    return app


app = create_app()
