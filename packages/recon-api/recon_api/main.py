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
    Startup: init DB pool, warm caches.
    Shutdown: close DB pool, flush buffers.

    Phase 1: No DB pool. Logs startup/shutdown only.
    Phase 2: Add DB pool init/close here.
    """
    settings = get_settings()
    configure_logging(debug=settings.debug)
    logger.info("recon_api_starting", env=settings.env, debug=settings.debug)

    # Phase 2: await init_db_pool(settings.database_url)
    yield
    # Phase 2: await close_db_pool()

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

    return app


app = create_app()
