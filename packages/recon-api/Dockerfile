# =============================================================================
# 0xRecon — recon-api / recon-worker image
# recon-api and recon-worker both use this image.
# docker-compose.yml sets CMD per service.
# =============================================================================
FROM python:3.11-slim AS base

LABEL org.opencontainers.image.title="0xRecon API"
LABEL org.opencontainers.image.version="1.0.0"

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd --gid 1001 recon \
    && useradd --uid 1001 --gid recon --shell /bin/bash --create-home recon

WORKDIR /app

# Install shared packages
COPY packages/recon-core       /app/packages/recon-core
COPY packages/recon-collectors /app/packages/recon-collectors
RUN pip install --no-cache-dir /app/packages/recon-core
RUN pip install --no-cache-dir /app/packages/recon-collectors

# Install application dependencies
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
    "python-docx==1.1.2" \
    "reportlab==4.2.5" \
    jinja2==3.1.4 \
    python-dotenv==1.0.1 \
    python-multipart==0.0.20 \
    structlog==24.4.0

# Copy application code
COPY packages/recon-api/recon_api /app/recon_api
COPY migrations                   /app/migrations

COPY packages/recon-api/entrypoint.sh        /app/entrypoint.sh
COPY packages/recon-api/entrypoint-worker.sh /app/entrypoint-worker.sh
RUN chmod +x /app/entrypoint.sh /app/entrypoint-worker.sh

RUN mkdir -p /app/data /app/reports && chown -R recon:recon /app/data /app/reports

USER recon

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health/ || exit 1

CMD ["/app/entrypoint.sh"]
