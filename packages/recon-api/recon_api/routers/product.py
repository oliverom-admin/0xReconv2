"""
Product identity endpoint. No authentication required.
Public — frontend fetches this on startup to determine which brand to render.
The backend is brand-agnostic: this returns what PRODUCT_* env vars dictate.
"""
from __future__ import annotations

from fastapi import APIRouter

from recon_api.config import get_product_config

router = APIRouter(tags=["product"])


@router.get("/product/config/")
async def product_config() -> dict:
    config = get_product_config()

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
