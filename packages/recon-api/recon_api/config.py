"""Application configuration loaded from environment variables."""
from __future__ import annotations

import json
from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="RECON_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    env: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    secret_key: str = "change_me"
    allowed_origins: str = "http://localhost:3000"

    database_url: str = ""
    database_url_sync: str = ""
    database_pool_min: int = 2
    database_pool_max: int = 10

    jwt_algorithm: str = "RS256"
    jwt_expiry_hours: int = 8
    jwt_private_key_path: str = ""
    jwt_public_key_path: str = ""

    vault_path: str = "/app/data/vault.enc"
    vault_master_password: str = ""

    @property
    def allowed_origins_list(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]


class ProductConfig(BaseSettings):
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
        '{"show_dpod_dashboard": true, "show_pqc_migration": true, '
        '"show_document_assessment": true}'
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
    return Settings()


@lru_cache
def get_product_config() -> ProductConfig:
    return ProductConfig()
