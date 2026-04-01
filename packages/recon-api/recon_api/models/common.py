"""
Standard API response envelopes.

Every route returns one of:
  SuccessResponse  —  {"data": ..., "meta": {...}}
  ErrorResponse    —  {"error": {"code": "...", "message": "...", "details": {...}}}
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class Meta(BaseModel):
    request_id: str | None = None
    total: int | None = None
    page: int | None = None
    per_page: int | None = None


class SuccessResponse(BaseModel):
    data: Any
    meta: Meta = Meta()


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: dict[str, Any] | None = None


class ErrorResponse(BaseModel):
    error: ErrorDetail
