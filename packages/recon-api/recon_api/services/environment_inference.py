"""
EnvironmentInferenceService — infer environment type from asset metadata.

Pure logic: no DB, no async. All methods are classmethods/staticmethods.
Confidence values preserved exactly from legacy reference.

Confidence scale:
  0.9   — Azure tags (explicit metadata)
  0.7   — Hostname keyword match
  0.6   — Luna HSM collector type inference
  0.5   — Port 443 default / infrastructure tier base
  0.4   — No-signal base confidence
  0.0   — Unknown / no signal
"""
from __future__ import annotations

import re
from typing import Any

import structlog

logger = structlog.get_logger("recon.environment_inference")

VALID_TYPES = ("production", "staging", "development", "testing", "unknown")

# Hostname patterns mapped to environment types
_HOSTNAME_PATTERNS: list[tuple[list[str], str]] = [
    (["prod", "production", "www"], "production"),
    (["staging", "stage", "uat", "stg"], "staging"),
    (["dev", "development", "localhost"], "development"),
    (["test", "testing", "qa"], "testing"),
]

# Standard port to environment heuristics
_PROD_PORTS = {443, 8443, 636}
_DEV_PORTS = {8000, 8001, 8008, 8080, 3000, 5000}


class EnvironmentInferenceService:
    """Stateless environment inference from hostnames, ports, and metadata."""

    @classmethod
    def infer_from_hostname(
        cls, hostname: str, port: int | None = None,
    ) -> dict[str, Any] | None:
        """
        Infer environment from hostname patterns.

        Confidence: 0.7 for explicit keyword match, 0.5 for port-443 default.
        Returns None if no signal.
        """
        if not hostname:
            return None

        h = hostname.lower()

        for patterns, env_type in _HOSTNAME_PATTERNS:
            if any(p in h for p in patterns):
                return {
                    "signal_type": "hostname",
                    "environment_type": env_type,
                    "confidence": 0.7,
                    "signal_details": {"hostname": hostname, "matched_pattern": True},
                }

        # Port 443 → production default (lower confidence)
        if port == 443:
            return {
                "signal_type": "hostname",
                "environment_type": "production",
                "confidence": 0.5,
                "signal_details": {"hostname": hostname, "port_based": True},
            }

        return None

    @classmethod
    def infer_from_infrastructure_tier(
        cls, hostname: str, port: int, ip: str | None = None,
    ) -> dict[str, Any] | None:
        """
        Infer environment from network tier (hostname keywords, port, IP).

        Confidence: 0.7 for hostname markers, 0.5 for port/IP heuristics.
        Returns None if no signal.
        """
        env_scores: dict[str, float] = {}

        if hostname:
            h = hostname.lower()
            for patterns, env_type in _HOSTNAME_PATTERNS:
                if any(p in h for p in patterns):
                    env_scores[env_type] = 0.7
                    break

        if port:
            if port in _PROD_PORTS:
                env_scores.setdefault("production", 0.5)
            elif port in _DEV_PORTS:
                env_scores.setdefault("development", 0.5)
            elif port > 8000:
                env_scores.setdefault("development", 0.4)

        if ip:
            if any(ip.startswith(p) for p in ("127.", "192.168.", "10.")):
                env_scores.setdefault("development", 0.5)

        if not env_scores:
            return None

        best_env = max(env_scores, key=lambda k: env_scores[k])
        return {
            "signal_type": "infrastructure_tier",
            "environment_type": best_env,
            "confidence": env_scores[best_env],
            "signal_details": {"hostname": hostname, "port": port, "ip": ip},
        }

    @classmethod
    def fuse_signals(
        cls, signals: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        """
        Fuse multiple environment signals. Highest confidence wins.
        On tie: prefer infrastructure_tier over hostname.
        Returns None if signals list is empty.
        """
        valid = [s for s in signals if s is not None]
        if not valid:
            return None

        # Sort by confidence descending, then by signal_type priority
        priority = {"infrastructure_tier": 0, "hostname": 1, "azure_tags": -1}

        def sort_key(s: dict) -> tuple:
            return (-s.get("confidence", 0.0),
                    priority.get(s.get("signal_type", ""), 2))

        valid.sort(key=sort_key)
        best = valid[0]

        return {
            "environment_type": best["environment_type"],
            "confidence": best["confidence"],
            "signal_type": best["signal_type"],
            "signal_details": best.get("signal_details"),
            "signals_count": len(valid),
        }

    @classmethod
    def infer(
        cls, hostname: str | None = None,
        port: int | None = None,
        ip: str | None = None,
    ) -> dict[str, Any] | None:
        """Convenience: collect all signals and fuse."""
        signals: list[dict | None] = []

        if hostname:
            signals.append(cls.infer_from_hostname(hostname, port))

        if hostname and port:
            signals.append(
                cls.infer_from_infrastructure_tier(hostname, port, ip)
            )

        return cls.fuse_signals([s for s in signals if s is not None])
