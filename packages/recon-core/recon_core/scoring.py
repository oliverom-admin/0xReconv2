"""
ScoringService — cryptographic risk scoring and aggregation.
Weight tables locked to legacy system output — must not change.
Zero external dependencies — stdlib only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ENVIRONMENT_WEIGHTS: dict[str, float] = {
    "production": 1.5, "staging": 1.1, "development": 0.7, "testing": 0.6, "unknown": 1.0,
}
COMPLIANCE_ADDITIVE: dict[str, float] = {
    "pci_dss": 0.30, "nsa2": 0.20, "sox": 0.10, "hipaa": 0.15, "gdpr": 0.10,
}
RECENCY_WEIGHTS: dict[str, float] = {
    "expires_30_days": 1.5, "expires_90_days": 1.2, "expires_365_days": 1.0, "long_lived": 0.9,
}
DEPENDENCY_WEIGHTS: dict[str, float] = {
    "high_5plus": 1.6, "medium_3to5": 1.3, "low_1to2": 1.0, "none": 0.8,
}
SEVERITY_BASE_SCORES: dict[str, float] = {
    "critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5,
}
GRADE_BOUNDARIES: list[tuple[float, str]] = [
    (90.0, "A+"), (80.0, "A"), (70.0, "B"), (60.0, "C"), (50.0, "D"), (0.0, "F"),
]


@dataclass
class ScoredFinding:
    finding_id: str
    severity: str
    title: str
    base_risk_score: float
    weighted_score: float
    priority_score: float
    environment: str = "unknown"
    compliance_frameworks: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class AssessmentScore:
    health_index: float
    grade: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    total_exposure_score: float
    priority_queue: list[ScoredFinding]


class ScoringEngine:
    @staticmethod
    def compute_weight(
        environment: str = "unknown",
        compliance_frameworks: list[str] | None = None,
        days_until_expiry: int | None = None,
        dependency_count: int | None = None,
    ) -> float:
        env_w = ENVIRONMENT_WEIGHTS.get(environment.lower(), 1.0)
        compliance_w = 1.0
        for fw in compliance_frameworks or []:
            compliance_w += COMPLIANCE_ADDITIVE.get(fw.lower(), 0.0)
        if days_until_expiry is None:
            recency_w = 1.0
        elif days_until_expiry <= 30:
            recency_w = RECENCY_WEIGHTS["expires_30_days"]
        elif days_until_expiry <= 90:
            recency_w = RECENCY_WEIGHTS["expires_90_days"]
        elif days_until_expiry <= 365:
            recency_w = RECENCY_WEIGHTS["expires_365_days"]
        else:
            recency_w = RECENCY_WEIGHTS["long_lived"]
        if dependency_count is None:
            dep_w = 1.0
        elif dependency_count >= 5:
            dep_w = DEPENDENCY_WEIGHTS["high_5plus"]
        elif dependency_count >= 3:
            dep_w = DEPENDENCY_WEIGHTS["medium_3to5"]
        elif dependency_count >= 1:
            dep_w = DEPENDENCY_WEIGHTS["low_1to2"]
        else:
            dep_w = DEPENDENCY_WEIGHTS["none"]
        return env_w * compliance_w * recency_w * dep_w

    @staticmethod
    def score_finding(
        finding_id: str, severity: str, title: str,
        environment: str = "unknown",
        compliance_frameworks: list[str] | None = None,
        days_until_expiry: int | None = None,
        dependency_count: int | None = None,
        effort_estimate: float = 1.0,
        details: dict[str, Any] | None = None,
    ) -> ScoredFinding:
        base = SEVERITY_BASE_SCORES.get(severity.lower(), 2.5)
        weight = ScoringEngine.compute_weight(
            environment, compliance_frameworks, days_until_expiry, dependency_count,
        )
        weighted = round(base * weight, 3)
        priority = round(weighted / max(effort_estimate, 0.1), 3)
        return ScoredFinding(
            finding_id=finding_id, severity=severity, title=title,
            base_risk_score=base, weighted_score=weighted, priority_score=priority,
            environment=environment, compliance_frameworks=compliance_frameworks or [],
            details=details or {},
        )


class AggregationEngine:
    @staticmethod
    def grade(health_index: float) -> str:
        for threshold, g in GRADE_BOUNDARIES:
            if health_index >= threshold:
                return g
        return "F"

    @staticmethod
    def aggregate(
        findings: list[ScoredFinding], total_assets: int = 0, assets_with_context: int = 0,
    ) -> AssessmentScore:
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        total_exposure = 0.0
        for f in findings:
            counts[f.severity.lower()] = counts.get(f.severity.lower(), 0) + 1
            total_exposure += f.weighted_score
        asset_count = max(total_assets, 1)
        exposure_per_asset = total_exposure / asset_count
        health_index = max(0.0, min(100.0, 100.0 - exposure_per_asset * 2.0))
        top_10 = sorted(findings, key=lambda f: f.priority_score, reverse=True)[:10]
        return AssessmentScore(
            health_index=round(health_index, 1),
            grade=AggregationEngine.grade(health_index),
            total_findings=len(findings),
            critical_count=counts["critical"], high_count=counts["high"],
            medium_count=counts["medium"], low_count=counts["low"],
            info_count=counts["info"],
            total_exposure_score=round(total_exposure, 3),
            priority_queue=top_10,
        )
