"""ScoringService unit tests — weight values locked to legacy system."""
from __future__ import annotations
import pytest
from recon_core.scoring import (
    AggregationEngine, ScoringEngine, ENVIRONMENT_WEIGHTS, SEVERITY_BASE_SCORES,
)


class TestScoringWeights:
    def test_environment_weights_exact(self):
        assert ENVIRONMENT_WEIGHTS["production"] == 1.5
        assert ENVIRONMENT_WEIGHTS["development"] == 0.7
        assert ENVIRONMENT_WEIGHTS["staging"] == 1.1
        assert ENVIRONMENT_WEIGHTS["testing"] == 0.6

    def test_severity_base_scores_exact(self):
        assert SEVERITY_BASE_SCORES["critical"] == 9.5
        assert SEVERITY_BASE_SCORES["high"] == 7.5
        assert SEVERITY_BASE_SCORES["medium"] == 5.0
        assert SEVERITY_BASE_SCORES["low"] == 2.5
        assert SEVERITY_BASE_SCORES["info"] == 0.5


class TestScoringEngine:
    def test_production_amplifies(self):
        prod = ScoringEngine.score_finding("1", "high", "T", environment="production")
        dev = ScoringEngine.score_finding("2", "high", "T", environment="development")
        assert prod.weighted_score > dev.weighted_score

    def test_expiry_30d_amplifies(self):
        urgent = ScoringEngine.score_finding("1", "high", "T", days_until_expiry=5)
        long_old = ScoringEngine.score_finding("2", "high", "T", days_until_expiry=730)
        assert urgent.weighted_score > long_old.weighted_score

    def test_high_dep_amplifies(self):
        many = ScoringEngine.score_finding("1", "high", "T", dependency_count=10)
        none = ScoringEngine.score_finding("2", "high", "T", dependency_count=0)
        assert many.weighted_score > none.weighted_score

    def test_compliance_amplifies(self):
        pci = ScoringEngine.score_finding("1", "high", "T", compliance_frameworks=["pci_dss"])
        base = ScoringEngine.score_finding("2", "high", "T")
        assert pci.weighted_score > base.weighted_score


class TestAggregationEngine:
    def test_grade_boundaries(self):
        assert AggregationEngine.grade(95.0) == "A+"
        assert AggregationEngine.grade(85.0) == "A"
        assert AggregationEngine.grade(75.0) == "B"
        assert AggregationEngine.grade(65.0) == "C"
        assert AggregationEngine.grade(55.0) == "D"
        assert AggregationEngine.grade(40.0) == "F"

    def test_no_findings_perfect_score(self):
        s = AggregationEngine.aggregate([], total_assets=10)
        assert s.health_index == 100.0
        assert s.grade == "A+"

    def test_severity_counts(self):
        findings = [
            ScoringEngine.score_finding(str(i), sev, "T")
            for i, sev in enumerate(["critical", "critical", "high", "medium", "low"])
        ]
        s = AggregationEngine.aggregate(findings, total_assets=5)
        assert s.critical_count == 2
        assert s.high_count == 1

    def test_priority_queue_capped_at_10(self):
        findings = [ScoringEngine.score_finding(str(i), "high", f"F{i}") for i in range(20)]
        s = AggregationEngine.aggregate(findings, total_assets=20)
        assert len(s.priority_queue) <= 10
