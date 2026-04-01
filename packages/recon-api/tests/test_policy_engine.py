"""Policy engine unit tests."""
from __future__ import annotations
import pytest
from recon_api.services.policy import RuleRegistry, RuleEvaluator, UnifiedAssessor

SAMPLE_POLICY = {
    "rules": [
        {
            "rule_id": "cert-expiry-30",
            "metadata": {"name": "Certificate expiring within 30 days"},
            "condition": {
                "type": "simple", "asset_field": "days_until_expiry",
                "operator": "less_than_or_equal", "values": 30,
            },
            "severity": "high", "risk_score": 7.5,
            "finding": {"title": "Certificate expiring soon",
                        "description": "Expires within 30 days",
                        "remediation": "Renew certificate"},
            "applies_to": ["certificate"],
        },
        {
            "rule_id": "weak-hash",
            "metadata": {"name": "Weak hash algorithm"},
            "condition": {"type": "expression",
                          "expression": "is_weak_hash(signature_algorithm)"},
            "severity": "critical", "risk_score": 9.0,
            "finding": {"title": "Weak hash algorithm",
                        "description": "Uses MD5 or SHA-1",
                        "remediation": "Replace with SHA-256+"},
            "applies_to": ["certificate"],
        },
        {
            "rule_id": "old-tls",
            "metadata": {"name": "Old TLS version"},
            "condition": {"type": "expression",
                          "expression": "is_old_tls(tls_version)"},
            "severity": "high", "risk_score": 7.0,
            "finding": {"title": "Legacy TLS", "description": "TLS 1.0/1.1",
                        "remediation": "Disable TLS 1.0 and 1.1"},
            "applies_to": ["tls"],
        },
    ]
}


class TestRuleRegistry:
    def test_load_policy(self):
        reg = RuleRegistry()
        assert reg.load_policy(SAMPLE_POLICY)
        assert len(reg.rules) == 3

    def test_load_empty_policy_fails(self):
        assert not RuleRegistry().load_policy({})

    def test_get_rules_for_collector(self):
        reg = RuleRegistry()
        reg.load_policy(SAMPLE_POLICY)
        assert len(reg.get_rules_for_collector("tls", "certificate")) >= 1


class TestRuleEvaluator:
    def setup_method(self):
        self.reg = RuleRegistry()
        self.reg.load_policy(SAMPLE_POLICY)
        self.ev = RuleEvaluator(self.reg)

    def test_simple_triggers(self):
        r = self.ev.evaluate_rule(self.reg.rules["cert-expiry-30"],
                                  {"days_until_expiry": 10})
        assert r.triggered and r.severity == "high"

    def test_simple_no_trigger(self):
        r = self.ev.evaluate_rule(self.reg.rules["cert-expiry-30"],
                                  {"days_until_expiry": 90})
        assert not r.triggered

    def test_expression_weak_hash(self):
        r = self.ev.evaluate_rule(self.reg.rules["weak-hash"],
                                  {"signature_algorithm": "sha1WithRSAEncryption"})
        assert r.triggered and r.severity == "critical"

    def test_expression_strong_hash(self):
        r = self.ev.evaluate_rule(self.reg.rules["weak-hash"],
                                  {"signature_algorithm": "sha256WithRSAEncryption"})
        assert not r.triggered

    def test_all_operators_present(self):
        expected = {"equals", "not_equals", "in_list", "not_in_list",
                    "less_than", "less_than_or_equal",
                    "greater_than", "greater_than_or_equal",
                    "contains", "matches_regex"}
        assert expected == set(self.ev.COMPARISON_OPERATORS.keys())

    def test_missing_field_no_trigger(self):
        r = self.ev.evaluate_rule(self.reg.rules["cert-expiry-30"],
                                  {"other_field": 5})
        assert not r.triggered

    def test_result_to_dict(self):
        r = self.ev.evaluate_rule(self.reg.rules["cert-expiry-30"],
                                  {"days_until_expiry": 5})
        d = r.to_dict()
        assert all(k in d for k in ("rule_id", "severity", "title"))

    def test_temporal_condition(self):
        rule = {
            "rule_id": "t1", "metadata": {"name": "Temporal"},
            "condition": {"type": "temporal", "field": "days_until_expiry",
                          "threshold_days": 60},
            "severity": "medium", "risk_score": 5.0,
            "finding": {"title": "Exp", "description": "", "remediation": ""},
            "applies_to": ["certificate"],
        }
        r = self.ev.evaluate_rule(rule, {"days_until_expiry": 30})
        assert r.triggered


class TestScanServiceImport:
    def test_import(self):
        from recon_api.services.scan import ScanService
        assert ScanService is not None

    def test_policy_engine_import(self):
        from recon_api.services.policy import (
            RuleRegistry, RuleEvaluator, UnifiedAssessor, PolicyService
        )
        assert all(c is not None for c in [
            RuleRegistry, RuleEvaluator, UnifiedAssessor, PolicyService
        ])
