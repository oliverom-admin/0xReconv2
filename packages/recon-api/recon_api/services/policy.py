"""
PolicyService — CRUD, version management, policy engine dispatch.

Policy engine v2.0 format ported from legacy rule_assessment.py.
Rule schema fields must not change — existing policies depend on this format.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

import asyncpg
import structlog

logger = structlog.get_logger("recon.policy")


class RuleResult:
    __slots__ = ("rule_id", "rule_name", "triggered", "severity", "risk_score",
                 "title", "description", "remediation", "evidence",
                 "compliance_impact", "category")

    def __init__(self, rule_id: str, rule_name: str, triggered: bool,
                 severity: str = "info", risk_score: float = 0.0,
                 title: str = "", description: str = "",
                 remediation: str = "", evidence: dict | None = None,
                 compliance_impact: str = "", category: str = "") -> None:
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.triggered = triggered
        self.severity = severity
        self.risk_score = risk_score
        self.title = title
        self.description = description
        self.remediation = remediation
        self.evidence = evidence or {}
        self.compliance_impact = compliance_impact
        self.category = category

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id, "rule_name": self.rule_name,
            "triggered": self.triggered, "severity": self.severity,
            "risk_score": self.risk_score, "title": self.title,
            "description": self.description, "remediation": self.remediation,
            "evidence": self.evidence, "compliance_impact": self.compliance_impact,
            "category": self.category,
        }


class RuleRegistry:
    def __init__(self) -> None:
        self.rules: dict[str, dict] = {}
        self.policy_metadata: dict = {}
        self.policy_parameters: dict = {}

    def load_policy(self, policy_dict: dict) -> bool:
        if not policy_dict:
            return False
        try:
            self.policy_metadata = policy_dict.get("metadata", {})
            self.policy_parameters = policy_dict.get("parameters", {})
            for rule in policy_dict.get("rules", []):
                rule_id = rule.get("rule_id")
                if rule_id:
                    self.rules[rule_id] = rule
            logger.info("policy_loaded", rule_count=len(self.rules))
            return True
        except Exception as exc:
            logger.error("policy_load_failed", error=str(exc))
            return False

    def get_rules_for_collector(self, collector_type: str, asset_type: str) -> list[dict]:
        result = []
        for rule in self.rules.values():
            applies_to = rule.get("applies_to", ["all"])
            if "all" in applies_to or collector_type in applies_to or asset_type in applies_to:
                result.append(rule)
        return result


class RuleEvaluator:
    COMPARISON_OPERATORS: dict[str, Any] = {
        "equals": lambda a, b: a == b,
        "not_equals": lambda a, b: a != b,
        "in_list": lambda a, b: (a in b if isinstance(b, list) else a == b),
        "not_in_list": lambda a, b: (a not in b if isinstance(b, list) else a != b),
        "less_than": lambda a, b: a < b,
        "less_than_or_equal": lambda a, b: a <= b,
        "greater_than": lambda a, b: a > b,
        "greater_than_or_equal": lambda a, b: a >= b,
        "contains": lambda a, b: b in a if isinstance(a, str) else False,
        "matches_regex": lambda a, b: bool(re.search(b, str(a))) if b else False,
    }

    def __init__(self, registry: RuleRegistry) -> None:
        self.registry = registry
        self._custom_functions = self._build_custom_functions()

    def evaluate_rule(self, rule: dict, asset: dict) -> RuleResult:
        rule_id = rule.get("rule_id", "unknown")
        rule_name = rule.get("metadata", {}).get("name", rule_id)
        try:
            triggered = self._evaluate_condition(rule, asset)
        except Exception as exc:
            logger.warning("rule_eval_error", rule_id=rule_id, error=str(exc))
            return RuleResult(rule_id=rule_id, rule_name=rule_name, triggered=False)

        if not triggered:
            return RuleResult(rule_id=rule_id, rule_name=rule_name, triggered=False)

        finding = rule.get("finding", {})
        return RuleResult(
            rule_id=rule_id, rule_name=rule_name, triggered=True,
            severity=rule.get("severity", "info"),
            risk_score=float(rule.get("risk_score", 2.5)),
            title=finding.get("title", rule_name),
            description=finding.get("description", ""),
            remediation=finding.get("remediation", ""),
            evidence={"asset": asset.get("unique_id") or asset.get("id")},
            compliance_impact=finding.get("compliance_impact", ""),
            category=rule.get("category", ""),
        )

    def _evaluate_condition(self, rule: dict, asset: dict) -> bool:
        condition = rule.get("condition", {})
        ctype = condition.get("type", "simple")
        if ctype == "simple":
            return self._eval_simple(condition, asset, rule)
        elif ctype == "expression":
            return self._eval_expression(condition, asset, rule)
        elif ctype == "temporal":
            return self._eval_temporal(condition, asset)
        else:
            logger.warning("unknown_condition_type", ctype=ctype)
            return False

    def _eval_simple(self, condition: dict, asset: dict, rule: dict) -> bool:
        field = condition.get("asset_field")
        operator = condition.get("operator", "equals")
        if not field:
            return False
        asset_value = self._get_field(asset, field)
        if asset_value is None:
            return False
        if "values" in condition:
            comp = condition["values"]
        elif "values_from_parameter" in condition:
            pname = condition["values_from_parameter"]
            param_def = rule.get("parameters", {}).get(pname) or \
                        self.registry.policy_parameters.get(pname, {})
            comp = param_def.get("value") if isinstance(param_def, dict) else param_def
            if comp is None:
                return False
        else:
            comp = condition.get("value")
        op_fn = self.COMPARISON_OPERATORS.get(operator)
        if not op_fn:
            return False
        try:
            return bool(op_fn(asset_value, comp))
        except Exception:
            return False

    def _eval_expression(self, condition: dict, asset: dict, rule: dict) -> bool:
        expression = condition.get("expression", "")
        if not expression:
            return False
        ctx: dict[str, Any] = dict(asset)
        ctx.update(self._custom_functions)
        for k, v in self.registry.policy_parameters.items():
            ctx[k] = v.get("value") if isinstance(v, dict) else v
        for k, v in rule.get("parameters", {}).items():
            ctx[k] = v.get("value") if isinstance(v, dict) else v
        ctx["re"] = re
        py_expr = re.sub(r"\bNOT\((.+?)\)", r"not (\1)", expression)
        try:
            return bool(eval(py_expr, {"__builtins__": {}}, ctx))  # noqa: S307
        except Exception:
            return False

    def _eval_temporal(self, condition: dict, asset: dict) -> bool:
        field = condition.get("field", "days_until_expiry")
        threshold = condition.get("threshold_days")
        operator = condition.get("operator", "less_than_or_equal")
        asset_value = self._get_field(asset, field)
        if asset_value is None or threshold is None:
            return False
        op_fn = self.COMPARISON_OPERATORS.get(operator)
        if not op_fn:
            return False
        try:
            return bool(op_fn(int(asset_value), int(threshold)))
        except Exception:
            return False

    @staticmethod
    def _get_field(asset: dict, field: str) -> Any:
        parts = field.split(".")
        val: Any = asset
        for part in parts:
            if isinstance(val, dict):
                val = val.get(part)
            else:
                return None
        return val

    @staticmethod
    def _build_custom_functions() -> dict[str, Any]:
        def is_weak_hash(algo: str | None) -> bool:
            if not algo:
                return False
            return any(w in algo.lower() for w in ("md5", "sha1", "sha-1"))

        def is_old_tls(version: str | None) -> bool:
            if not version:
                return False
            return any(o in version.lower() for o in
                       ("sslv2", "sslv3", "tls 1.0", "tlsv1", "tls 1.1", "tlsv1.1"))

        def days_until(date_str: str | None) -> int | None:
            if not date_str:
                return None
            try:
                dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                return (dt - datetime.now(timezone.utc)).days
            except Exception:
                return None

        def days_since(date_str: str | None) -> int | None:
            d = days_until(date_str)
            return -d if d is not None else None

        def content_matches_any(content: Any, patterns: list) -> bool:
            if content is None:
                return False
            s = str(content).lower()
            return any(p.lower() in s for p in patterns)

        return {
            "is_weak_hash": is_weak_hash, "is_old_tls": is_old_tls,
            "days_until": days_until, "days_since": days_since,
            "content_matches_any": content_matches_any,
        }


class UnifiedAssessor:
    def __init__(self) -> None:
        self.registry = RuleRegistry()
        self.evaluator = RuleEvaluator(self.registry)

    def load_policy(self, policy: dict) -> bool:
        return self.registry.load_policy(policy)

    def assess_certificate(self, cert_dict: dict) -> list[RuleResult]:
        source = cert_dict.get("source", "")
        ctype = self._infer_collector_type(source)
        rules = self.registry.get_rules_for_collector(ctype, "certificate")
        return [self.evaluator.evaluate_rule(r, cert_dict) for r in rules]

    def assess_key(self, key_dict: dict) -> list[RuleResult]:
        return [self.evaluator.evaluate_rule(r, key_dict)
                for r in self.registry.get_rules_for_collector("all", "key")]

    def assess_tls(self, tls_dict: dict) -> list[RuleResult]:
        return [self.evaluator.evaluate_rule(r, tls_dict)
                for r in self.registry.get_rules_for_collector("tls", "tls")]

    def assess_crl(self, crl_dict: dict) -> list[RuleResult]:
        return [self.evaluator.evaluate_rule(r, crl_dict)
                for r in self.registry.get_rules_for_collector("crl", "crl")]

    @staticmethod
    def _infer_collector_type(source: str) -> str:
        s = source.lower()
        if s.startswith("tls"):
            return "tls"
        if "azure" in s:
            return "azure_keyvault"
        if "ejbca" in s:
            return "ejbca"
        if "luna" in s or "hsm" in s:
            return "luna_hsm"
        if "file" in s:
            return "file"
        return "all"


class PolicyService:
    def __init__(self, db: asyncpg.Connection) -> None:
        self._db = db

    async def create_policy(
        self, project_id: str, name: str, rules: list,
        assessment_type_id: str | None, created_by: str,
        description: str | None = None,
    ) -> dict[str, Any]:
        rules_hash = hashlib.sha256(json.dumps(rules, sort_keys=True).encode()).hexdigest()
        row = await self._db.fetchrow(
            """
            INSERT INTO policies
              (project_id, name, description, rules, assessment_type_id, schema_version, created_by)
            VALUES ($1,$2,$3,$4::jsonb,$5,'2.0',$6)
            RETURNING id, name, schema_version, created_at
            """,
            project_id, name, description, json.dumps(rules), assessment_type_id, created_by,
        )
        policy_id = row["id"]
        await self._db.execute(
            """
            INSERT INTO policy_versions
              (policy_id, version_number, rules_snapshot, rules_hash, created_by)
            VALUES ($1,1,$2::jsonb,$3,$4)
            """,
            policy_id, json.dumps(rules), rules_hash, created_by,
        )
        return dict(row)

    async def get_policy(self, policy_id: str) -> dict[str, Any] | None:
        row = await self._db.fetchrow("SELECT * FROM policies WHERE id=$1", policy_id)
        return dict(row) if row else None

    async def list_policies(self, project_id: str) -> list[dict]:
        rows = await self._db.fetch(
            "SELECT id,name,description,schema_version,is_active,created_at "
            "FROM policies WHERE project_id=$1 ORDER BY name", project_id,
        )
        return [dict(r) for r in rows]

    async def update_policy(self, policy_id: str, rules: list, updated_by: str) -> None:
        rules_hash = hashlib.sha256(json.dumps(rules, sort_keys=True).encode()).hexdigest()
        current_version = await self._db.fetchval(
            "SELECT MAX(version_number) FROM policy_versions WHERE policy_id=$1", policy_id,
        ) or 0
        await self._db.execute(
            "UPDATE policies SET rules=$2::jsonb, updated_at=NOW() WHERE id=$1",
            policy_id, json.dumps(rules),
        )
        await self._db.execute(
            """
            INSERT INTO policy_versions
              (policy_id, version_number, rules_snapshot, rules_hash, created_by)
            VALUES ($1,$2,$3::jsonb,$4,$5)
            """,
            policy_id, current_version + 1, json.dumps(rules), rules_hash, updated_by,
        )

    async def delete_policy(self, policy_id: str) -> None:
        await self._db.execute(
            "UPDATE policies SET is_active=false, updated_at=NOW() WHERE id=$1", policy_id,
        )
