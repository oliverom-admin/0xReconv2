"""
ReportFinancialCalculator — financial impact analysis for scan results.

All financial constants are calibrated values in GBP. Do not change.
Reference: docs/reference/legacy_financial_calculator.py
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger("recon.financial")


class ReportFinancialCalculator:
    # ── Financial constants (GBP, calibrated) ─────────────────
    AVG_DATA_BREACH_COST: int = 3_555_000
    AVG_COST_PER_RECORD: int = 152
    AVG_DETECTION_DAYS: int = 207
    COMPLIANCE_FINE_MIN: int = 21_000

    RISK_MULTIPLIERS: dict[str, float] = {
        "CRITICAL": 0.35,
        "HIGH": 0.20,
        "MEDIUM": 0.10,
        "LOW": 0.03,
    }

    def __init__(self, scan_data: dict[str, Any]) -> None:
        self._certificates = scan_data.get("certificates", [])
        self._keys = scan_data.get("keys", [])
        self._findings = scan_data.get("findings", [])

    def calculate_annual_risk_cost(self) -> dict[str, Any]:
        """Calculate annualised risk cost based on findings and cert health."""
        risk_level = self._determine_risk_level(self._findings)
        multiplier = self.RISK_MULTIPLIERS.get(risk_level, 0.03)
        breach_risk_cost = int(self.AVG_DATA_BREACH_COST * multiplier)

        expired_count = sum(
            1 for c in self._certificates
            if c.get("is_expired") or c.get("days_until_expiry", 999) < 0
        )
        weak_count = sum(
            1 for c in self._certificates
            if (c.get("key_size") or c.get("public_key_size") or 2048) < 2048
        )
        compliance_risk_cost = (expired_count + weak_count) * self.COMPLIANCE_FINE_MIN
        total = breach_risk_cost + compliance_risk_cost

        critical_count = sum(
            1 for f in self._findings
            if (f.get("severity") or "").lower() == "critical"
        )
        high_count = sum(
            1 for f in self._findings
            if (f.get("severity") or "").lower() == "high"
        )

        return {
            "total_annual_cost": total,
            "risk_level": risk_level,
            "breach_risk_cost": breach_risk_cost,
            "compliance_risk_cost": compliance_risk_cost,
            "multiplier": multiplier,
            "assumptions": (
                f"Based on industry average breach cost of "
                f"£{self.AVG_DATA_BREACH_COST:,}, "
                f"risk multiplier {multiplier:.0%} for {risk_level} risk level, "
                f"and £{self.COMPLIANCE_FINE_MIN:,} per compliance exposure."
            ),
            "breakdown": {
                "critical_findings": critical_count,
                "high_findings": high_count,
                "expired_certificates": expired_count,
                "weak_key_certificates": weak_count,
            },
        }

    def calculate_remediation_costs(self) -> dict[str, Any]:
        """Calculate phased remediation cost estimate."""
        critical_count = sum(
            1 for f in self._findings
            if (f.get("severity") or "").lower() == "critical"
        )
        high_count = sum(
            1 for f in self._findings
            if (f.get("severity") or "").lower() == "high"
        )
        expired_count = sum(
            1 for c in self._certificates
            if c.get("is_expired") or c.get("days_until_expiry", 999) < 0
        )
        weak_count = sum(
            1 for c in self._certificates
            if (c.get("key_size") or c.get("public_key_size") or 2048) < 2048
        )

        phase_1_cost = critical_count * 5_000
        phase_2_cost = high_count * 2_000
        phase_3_cost = (expired_count * 500) + (weak_count * 1_000)
        total = phase_1_cost + phase_2_cost + phase_3_cost

        return {
            "total_cost": total,
            "phases": [
                {
                    "name": "Phase 1 — Incident Response Readiness",
                    "duration_weeks": 4,
                    "cost": phase_1_cost,
                    "items": critical_count,
                    "description": "Address critical findings requiring immediate action",
                },
                {
                    "name": "Phase 2 — High Priority Mitigation",
                    "duration_weeks": 8,
                    "cost": phase_2_cost,
                    "items": high_count,
                    "description": "Remediate high-severity findings",
                },
                {
                    "name": "Phase 3 — Long-term Hardening",
                    "duration_weeks": 12,
                    "cost": phase_3_cost,
                    "items": expired_count + weak_count,
                    "description": "Replace expired certificates and migrate weak keys",
                },
            ],
            "timeline_weeks": 24,
            "timeline_months": 6,
            "cost_breakdown": {
                "critical_issue": 5_000,
                "high_issue": 2_000,
                "expired_cert": 500,
                "weak_key_migration": 1_000,
            },
        }

    def calculate_roi(self) -> dict[str, Any]:
        """Calculate ROI and payback period for remediation investment."""
        annual = self.calculate_annual_risk_cost()
        remediation = self.calculate_remediation_costs()

        annual_cost = annual["total_annual_cost"]
        remediation_cost = remediation["total_cost"]
        annual_savings = int(annual_cost * 0.70)  # 70% risk reduction

        payback_months = (
            max(1, remediation_cost // max(1, annual_savings))
            if remediation_cost > 0 else 0
        )
        payback_months = min(12, payback_months)

        roi_percent = (
            int((annual_savings / remediation_cost) * 100)
            if remediation_cost > 0 else 0
        )
        three_year_savings = (annual_savings * 3) - remediation_cost
        roi_year1 = annual_savings - remediation_cost

        return {
            "annual_risk_cost_current": annual_cost,
            "remediation_investment": remediation_cost,
            "annual_risk_reduction": annual_savings,
            "annual_savings_year1": roi_year1,
            "annual_savings_year2": annual_savings,
            "annual_savings_year3": annual_savings,
            "payback_months": payback_months,
            "roi_percent": roi_percent,
            "roi_year1": roi_year1,
            "roi_year3": three_year_savings,
            "roi_message": (
                f"Investing £{remediation_cost:,} in remediation reduces annual "
                f"risk by £{annual_savings:,} (70% reduction), with "
                f"payback in {payback_months} month(s) and "
                f"£{three_year_savings:,} net benefit over 3 years."
            ),
            "assumptions": (
                "Based on 70% risk reduction from full remediation programme. "
                "Actual results depend on implementation completeness and "
                "organisational risk factors."
            ),
        }

    def get_financial_summary(self) -> dict[str, Any]:
        """Return complete financial analysis."""
        return {
            "annual_risk_cost": self.calculate_annual_risk_cost(),
            "remediation_costs": self.calculate_remediation_costs(),
            "roi_analysis": self.calculate_roi(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "model_version": "1.0",
            "disclaimer": (
                "Financial estimates are based on industry benchmarks and "
                "statistical models. Actual costs may vary based on "
                "organisation size, sector, and specific risk factors. "
                "All values in GBP."
            ),
        }

    def _determine_risk_level(self, findings: list[dict]) -> str:
        """Determine overall risk level from findings. CRITICAL > HIGH > MEDIUM > LOW."""
        for finding in findings:
            sev = (finding.get("severity") or "").lower()
            if sev == "critical":
                return "CRITICAL"
        for finding in findings:
            sev = (finding.get("severity") or "").lower()
            if sev == "high":
                return "HIGH"
        for finding in findings:
            sev = (finding.get("severity") or "").lower()
            if sev == "medium":
                return "MEDIUM"
        return "LOW"
