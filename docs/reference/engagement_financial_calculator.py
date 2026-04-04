"""
Engagement Financial Impact Calculator - WP3

Calculates financial risk costs and remediation ROI from merged engagement data.

Purpose:
- Quantify cryptographic risk in financial terms (CFO-friendly)
- Show annual cost of inaction (risk cost)
- Estimate remediation costs and timelines
- Calculate ROI and payback period
- Build business case for executives

Model Components:
1. Annual Risk Cost - cost of maintaining current state
2. Remediation Costs - investment needed to fix issues
3. Timeline - phased remediation approach
4. ROI Calculation - business case quantification

Conservative assumptions for credibility.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

logger = logging.getLogger('caip.reporting.financial')


class EngagementFinancialCalculator:
    """
    Calculates financial impact from cryptographic risks.

    Based on industry benchmarks and conservative assumptions:
    - Data breach cost: £3.8M average (IBM 2023, converted from USD)
    - Detection time: 207 days average
    - Cost per record: £152 average (converted from USD)
    - Compliance breach: £21k minimum per incident

    Currency: British Pounds (GBP)
    """

    # Industry benchmarks - converted to GBP (USD rate: 1 USD = 0.79 GBP)
    AVG_DATA_BREACH_COST = 3_555_000  # GBP (4.5M USD × 0.79)
    AVG_COST_PER_RECORD = 152  # GBP (180 USD × 0.84)
    AVG_DETECTION_DAYS = 207  # days
    COMPLIANCE_FINE_MIN = 21_000  # GBP (25k USD × 0.84)

    # Annual risk multipliers based on risk level
    RISK_MULTIPLIERS = {
        'CRITICAL': 0.35,  # 35% annual risk of breach
        'HIGH': 0.20,      # 20% annual risk
        'MEDIUM': 0.10,    # 10% annual risk
        'LOW': 0.03,       # 3% annual risk
    }

    def __init__(self, merged_data: Dict[str, Any]):
        """
        Initialize financial calculator with merged engagement data.

        Args:
            merged_data: Output from _merge_crypto_reports()
        """
        self.merged_data = merged_data
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def calculate_annual_risk_cost(self) -> Dict[str, Any]:
        """
        Calculate annual cost of current risk exposure.

        Returns:
            {
                'total_annual_cost': 450000,
                'risk_level': 'HIGH',
                'multiplier': 0.20,
                'assumptions': '...',
                'breakdown': {...}
            }
        """
        findings = self.merged_data.get('findings', [])
        certificates = self.merged_data.get('certificates', [])

        # Determine risk level from findings
        risk_level = self._determine_risk_level(findings)
        multiplier = self.RISK_MULTIPLIERS.get(risk_level, 0.03)

        # Calculate base annual cost (as % of avg breach cost)
        annual_cost = int(self.AVG_DATA_BREACH_COST * multiplier)

        # Add compliance risk (expired/weak certs increase regulatory risk)
        expired_count = sum(1 for c in certificates if c.get('is_expired'))
        weak_count = sum(1 for c in certificates if c.get('key_size', 2048) < 2048)
        compliance_risk = (expired_count + weak_count) * self.COMPLIANCE_FINE_MIN

        total_cost = annual_cost + compliance_risk

        return {
            'total_annual_cost': total_cost,
            'risk_level': risk_level,
            'breach_risk_cost': annual_cost,
            'compliance_risk_cost': compliance_risk,
            'multiplier': multiplier,
            'assumptions': (
                f'Based on industry benchmarks: £{self.AVG_DATA_BREACH_COST:,} average breach cost, '
                f'{self.AVG_DETECTION_DAYS} days detection time, '
                f'{multiplier*100:.0f}% annual probability of breach'
            ),
            'breakdown': {
                'critical_findings': sum(1 for f in findings if f.get('severity', '').lower() == 'critical'),
                'high_findings': sum(1 for f in findings if f.get('severity', '').lower() == 'high'),
                'expired_certificates': expired_count,
                'weak_key_certificates': weak_count,
            }
        }

    def calculate_remediation_costs(self) -> Dict[str, Any]:
        """
        Calculate cost to remediate identified issues.

        Returns:
            {
                'total_cost': 50000,
                'phases': [...],
                'timeline_months': 6
            }
        """
        findings = self.merged_data.get('findings', [])
        certificates = self.merged_data.get('certificates', [])

        critical_count = sum(1 for f in findings if f.get('severity', '').lower() == 'critical')
        high_count = sum(1 for f in findings if f.get('severity', '').lower() == 'high')
        expired_count = sum(1 for c in certificates if c.get('is_expired'))
        weak_count = sum(1 for c in certificates if c.get('key_size', 2048) < 2048)

        # Cost estimates per action
        costs = {
            'critical_issue': 5_000,      # $5k per critical issue (incident response prep)
            'high_issue': 2_000,          # $2k per high issue (mitigation)
            'expired_cert': 500,          # $500 per expired cert (renewal + deployment)
            'weak_key_migration': 1_000,  # $1k per weak key (replacement + rotation)
        }

        # Calculate phase costs
        phase_1_cost = critical_count * costs['critical_issue']  # Immediate actions
        phase_2_cost = high_count * costs['high_issue']  # Medium-term fixes
        phase_3_cost = (expired_count * costs['expired_cert'] +
                       weak_count * costs['weak_key_migration'])  # Long-term improvements

        total_cost = phase_1_cost + phase_2_cost + phase_3_cost

        return {
            'total_cost': total_cost,
            'phases': [
                {
                    'name': 'Phase 1: Incident Response Readiness',
                    'duration_weeks': 4,
                    'cost': phase_1_cost,
                    'items': f'{critical_count} critical findings',
                    'description': 'Prepare detection and response capabilities for critical risks'
                },
                {
                    'name': 'Phase 2: High Priority Mitigation',
                    'duration_weeks': 8,
                    'cost': phase_2_cost,
                    'items': f'{high_count} high-severity findings',
                    'description': 'Implement mitigations for high-risk cryptographic issues'
                },
                {
                    'name': 'Phase 3: Long-term Hardening',
                    'duration_weeks': 12,
                    'cost': phase_3_cost,
                    'items': f'{expired_count} expired + {weak_count} weak-key certificates',
                    'description': 'Replace expired certificates, migrate weak keys to strong algorithms'
                }
            ],
            'timeline_weeks': 24,
            'timeline_months': 6,
            'cost_breakdown': {
                'critical_remediation': phase_1_cost,
                'high_remediation': phase_2_cost,
                'certificate_renewal': phase_3_cost,
            }
        }

    def calculate_roi(self) -> Dict[str, Any]:
        """
        Calculate ROI from risk mitigation investment.

        Returns:
            {
                'annual_risk_reduction': 300000,
                'investment': 50000,
                'roi_percent': 600,
                'payback_months': 2,
                'three_year_savings': 850000
            }
        """
        annual_cost = self.calculate_annual_risk_cost()['total_annual_cost']
        remediation = self.calculate_remediation_costs()['total_cost']

        # Conservative assumption: remediation reduces annual risk by 70%
        risk_reduction_percent = 0.70
        annual_savings = int(annual_cost * risk_reduction_percent)

        # Payback period
        if remediation > 0:
            payback_months = max(1, remediation // max(1, annual_savings))
        else:
            payback_months = 0

        # ROI calculation
        if remediation > 0:
            roi_percent = int((annual_savings / remediation) * 100)
        else:
            roi_percent = 0

        # Multi-year projection
        three_year_savings = (annual_savings * 3) - remediation

        return {
            'annual_risk_cost_current': annual_cost,
            'remediation_investment': remediation,
            'annual_risk_reduction': annual_savings,
            'annual_savings_year1': annual_savings - remediation,  # Net year 1 (includes investment)
            'annual_savings_year2': annual_savings,
            'annual_savings_year3': annual_savings,
            'payback_months': min(12, payback_months),
            'roi_percent': roi_percent,
            'roi_year1': -remediation + annual_savings,  # Negative initially
            'roi_year3': three_year_savings,
            'roi_message': (
                f'Investing £{remediation:,} in remediation saves £{annual_savings:,} annually. '
                f'Full payback in {min(12, payback_months)} months. '
                f'3-year net benefit: £{three_year_savings:,}'
            ),
            'assumptions': (
                f'Assumes 70% risk reduction through remediation, '
                f'£{self.AVG_DATA_BREACH_COST:,} average breach cost, '
                f'{self.AVG_DETECTION_DAYS} day detection window'
            )
        }

    def get_financial_summary(self) -> Dict[str, Any]:
        """
        Get complete financial impact summary.

        Returns all financial calculations in one structure.
        """
        return {
            'annual_risk_cost': self.calculate_annual_risk_cost(),
            'remediation_costs': self.calculate_remediation_costs(),
            'roi_analysis': self.calculate_roi(),
            'generated_at': datetime.now().isoformat(),
            'model_version': '1.0',
            'disclaimer': (
                'Financial estimates are based on industry benchmarks and conservative assumptions. '
                'Actual costs may vary based on organizational factors. '
                'Consult with CFO and legal teams for budget decisions.'
            )
        }

    # ==================== Private Methods ====================

    def _determine_risk_level(self, findings: List[Dict[str, Any]]) -> str:
        """
        Determine overall risk level from findings.

        Logic:
        - CRITICAL if any critical findings
        - HIGH if any high findings
        - MEDIUM if any medium findings
        - LOW otherwise
        """
        for finding in findings:
            severity = finding.get('severity', '').lower()
            if severity == 'critical':
                return 'CRITICAL'

        for finding in findings:
            severity = finding.get('severity', '').lower()
            if severity == 'high':
                return 'HIGH'

        for finding in findings:
            severity = finding.get('severity', '').lower()
            if severity == 'medium':
                return 'MEDIUM'

        return 'LOW'


def calculate_engagement_financial_impact(merged_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience function to calculate financial impact.

    Args:
        merged_data: Merged engagement report data

    Returns:
        Complete financial impact summary
    """
    calculator = EngagementFinancialCalculator(merged_data)
    return calculator.get_financial_summary()
