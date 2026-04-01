# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: caip_reporting_functions/engagement_docx_builder.py
# Copied: 2026-04-01
# Used in: Phase 14 — Reporting
#
# When porting logic from this file:
#   - Rewrite using the new stack (FastAPI, asyncpg, python-pkcs11, httpx)
#   - Remove all Flask/SQLite/PyKCS11/requests dependencies
#   - Remove all caip_* naming conventions
#   - Fix any bare except: or except Exception: pass blocks
#   - Add proper async/await patterns
#   - Do not copy — port deliberately
# =============================================================================

"""
Engagement DOCX Report Builder - Phase 2

Adapts merged engagement data to DOCX service format.

Purpose:
- Take merged crypto reports (multiple assessments consolidated)
- Convert to format that ExecutiveReportDocxService expects
- Handle multi-report summarization and deduplication

Data Flow:
1. Engagement has 2-5 crypto asset reports (scans)
2. Reports merged by engagement_routes.py using _merge_crypto_reports()
3. This builder converts merged data to DOCX-compatible format
4. ExecutiveReportDocxService generates DOCX with merged data
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger('caip.reporting.engagement_docx')


class EngagementDataAdapter:
    """
    Adapt merged engagement data to ExecutiveReportDocxService format.

    The DOCX service expects:
    - engagement_name: str (engagement identifier)
    - scan_data: Dict with findings, certificates, assessment, etc.

    Merged engagement data provides:
    - Multiple report structures (deduplicated findings + certificates)
    - Metadata about source reports

    This adapter bridges the gap.
    """

    def __init__(self, merged_data: Dict[str, Any], engagement_info: Dict[str, Any]):
        """
        Initialize adapter with merged engagement data.

        Args:
            merged_data: Output from _merge_crypto_reports()
            engagement_info: Engagement metadata (name, customer, project, etc.)
        """
        self.merged_data = merged_data
        self.engagement_info = engagement_info
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def adapt_for_docx_service(self) -> Dict[str, Any]:
        """
        Convert merged engagement data to DOCX service format.

        Returns:
            Dictionary compatible with ExecutiveReportDocxService.generate_executive_report()
        """
        self.logger.info(f"Adapting merged engagement data for DOCX service")

        # Build the adapted structure
        adapted = {
            'metadata': self._build_metadata(),
            'findings': self.merged_data.get('findings', []),
            'certificates': self.merged_data.get('certificates', []),
            'assessment': self._build_assessment_summary(),
            'policy_assessment': self._build_policy_summary(),
            'engagement_name': self.engagement_info.get('engagement_id', 'Engagement'),
            'document_assessments': self.engagement_info.get('document_assessments', []),  # Include document assessments
        }

        self.logger.debug(f"Adapted data: {len(adapted['findings'])} findings, "
                         f"{len(adapted['certificates'])} certificates, "
                         f"{len(adapted['document_assessments'])} document assessments")

        return adapted

    def _build_metadata(self) -> Dict[str, Any]:
        """Build metadata from merged data and engagement info."""
        merged_metadata = self.merged_data.get('metadata', {})

        return {
            'engagement_id': self.engagement_info.get('engagement_id', 'Unknown'),
            'customer_name': self.engagement_info.get('customer_name', 'Organization'),
            'project_name': self.engagement_info.get('project_name', 'Assessment'),
            'assessment_type': 'engagement_summary',  # Mark as engagement (not single scan)
            'source_reports': merged_metadata.get('source_reports', []),
            'number_of_reports': len(merged_metadata.get('source_reports', [])),
            'assessment_date': datetime.now().isoformat(),
        }

    def _build_assessment_summary(self) -> Dict[str, Any]:
        """
        Build aggregated assessment summary from all merged reports.

        Aggregates:
        - Risk rating (highest severity from all reports)
        - Risk score (average of all reports)
        - Health index (average of all reports)
        """
        findings = self.merged_data.get('findings', [])
        certificates = self.merged_data.get('certificates', [])

        # Determine risk rating based on finding severity distribution
        risk_rating = self._calculate_risk_rating(findings)

        # Calculate average risk score (0-100)
        risk_score = self._calculate_risk_score(findings)

        # Calculate health index based on certificate inventory
        health_index = self._calculate_health_index(certificates)

        return {
            'risk_rating': risk_rating,
            'risk_score': risk_score,
            'health_index': health_index,
            'findings_count': len(findings),
            'critical_findings': self._count_findings_by_severity(findings, 'critical'),
            'high_findings': self._count_findings_by_severity(findings, 'high'),
            'medium_findings': self._count_findings_by_severity(findings, 'medium'),
            'low_findings': self._count_findings_by_severity(findings, 'low'),
        }

    def _build_policy_summary(self) -> Dict[str, Any]:
        """Build policy assessment summary."""
        findings = self.merged_data.get('findings', [])

        return {
            'findings': findings,
            'total_findings': len(findings),
            'findings_by_severity': {
                'critical': self._count_findings_by_severity(findings, 'critical'),
                'high': self._count_findings_by_severity(findings, 'high'),
                'medium': self._count_findings_by_severity(findings, 'medium'),
                'low': self._count_findings_by_severity(findings, 'low'),
            }
        }

    # ==================== Aggregation Helpers ====================

    def _calculate_risk_rating(self, findings: List[Dict[str, Any]]) -> str:
        """
        Determine risk rating based on finding severity distribution.

        Logic:
        - If any CRITICAL: Rating = CRITICAL
        - Else if HIGH findings > 0: Rating = HIGH
        - Else if MEDIUM findings > 2: Rating = MEDIUM
        - Else: Rating = LOW
        """
        critical_count = self._count_findings_by_severity(findings, 'critical')
        high_count = self._count_findings_by_severity(findings, 'high')
        medium_count = self._count_findings_by_severity(findings, 'medium')

        if critical_count > 0:
            return 'CRITICAL'
        elif high_count > 0:
            return 'HIGH'
        elif medium_count > 2:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _calculate_risk_score(self, findings: List[Dict[str, Any]]) -> float:
        """
        Calculate numerical risk score (0-100).

        Formula:
        - Each CRITICAL = 25 points
        - Each HIGH = 15 points
        - Each MEDIUM = 8 points
        - Each LOW = 2 points
        - Capped at 100
        """
        score = 0
        score += self._count_findings_by_severity(findings, 'critical') * 25
        score += self._count_findings_by_severity(findings, 'high') * 15
        score += self._count_findings_by_severity(findings, 'medium') * 8
        score += self._count_findings_by_severity(findings, 'low') * 2

        return min(100.0, float(score))

    def _calculate_health_index(self, certificates: List[Dict[str, Any]]) -> float:
        """
        Calculate health index based on certificate inventory (0-100).

        Factors:
        - Expiration status (expired = -20, expiring soon = -10)
        - Algorithm strength (weak = -15, strong = +5)
        - Self-signed (risk = -10)

        Base: 100, with penalties applied
        """
        health = 100.0

        if not certificates:
            return 50.0  # Neutral if no certs

        for cert in certificates:
            # Check expiration
            if cert.get('is_expired'):
                health -= 20
            elif cert.get('days_until_expiry', 999) < 30:
                health -= 10

            # Check algorithm strength
            key_size = cert.get('key_size', 0)
            if key_size < 2048:
                health -= 15
            elif key_size >= 4096:
                health += 5

            # Check self-signed
            if cert.get('is_self_signed'):
                health -= 10

        return max(0.0, min(100.0, health))

    def _count_findings_by_severity(self, findings: List[Dict[str, Any]],
                                   severity: str) -> int:
        """Count findings by severity level."""
        return len([f for f in findings
                   if f.get('severity', '').lower() == severity.lower()])


class EngagementSummaryCalculator:
    """
    Calculate summary metrics from merged engagement data.

    These metrics are used for charting and reporting in Phase 2.
    """

    def __init__(self, merged_data: Dict[str, Any]):
        """
        Initialize with merged engagement data.

        Args:
            merged_data: Output from _merge_crypto_reports()
        """
        self.merged_data = merged_data
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def calculate_certificate_summary(self) -> Dict[str, Any]:
        """
        Calculate certificate inventory summary.

        Returns:
            Dictionary with cert counts by status, algorithm, key size, etc.
        """
        certificates = self.merged_data.get('certificates', [])

        if not certificates:
            return {
                'total': 0,
                'valid': 0,
                'expired': 0,
                'expiring_7_days': 0,
                'expiring_30_days': 0,
                'by_algorithm': {},
                'by_key_size': {},
            }

        # Initialize counters
        summary = {
            'total': len(certificates),
            'valid': 0,
            'expired': 0,
            'expiring_7_days': 0,
            'expiring_30_days': 0,
            'self_signed': 0,
            'by_algorithm': {},
            'by_key_size': {},
        }

        # Tally certificates
        for cert in certificates:
            # Status
            if cert.get('is_expired'):
                summary['expired'] += 1
            else:
                summary['valid'] += 1

            # Expiration timeline
            days_until_expiry = cert.get('days_until_expiry', 999)
            if days_until_expiry < 7:
                summary['expiring_7_days'] += 1
            elif days_until_expiry < 30:
                summary['expiring_30_days'] += 1

            # Self-signed
            if cert.get('is_self_signed'):
                summary['self_signed'] += 1

            # Algorithm
            algo = cert.get('signature_algorithm', 'Unknown')
            summary['by_algorithm'][algo] = summary['by_algorithm'].get(algo, 0) + 1

            # Key size
            key_size = cert.get('key_size', 0)
            if key_size < 2048:
                size_category = 'weak'
            elif key_size < 4096:
                size_category = 'valid'
            else:
                size_category = 'strong'
            summary['by_key_size'][size_category] = summary['by_key_size'].get(size_category, 0) + 1

        return summary

    def calculate_finding_summary(self) -> Dict[str, Any]:
        """
        Calculate findings summary by severity.

        Returns:
            Dictionary with finding counts and risk analysis
        """
        findings = self.merged_data.get('findings', [])

        summary = {
            'total': len(findings),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'informational': 0,
        }

        for finding in findings:
            severity = finding.get('severity', 'informational').lower()
            if severity in summary:
                summary[severity] += 1

        return summary


class EngagementChartIntegrator:
    """
    Generates and provides charts for engagement DOCX reports.

    Integrates EngagementChartBuilder to create visual charts
    that will be embedded in the DOCX report.

    Charts are generated as PNG images for embedding.
    """

    def __init__(self, merged_data: Dict[str, Any], output_dir: str = '/tmp'):
        """
        Initialize chart integrator.

        Args:
            merged_data: Merged engagement report data
            output_dir: Directory for chart PNG files
        """
        self.merged_data = merged_data
        self.output_dir = output_dir
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.charts = {}

    def generate_charts(self) -> Dict[str, str]:
        """
        Generate all engagement charts.

        Returns:
            Dictionary mapping chart names to file paths:
            {
                'certificate_inventory': '/tmp/chart_certificate_inventory_....png',
                'expiration_timeline': '/tmp/chart_expiration_timeline_....png',
                ...
            }

        Raises:
            ImportError: If engagement_chart_builder not available
            Exception: If chart generation fails
        """
        try:
            # Import PIL version (works without Cairo graphics library)
            from .engagement_chart_builder_pil import generate_engagement_charts_pil

            self.logger.info("Generating engagement charts (PIL)...")
            self.charts = generate_engagement_charts_pil(self.merged_data, self.output_dir)

            self.logger.debug(f"Generated {len(self.charts)} charts")
            return self.charts

        except ImportError as e:
            self.logger.error(f"Chart builder not available: {e}")
            return {}
        except Exception as e:
            self.logger.error(f"Error generating charts: {e}")
            raise

    def get_chart(self, chart_name: str) -> Optional[str]:
        """
        Get path to a specific chart.

        Args:
            chart_name: Name of chart (certificate_inventory, expiration_timeline, etc.)

        Returns:
            Path to chart PNG file, or None if not found
        """
        return self.charts.get(chart_name)

    def get_all_charts(self) -> Dict[str, str]:
        """Get all generated charts."""
        return self.charts


def adapt_engagement_for_docx(merged_data: Dict[str, Any],
                              engagement_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience function to adapt engagement data for DOCX service.

    Args:
        merged_data: Merged engagement report data
        engagement_info: Engagement metadata

    Returns:
        Data structure ready for ExecutiveReportDocxService
    """
    adapter = EngagementDataAdapter(merged_data, engagement_info)
    return adapter.adapt_for_docx_service()


class EngagementFinancialIntegrator:
    """
    Generates and provides financial impact analysis for engagement DOCX reports.

    Integrates EngagementFinancialCalculator to create financial analysis
    that will be embedded in the DOCX report.

    Includes annual risk cost, remediation investment, and ROI calculations.
    """

    def __init__(self, merged_data: Dict[str, Any]):
        """
        Initialize financial integrator.

        Args:
            merged_data: Merged engagement report data
        """
        self.merged_data = merged_data
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.financial_data = {}

    def generate_financial_analysis(self) -> Dict[str, Any]:
        """
        Generate comprehensive financial impact analysis.

        Returns:
            Dictionary with financial summary:
            {
                'annual_risk_cost': {...},
                'remediation_costs': {...},
                'roi_analysis': {...},
                'generated_at': '2025-...',
                ...
            }

        Raises:
            ImportError: If engagement_financial_calculator not available
            Exception: If financial analysis fails
        """
        try:
            # Import here to avoid circular dependency
            from .engagement_financial_calculator import EngagementFinancialCalculator

            self.logger.info("Generating financial impact analysis...")
            calculator = EngagementFinancialCalculator(self.merged_data)
            self.financial_data = calculator.get_financial_summary()

            self.logger.debug("Financial analysis generated successfully")
            return self.financial_data

        except ImportError as e:
            self.logger.error(f"Financial calculator not available: {e}")
            return {}
        except Exception as e:
            self.logger.error(f"Error generating financial analysis: {e}")
            raise

    def get_financial_summary(self) -> Dict[str, Any]:
        """Get financial summary data."""
        return self.financial_data


def generate_engagement_charts_for_docx(merged_data: Dict[str, Any],
                                       output_dir: str = '/tmp') -> Dict[str, str]:
    """
    Convenience function to generate charts for engagement DOCX.

    Args:
        merged_data: Merged engagement report data
        output_dir: Directory for chart PNG files

    Returns:
        Dictionary mapping chart names to file paths
    """
    integrator = EngagementChartIntegrator(merged_data, output_dir)
    return integrator.generate_charts()


def generate_engagement_financial_analysis(merged_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience function to generate financial analysis for engagement DOCX.

    Args:
        merged_data: Merged engagement report data

    Returns:
        Dictionary with financial impact summary
    """
    integrator = EngagementFinancialIntegrator(merged_data)
    return integrator.generate_financial_analysis()
