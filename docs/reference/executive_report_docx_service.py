"""
Executive Report DOCX Service - Phase 1 Implementation

Main orchestrator for generating professional Word (.docx) executive reports.

Coordinates:
- Document creation and styling
- Template construction (cover page, headers/footers, TOC)
- Executive summary extraction and presentation
- File management and delivery

Entry point for DOCX report generation.

Usage:
    from executive_report_docx_service import ExecutiveReportDocxService

    service = ExecutiveReportDocxService(logo_path="logo.png")
    output_path = service.generate_executive_report(
        scan_data=scan_results,
        engagement_name="Acme Corp",
        organization_name="Acme Corporation",
        output_dir="reports/"
    )
    # Returns: reports/acme_corp_executive_20240215.docx
"""

import os
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from docx import Document
from docx.shared import Inches

from .report_docx_styles import StyleManager
from .report_docx_template import (
    CoverPageBuilder,
    HeaderFooterBuilder,
    TableOfContentsBuilder,
    PageBreakBuilder
)
from .report_docx_sections import (
    ExecutiveSummaryBuilder,
    ExecutiveSummaryDataExtractor
)


logger = logging.getLogger('caip.reporting')


class ExecutiveReportDocxService:
    """
    Service for generating professional executive reports in Word format (.docx).

    Provides:
    - Professional cover page with engagement details
    - Auto-updating table of contents
    - Executive summary with risk assessment and key metrics
    - Consistent styling and formatting
    - Editable document (unlike PDF)

    Configuration:
    - Customizable logo placement
    - Configurable classification marking
    - Flexible output directory

    Phase 1 Scope:
    - Cover page (engagement name, organization, date, classification)
    - Table of contents (auto-updating)
    - Executive summary (risk rating, metrics, top actions)
    - Headers/footers with security marking
    - Professional styling (navy palette, Calibri fonts, 1.15 spacing)

    Phase 2+ Scope:
    - Visual charts (heat map, inventory, timeline, compliance)
    - Financial impact section
    - Role-specific sections (CISO, CFO)
    - Strategic narrative
    """

    def __init__(
        self,
        logo_path: Optional[str] = None,
        classification: str = "CONFIDENTIAL",
        debug: bool = False
    ):
        """
        Initialize DOCX report service.

        Args:
            logo_path: Optional path to logo image file
            classification: Classification level (CONFIDENTIAL, SECRET, etc.)
            debug: Enable debug logging
        """
        self.logo_path = logo_path
        self.classification = classification
        self.debug = debug
        self.style_manager = StyleManager()

        if debug:
            logger.setLevel(logging.DEBUG)

    def generate_executive_report(
        self,
        scan_data: Dict[str, Any],
        engagement_name: str,
        organization_name: str,
        output_dir: str = "./reports/",
        output_filename: Optional[str] = None
    ) -> str:
        """
        Generate professional executive report in DOCX format.

        Main entry point for report generation. Orchestrates:
        1. Document creation
        2. Template setup (cover, TOC, headers/footers)
        3. Executive summary extraction and building
        4. File writing

        Args:
            scan_data: Assessment results JSON from CAIP
            engagement_name: Name of engagement/assessment
            organization_name: Customer organization name
            output_dir: Directory for report output (default: ./reports/)
            output_filename: Optional custom filename (else auto-generated)

        Returns:
            Path to generated DOCX file

        Raises:
            ValueError: If scan_data is missing required fields
            IOError: If output directory cannot be created or written
        """
        # Validate inputs
        self._validate_inputs(scan_data, engagement_name, output_dir)

        # Create output directory
        output_path_obj = Path(output_dir)
        output_path_obj.mkdir(parents=True, exist_ok=True)

        # Generate filename if not provided
        if not output_filename:
            output_filename = self._generate_filename(engagement_name)

        full_output_path = output_path_obj / output_filename

        try:
            logger.info(f"Starting DOCX generation: {engagement_name}")

            # 1. Create document
            doc = Document()
            logger.debug("Document created")

            # 2. Add headers/footers BEFORE cover page
            HeaderFooterBuilder.add_headers_and_footers(
                doc,
                self.style_manager,
                classification=self.classification,
                organization_name=organization_name
            )
            logger.debug("Headers/footers added")

            # 3. Configure to skip header on first page (cover page)
            HeaderFooterBuilder.skip_header_on_first_page(doc)
            logger.debug("Configured different first page")

            # 4. Build cover page
            report_date = datetime.now().strftime("%Y-%m-%d")
            CoverPageBuilder.build(
                doc,
                self.style_manager,
                engagement_name=engagement_name,
                organization_name=organization_name,
                report_date=report_date,
                classification=self.classification,
                logo_path=self.logo_path
            )
            logger.debug("Cover page built")

            # 5. Build table of contents
            TableOfContentsBuilder.build(doc, self.style_manager)
            logger.debug("Table of contents built")

            # 6. Extract and build executive summary
            extractor = ExecutiveSummaryDataExtractor(scan_data)
            summary_data = extractor.extract()
            logger.debug(f"Summary data extracted: {summary_data.risk_rating} risk rating")

            # OLD FLOW (commented out - replaced by redesigned flow below)
            # ExecutiveSummaryBuilder.build(doc, self.style_manager, summary_data)
            # logger.debug("Executive summary built")

            # NEW FLOW: Use redesigned document structure
            # This restructures the entire document to follow decision-making flow:
            # 1. Risk Dashboard (page 1)
            # 2. Business Impact (pages 2-3)
            # 3. Visual Diagnostics / Charts (pages 4-5)
            # 4. Remediation Roadmap (pages 6-8)
            # 5. Appendix / Detailed Findings (pages 9+)

            # 7. Generate financial analysis (needed for Business Impact + Remediation sections)
            financial_summary = {}
            try:
                from .engagement_docx_builder import generate_engagement_financial_analysis
                if 'findings' in scan_data and 'certificates' in scan_data:
                    financial_summary = generate_engagement_financial_analysis(scan_data)
                    logger.debug("Financial analysis generated for redesigned flow")
            except Exception as e:
                logger.debug(f"Financial analysis not available for redesigned flow: {e}")

            # 8. Generate charts (needed for Visual Diagnostics section)
            charts = {}
            try:
                charts = self._get_charts_for_document(scan_data, output_path_obj)
                logger.debug(f"Generated {len(charts)} charts for redesigned flow")
            except Exception as e:
                logger.debug(f"Charts not available for redesigned flow: {e}")

            # 9. Apply redesigned document structure (includes charts and financial in correct positions)
            try:
                from .executive_report_redesigned import ExecutiveReportRedesigned
                redesigned = ExecutiveReportRedesigned()
                # Extract document_assessments from scan_data if available
                document_assessments = scan_data.get('document_assessments', [])
                redesigned.restructure_document_flow(doc, summary_data, charts, financial_summary, self.style_manager, document_assessments)
                logger.debug("Applied redesigned document flow")
            except Exception as e:
                # Fallback to old summary if redesign fails
                logger.warning(f"Redesigned flow failed, using fallback: {e}")
                ExecutiveSummaryBuilder.build(doc, self.style_manager, summary_data)
                logger.debug("Using fallback executive summary")

            # 11. Save document
            doc.save(str(full_output_path))
            logger.info(f"DOCX report generated: {full_output_path}")

            return str(full_output_path)

        except Exception as e:
            logger.error(f"Error generating DOCX report: {e}", exc_info=True)
            raise

    def _add_charts_to_document(self, doc: Document, scan_data: Dict[str, Any],
                               output_dir: Path) -> None:
        """
        Add visual charts to DOCX document if available.

        Attempts to generate and add charts from scan data. If chart generation
        is not available or fails, continues without charts (graceful degradation).

        Args:
            doc: python-docx Document object
            scan_data: Scan/assessment data containing findings and certificates
            output_dir: Directory for temporary chart files
        """
        try:
            # Check if this is engagement data (has merged structure)
            if 'findings' not in scan_data or 'certificates' not in scan_data:
                logger.debug("Scan data does not contain findings/certificates - skipping charts")
                return

            # Try to import and use chart builder
            try:
                from .engagement_docx_charts import EngagementChartSectionBuilder
                from .engagement_docx_builder import generate_engagement_charts_for_docx
            except ImportError:
                logger.debug("Chart modules not available - skipping charts")
                return

            # Generate charts
            logger.debug("Generating charts for document")
            charts = generate_engagement_charts_for_docx(scan_data, str(output_dir))

            if not charts:
                logger.debug("No charts generated")
                return

            # Add charts to document
            chart_builder = EngagementChartSectionBuilder()
            chart_builder.add_charts_to_document(doc, charts, self.style_manager)

        except Exception as e:
            # Log warning but don't fail document generation
            logger.warning(f"Could not add charts to document: {e}")
            # Continue without charts (graceful degradation)

    def _add_financial_section_to_document(self, doc: Document,
                                          scan_data: Dict[str, Any]) -> None:
        """
        Add financial impact analysis section to DOCX document if available.

        Attempts to generate and add financial analysis from scan data. If financial
        analysis is not available or fails, continues without it (graceful degradation).

        Args:
            doc: python-docx Document object
            scan_data: Scan/assessment data containing findings and certificates
        """
        try:
            # Check if this is engagement data (has merged structure)
            if 'findings' not in scan_data or 'certificates' not in scan_data:
                logger.debug("Scan data does not contain findings/certificates - skipping financial analysis")
                return

            # Try to import and use financial builder
            try:
                from .engagement_financial_section import EngagementFinancialSectionBuilder
                from .engagement_docx_builder import generate_engagement_financial_analysis
            except ImportError:
                logger.debug("Financial modules not available - skipping financial analysis")
                return

            # Generate financial analysis
            logger.debug("Generating financial analysis for document")
            financial_summary = generate_engagement_financial_analysis(scan_data)

            if not financial_summary:
                logger.debug("No financial analysis generated")
                return

            # Add financial section to document
            financial_builder = EngagementFinancialSectionBuilder()
            financial_builder.add_financial_section_to_document(doc, financial_summary, self.style_manager)

        except Exception as e:
            # Log warning but don't fail document generation
            logger.warning(f"Could not add financial section to document: {e}")
            # Continue without financial section (graceful degradation)

    # ==================== Private Methods ====================

    def _get_charts_for_document(self, scan_data: Dict[str, Any], output_dir: Path) -> Dict[str, str]:
        """
        Generate charts for document if engagement data available.

        Args:
            scan_data: Scan/assessment data
            output_dir: Directory for chart files

        Returns:
            Dictionary of chart names to file paths
        """
        try:
            if 'findings' not in scan_data or 'certificates' not in scan_data:
                logger.debug("Scan data does not contain findings/certificates - no charts")
                return {}

            from .engagement_docx_builder import generate_engagement_charts_for_docx
            charts = generate_engagement_charts_for_docx(scan_data, str(output_dir))
            return charts if charts else {}

        except Exception as e:
            logger.debug(f"Could not generate charts: {e}")
            return {}

    def _validate_inputs(
        self,
        scan_data: Dict[str, Any],
        engagement_name: str,
        output_dir: str
    ) -> None:
        """
        Validate input parameters.

        Args:
            scan_data: Assessment results
            engagement_name: Engagement name
            output_dir: Output directory path

        Raises:
            ValueError: If validation fails
        """
        if not isinstance(scan_data, dict):
            raise ValueError("scan_data must be a dictionary")

        if not engagement_name or not isinstance(engagement_name, str):
            raise ValueError("engagement_name must be a non-empty string")

        if not output_dir or not isinstance(output_dir, str):
            raise ValueError("output_dir must be a non-empty string")

        # Verify output directory is writable
        try:
            test_path = Path(output_dir)
            test_path.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            raise ValueError(f"No write permission for output directory: {output_dir}")

    def _generate_filename(self, engagement_name: str) -> str:
        """
        Generate standardized filename for report.

        Format: {engagement_name_sanitized}_executive_{YYYYMMDD}.docx

        Args:
            engagement_name: Engagement name

        Returns:
            Generated filename
        """
        # Sanitize engagement name (remove special chars, replace spaces with underscores)
        sanitized = "".join(
            c if c.isalnum() or c == ' ' else ''
            for c in engagement_name
        ).strip()
        sanitized = sanitized.replace(' ', '_').lower()

        # Add date
        date_str = datetime.now().strftime("%Y%m%d")

        return f"{sanitized}_executive_{date_str}.docx"

    # ==================== Integration Methods (Phase 1+) ====================

    def generate_executive_report_from_file(
        self,
        json_file: str,
        engagement_name: str,
        organization_name: str,
        output_dir: str = "./reports/"
    ) -> str:
        """
        Generate report from JSON assessment file.

        Convenience method for file-based input.

        Args:
            json_file: Path to JSON assessment file
            engagement_name: Engagement name
            organization_name: Organization name
            output_dir: Output directory

        Returns:
            Path to generated DOCX file
        """
        import json

        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                scan_data = json.load(f)
        except FileNotFoundError:
            raise IOError(f"JSON file not found: {json_file}")
        except json.JSONDecodeError:
            raise ValueError(f"Invalid JSON file: {json_file}")

        return self.generate_executive_report(
            scan_data,
            engagement_name,
            organization_name,
            output_dir
        )


# ==================== Convenience Functions ====================

def generate_docx_report(
    scan_results: Dict[str, Any],
    engagement_name: str,
    organization_name: str,
    output_dir: str = "./reports/",
    logo_path: Optional[str] = None,
    classification: str = "CONFIDENTIAL"
) -> str:
    """
    Convenience function for generating DOCX reports.

    Equivalent to:
        service = ExecutiveReportDocxService(logo_path=logo_path)
        return service.generate_executive_report(...)

    Args:
        scan_results: Assessment results JSON
        engagement_name: Engagement name
        organization_name: Organization name
        output_dir: Output directory (default ./reports/)
        logo_path: Optional logo image path
        classification: Classification marking

    Returns:
        Path to generated DOCX file
    """
    service = ExecutiveReportDocxService(
        logo_path=logo_path,
        classification=classification
    )
    return service.generate_executive_report(
        scan_results,
        engagement_name,
        organization_name,
        output_dir
    )


if __name__ == "__main__":
    # Example usage
    import sys
    import json

    if len(sys.argv) < 3:
        print("Usage: python executive_report_docx_service.py <json_file> <engagement_name> [org_name] [output_dir]")
        sys.exit(1)

    json_file = sys.argv[1]
    engagement_name = sys.argv[2]
    org_name = sys.argv[3] if len(sys.argv) > 3 else engagement_name
    output_dir = sys.argv[4] if len(sys.argv) > 4 else "./reports/"

    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        result = generate_docx_report(
            data,
            engagement_name,
            org_name,
            output_dir
        )

        print(f"✓ Report generated: {result}")

    except Exception as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        sys.exit(1)
