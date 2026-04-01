# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: caip_reporting_functions/executive_report_service.py
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
Executive Report Service for CAIP - Enhanced Version

Generates professional PDF executive summary reports from scan results.
Provides:
- Executive summary with risk posture overview
- Key findings breakdown by severity
- Detailed findings with compliance impact
- Prioritized remediation roadmap

Uses reportlab for PDF generation with enhanced corporate styling.
"""

import os
import datetime
from datetime import timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import logging
import json

# ReportLab imports
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle,
    Image, ListFlowable, ListItem, KeepTogether, CondPageBreak
)
from reportlab.platypus.flowables import HRFlowable, Flowable
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie

logger = logging.getLogger('caip.operational')


class RoundedRect(Flowable):
    """A rounded rectangle flowable for visual elements."""
    def __init__(self, width, height, radius=5, fill_color=None, stroke_color=None):
        Flowable.__init__(self)
        self.width = width
        self.height = height
        self.radius = radius
        self.fill_color = fill_color
        self.stroke_color = stroke_color

    def draw(self):
        self.canv.saveState()
        if self.fill_color:
            self.canv.setFillColor(self.fill_color)
        if self.stroke_color:
            self.canv.setStrokeColor(self.stroke_color)
        self.canv.roundRect(0, 0, self.width, self.height, self.radius, 
                           fill=1 if self.fill_color else 0,
                           stroke=1 if self.stroke_color else 0)
        self.canv.restoreState()


class ExecutiveReportService:
    """
    Service for generating executive summary PDF reports.
    
    Transforms scan findings into professional executive reports with:
    - Risk posture assessment
    - Severity-based findings breakdown
    - Compliance impact analysis
    - Prioritized remediation roadmap
    """
    
    # Severity order for sorting (highest first)
    SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'informational': 4}
    
    # Enhanced corporate color scheme
    COLORS = {
        'primary': colors.HexColor('#0D1B2A'),       # Deep navy
        'primary_light': colors.HexColor('#1B3A5F'), # Navy blue
        'secondary': colors.HexColor('#415A77'),     # Steel blue
        'accent': colors.HexColor('#778DA9'),        # Muted blue
        'highlight': colors.HexColor('#E0E1DD'),     # Light gray
        'critical': colors.HexColor('#C1121F'),      # Deep red
        'critical_bg': colors.HexColor('#FFE5E5'),   # Light red bg
        'high': colors.HexColor('#E36414'),          # Burnt orange
        'high_bg': colors.HexColor('#FFF3E0'),       # Light orange bg
        'medium': colors.HexColor('#F4A261'),        # Sandy orange
        'medium_bg': colors.HexColor('#FFF8E1'),     # Light yellow bg
        'low': colors.HexColor('#2A9D8F'),           # Teal
        'low_bg': colors.HexColor('#E0F2F1'),        # Light teal bg
        'info': colors.HexColor('#6C757D'),          # Gray
        'info_bg': colors.HexColor('#F5F5F5'),       # Light gray bg
        'text': colors.HexColor('#1E293B'),          # Dark slate
        'text_secondary': colors.HexColor('#64748B'), # Slate gray
        'light_bg': colors.HexColor('#F8FAFC'),      # Very light bg
        'white': colors.HexColor('#FFFFFF'),
        'border': colors.HexColor('#CBD5E1'),        # Border gray
        'success': colors.HexColor('#059669'),       # Green
        'table_header': colors.HexColor('#1E3A5F'),  # Dark blue header
        'table_alt': colors.HexColor('#F1F5F9'),     # Alternating row
    }
    
    # Governance impact descriptions for different finding categories
    GOVERNANCE_IMPACTS = {
        'cryptography': {
            'title': 'Cryptographic Controls',
            'critical': 'Weak or compromised cryptographic controls can result in complete loss of data confidentiality and integrity. This directly impacts the organisation\'s ability to protect sensitive information and maintain trust with stakeholders, regulators, and customers.',
            'high': 'Inadequate cryptographic implementations create exploitable vulnerabilities that could be leveraged by sophisticated threat actors. This represents a material risk to information security governance.',
            'medium': 'Sub-optimal cryptographic configurations indicate gaps in security standards implementation. While not immediately exploitable, these weaken the overall security posture.',
            'low': 'Minor deviations from cryptographic best practices. These should be addressed as part of continuous improvement to maintain defence-in-depth.'
        },
        'expiration': {
            'title': 'Certificate Lifecycle Management',
            'critical': 'Expired or imminently expiring certificates pose immediate operational risk. Certificate failures can cause service outages, break authentication chains, and disrupt business operations.',
            'high': 'Certificates approaching expiry without renewal plans indicate governance gaps in lifecycle management. This creates operational risk and potential compliance exposure.',
            'medium': 'Certificate validity periods outside policy parameters suggest process improvements are needed in lifecycle monitoring and renewal workflows.',
            'low': 'Minor certificate validity observations. Ensure lifecycle management processes are capturing all assets.'
        },
        'compliance': {
            'title': 'Regulatory & Standards Compliance',
            'critical': 'Non-compliance with regulatory requirements creates immediate legal and financial exposure. This may result in regulatory action, fines, or loss of operating licenses.',
            'high': 'Significant compliance gaps that could be cited in audits or regulatory examinations. These require management attention and remediation planning.',
            'medium': 'Compliance observations that should be addressed to maintain audit readiness and demonstrate due diligence.',
            'low': 'Minor compliance observations. Document rationale if deviations are accepted as part of risk acceptance process.'
        },
        'configuration': {
            'title': 'Security Configuration Management',
            'critical': 'Critical misconfigurations that could be exploited to compromise PKI infrastructure. These represent fundamental security architecture issues requiring immediate attention.',
            'high': 'Configuration weaknesses that deviate from security hardening standards. These reduce the effectiveness of security controls and increase attack surface.',
            'medium': 'Configuration items that should be reviewed against security baselines. These represent improvement opportunities.',
            'low': 'Minor configuration observations. Consider addressing during regular maintenance cycles.'
        },
        'key_management': {
            'title': 'Key Management Practices',
            'critical': 'Severe key management deficiencies that could result in key compromise or loss of key control. This directly threatens the integrity of the entire PKI trust model.',
            'high': 'Key management practices that deviate significantly from industry standards. These create risk of key exposure or misuse.',
            'medium': 'Key management process improvements identified. Addressing these will strengthen overall key governance.',
            'low': 'Minor key management observations. These represent opportunities to enhance key lifecycle processes.'
        },
        'revocation': {
            'title': 'Certificate Revocation Controls',
            'critical': 'Revocation mechanism failures mean compromised certificates cannot be effectively invalidated. This creates ongoing risk exposure even after incident detection.',
            'high': 'Revocation process gaps that could delay response to certificate compromise. Timely revocation is essential for incident containment.',
            'medium': 'Revocation configuration improvements identified. These will enhance incident response capabilities.',
            'low': 'Minor revocation observations. Ensure revocation testing is part of operational procedures.'
        },
        'general': {
            'title': 'General Security Controls',
            'critical': 'Critical security control failures requiring immediate executive attention and remediation resources.',
            'high': 'Significant security control gaps that should be prioritised in remediation planning.',
            'medium': 'Security control improvements that will strengthen overall posture when addressed.',
            'low': 'Minor security observations for continuous improvement consideration.'
        }
    }
    
    def __init__(self, logo_path: Optional[str] = None, company_name: str = "Thales"):
        """
        Initialize the executive report service.
        
        Args:
            logo_path: Optional path to company logo image
            company_name: Company name for branding
        """
        self.logo_path = logo_path
        self.company_name = company_name
        self.styles = self._create_styles()
    
    def _create_styles(self) -> Dict[str, ParagraphStyle]:
        """Create custom paragraph styles for the report."""
        base_styles = getSampleStyleSheet()
        
        custom_styles = {
            'CoverTitle': ParagraphStyle(
                'CoverTitle',
                parent=base_styles['Title'],
                fontSize=32,
                textColor=self.COLORS['primary'],
                spaceAfter=12,
                alignment=TA_CENTER,
                fontName='Helvetica-Bold',
                leading=38
            ),
            'CoverSubtitle': ParagraphStyle(
                'CoverSubtitle',
                parent=base_styles['Normal'],
                fontSize=14,
                textColor=self.COLORS['text_secondary'],
                spaceAfter=8,
                alignment=TA_CENTER,
                fontName='Helvetica'
            ),
            'SectionHeading': ParagraphStyle(
                'SectionHeading',
                parent=base_styles['Heading1'],
                fontSize=18,
                textColor=self.COLORS['primary'],
                spaceBefore=24,
                spaceAfter=12,
                fontName='Helvetica-Bold',
                leading=22,
            ),
            'SubHeading': ParagraphStyle(
                'SubHeading',
                parent=base_styles['Heading2'],
                fontSize=13,
                textColor=self.COLORS['primary_light'],
                spaceBefore=16,
                spaceAfter=8,
                fontName='Helvetica-Bold',
                leading=16
            ),
            'SubHeading2': ParagraphStyle(
                'SubHeading2',
                parent=base_styles['Heading3'],
                fontSize=11,
                textColor=self.COLORS['secondary'],
                spaceBefore=12,
                spaceAfter=6,
                fontName='Helvetica-Bold',
                leading=14
            ),
            'BodyText': ParagraphStyle(
                'BodyText',
                parent=base_styles['Normal'],
                fontSize=10,
                textColor=self.COLORS['text'],
                spaceBefore=4,
                spaceAfter=8,
                alignment=TA_JUSTIFY,
                fontName='Helvetica',
                leading=14
            ),
            'BodyTextNoSpace': ParagraphStyle(
                'BodyTextNoSpace',
                parent=base_styles['Normal'],
                fontSize=10,
                textColor=self.COLORS['text'],
                spaceBefore=0,
                spaceAfter=0,
                fontName='Helvetica',
                leading=13
            ),
            'GovernanceText': ParagraphStyle(
                'GovernanceText',
                parent=base_styles['Normal'],
                fontSize=9,
                textColor=self.COLORS['text'],
                spaceBefore=4,
                spaceAfter=6,
                alignment=TA_JUSTIFY,
                fontName='Helvetica-Oblique',
                leading=12,
                leftIndent=10,
                rightIndent=10,
                backColor=self.COLORS['light_bg']
            ),
            'FindingTitle': ParagraphStyle(
                'FindingTitle',
                parent=base_styles['Normal'],
                fontSize=11,
                textColor=self.COLORS['primary'],
                spaceBefore=0,
                spaceAfter=4,
                fontName='Helvetica-Bold',
                leading=14
            ),
            'FindingBody': ParagraphStyle(
                'FindingBody',
                parent=base_styles['Normal'],
                fontSize=9,
                textColor=self.COLORS['text'],
                spaceBefore=2,
                spaceAfter=4,
                fontName='Helvetica',
                leading=12
            ),
            'FindingLabel': ParagraphStyle(
                'FindingLabel',
                parent=base_styles['Normal'],
                fontSize=8,
                textColor=self.COLORS['text_secondary'],
                spaceBefore=0,
                spaceAfter=0,
                fontName='Helvetica-Bold',
                leading=10
            ),
            'BulletText': ParagraphStyle(
                'BulletText',
                parent=base_styles['Normal'],
                fontSize=10,
                textColor=self.COLORS['text'],
                leftIndent=15,
                spaceBefore=2,
                spaceAfter=4,
                fontName='Helvetica',
                leading=13
            ),
            'TableHeader': ParagraphStyle(
                'TableHeader',
                parent=base_styles['Normal'],
                fontSize=9,
                textColor=colors.white,
                fontName='Helvetica-Bold',
                alignment=TA_LEFT,
                leading=11
            ),
            'TableCell': ParagraphStyle(
                'TableCell',
                parent=base_styles['Normal'],
                fontSize=8,
                textColor=self.COLORS['text'],
                fontName='Helvetica',
                leading=11,
                wordWrap='CJK'
            ),
            'TableCellBold': ParagraphStyle(
                'TableCellBold',
                parent=base_styles['Normal'],
                fontSize=8,
                textColor=self.COLORS['text'],
                fontName='Helvetica-Bold',
                leading=11
            ),
            'Footer': ParagraphStyle(
                'Footer',
                parent=base_styles['Normal'],
                fontSize=8,
                textColor=self.COLORS['text_secondary'],
                alignment=TA_CENTER,
                fontName='Helvetica'
            ),
            'Callout': ParagraphStyle(
                'Callout',
                parent=base_styles['Normal'],
                fontSize=10,
                textColor=self.COLORS['primary'],
                fontName='Helvetica-Oblique',
                alignment=TA_CENTER,
                spaceBefore=8,
                spaceAfter=8
            ),
            'StatNumber': ParagraphStyle(
                'StatNumber',
                parent=base_styles['Normal'],
                fontSize=24,
                textColor=self.COLORS['primary'],
                fontName='Helvetica-Bold',
                alignment=TA_CENTER
            ),
            'StatLabel': ParagraphStyle(
                'StatLabel',
                parent=base_styles['Normal'],
                fontSize=9,
                textColor=self.COLORS['text_secondary'],
                fontName='Helvetica',
                alignment=TA_CENTER
            ),
        }
        
        return custom_styles
    
    def generate_executive_report(self,
                                   report_data: Dict[str, Any],
                                   report_name: str,
                                   report_type: str,
                                   output_path: str,
                                   document_assessment: Optional[Dict[str, Any]] = None,
                                   policy: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate a complete executive summary PDF report.
        
        Args:
            report_data: Complete report data from scan/reassessment/aggregation
            report_name: Name of the report/scan
            report_type: Type of report ('scan', 'reassessment', 'aggregation')
            output_path: Full path where PDF will be saved
            document_assessment: Optional document assessment data to include
            policy: Optional policy data (if not in report_data)
            
        Returns:
            Path to generated PDF file
        """
        try:
            # Create the PDF document
            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=0.6*inch,
                leftMargin=0.6*inch,
                topMargin=0.6*inch,
                bottomMargin=0.6*inch
            )
            
            # Build the story (content)
            story = []
            
            # Extract and analyze findings
            findings = report_data.get('findings', [])
            findings_analysis = self._analyze_findings(findings)
            
            # Extract metadata
            metadata = report_data.get('metadata', {})
            # Use provided policy or fall back to policy in report_data
            if policy is None:
                policy = report_data.get('policy', {})
            collector_summaries = report_data.get('collector_summaries', {})
            
            # Determine if this is a combined report
            is_combined_report = document_assessment is not None
            
            # Track section numbers
            section_num = 1
            
            # 1. Cover Page
            story.extend(self._build_cover_page(report_name, report_type, metadata, 
                                                is_combined=is_combined_report))
            story.append(PageBreak())
            
            # 2. Executive Summary (Crypto Assets)
            story.extend(self._build_executive_summary(
                report_data, findings_analysis, metadata, policy, section_num
            ))
            section_num += 1
            
            # 3. Document Assessment Section (if provided)
            if document_assessment:
                story.append(PageBreak())
                story.extend(self._build_document_assessment_section(document_assessment, section_num))
                section_num += 1
                # Combined Risk Summary
                story.extend(self._build_combined_risk_summary(findings_analysis, document_assessment, section_num))
                section_num += 1
            
            story.append(PageBreak())
            
            # Key Findings Overview (Crypto)
            story.extend(self._build_key_findings_overview(findings_analysis, section_num))
            section_num += 1
            
            # Detailed Findings by Severity
            story.extend(self._build_detailed_findings(findings, policy, findings_analysis, section_num))
            section_num += 1
            story.append(PageBreak())
            
            # Remediation Roadmap
            story.extend(self._build_remediation_roadmap(findings, findings_analysis, section_num))
            section_num += 1
            story.append(PageBreak())
            
            # Appendix
            story.extend(self._build_appendix(metadata, collector_summaries, policy, 
                                              document_assessment=document_assessment,
                                              section_num=section_num))
            
            # Build the PDF
            doc.build(story, onFirstPage=self._add_page_header_footer,
                     onLaterPages=self._add_page_header_footer)
            
            logger.info(f"Executive report generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error generating executive report: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    def _analyze_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze findings to extract summary statistics."""
        analysis = {
            'total': len(findings),
            'by_severity': defaultdict(list),
            'by_category': defaultdict(list),
            'total_risk_score': 0.0,
            'max_risk_score': 0.0,
            'compliance_frameworks': set(),
            'severity_counts': defaultdict(int),
            'unique_rules': set(),
            'affected_entities': set()
        }
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            category = finding.get('category', 'general')
            risk_score = finding.get('risk_score', 0.0)
            compliance_impact = finding.get('compliance_impact', '')
            rule_id = finding.get('rule_id', '')
            evidence = finding.get('evidence', {})
            
            analysis['by_severity'][severity].append(finding)
            analysis['by_category'][category].append(finding)
            analysis['severity_counts'][severity] += 1
            analysis['total_risk_score'] += risk_score
            analysis['max_risk_score'] = max(analysis['max_risk_score'], risk_score)
            
            if rule_id:
                analysis['unique_rules'].add(rule_id)
            
            # Track affected entities
            affected = evidence.get('affected_entity', evidence.get('subject_cn', ''))
            if affected:
                analysis['affected_entities'].add(affected)
            
            # Extract compliance frameworks mentioned
            if compliance_impact:
                for framework in ['NCSC', 'GCHQ', 'PCI-DSS', 'PCI DSS', 'ISO 27001', 
                                 'ISO/IEC 27001', 'NIST', 'SOC 2', 'GDPR', 'HIPAA',
                                 'CAB Forum', 'CA/Browser']:
                    if framework.lower() in compliance_impact.lower():
                        analysis['compliance_frameworks'].add(framework)
        
        # Calculate average risk score
        if analysis['total'] > 0:
            analysis['avg_risk_score'] = analysis['total_risk_score'] / analysis['total']
        else:
            analysis['avg_risk_score'] = 0.0
        
        return analysis
    
    def _build_cover_page(self, report_name: str, report_type: str,
                          metadata: Dict[str, Any], is_combined: bool = False) -> List:
        """Build the cover page elements."""
        elements = []
        
        # Add spacing at top
        elements.append(Spacer(1, 0.8*inch))
        
        # Logo (if available)
        if self.logo_path and os.path.exists(self.logo_path):
            try:
                logo = Image(self.logo_path, width=2.2*inch, height=0.8*inch)
                logo.hAlign = 'CENTER'
                elements.append(logo)
                elements.append(Spacer(1, 0.4*inch))
            except Exception as e:
                logger.warning(f"Could not load logo: {e}")
        
        # Company name
        elements.append(Paragraph(self.company_name.upper(), ParagraphStyle(
            'CompanyName',
            parent=self.styles['CoverSubtitle'],
            fontSize=12,
            letterSpacing=3,
            textColor=self.COLORS['secondary']
        )))
        elements.append(Spacer(1, 0.5*inch))
        
        # Decorative line
        elements.append(HRFlowable(width="40%", thickness=2, color=self.COLORS['primary'], hAlign='CENTER'))
        elements.append(Spacer(1, 0.3*inch))
        
        # Title
        if is_combined:
            title_text = "PKI & Documentation Assessment"
        else:
            title_text = "PKI Security Assessment"
        elements.append(Paragraph(title_text, self.styles['CoverTitle']))
        elements.append(Paragraph("Executive Summary Report", ParagraphStyle(
            'CoverSubtitle2',
            parent=self.styles['CoverSubtitle'],
            fontSize=16,
            textColor=self.COLORS['primary_light']
        )))
        elements.append(Spacer(1, 0.3*inch))
        
        # Decorative line
        elements.append(HRFlowable(width="40%", thickness=2, color=self.COLORS['primary'], hAlign='CENTER'))
        elements.append(Spacer(1, 0.6*inch))
        
        # Report details in a styled box
        if is_combined:
            report_type_display = {
                'scan': 'Combined Security & Documentation Scan',
                'reassessment': 'Combined Policy & Documentation Reassessment',
                'aggregation': 'Combined Aggregated Analysis',
                'engagement': 'Customer Engagement Assessment'
            }.get(report_type, 'Combined Assessment')
        else:
            report_type_display = {
                'scan': 'Security Scan Assessment',
                'reassessment': 'Policy Reassessment',
                'aggregation': 'Aggregated Analysis',
                'engagement': 'Customer Engagement Assessment'
            }.get(report_type, 'Assessment')
        
        # Report info
        report_date = datetime.datetime.now().strftime('%d %B %Y')
        
        info_data = [
            ['Report Name', report_name],
            ['Report Type', report_type_display],
            ['Report Date', report_date],
        ]
        
        # Add customer/project info if available
        if metadata.get('customer_name'):
            info_data.insert(0, ['Customer', metadata['customer_name']])
        if metadata.get('project_name'):
            info_data.insert(1, ['Project', metadata['project_name']])
        if metadata.get('engagement_id'):
            info_data.append(['Engagement ID', metadata['engagement_id']])
        if metadata.get('lead_consultant'):
            info_data.append(['Lead Consultant', metadata['lead_consultant']])
        
        info_table = Table([[Paragraph(k, self.styles['TableCellBold']),
                            Paragraph(str(v), self.styles['TableCell'])] for k, v in info_data],
                          colWidths=[1.8*inch, 3.5*inch])
        info_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
            ('BACKGROUND', (0, 0), (0, -1), self.COLORS['light_bg']),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ]))
        
        # Center the table
        centered_table = Table([[info_table]], colWidths=[5.5*inch])
        centered_table.setStyle(TableStyle([('ALIGN', (0, 0), (-1, -1), 'CENTER')]))
        elements.append(centered_table)
        
        # Confidentiality notice at bottom
        elements.append(Spacer(1, 1.5*inch))
        elements.append(Paragraph("CONFIDENTIAL", ParagraphStyle(
                                               'Confidential',
                                               parent=self.styles['CoverSubtitle'],
                                               textColor=self.COLORS['critical'],
                                               fontSize=10,
                                               fontName='Helvetica-Bold')))
        elements.append(Paragraph("This document contains sensitive security information", 
                                 ParagraphStyle('ConfidentialSub', 
                                               parent=self.styles['CoverSubtitle'],
                                               textColor=self.COLORS['text_secondary'],
                                               fontSize=9)))
        
        return elements
    
    def _build_executive_summary(self, report_data: Dict[str, Any],
                                  findings_analysis: Dict[str, Any],
                                  metadata: Dict[str, Any],
                                  policy: Dict[str, Any],
                                  section_num: int = 1) -> List:
        """Build the executive summary section with enhanced context."""
        elements = []
        
        elements.append(Paragraph(f"{section_num}. Executive Summary", self.styles['SectionHeading']))
        elements.append(HRFlowable(width="100%", thickness=2, color=self.COLORS['primary']))
        elements.append(Spacer(1, 0.15*inch))
        
        # Key metrics
        total_certs = metadata.get('total_certificates', len(report_data.get('certificates', [])))
        total_keys = metadata.get('total_keys', len(report_data.get('keys', [])))
        total_findings = findings_analysis['total']
        
        critical_count = findings_analysis['severity_counts'].get('critical', 0)
        high_count = findings_analysis['severity_counts'].get('high', 0)
        medium_count = findings_analysis['severity_counts'].get('medium', 0)
        low_count = findings_analysis['severity_counts'].get('low', 0)
        
        # Purpose and Scope
        elements.append(Paragraph(f"{section_num}.1 Purpose and Scope", self.styles['SubHeading']))
        
        scope_text = f"""This report presents the findings from a comprehensive security assessment of the 
        Public Key Infrastructure (PKI) environment. The assessment evaluated <b>{total_certs:,} certificates</b> 
        and <b>{total_keys:,} cryptographic keys</b> against established security policies and industry best practices."""
        elements.append(Paragraph(scope_text, self.styles['BodyText']))
        
        policy_meta = policy.get('metadata', {}) if policy else {}
        policy_name = policy_meta.get('name', 'Default Security Policy')
        
        methodology_text = f"""The assessment was conducted using the <b>{policy_name}</b>, which incorporates 
        requirements from recognised security frameworks and regulatory standards. Each cryptographic asset was 
        evaluated for compliance with defined security controls, configuration best practices, and operational requirements."""
        elements.append(Paragraph(methodology_text, self.styles['BodyText']))
        
        # Key Statistics in visual format
        elements.append(Spacer(1, 0.1*inch))
        elements.append(Paragraph(f"{section_num}.2 Assessment Overview", self.styles['SubHeading']))
        
        # Create statistics as 4 separate mini-tables side by side
        def make_stat_box(value, label):
            """Create a single stat box with value above label."""
            value_style = ParagraphStyle('SV', fontSize=22, 
                       textColor=self.COLORS['primary'], alignment=TA_CENTER, 
                       fontName='Helvetica-Bold', leading=24)
            label_style = ParagraphStyle('SL', fontSize=8, 
                       textColor=self.COLORS['text_secondary'], alignment=TA_CENTER,
                       leading=10)
            
            inner = Table(
                [[Paragraph(f"<b>{value}</b>", value_style)],
                 [Paragraph(label, label_style)]],
                colWidths=[1.5*inch],
                rowHeights=[0.45*inch, 0.4*inch]
            )
            inner.setStyle(TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (0, 0), 'BOTTOM'),
                ('VALIGN', (0, 1), (0, 1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 0),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
            ]))
            return inner
        
        stat_boxes = [
            make_stat_box(str(total_certs), "Certificates<br/>Assessed"),
            make_stat_box(str(total_keys), "Keys<br/>Assessed"),
            make_stat_box(str(total_findings), "Total<br/>Findings"),
            make_stat_box(str(len(findings_analysis['unique_rules'])), "Rules<br/>Triggered"),
        ]
        
        stats_table = Table([stat_boxes], colWidths=[1.7*inch, 1.7*inch, 1.7*inch, 1.7*inch],
                           rowHeights=[0.95*inch])
        stats_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOX', (0, 0), (0, 0), 1, self.COLORS['border']),
            ('BOX', (1, 0), (1, 0), 1, self.COLORS['border']),
            ('BOX', (2, 0), (2, 0), 1, self.COLORS['border']),
            ('BOX', (3, 0), (3, 0), 1, self.COLORS['border']),
            ('BACKGROUND', (0, 0), (-1, -1), self.COLORS['light_bg']),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(stats_table)
        
        # Risk Posture Assessment
        elements.append(Spacer(1, 0.15*inch))
        elements.append(Paragraph(f"{section_num}.3 Risk Posture Assessment", self.styles['SubHeading']))
        
        # Determine overall risk level and provide contextual analysis
        if critical_count > 0:
            risk_level = "CRITICAL"
            risk_color = self.COLORS['critical']
            risk_context = self._generate_risk_context('critical', critical_count, high_count, 
                                                       total_findings, findings_analysis)
        elif high_count > 0:
            risk_level = "HIGH"
            risk_color = self.COLORS['high']
            risk_context = self._generate_risk_context('high', critical_count, high_count, 
                                                       total_findings, findings_analysis)
        elif medium_count > 0:
            risk_level = "MEDIUM"
            risk_color = self.COLORS['medium']
            risk_context = self._generate_risk_context('medium', critical_count, high_count, 
                                                       total_findings, findings_analysis)
        else:
            risk_level = "LOW"
            risk_color = self.COLORS['low']
            risk_context = self._generate_risk_context('low', critical_count, high_count, 
                                                       total_findings, findings_analysis)
        
        # Risk level indicator
        risk_table = Table(
            [[Paragraph(f"Overall Risk Level: <b>{risk_level}</b>", 
                       ParagraphStyle('RiskLevel', parent=self.styles['BodyText'],
                                     fontSize=12, textColor=colors.white, 
                                     fontName='Helvetica-Bold'))]],
            colWidths=[6.8*inch]
        )
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), risk_color),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('LEFTPADDING', (0, 0), (-1, -1), 15),
            ('RIGHTPADDING', (0, 0), (-1, -1), 15),
        ]))
        elements.append(risk_table)
        elements.append(Spacer(1, 0.1*inch))
        
        elements.append(Paragraph(risk_context, self.styles['BodyText']))
        
        # Findings distribution table
        elements.append(Spacer(1, 0.1*inch))
        severity_table_data = [
            [Paragraph('<b>Severity</b>', self.styles['TableHeader']),
             Paragraph('<b>Count</b>', self.styles['TableHeader']),
             Paragraph('<b>Percentage</b>', self.styles['TableHeader']),
             Paragraph('<b>Immediate Action Required</b>', self.styles['TableHeader'])]
        ]
        
        for sev, count in [('Critical', critical_count), ('High', high_count), 
                           ('Medium', medium_count), ('Low', low_count)]:
            pct = (count / total_findings * 100) if total_findings > 0 else 0
            action = "Yes - Urgent" if sev in ['Critical', 'High'] else "Recommended" if sev == 'Medium' else "Optional"
            severity_table_data.append([
                Paragraph(sev, self.styles['TableCell']),
                Paragraph(str(count), self.styles['TableCell']),
                Paragraph(f"{pct:.1f}%", self.styles['TableCell']),
                Paragraph(action, self.styles['TableCell'])
            ])
        
        severity_table = Table(severity_table_data, colWidths=[1.5*inch, 1*inch, 1.2*inch, 3.1*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['table_header']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('BACKGROUND', (0, 1), (-1, 1), self.COLORS['critical_bg']),
            ('BACKGROUND', (0, 2), (-1, 2), self.COLORS['high_bg']),
            ('BACKGROUND', (0, 3), (-1, 3), self.COLORS['medium_bg']),
            ('BACKGROUND', (0, 4), (-1, 4), self.COLORS['low_bg']),
            ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(severity_table)
        
        # Compliance Impact Summary
        if findings_analysis['compliance_frameworks']:
            elements.append(Spacer(1, 0.15*inch))
            elements.append(Paragraph(f"{section_num}.4 Compliance Implications", self.styles['SubHeading']))
            
            frameworks_list = sorted(findings_analysis['compliance_frameworks'])
            compliance_text = f"""The identified findings have potential implications for compliance with the following 
            regulatory frameworks and industry standards: <b>{', '.join(frameworks_list)}</b>."""
            elements.append(Paragraph(compliance_text, self.styles['BodyText']))
            
            compliance_detail = """Organisations subject to these requirements should prioritise remediation of 
            findings that directly impact compliance obligations. Failure to address critical and high-severity 
            findings may result in audit observations, regulatory penalties, or increased operational risk."""
            elements.append(Paragraph(compliance_detail, self.styles['BodyText']))
        
        return elements
    
    def _build_governance_maturity_summary(self, document_assessments: List[Dict[str, Any]],
                                          section_num: int = 2) -> List:
        """Build CxO-focused governance maturity summary for document assessments."""
        elements = []

        if not document_assessments:
            return elements

        elements.append(Paragraph(f"{section_num}. Governance Maturity Assessment", self.styles['SectionHeading']))
        elements.append(HRFlowable(width="100%", thickness=2, color=self.COLORS['primary']))
        elements.append(Spacer(1, 0.15*inch))

        # Intro text
        gov_summary = """The governance maturity assessment evaluates the completeness and quality of PKI policies,
        procedures, and operational documentation against industry-standard frameworks. Strong governance is critical
        for audit readiness, compliance, and operational consistency."""
        elements.append(Paragraph(gov_summary, self.styles['BodyText']))

        # Calculate aggregate metrics
        total_coverage = 0
        total_docs = len(document_assessments)
        framework_scores = {}
        critical_gaps = []

        for doc in document_assessments:
            coverage = doc.get('coverage_score', 0)
            total_coverage += coverage

            compliance_scores = doc.get('compliance_scores', {})
            if isinstance(compliance_scores, str):
                try:
                    compliance_scores = json.loads(compliance_scores)
                except:
                    compliance_scores = {}

            for framework, score in compliance_scores.items():
                if framework not in framework_scores:
                    framework_scores[framework] = []
                framework_scores[framework].append(score)

            # Extract critical/high severity missing items
            findings = doc.get('findings', [])
            for finding in findings:
                if finding.get('status') == 'missing' and finding.get('severity') in ['critical', 'high']:
                    critical_gaps.append({
                        'element': finding.get('element_name', 'Unknown'),
                        'severity': finding.get('severity', 'high'),
                        'doc': doc.get('filename', 'Unknown')
                    })

        avg_coverage = total_coverage / total_docs if total_docs > 0 else 0

        # Maturity grade based on coverage
        if avg_coverage >= 90:
            grade = 'A'
            grade_color = self.COLORS['success']
            maturity = 'Mature'
            interpretation = 'Governance framework is comprehensive and audit-ready'
        elif avg_coverage >= 75:
            grade = 'B'
            grade_color = self.COLORS['low']
            maturity = 'Developing'
            interpretation = 'Governance is largely established with minor gaps'
        elif avg_coverage >= 60:
            grade = 'C'
            grade_color = self.COLORS['medium']
            maturity = 'Emerging'
            interpretation = 'Governance foundation exists but needs strengthening'
        else:
            grade = 'D'
            grade_color = self.COLORS['high']
            maturity = 'Initial'
            interpretation = 'Governance framework requires significant development'

        # Display maturity summary with stat boxes
        elements.append(Spacer(1, 0.1*inch))

        def make_maturity_box(value, label, color=None):
            value_color = color if color else self.COLORS['primary']
            value_style = ParagraphStyle('MV', fontSize=24, textColor=value_color,
                                        alignment=TA_CENTER, fontName='Helvetica-Bold', leading=26)
            label_style = ParagraphStyle('ML', fontSize=9, textColor=self.COLORS['text_secondary'],
                                        alignment=TA_CENTER, leading=11)
            inner = Table([[Paragraph(f"<b>{value}</b>", value_style)],
                          [Paragraph(label, label_style)]],
                         colWidths=[1.4*inch], rowHeights=[0.45*inch, 0.35*inch])
            inner.setStyle(TableStyle([('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                                       ('VALIGN', (0, 0), (0, 0), 'BOTTOM'),
                                       ('VALIGN', (0, 1), (0, 1), 'TOP')]))
            return inner

        maturity_boxes = [
            make_maturity_box(grade, "Maturity<br/>Grade", grade_color),
            make_maturity_box(f"{avg_coverage:.0f}%", "Documentation<br/>Coverage"),
            make_maturity_box(maturity, "Readiness<br/>Level"),
        ]

        maturity_table = Table([maturity_boxes], colWidths=[1.5*inch, 1.5*inch, 1.5*inch], rowHeights=[0.85*inch])
        maturity_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOX', (0, 0), (0, 0), 1, self.COLORS['border']),
            ('BOX', (1, 0), (1, 0), 1, self.COLORS['border']),
            ('BOX', (2, 0), (2, 0), 1, self.COLORS['border']),
            ('BACKGROUND', (0, 0), (-1, -1), self.COLORS['light_bg']),
        ]))
        elements.append(maturity_table)

        # Interpretation
        elements.append(Spacer(1, 0.1*inch))
        elements.append(Paragraph(f"<b>Assessment:</b> {interpretation}", self.styles['BodyText']))

        # Framework compliance readiness
        if framework_scores:
            elements.append(Spacer(1, 0.1*inch))
            elements.append(Paragraph("Audit Readiness by Framework:", self.styles['BodyText']))

            framework_data = []
            for framework, scores in sorted(framework_scores.items()):
                avg_score = sum(scores) / len(scores) if scores else 0
                if avg_score >= 80:
                    status = 'Audit-Ready'
                    color = self.COLORS['success']
                    icon = '✓'
                elif avg_score >= 60:
                    status = 'Partial'
                    color = self.COLORS['medium']
                    icon = '~'
                else:
                    status = 'Needs Work'
                    color = self.COLORS['critical']
                    icon = '✗'

                framework_data.append([
                    framework,
                    f"{avg_score:.0f}%",
                    f'<font color="{color.hexval()}">{icon} {status}</font>'
                ])

            framework_data.insert(0, [
                Paragraph('<b>Framework</b>', self.styles['TableHeader']),
                Paragraph('<b>Score</b>', self.styles['TableHeader']),
                Paragraph('<b>Audit Status</b>', self.styles['TableHeader'])
            ])

            fw_table = Table(framework_data, colWidths=[2.2*inch, 1.2*inch, 2.1*inch])
            fw_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['table_header']),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            elements.append(fw_table)

        # Critical gaps affecting audit readiness
        if critical_gaps:
            elements.append(Spacer(1, 0.15*inch))
            elements.append(Paragraph("Critical Governance Gaps (Audit Risk):", self.styles['BodyText']))

            # Show top 3-5 critical gaps
            top_gaps = sorted(critical_gaps, key=lambda g: 0 if g['severity'] == 'critical' else 1)[:5]

            gap_items = []
            for i, gap in enumerate(top_gaps, 1):
                severity_icon = '⚠' if gap['severity'] == 'critical' else '!'
                gap_items.append(f"{i}. {gap['element']} {severity_icon} (from {gap['doc']})")

            gap_text = '\n'.join(gap_items)
            elements.append(Paragraph(gap_text, self.styles['BodyText']))

            if len(critical_gaps) > 5:
                elements.append(Paragraph(f"<i>+ {len(critical_gaps)-5} more critical gaps (see detailed section)</i>",
                                         self.styles['BodyText']))

        return elements

    def _generate_risk_context(self, risk_level: str, critical: int, high: int,
                               total: int, analysis: Dict[str, Any]) -> str:
        """Generate contextual risk analysis text."""

        categories = list(analysis['by_category'].keys())
        top_categories = sorted(categories, key=lambda c: len(analysis['by_category'][c]), reverse=True)[:3]
        
        if risk_level == 'critical':
            return f"""The assessment has identified <font color="#C1121F"><b>{critical} critical</b></font> and 
            <font color="#E36414"><b>{high} high-severity</b></font> findings that require immediate attention. 
            Critical findings represent significant security vulnerabilities that could lead to compromise of 
            cryptographic controls, unauthorised access, or regulatory non-compliance. The most affected areas 
            are: <b>{', '.join(top_categories)}</b>. Immediate remediation action is strongly recommended, with 
            critical items addressed within 24-48 hours where possible."""
        
        elif risk_level == 'high':
            return f"""The assessment has identified <font color="#E36414"><b>{high} high-severity</b></font> findings 
            that warrant prompt remediation. While no critical vulnerabilities were detected, these findings represent 
            notable security concerns that could be exploited or lead to compliance gaps. Primary areas of concern 
            include: <b>{', '.join(top_categories)}</b>. A structured remediation programme should be initiated 
            within the next 1-2 weeks."""
        
        elif risk_level == 'medium':
            medium_count = analysis['severity_counts'].get('medium', 0)
            return f"""The PKI environment demonstrates a generally acceptable security posture with 
            <font color="#F4A261"><b>{medium_count} medium-severity</b></font> findings identified. These findings 
            represent opportunities for improvement rather than immediate security risks. Areas for enhancement 
            include: <b>{', '.join(top_categories)}</b>. Remediation should be scheduled as part of regular 
            security maintenance cycles."""
        
        else:
            low_count = analysis['severity_counts'].get('low', 0)
            return f"""The assessment indicates a strong security posture with only <font color="#2A9D8F"><b>{low_count} 
            low-severity</b></font> findings. The PKI infrastructure demonstrates good adherence to security best 
            practices and policy requirements. The identified items represent minor deviations that should be 
            addressed as part of continuous improvement efforts but do not pose significant risk."""
    
    def _build_document_assessment_section(self, document_assessment: Dict[str, Any], 
                                            section_num: int = 2) -> List:
        """Build the document assessment section with enhanced governance context."""
        elements = []
        
        elements.append(Paragraph(f"{section_num}. Documentation Compliance Assessment", self.styles['SectionHeading']))
        elements.append(HRFlowable(width="100%", thickness=2, color=self.COLORS['primary']))
        elements.append(Spacer(1, 0.15*inch))
        
        # Governance introduction
        gov_intro = """Effective PKI governance requires comprehensive documentation that defines policies, 
        procedures, and controls. This documentation forms the foundation for consistent operations, 
        audit readiness, and regulatory compliance. The following assessment evaluates the organisation's 
        PKI documentation against industry-standard requirements."""
        elements.append(Paragraph(gov_intro, self.styles['BodyText']))
        
        # Document metadata
        elements.append(Paragraph(f"{section_num}.1 Document Details", self.styles['SubHeading']))
        
        doc_data = [
            ['Document Name', document_assessment.get('filename', 'Unknown')],
            ['Document Type', document_assessment.get('document_type', 'Unknown').replace('_', ' ').title()],
            ['Assessment Date', str(document_assessment.get('created_at', 'Unknown'))[:10]],
        ]
        
        if document_assessment.get('template_used'):
            doc_data.append(['Template Applied', document_assessment.get('template_used')])
        
        doc_table = Table([[Paragraph(k, self.styles['TableCellBold']), 
                           Paragraph(str(v), self.styles['TableCell'])] for k, v in doc_data],
                         colWidths=[2*inch, 4.8*inch])
        doc_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
            ('BACKGROUND', (0, 0), (0, -1), self.COLORS['light_bg']),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(doc_table)
        
        # Coverage Score and Grade
        elements.append(Spacer(1, 0.15*inch))
        elements.append(Paragraph(f"{section_num}.2 Coverage Assessment", self.styles['SubHeading']))
        
        coverage_score = document_assessment.get('coverage_score', 0)
        summary = document_assessment.get('summary', {})
        if isinstance(summary, str):
            try:
                summary = json.loads(summary)
            except:
                summary = {}
        
        grade = summary.get('assessment_grade', self._calculate_doc_grade(coverage_score))
        grade_colors = {'A': self.COLORS['success'], 'B': self.COLORS['low'], 
                       'C': self.COLORS['medium'], 'D': self.COLORS['high'], 'F': self.COLORS['critical']}
        grade_color = grade_colors.get(grade, self.COLORS['info'])
        
        elements_found = summary.get('elements_found', 0)
        elements_partial = summary.get('elements_partial', 0)
        elements_missing = summary.get('elements_missing', 0)
        total_elements = elements_found + elements_partial + elements_missing
        
        # Stats boxes
        def make_doc_stat_box(value, label, color=None):
            value_color = color if color else self.COLORS['primary']
            value_style = ParagraphStyle('DSV', fontSize=20, textColor=value_color, 
                                        alignment=TA_CENTER, fontName='Helvetica-Bold', leading=22)
            label_style = ParagraphStyle('DSL', fontSize=8, textColor=self.COLORS['text_secondary'], 
                                        alignment=TA_CENTER, leading=10)
            inner = Table([[Paragraph(f"<b>{value}</b>", value_style)],
                          [Paragraph(label, label_style)]],
                         colWidths=[1.3*inch], rowHeights=[0.4*inch, 0.35*inch])
            inner.setStyle(TableStyle([('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                                       ('VALIGN', (0, 0), (0, 0), 'BOTTOM'),
                                       ('VALIGN', (0, 1), (0, 1), 'TOP')]))
            return inner
        
        doc_stat_boxes = [
            make_doc_stat_box(grade, "Grade", grade_color),
            make_doc_stat_box(f"{coverage_score:.0f}%", "Coverage"),
            make_doc_stat_box(str(elements_found), "Found", self.COLORS['success']),
            make_doc_stat_box(str(elements_partial), "Partial", self.COLORS['medium']),
            make_doc_stat_box(str(elements_missing), "Missing", self.COLORS['critical']),
        ]
        
        doc_stats_table = Table([doc_stat_boxes], 
                               colWidths=[1.4*inch, 1.4*inch, 1.4*inch, 1.4*inch, 1.4*inch],
                               rowHeights=[0.85*inch])
        doc_stats_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOX', (0, 0), (0, 0), 1, self.COLORS['border']),
            ('BOX', (1, 0), (1, 0), 1, self.COLORS['border']),
            ('BOX', (2, 0), (2, 0), 1, self.COLORS['border']),
            ('BOX', (3, 0), (3, 0), 1, self.COLORS['border']),
            ('BOX', (4, 0), (4, 0), 1, self.COLORS['border']),
            ('BACKGROUND', (0, 0), (-1, -1), self.COLORS['light_bg']),
        ]))
        elements.append(doc_stats_table)
        
        # Grade interpretation
        grade_interpretations = {
            'A': 'Documentation is comprehensive and meets industry standards. Minor refinements may be beneficial.',
            'B': 'Documentation is largely complete with some gaps. Address partial coverage items to achieve full compliance.',
            'C': 'Documentation has notable gaps that should be addressed. Prioritise missing critical elements.',
            'D': 'Documentation requires significant improvement. Multiple governance controls are undocumented.',
            'F': 'Documentation is substantially incomplete. Immediate action required to establish governance baseline.'
        }
        elements.append(Spacer(1, 0.1*inch))
        elements.append(Paragraph(f"<b>Assessment Interpretation:</b> {grade_interpretations.get(grade, 'Assessment complete.')}", 
                                 self.styles['BodyText']))
        
        # Compliance Framework Scores
        compliance_scores = document_assessment.get('compliance_scores', {})
        if isinstance(compliance_scores, str):
            try:
                compliance_scores = json.loads(compliance_scores)
            except:
                compliance_scores = {}
        
        if compliance_scores:
            elements.append(Spacer(1, 0.15*inch))
            elements.append(Paragraph(f"{section_num}.3 Compliance Framework Scores", self.styles['SubHeading']))
            
            framework_intro = """The document was assessed against multiple compliance frameworks. 
            Scores below 80% indicate areas requiring attention to achieve compliance readiness."""
            elements.append(Paragraph(framework_intro, self.styles['BodyText']))
            
            framework_table_data = [
                [Paragraph('<b>Framework</b>', self.styles['TableHeader']),
                 Paragraph('<b>Score</b>', self.styles['TableHeader']),
                 Paragraph('<b>Status</b>', self.styles['TableHeader']),
                 Paragraph('<b>Implication</b>', self.styles['TableHeader'])]
            ]
            
            for framework, score in sorted(compliance_scores.items()):
                if score >= 80:
                    status = "Compliant"
                    status_color = self.COLORS['success']
                    implication = "Audit-ready for this framework"
                elif score >= 60:
                    status = "Partial"
                    status_color = self.COLORS['medium']
                    implication = "Gaps may result in audit observations"
                else:
                    status = "Non-Compliant"
                    status_color = self.COLORS['critical']
                    implication = "Significant remediation required"
                    
                framework_table_data.append([
                    Paragraph(framework, self.styles['TableCell']),
                    Paragraph(f"{score:.1f}%", self.styles['TableCell']),
                    Paragraph(f'<font color="{status_color.hexval()}">{status}</font>', self.styles['TableCell']),
                    Paragraph(implication, self.styles['TableCell'])
                ])
            
            framework_table = Table(framework_table_data, colWidths=[1.8*inch, 1*inch, 1.3*inch, 2.7*inch])
            framework_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['table_header']),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ]))
            elements.append(framework_table)
        
        # Element-by-Element Breakdown - Comprehensive View
        findings = document_assessment.get('findings', [])
        
        # Debug: Log document assessment structure
        logger.info(f"Document assessment keys: {list(document_assessment.keys())}")
        logger.info(f"Document assessment has {len(findings)} findings")
        if findings and len(findings) > 0:
            logger.info(f"First finding keys: {list(findings[0].keys())}")
            logger.info(f"First finding status: {findings[0].get('status')}")
            logger.info(f"First finding element_name: {findings[0].get('element_name')}")
        
        if not findings:
            # Show message that no findings data is available
            elements.append(Spacer(1, 0.15*inch))
            elements.append(Paragraph(f"{section_num}.4 Element Assessment Detail", self.styles['SubHeading']))
            elements.append(Paragraph("<i>No element-level findings data available for this assessment. "
                                     "This may indicate the assessment was run with an older version or findings were not stored.</i>", 
                                     self.styles['BodyText']))
        else:
            # Parse JSON fields in findings if needed (database stores as *_json columns)
            parsed_findings = []
            for f in findings:
                pf = dict(f)  # Copy to avoid modifying original
                # Parse compliance_refs_json
                if 'compliance_refs_json' in pf and pf['compliance_refs_json']:
                    try:
                        pf['compliance_refs'] = json.loads(pf['compliance_refs_json'])
                    except:
                        pf['compliance_refs'] = []
                elif 'compliance_refs' not in pf:
                    pf['compliance_refs'] = []
                # Parse details_json
                if 'details_json' in pf and pf['details_json']:
                    try:
                        pf['details'] = json.loads(pf['details_json'])
                    except:
                        pf['details'] = {}
                parsed_findings.append(pf)
            findings = parsed_findings
            
            elements.append(Spacer(1, 0.15*inch))
            elements.append(Paragraph(f"{section_num}.4 Element Assessment Detail", self.styles['SubHeading']))
            
            element_intro = """The following table provides a comprehensive view of each governance element 
            assessed, including the document section where content was found (if any), applicable compliance 
            references, and specific recommendations for gaps."""
            elements.append(Paragraph(element_intro, self.styles['BodyText']))
            
            # Group findings by status
            found_items = [f for f in findings if f.get('status') == 'found']
            partial_items = [f for f in findings if f.get('status') == 'partial']
            missing_items = [f for f in findings if f.get('status') == 'missing']
            
            # MISSING ELEMENTS TABLE - Most important, show all
            if missing_items:
                elements.append(Spacer(1, 0.1*inch))
                elements.append(Paragraph(f"<b>Missing Elements ({len(missing_items)})</b> - Immediate attention required", 
                                         ParagraphStyle('MissingHeader', parent=self.styles['BodyText'],
                                                       textColor=self.COLORS['critical'], fontName='Helvetica-Bold')))
                
                missing_table_data = [
                    [Paragraph('<b>Element</b>', self.styles['TableHeader']),
                     Paragraph('<b>Compliance Refs</b>', self.styles['TableHeader']),
                     Paragraph('<b>Recommendation</b>', self.styles['TableHeader'])]
                ]
                
                for item in missing_items:
                    element_name = item.get('element_name', item.get('element', item.get('requirement', 'Unknown')))
                    compliance_refs = item.get('compliance_refs', [])
                    if isinstance(compliance_refs, list) and compliance_refs:
                        refs_text = ', '.join(str(r) for r in compliance_refs[:3])
                        if len(compliance_refs) > 3:
                            refs_text += f' (+{len(compliance_refs)-3})'
                    elif compliance_refs:
                        refs_text = str(compliance_refs)
                    else:
                        # Infer compliance refs from element name
                        refs_text = self._infer_compliance_refs(element_name)
                    recommendation = item.get('recommendation') or self._get_element_recommendation(element_name, 'missing')
                    
                    missing_table_data.append([
                        Paragraph(element_name, self.styles['TableCell']),
                        Paragraph(refs_text, ParagraphStyle('RefCell', parent=self.styles['TableCell'], fontSize=7)),
                        Paragraph(recommendation, self.styles['TableCell'])
                    ])
                
                missing_table = Table(missing_table_data, colWidths=[2.2*inch, 1.3*inch, 3.3*inch])
                missing_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['critical']),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
                    ('BACKGROUND', (0, 1), (-1, -1), self.COLORS['critical_bg']),
                    ('TOPPADDING', (0, 0), (-1, -1), 5),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                elements.append(missing_table)
            
            # PARTIAL ELEMENTS TABLE - Show all with matched content
            if partial_items:
                elements.append(Spacer(1, 0.15*inch))
                elements.append(Paragraph(f"<b>Partial Coverage ({len(partial_items)})</b> - Enhancement needed", 
                                         ParagraphStyle('PartialHeader', parent=self.styles['BodyText'],
                                                       textColor=self.COLORS['medium'], fontName='Helvetica-Bold')))
                
                partial_table_data = [
                    [Paragraph('<b>Element</b>', self.styles['TableHeader']),
                     Paragraph('<b>Found In Section</b>', self.styles['TableHeader']),
                     Paragraph('<b>Gap / Enhancement Needed</b>', self.styles['TableHeader'])]
                ]
                
                for item in partial_items:
                    element_name = item.get('element_name', item.get('element', item.get('requirement', 'Unknown')))
                    matched_section = item.get('matched_section') or '-'
                    if matched_section and len(matched_section) > 35:
                        matched_section = matched_section[:32] + '...'
                    recommendation = item.get('recommendation') or 'Expand coverage to address all required aspects'
                    
                    partial_table_data.append([
                        Paragraph(element_name, self.styles['TableCell']),
                        Paragraph(matched_section if matched_section else '-', self.styles['TableCell']),
                        Paragraph(recommendation, self.styles['TableCell'])
                    ])
                
                partial_table = Table(partial_table_data, colWidths=[2.2*inch, 1.8*inch, 2.8*inch])
                partial_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['medium']),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
                    ('BACKGROUND', (0, 1), (-1, -1), self.COLORS['medium_bg']),
                    ('TOPPADDING', (0, 0), (-1, -1), 5),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                elements.append(partial_table)
            
            # FOUND ELEMENTS - Summary with matched sections
            if found_items:
                elements.append(Spacer(1, 0.15*inch))
                elements.append(Paragraph(f"<b>Fully Addressed ({len(found_items)})</b> - Requirements satisfied", 
                                         ParagraphStyle('FoundHeader', parent=self.styles['BodyText'],
                                                       textColor=self.COLORS['success'], fontName='Helvetica-Bold')))
                
                found_table_data = [
                    [Paragraph('<b>Element</b>', self.styles['TableHeader']),
                     Paragraph('<b>Found In Section</b>', self.styles['TableHeader']),
                     Paragraph('<b>Confidence</b>', self.styles['TableHeader'])]
                ]
                
                for item in found_items[:12]:  # Show up to 12 found items
                    element_name = item.get('element_name', item.get('element', item.get('requirement', 'Unknown')))
                    matched_section = item.get('matched_section', '-')
                    if matched_section and len(matched_section) > 40:
                        matched_section = matched_section[:37] + '...'
                    confidence = item.get('confidence', 0)
                    confidence_text = f"{confidence*100:.0f}%" if isinstance(confidence, float) and confidence <= 1 else f"{confidence:.0f}%"
                    
                    found_table_data.append([
                        Paragraph(element_name, self.styles['TableCell']),
                        Paragraph(matched_section if matched_section else '-', self.styles['TableCell']),
                        Paragraph(confidence_text, self.styles['TableCell'])
                    ])
                
                if len(found_items) > 12:
                    found_table_data.append([
                        Paragraph(f"<i>... and {len(found_items) - 12} additional elements found</i>", self.styles['TableCell']),
                        Paragraph('', self.styles['TableCell']),
                        Paragraph('', self.styles['TableCell'])
                    ])
                
                found_table = Table(found_table_data, colWidths=[2.5*inch, 3.3*inch, 1*inch])
                found_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['success']),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
                    ('BACKGROUND', (0, 1), (-1, -1), self.COLORS['low_bg']),
                    ('TOPPADDING', (0, 0), (-1, -1), 5),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('ALIGN', (2, 1), (2, -1), 'CENTER'),
                ]))
                elements.append(found_table)
        
        # Critical Gaps with Comprehensive Detail
        critical_gaps = summary.get('critical_gaps', [])
        if critical_gaps:
            elements.append(Spacer(1, 0.15*inch))
            elements.append(Paragraph(f"{section_num}.5 Critical Documentation Gaps", self.styles['SubHeading']))
            
            gaps_intro = """The following critical governance elements are missing or substantially incomplete. 
            These gaps represent the highest priority items for documentation improvement as they form 
            foundational elements of PKI governance and are typically required for regulatory compliance."""
            elements.append(Paragraph(gaps_intro, self.styles['BodyText']))
            
            gaps_table_data = [
                [Paragraph('<b>Critical Gap</b>', self.styles['TableHeader']),
                 Paragraph('<b>Compliance Impact</b>', self.styles['TableHeader']),
                 Paragraph('<b>Governance Risk</b>', self.styles['TableHeader']),
                 Paragraph('<b>Priority</b>', self.styles['TableHeader'])]
            ]
            
            for idx, gap in enumerate(critical_gaps):
                element = gap.get('element', 'Unknown')
                risk = self._get_gap_governance_risk(element)
                
                # Get compliance refs from gap or infer from element
                compliance_refs = gap.get('compliance_refs', [])
                if isinstance(compliance_refs, list) and compliance_refs:
                    compliance_text = ', '.join(compliance_refs[:2])
                else:
                    compliance_text = self._infer_compliance_refs(element)
                
                # Assign priority based on position and element type
                priority = "P1 - Immediate" if idx < 3 else "P2 - High" if idx < 6 else "P3 - Medium"
                
                gaps_table_data.append([
                    Paragraph(element, self.styles['TableCell']),
                    Paragraph(compliance_text, ParagraphStyle('CompRef', parent=self.styles['TableCell'], fontSize=7)),
                    Paragraph(risk, self.styles['TableCell']),
                    Paragraph(priority, self.styles['TableCellBold'])
                ])
            
            gaps_table = Table(gaps_table_data, colWidths=[1.8*inch, 1.3*inch, 2.5*inch, 1.2*inch])
            gaps_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['critical']),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
                ('BACKGROUND', (0, 1), (-1, -1), self.COLORS['critical_bg']),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(gaps_table)
            
            # Detailed recommendations for top critical gaps
            elements.append(Spacer(1, 0.15*inch))
            elements.append(Paragraph(f"{section_num}.6 Detailed Remediation Guidance", self.styles['SubHeading']))
            
            for idx, gap in enumerate(critical_gaps[:5]):  # Top 5 gaps with detailed guidance
                element = gap.get('element', 'Unknown')
                recommendation = gap.get('recommendation', self._get_detailed_gap_recommendation(element))
                
                elements.append(Paragraph(f"<b>{idx+1}. {element}</b>", 
                                         ParagraphStyle('GapTitle', parent=self.styles['BodyText'], 
                                                       fontSize=9, fontName='Helvetica-Bold', spaceBefore=8)))
                elements.append(Paragraph(recommendation, 
                                         ParagraphStyle('GapRec', parent=self.styles['BodyText'], 
                                                       fontSize=9, leftIndent=15, spaceBefore=2)))
        
        # Next Steps Section
        elements.append(Spacer(1, 0.15*inch))
        next_section_num = section_num + 1 if not critical_gaps else section_num
        subsection = ".7" if critical_gaps else ".5"
        elements.append(Paragraph(f"{section_num}{subsection} Recommended Next Steps", self.styles['SubHeading']))
        
        # Generate prioritised next steps based on assessment results
        next_steps = []
        
        if elements_missing > 0:
            next_steps.append(f"<b>1. Address Critical Documentation Gaps:</b> {elements_missing} required elements are missing. "
                            "Begin with P1 priority items identified above. Assign document owners and establish target completion dates.")
        
        if elements_partial > 0:
            next_steps.append(f"<b>2. Enhance Partial Coverage:</b> {elements_partial} elements have incomplete coverage. "
                            "Review matched sections and expand content to fully address requirements.")
        
        if compliance_scores:
            low_frameworks = [f for f, s in compliance_scores.items() if s < 70]
            if low_frameworks:
                next_steps.append(f"<b>3. Focus on Low-Scoring Frameworks:</b> {', '.join(low_frameworks)} score below 70%. "
                                "These frameworks require targeted remediation to achieve compliance readiness.")
        
        next_steps.append("<b>4. Establish Review Cycle:</b> Implement quarterly documentation reviews to ensure "
                        "content remains current and aligned with operational practices.")
        
        next_steps.append("<b>5. Schedule Reassessment:</b> After remediation activities, conduct a follow-up assessment "
                        "to verify improvements and identify any remaining gaps.")
        
        for step in next_steps:
            elements.append(Paragraph(step, ParagraphStyle('NextStep', parent=self.styles['BodyText'], 
                                                          spaceBefore=6, spaceAfter=4)))
        
        return elements
    
    def _get_element_governance_significance(self, element: str, status: str) -> str:
        """Get governance significance text for a document element."""
        element_lower = element.lower()
        
        if status == 'missing':
            if 'key' in element_lower and ('generation' in element_lower or 'management' in element_lower):
                return 'Undocumented key management creates accountability gaps and audit exposure'
            elif 'revocation' in element_lower:
                return 'Missing revocation procedures impair incident response capability'
            elif 'backup' in element_lower or 'recovery' in element_lower:
                return 'Absence of recovery procedures creates business continuity risk'
            elif 'audit' in element_lower or 'logging' in element_lower:
                return 'Missing audit requirements limit forensic and compliance capabilities'
            elif 'role' in element_lower or 'responsibility' in element_lower:
                return 'Undefined roles create accountability gaps and separation of duties issues'
            elif 'policy' in element_lower:
                return 'Missing policy foundation undermines entire governance framework'
            elif 'certificate' in element_lower and 'profile' in element_lower:
                return 'Undefined profiles lead to inconsistent certificate issuance'
            else:
                return 'Documentation gap may result in inconsistent practices'
        else:  # partial
            if 'key' in element_lower:
                return 'Incomplete key management documentation needs enhancement'
            elif 'revocation' in element_lower:
                return 'Partial revocation coverage may leave scenarios unaddressed'
            elif 'audit' in element_lower:
                return 'Audit requirements need expansion for comprehensive coverage'
            else:
                return 'Element requires additional detail for complete coverage'
    
    def _get_gap_governance_risk(self, element: str) -> str:
        """Get governance risk description for a critical gap."""
        element_lower = element.lower()
        
        if 'key' in element_lower:
            return 'Key compromise or loss could occur without defined procedures'
        elif 'revocation' in element_lower:
            return 'Compromised certificates may remain trusted indefinitely'
        elif 'backup' in element_lower or 'recovery' in element_lower:
            return 'PKI service restoration may be impossible after failure'
        elif 'audit' in element_lower:
            return 'Security incidents may go undetected; audit failures likely'
        elif 'role' in element_lower or 'responsibility' in element_lower:
            return 'Unclear accountability; potential for unauthorised actions'
        elif 'policy' in element_lower:
            return 'No baseline for compliance assessment or consistent operations'
        elif 'certificate' in element_lower:
            return 'Inconsistent certificate issuance; interoperability issues'
        else:
            return 'Governance gap creates operational and compliance risk'
    
    def _get_element_recommendation(self, element: str, status: str) -> str:
        """Get specific recommendation for a missing or partial element."""
        element_lower = element.lower()
        
        if status == 'missing':
            if 'key' in element_lower and 'generation' in element_lower:
                return 'Document key generation procedures including entropy sources, ceremony requirements, and witness protocols'
            elif 'key' in element_lower and 'storage' in element_lower:
                return 'Define key storage requirements including HSM usage, access controls, and physical security'
            elif 'key' in element_lower and 'destruction' in element_lower:
                return 'Establish key destruction procedures with verification steps and audit trail requirements'
            elif 'revocation' in element_lower:
                return 'Create revocation procedures covering request validation, CRL/OCSP updates, and notification processes'
            elif 'backup' in element_lower:
                return 'Document backup procedures including frequency, encryption, offsite storage, and restoration testing'
            elif 'recovery' in element_lower or 'disaster' in element_lower:
                return 'Develop disaster recovery plan with RTO/RPO targets, failover procedures, and testing schedule'
            elif 'audit' in element_lower or 'logging' in element_lower:
                return 'Define audit logging requirements, retention periods, review procedures, and tamper protection'
            elif 'role' in element_lower or 'responsibility' in element_lower:
                return 'Document roles with clear responsibilities, required training, and separation of duties matrix'
            elif 'policy' in element_lower:
                return 'Establish policy framework with approval authority, review cycle, and exception process'
            elif 'certificate' in element_lower and 'profile' in element_lower:
                return 'Define certificate profiles including extensions, validity periods, and permitted uses'
            elif 'subscriber' in element_lower or 'registration' in element_lower:
                return 'Document subscriber registration including identity verification, agreement requirements, and approval workflow'
            elif 'physical' in element_lower and 'security' in element_lower:
                return 'Define physical security controls for CA facilities including access control and environmental protections'
            else:
                return 'Document this element following applicable framework requirements (RFC 3647, NCSC, NIST)'
        else:
            return 'Expand existing documentation to fully address all aspects of this requirement'
    
    def _infer_compliance_refs(self, element: str) -> str:
        """Infer likely compliance references based on element name."""
        element_lower = element.lower()
        
        if 'key' in element_lower:
            return 'NIST SP 800-57, NCSC'
        elif 'revocation' in element_lower or 'crl' in element_lower:
            return 'RFC 3647 §4.9, WebTrust'
        elif 'audit' in element_lower:
            return 'ISO 27001, WebTrust'
        elif 'backup' in element_lower or 'recovery' in element_lower:
            return 'ISO 27001, NIST SP 800-34'
        elif 'role' in element_lower or 'responsibility' in element_lower:
            return 'RFC 3647 §5.2, ISO 27001'
        elif 'certificate' in element_lower and 'profile' in element_lower:
            return 'RFC 3647 §7, RFC 5280'
        elif 'subscriber' in element_lower:
            return 'RFC 3647 §3.2, WebTrust'
        elif 'physical' in element_lower:
            return 'RFC 3647 §5.1, ISO 27001'
        elif 'policy' in element_lower:
            return 'RFC 3647 §1.5, NCSC'
        else:
            return 'RFC 3647, ISO 27001'
    
    def _get_detailed_gap_recommendation(self, element: str) -> str:
        """Get detailed remediation guidance for a critical gap."""
        element_lower = element.lower()
        
        if 'key' in element_lower and 'generation' in element_lower:
            return ("Create a key generation procedure document that covers: (1) Approved algorithms and key sizes, "
                   "(2) Entropy source requirements, (3) Key ceremony procedures for CA keys, (4) Witness and "
                   "audit requirements, (5) Key activation data handling. Reference NIST SP 800-57 for algorithm guidance.")
        elif 'key' in element_lower and 'storage' in element_lower:
            return ("Document key storage requirements including: (1) HSM requirements and FIPS 140-2 level, "
                   "(2) Access control procedures, (3) Key wrapping for export/backup, (4) Physical security "
                   "requirements for HSM locations. Align with NCSC key management guidance.")
        elif 'revocation' in element_lower:
            return ("Develop comprehensive revocation procedures covering: (1) Revocation request channels and "
                   "authentication, (2) Authorised revocation reasons per RFC 5280, (3) CRL generation and "
                   "publication timelines, (4) OCSP responder update procedures, (5) Subscriber notification process.")
        elif 'backup' in element_lower or 'recovery' in element_lower:
            return ("Establish backup and recovery documentation including: (1) Backup scope and frequency, "
                   "(2) Encryption requirements for backup media, (3) Offsite storage locations, (4) Restoration "
                   "testing schedule and success criteria, (5) RTO/RPO targets for PKI services.")
        elif 'audit' in element_lower:
            return ("Define audit and logging requirements covering: (1) Events to be logged per RFC 3647, "
                   "(2) Log format and integrity protection, (3) Retention periods, (4) Review frequency and "
                   "responsibility, (5) Incident escalation triggers from log review.")
        elif 'role' in element_lower or 'responsibility' in element_lower:
            return ("Document PKI roles and responsibilities including: (1) Role definitions (CA Admin, RA Operator, "
                   "Auditor, etc.), (2) Required training and certification, (3) Separation of duties matrix, "
                   "(4) Role assignment and revocation procedures, (5) Backup personnel requirements.")
        elif 'policy' in element_lower:
            return ("Establish the policy framework including: (1) Policy approval authority, (2) Change management "
                   "process, (3) Review and update cycle (recommend annual), (4) Exception request and approval "
                   "process, (5) Communication of policy changes to stakeholders.")
        else:
            return ("Document this governance element following the structure in RFC 3647 where applicable. "
                   "Include scope, procedures, responsibilities, and compliance mapping. Ensure alignment with "
                   "organisational security policies and applicable regulatory requirements.")
    
    def _calculate_doc_grade(self, score: float) -> str:
        """Calculate letter grade from document coverage score."""
        if score >= 90: return 'A'
        elif score >= 80: return 'B'
        elif score >= 70: return 'C'
        elif score >= 60: return 'D'
        else: return 'F'
    
    def _build_combined_risk_summary(self, crypto_analysis: Dict[str, Any], 
                                      document_assessment: Dict[str, Any],
                                      section_num: int = 3) -> List:
        """Build combined risk summary for reports with both crypto and doc assessments."""
        elements = []
        
        elements.append(Spacer(1, 0.2*inch))
        elements.append(Paragraph(f"{section_num}. Combined Risk Assessment", self.styles['SectionHeading']))
        elements.append(HRFlowable(width="100%", thickness=2, color=self.COLORS['primary']))
        elements.append(Spacer(1, 0.15*inch))
        
        intro_text = """This section provides a unified view of the organisation's PKI security posture 
        by combining technical cryptographic asset assessment with documentation compliance review. 
        Effective PKI governance requires both robust technical controls and comprehensive documentation 
        to ensure consistent, auditable, and compliant operations."""
        elements.append(Paragraph(intro_text, self.styles['BodyText']))
        
        # Calculate metrics
        critical_count = crypto_analysis['severity_counts'].get('critical', 0)
        high_count = crypto_analysis['severity_counts'].get('high', 0)
        medium_count = crypto_analysis['severity_counts'].get('medium', 0)
        
        if critical_count > 0:
            crypto_risk, crypto_score = "Critical", 25
        elif high_count > 0:
            crypto_risk, crypto_score = "High", 50
        elif medium_count > 0:
            crypto_risk, crypto_score = "Medium", 75
        else:
            crypto_risk, crypto_score = "Low", 95
        
        doc_coverage = document_assessment.get('coverage_score', 0)
        summary = document_assessment.get('summary', {})
        if isinstance(summary, str):
            try:
                summary = json.loads(summary)
            except:
                summary = {}
        doc_grade = summary.get('assessment_grade', self._calculate_doc_grade(doc_coverage))
        
        # Combined score (60% crypto, 40% documentation)
        combined_score = (crypto_score * 0.6) + (doc_coverage * 0.4)
        
        if combined_score >= 80:
            combined_level, combined_color = "STRONG", self.COLORS['success']
        elif combined_score >= 60:
            combined_level, combined_color = "MODERATE", self.COLORS['medium']
        elif combined_score >= 40:
            combined_level, combined_color = "WEAK", self.COLORS['high']
        else:
            combined_level, combined_color = "CRITICAL", self.COLORS['critical']
        
        elements.append(Paragraph(f"{section_num}.1 Security Posture Summary", self.styles['SubHeading']))
        
        # Posture table
        crypto_color = self.COLORS.get(crypto_risk.lower(), self.COLORS['info'])
        doc_color = self.COLORS['success'] if doc_coverage >= 80 else self.COLORS['medium'] if doc_coverage >= 60 else self.COLORS['critical']
        
        posture_table_data = [
            [Paragraph('<b>Assessment Area</b>', self.styles['TableHeader']),
             Paragraph('<b>Risk/Score</b>', self.styles['TableHeader']),
             Paragraph('<b>Status</b>', self.styles['TableHeader']),
             Paragraph('<b>Weight</b>', self.styles['TableHeader'])],
            [Paragraph("Cryptographic Assets", self.styles['TableCell']),
             Paragraph(f'<font color="{crypto_color.hexval()}"><b>{crypto_risk}</b></font>', self.styles['TableCell']),
             Paragraph(f"{crypto_analysis['total']} findings", self.styles['TableCell']),
             Paragraph("60%", self.styles['TableCell'])],
            [Paragraph("Documentation Compliance", self.styles['TableCell']),
             Paragraph(f'<font color="{doc_color.hexval()}"><b>Grade {doc_grade} ({doc_coverage:.0f}%)</b></font>', self.styles['TableCell']),
             Paragraph(f"{summary.get('elements_missing', 0)} gaps", self.styles['TableCell']),
             Paragraph("40%", self.styles['TableCell'])],
            [Paragraph("<b>Combined Posture</b>", self.styles['TableCellBold']),
             Paragraph(f'<font color="{combined_color.hexval()}"><b>{combined_level}</b></font>', self.styles['TableCell']),
             Paragraph(f"Score: {combined_score:.0f}/100", self.styles['TableCell']),
             Paragraph("100%", self.styles['TableCell'])]
        ]
        
        posture_table = Table(posture_table_data, colWidths=[2*inch, 1.8*inch, 2.2*inch, 0.8*inch])
        posture_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['table_header']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, -1), (-1, -1), self.COLORS['light_bg']),
        ]))
        elements.append(posture_table)
        
        # Governance interpretation
        elements.append(Spacer(1, 0.15*inch))
        elements.append(Paragraph(f"{section_num}.2 Governance Interpretation", self.styles['SubHeading']))
        
        if combined_level == "CRITICAL":
            interpretation = """The combined assessment indicates critical weaknesses in both technical 
            implementation and governance documentation. This creates compounded risk where technical 
            vulnerabilities may persist due to inadequate documented procedures, and incident response 
            may be impaired by missing operational guidance. Executive attention and dedicated 
            remediation resources are required."""
        elif combined_level == "WEAK":
            interpretation = """The assessment reveals significant gaps that require management attention. 
            Either technical controls or documentation (or both) require substantial improvement to 
            achieve an acceptable security posture. A structured remediation programme with clear 
            ownership and timelines should be established."""
        elif combined_level == "MODERATE":
            interpretation = """The PKI environment demonstrates a reasonable security posture with 
            identified improvement opportunities. Technical controls and documentation are functional 
            but have gaps that should be addressed to strengthen governance and reduce risk. 
            Prioritise critical and high-severity items in remediation planning."""
        else:
            interpretation = """The combined assessment indicates a strong security posture with both 
            technical controls and documentation meeting expected standards. Continue current practices 
            and address identified low-severity items through normal maintenance processes. Regular 
            reassessment is recommended to maintain this posture."""
        
        elements.append(Paragraph(interpretation, self.styles['BodyText']))
        
        return elements
    
    def _build_key_findings_overview(self, findings_analysis: Dict[str, Any], 
                                      section_num: int = 2) -> List:
        """Build the key findings overview section."""
        elements = []
        
        elements.append(Paragraph(f"{section_num}. Key Findings Overview", self.styles['SectionHeading']))
        elements.append(HRFlowable(width="100%", thickness=2, color=self.COLORS['primary']))
        elements.append(Spacer(1, 0.15*inch))
        
        intro_text = """This section provides a summary view of findings organised by severity level and category. 
        Each finding represents a deviation from policy requirements or security best practices that warrants 
        attention and potential remediation."""
        elements.append(Paragraph(intro_text, self.styles['BodyText']))
        
        # Findings by severity table
        elements.append(Paragraph(f"{section_num}.1 Findings by Severity", self.styles['SubHeading']))
        
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        table_data = [
            [Paragraph('<b>Severity</b>', self.styles['TableHeader']),
             Paragraph('<b>Count</b>', self.styles['TableHeader']),
             Paragraph('<b>Categories Affected</b>', self.styles['TableHeader']),
             Paragraph('<b>Risk Implication</b>', self.styles['TableHeader'])]
        ]
        
        risk_implications = {
            'critical': 'Immediate security risk; potential for significant impact',
            'high': 'Elevated risk; should be addressed promptly',
            'medium': 'Moderate risk; schedule for remediation',
            'low': 'Minor deviation; address during maintenance',
            'info': 'Informational; consider for improvement'
        }
        
        for severity in severity_order:
            findings_list = findings_analysis['by_severity'].get(severity, [])
            if findings_list:
                count = len(findings_list)
                categories = set(f.get('category', 'general') for f in findings_list)
                categories_str = ', '.join(sorted(categories)[:3])
                if len(categories) > 3:
                    categories_str += f' (+{len(categories)-3} more)'
                
                table_data.append([
                    Paragraph(severity.upper(), self.styles['TableCellBold']),
                    Paragraph(str(count), self.styles['TableCell']),
                    Paragraph(categories_str, self.styles['TableCell']),
                    Paragraph(risk_implications.get(severity, ''), self.styles['TableCell'])
                ])
        
        if len(table_data) > 1:
            findings_table = Table(table_data, colWidths=[1.1*inch, 0.7*inch, 2.2*inch, 2.8*inch])
            
            table_style = [
                ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['table_header']),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]
            
            # Add severity colors to first column
            row_idx = 1
            for severity in severity_order:
                if findings_analysis['by_severity'].get(severity):
                    severity_color = self.COLORS.get(severity, self.COLORS['info'])
                    bg_color = self.COLORS.get(f'{severity}_bg', self.COLORS['light_bg'])
                    table_style.append(('BACKGROUND', (0, row_idx), (0, row_idx), severity_color))
                    table_style.append(('TEXTCOLOR', (0, row_idx), (0, row_idx), colors.white))
                    table_style.append(('BACKGROUND', (1, row_idx), (-1, row_idx), bg_color))
                    row_idx += 1
            
            findings_table.setStyle(TableStyle(table_style))
            elements.append(findings_table)
        else:
            elements.append(Paragraph("<i>No findings were identified during this assessment.</i>", 
                                     self.styles['BodyText']))
        
        # Findings by Category
        elements.append(Spacer(1, 0.15*inch))
        elements.append(Paragraph(f"{section_num}.2 Findings by Category", self.styles['SubHeading']))
        
        if findings_analysis['by_category']:
            cat_data = [
                [Paragraph('<b>Category</b>', self.styles['TableHeader']),
                 Paragraph('<b>Total</b>', self.styles['TableHeader']),
                 Paragraph('<b>Critical</b>', self.styles['TableHeader']),
                 Paragraph('<b>High</b>', self.styles['TableHeader']),
                 Paragraph('<b>Medium</b>', self.styles['TableHeader']),
                 Paragraph('<b>Low</b>', self.styles['TableHeader'])]
            ]
            
            for category in sorted(findings_analysis['by_category'].keys()):
                cat_findings = findings_analysis['by_category'][category]
                crit = sum(1 for f in cat_findings if f.get('severity', '').lower() == 'critical')
                high = sum(1 for f in cat_findings if f.get('severity', '').lower() == 'high')
                med = sum(1 for f in cat_findings if f.get('severity', '').lower() == 'medium')
                low = sum(1 for f in cat_findings if f.get('severity', '').lower() == 'low')
                
                cat_data.append([
                    Paragraph(category.replace('_', ' ').title(), self.styles['TableCell']),
                    Paragraph(str(len(cat_findings)), self.styles['TableCellBold']),
                    Paragraph(str(crit) if crit > 0 else '-', self.styles['TableCell']),
                    Paragraph(str(high) if high > 0 else '-', self.styles['TableCell']),
                    Paragraph(str(med) if med > 0 else '-', self.styles['TableCell']),
                    Paragraph(str(low) if low > 0 else '-', self.styles['TableCell'])
                ])
            
            cat_table = Table(cat_data, colWidths=[2.3*inch, 0.8*inch, 0.8*inch, 0.8*inch, 0.9*inch, 0.8*inch])
            cat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['table_header']),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
                ('BACKGROUND', (0, 1), (-1, -1), self.COLORS['light_bg']),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ]))
            elements.append(cat_table)
        
        # Security Posture Indicators - Strengths and Concerns
        elements.append(Spacer(1, 0.15*inch))
        elements.append(Paragraph(f"{section_num}.3 Security Posture Indicators", self.styles['SubHeading']))
        
        posture_intro = """The following table provides a balanced view of the security assessment, 
        highlighting both areas of strength and areas requiring attention."""
        elements.append(Paragraph(posture_intro, self.styles['BodyText']))
        
        # Identify strengths (categories with no critical/high findings, or rules that passed)
        strengths = []
        concerns = []
        
        # Analyse by category
        all_categories = set()
        categories_with_issues = set()
        
        for severity in ['critical', 'high']:
            for finding in findings_analysis['by_severity'].get(severity, []):
                cat = finding.get('category', 'general')
                categories_with_issues.add(cat)
                all_categories.add(cat)
        
        # Also get all categories from by_category
        for cat in findings_analysis.get('by_category', {}).keys():
            all_categories.add(cat)
        
        # Categories with no critical/high issues are strengths
        clean_categories = all_categories - categories_with_issues
        for cat in clean_categories:
            cat_display = cat.replace('_', ' ').title()
            strengths.append(f"{cat_display}: No critical or high severity issues identified")
        
        # If no critical findings at all
        if findings_analysis['severity_counts'].get('critical', 0) == 0:
            strengths.append("No critical severity findings requiring immediate action")
        
        # Check for specific positive indicators
        total_findings = sum(findings_analysis['severity_counts'].values())
        low_info_count = findings_analysis['severity_counts'].get('low', 0) + findings_analysis['severity_counts'].get('info', 0)
        
        if total_findings > 0 and low_info_count / total_findings > 0.5:
            strengths.append("Majority of findings are low severity or informational")
        
        if len(findings_analysis['by_category']) <= 2 and total_findings > 0:
            strengths.append("Issues concentrated in limited categories, suggesting focused remediation")
        
        # Build concerns list from actual findings
        critical_count = findings_analysis['severity_counts'].get('critical', 0)
        high_count = findings_analysis['severity_counts'].get('high', 0)
        medium_count = findings_analysis['severity_counts'].get('medium', 0)
        
        if critical_count > 0:
            concerns.append(f"{critical_count} critical finding(s) requiring immediate attention")
        if high_count > 0:
            concerns.append(f"{high_count} high severity finding(s) requiring prompt remediation")
        if medium_count > 5:
            concerns.append(f"{medium_count} medium severity findings indicating systemic issues")
        
        # Category-specific concerns
        for category, cat_findings in findings_analysis['by_category'].items():
            crit_high = sum(1 for f in cat_findings if f.get('severity', '').lower() in ['critical', 'high'])
            if crit_high >= 2:
                cat_display = category.replace('_', ' ').title()
                concerns.append(f"{cat_display}: {crit_high} critical/high findings indicate focused attention needed")
        
        # Ensure we have content for both columns
        if not strengths:
            strengths.append("Assessment identified areas for improvement across categories")
        if not concerns:
            concerns.append("No significant concerns - maintain current security practices")
        
        # Build the two-column table
        max_rows = max(len(strengths), len(concerns))
        
        posture_table_data = [
            [Paragraph('<b>Strengths Identified</b>', self.styles['TableHeader']),
             Paragraph('<b>Areas of Concern</b>', self.styles['TableHeader'])]
        ]
        
        for i in range(max_rows):
            strength_text = strengths[i] if i < len(strengths) else ''
            concern_text = concerns[i] if i < len(concerns) else ''
            
            # Add bullet styling
            strength_cell = Paragraph(f"✓ {strength_text}" if strength_text else '', 
                                     ParagraphStyle('StrengthCell', parent=self.styles['TableCell'],
                                                   textColor=self.COLORS['success']))
            concern_cell = Paragraph(f"⚠ {concern_text}" if concern_text else '', 
                                    ParagraphStyle('ConcernCell', parent=self.styles['TableCell'],
                                                  textColor=self.COLORS['critical']))
            
            posture_table_data.append([strength_cell, concern_cell])
        
        posture_table = Table(posture_table_data, colWidths=[3.4*inch, 3.4*inch])
        posture_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), self.COLORS['success']),
            ('BACKGROUND', (1, 0), (1, 0), self.COLORS['critical']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
            ('BACKGROUND', (0, 1), (0, -1), self.COLORS['low_bg']),
            ('BACKGROUND', (1, 1), (1, -1), self.COLORS['critical_bg']),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(posture_table)
        
        return elements
    
    def _build_detailed_findings(self, findings: List[Dict[str, Any]], 
                                  policy: Dict[str, Any],
                                  findings_analysis: Dict[str, Any],
                                  section_num: int = 3) -> List:
        """Build the detailed findings section grouped by rule with all affected entities."""
        elements = []
        
        elements.append(Paragraph(f"{section_num}. Detailed Findings", self.styles['SectionHeading']))
        elements.append(HRFlowable(width="100%", thickness=2, color=self.COLORS['primary']))
        elements.append(Spacer(1, 0.15*inch))
        
        if not findings:
            elements.append(Paragraph("No findings were identified during this assessment.", 
                                     self.styles['BodyText']))
            return elements
        
        intro_text = """The following section provides detailed information on each finding type, grouped by 
        security rule. Each finding includes governance context explaining why the issue matters, 
        affected entity details, and recommended remediation actions."""
        elements.append(Paragraph(intro_text, self.styles['BodyText']))
        
        # Group findings by rule_id
        grouped_findings = {}
        for finding in findings:
            rule_id = finding.get('rule_id', finding.get('rule_name', 'Unknown'))
            if rule_id not in grouped_findings:
                grouped_findings[rule_id] = {
                    'rule_id': rule_id,
                    'rule_name': finding.get('rule_name', finding.get('title', 'Unknown Rule')),
                    'description': finding.get('description', ''),
                    'severity': finding.get('severity', 'info'),
                    'risk_score': finding.get('risk_score', 0),
                    'remediation': finding.get('remediation', ''),
                    'compliance_impact': finding.get('compliance_impact', ''),
                    'category': finding.get('category', 'general'),
                    'entities': []
                }
            
            # Extract comprehensive entity information from evidence
            evidence = finding.get('evidence', {})
            entity_info = {
                'name': (evidence.get('affected_entity') or 
                        evidence.get('subject_cn') or 
                        evidence.get('entity_name') or
                        finding.get('title', 'Unknown Entity')),
                'evidence': evidence
            }
            
            # Extract additional entity details for display
            entity_details = []
            if evidence.get('issuer_cn'):
                entity_details.append(f"Issuer: {evidence['issuer_cn']}")
            if evidence.get('not_after'):
                entity_details.append(f"Expires: {str(evidence['not_after'])[:10]}")
            if evidence.get('key_algorithm'):
                entity_details.append(f"Algorithm: {evidence['key_algorithm']}")
            if evidence.get('key_size'):
                entity_details.append(f"Key Size: {evidence['key_size']}")
            if evidence.get('serial_number'):
                serial = str(evidence['serial_number'])
                if len(serial) > 20:
                    serial = serial[:17] + '...'
                entity_details.append(f"Serial: {serial}")
            if evidence.get('source'):
                entity_details.append(f"Source: {evidence['source']}")
            
            entity_info['details'] = entity_details
            grouped_findings[rule_id]['entities'].append(entity_info)
        
        # Sort groups by severity
        sorted_groups = sorted(
            grouped_findings.values(),
            key=lambda g: (self.SEVERITY_ORDER.get(g['severity'].lower(), 5), -g['risk_score'])
        )
        
        # Build findings by severity
        current_severity = None
        finding_num = 1
        
        for idx, group in enumerate(sorted_groups):
            severity = group['severity'].lower()
            
            # Add severity header if changed
            if severity != current_severity:
                current_severity = severity
                severity_color = self.COLORS.get(severity, self.COLORS['info'])
                
                # Count findings in this severity
                sev_count = sum(1 for g in sorted_groups if g['severity'].lower() == severity)
                sev_entities = sum(len(g['entities']) for g in sorted_groups if g['severity'].lower() == severity)
                
                # Severity section header
                sev_header = Table(
                    [[Paragraph(f"{severity.upper()} SEVERITY FINDINGS ({sev_count} rules, {sev_entities} affected entities)", 
                               ParagraphStyle('SevHeader', parent=self.styles['SubHeading'],
                                            textColor=colors.white, fontSize=11))]],
                    colWidths=[6.8*inch]
                )
                sev_header.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), severity_color),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ]))
                
                # Build first finding card header to keep with severity banner
                first_finding_header = self._build_finding_header_only(group, finding_num, section_num)
                
                # Keep severity banner with first finding header
                elements.append(KeepTogether([
                    Spacer(1, 0.15*inch),
                    sev_header,
                    Spacer(1, 0.1*inch),
                    first_finding_header
                ]))
                
                # Add entities and remediation for first finding
                elements.extend(self._build_finding_entities_and_remediation(group))
                finding_num += 1
            else:
                # Not the first finding in this severity - normal flow
                finding_elements = self._build_finding_group_card(group, finding_num, section_num)
                elements.extend(finding_elements)
                finding_num += 1
        
        return elements
    
    def _build_finding_header_only(self, group: Dict[str, Any], finding_num: int, 
                                    section_num: int = 3) -> Table:
        """Build just the finding header section (for keeping with severity banner)."""
        severity = group['severity'].lower()
        severity_color = self.COLORS.get(severity, self.COLORS['info'])
        bg_color = self.COLORS.get(f'{severity}_bg', self.COLORS['light_bg'])
        entity_count = len(group['entities'])
        category = group.get('category', 'general')
        
        header_content = []
        
        # Header row with title and severity badge
        header_data = [[
            Paragraph(f"<b>{section_num}.{finding_num}</b>&nbsp;&nbsp;{group['rule_name']}", self.styles['FindingTitle']),
            Paragraph(f"<b>{severity.upper()}</b>", 
                     ParagraphStyle('Badge', parent=self.styles['TableCell'],
                                   textColor=colors.white, alignment=TA_CENTER,
                                   fontName='Helvetica-Bold'))
        ]]
        header_table = Table(header_data, colWidths=[5.5*inch, 1*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (1, 0), (1, 0), severity_color),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('BACKGROUND', (0, 0), (0, 0), bg_color),
        ]))
        header_content.append(header_table)
        
        # Meta info
        meta_text = f"Rule: {group['rule_id']} | Risk Score: {group['risk_score']:.1f} | Category: {category.replace('_', ' ').title()} | <b>{entity_count} affected</b>"
        header_content.append(Paragraph(meta_text, ParagraphStyle(
            'Meta', parent=self.styles['FindingBody'], textColor=self.COLORS['text_secondary'],
            fontSize=8, spaceBefore=4, spaceAfter=6)))
        
        # Description
        if group['description']:
            header_content.append(Paragraph("<b>Description</b>", self.styles['FindingLabel']))
            header_content.append(Paragraph(group['description'], self.styles['FindingBody']))
        
        # Governance Impact - NEW SECTION
        governance_impact = self._get_governance_impact(category, severity)
        header_content.append(Paragraph("<b>Governance Impact</b>", self.styles['FindingLabel']))
        header_content.append(Paragraph(governance_impact, self.styles['GovernanceText']))
        
        # Compliance impact
        if group['compliance_impact']:
            header_content.append(Paragraph("<b>Compliance Impact</b>", self.styles['FindingLabel']))
            header_content.append(Paragraph(group['compliance_impact'], self.styles['FindingBody']))
        
        # Wrap header in styled box
        header_inner = Table([[c] for c in header_content], colWidths=[6.5*inch])
        header_inner.setStyle(TableStyle([
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ]))
        
        header_box = Table([[header_inner]], colWidths=[6.8*inch])
        header_box.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), bg_color),
            ('BOX', (0, 0), (-1, -1), 1, self.COLORS['border']),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        
        return header_box
    
    def _get_governance_impact(self, category: str, severity: str) -> str:
        """Get governance impact text based on category and severity."""
        category_lower = category.lower().replace(' ', '_').replace('-', '_')
        severity_lower = severity.lower()
        
        # Find matching category
        matched_category = 'general'
        for cat_key in self.GOVERNANCE_IMPACTS.keys():
            if cat_key in category_lower:
                matched_category = cat_key
                break
        
        impacts = self.GOVERNANCE_IMPACTS.get(matched_category, self.GOVERNANCE_IMPACTS['general'])
        return impacts.get(severity_lower, impacts.get('medium', 'Governance review recommended.'))
    
    def _build_finding_entities_and_remediation(self, group: Dict[str, Any]) -> List:
        """Build the entities table and remediation section for a finding."""
        elements = []
        severity = group['severity'].lower()
        bg_color = self.COLORS.get(f'{severity}_bg', self.COLORS['light_bg'])
        entity_count = len(group['entities'])
        
        # Entities header with background
        entities_header_table = Table(
            [[Paragraph(f"<b>Affected Entities ({entity_count})</b>", self.styles['FindingLabel'])]],
            colWidths=[6.8*inch]
        )
        entities_header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), bg_color),
            ('BOX', (0, 0), (-1, -1), 1, self.COLORS['border']),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(entities_header_table)
        
        # Build entities table with enhanced details
        entities_table = self._build_entities_table(group['entities'], bg_color)
        elements.append(entities_table)
        
        # Remediation section
        remediation_content = []
        remediation_content.append(Paragraph("<b>Recommended Action</b>", self.styles['FindingLabel']))
        remediation_content.append(Paragraph(group['remediation'] or 'No specific remediation provided', 
                                            self.styles['FindingBody']))
        
        remediation_inner = Table([[c] for c in remediation_content], colWidths=[6.5*inch])
        remediation_inner.setStyle(TableStyle([
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ]))
        
        remediation_box = Table([[remediation_inner]], colWidths=[6.8*inch])
        remediation_box.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), bg_color),
            ('BOX', (0, 0), (-1, -1), 1, self.COLORS['border']),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        elements.append(KeepTogether([remediation_box]))
        elements.append(Spacer(1, 0.15*inch))
        
        return elements
    
    def _build_entities_table(self, entities: List[Dict], bg_color) -> Table:
        """Build the entities table with enhanced entity details."""
        # Table header - now with Entity Details column
        entities_table_header = [[
            Paragraph('<b>#</b>', ParagraphStyle('TH', fontSize=7, 
                     textColor=colors.white, fontName='Helvetica-Bold', alignment=TA_CENTER)),
            Paragraph('<b>Entity</b>', ParagraphStyle('TH', fontSize=7, 
                     textColor=colors.white, fontName='Helvetica-Bold')),
            Paragraph('<b>Entity Details</b>', ParagraphStyle('TH', fontSize=7, 
                     textColor=colors.white, fontName='Helvetica-Bold'))
        ]]
        
        # Build ALL entity rows with enhanced details
        entity_rows = []
        for idx, entity in enumerate(entities, 1):
            entity_name = str(entity['name'])
            if len(entity_name) > 45:
                entity_name = entity_name[:42] + '...'
            
            # Get entity details (new enhanced format)
            details = entity.get('details', [])
            if details:
                details_text = ' | '.join(details[:3])  # Show up to 3 details
                if len(details) > 3:
                    details_text += f' (+{len(details)-3} more)'
            else:
                # Fallback to evidence for backward compatibility
                evidence = entity.get('evidence', {})
                evidence_items = []
                for key, value in list(evidence.items())[:3]:
                    if key not in ['affected_entity', 'subject_cn', 'entity_name']:
                        if isinstance(value, list):
                            val_str = str(value[0])[:30] if value else ''
                        else:
                            val_str = str(value)[:30]
                        evidence_items.append(f"{key}: {val_str}")
                details_text = ' | '.join(evidence_items) if evidence_items else '-'
            
            entity_rows.append([
                Paragraph(str(idx), ParagraphStyle('TC', fontSize=7, alignment=TA_CENTER)),
                Paragraph(entity_name, ParagraphStyle('TC', fontSize=7)),
                Paragraph(details_text, ParagraphStyle('TC', fontSize=7, textColor=self.COLORS['text_secondary']))
            ])
        
        # Create table
        entities_table_data = entities_table_header + entity_rows
        entities_table = Table(entities_table_data, colWidths=[0.4*inch, 2.2*inch, 4.2*inch],
                              repeatRows=1)
        
        table_style = [
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['secondary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ALIGN', (0, 0), (0, -1), 'CENTER'),
            # Left and right borders to match box styling
            ('LINEAFTER', (-1, 0), (-1, -1), 1, self.COLORS['border']),
            ('LINEBEFORE', (0, 0), (0, -1), 1, self.COLORS['border']),
        ]
        
        # Alternating row colors
        for row_idx in range(1, len(entities_table_data)):
            if row_idx % 2 == 0:
                table_style.append(('BACKGROUND', (0, row_idx), (-1, row_idx), self.COLORS['light_bg']))
            else:
                table_style.append(('BACKGROUND', (0, row_idx), (-1, row_idx), bg_color))
        
        entities_table.setStyle(TableStyle(table_style))
        return entities_table
    
    def _build_finding_group_card(self, group: Dict[str, Any], finding_num: int,
                                   section_num: int = 3) -> List:
        """Build a finding group card with all affected entities and proper page handling."""
        elements = []
        
        # Build header and keep together
        header_box = self._build_finding_header_only(group, finding_num, section_num)
        elements.append(KeepTogether([header_box]))
        
        # Add entities and remediation
        elements.extend(self._build_finding_entities_and_remediation(group))
        
        return elements
    
    def _build_remediation_roadmap(self, findings: List[Dict[str, Any]], 
                                    findings_analysis: Dict[str, Any],
                                    section_num: int = 4) -> List:
        """Build the prioritised remediation roadmap with improved tables."""
        elements = []
        
        elements.append(Paragraph(f"{section_num}. Remediation Roadmap", self.styles['SectionHeading']))
        elements.append(HRFlowable(width="100%", thickness=2, color=self.COLORS['primary']))
        elements.append(Spacer(1, 0.15*inch))
        
        if not findings:
            elements.append(Paragraph("No remediation actions required.", self.styles['BodyText']))
            return elements
        
        intro_text = """This section presents a prioritised remediation roadmap based on a combination of 
        finding severity and implementation complexity. Actions are categorised as Quick Wins (high impact, 
        relatively low effort) or Long-term Initiatives (requiring planning, resources, and coordination). 
        This approach enables organisations to achieve rapid security improvements while planning for more 
        substantial changes."""
        elements.append(Paragraph(intro_text, self.styles['BodyText']))
        
        # Categorise findings
        quick_wins = []
        long_term = []
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            remediation = finding.get('remediation', '').lower()
            risk_score = finding.get('risk_score', 0)
            
            is_quick = self._is_quick_win(severity, remediation)
            
            # Add priority score for sorting (combines severity and risk score)
            finding['_priority_score'] = self.SEVERITY_ORDER.get(severity, 5) * 100 - risk_score
            
            if is_quick:
                quick_wins.append(finding)
            else:
                long_term.append(finding)
        
        # Sort by priority score
        quick_wins.sort(key=lambda f: f.get('_priority_score', 0))
        long_term.sort(key=lambda f: f.get('_priority_score', 0))
        
        # Quick Wins Section - keep header with table
        quick_wins_elements = []
        quick_wins_elements.append(Paragraph(f"{section_num}.1 Quick Wins (Immediate Actions)", self.styles['SubHeading']))
        
        quick_win_text = """These items can typically be resolved within days and provide immediate security 
        improvements. They often involve configuration changes, policy updates, or certificate renewals that 
        do not require significant infrastructure changes."""
        quick_wins_elements.append(Paragraph(quick_win_text, self.styles['BodyText']))
        
        if quick_wins:
            quick_wins_table = self._build_roadmap_table(quick_wins[:10])
            # Keep section heading with at least first part of table
            elements.append(KeepTogether(quick_wins_elements + quick_wins_table[:1] if quick_wins_table else quick_wins_elements))
            if len(quick_wins_table) > 1:
                elements.extend(quick_wins_table[1:])
        else:
            quick_wins_elements.append(Paragraph("<i>No quick win items identified. All findings require longer-term planning.</i>", 
                                     self.styles['BodyText']))
            elements.append(KeepTogether(quick_wins_elements))
        
        # Long-term Section - keep header with table
        elements.append(Spacer(1, 0.2*inch))
        long_term_elements = []
        long_term_elements.append(Paragraph(f"{section_num}.2 Long-term Initiatives", self.styles['SubHeading']))
        
        long_term_text = """These items require planning, resource allocation, or coordination across teams. 
        They may involve infrastructure changes, migration to new algorithms, or organisation-wide policy updates. 
        Schedule these as part of regular security improvement cycles or dedicated remediation projects."""
        long_term_elements.append(Paragraph(long_term_text, self.styles['BodyText']))
        
        if long_term:
            long_term_table = self._build_roadmap_table(long_term[:10])
            # Keep section heading with at least first part of table
            elements.append(KeepTogether(long_term_elements + long_term_table[:1] if long_term_table else long_term_elements))
            if len(long_term_table) > 1:
                elements.extend(long_term_table[1:])
        else:
            long_term_elements.append(Paragraph("<i>No long-term initiatives identified. All findings can be addressed quickly.</i>", 
                                     self.styles['BodyText']))
            elements.append(KeepTogether(long_term_elements))
        
        # Summary recommendation
        elements.append(Spacer(1, 0.2*inch))
        elements.append(Paragraph(f"{section_num}.3 Recommended Approach", self.styles['SubHeading']))
        
        critical_count = findings_analysis['severity_counts'].get('critical', 0)
        high_count = findings_analysis['severity_counts'].get('high', 0)
        
        if critical_count > 0:
            approach_text = f"""Given the presence of <b>{critical_count} critical findings</b>, immediate action is 
            recommended. Establish an emergency remediation team and address critical items within 24-48 hours. 
            High-severity items should follow within 1-2 weeks. Implement a tracking mechanism to monitor 
            remediation progress and verify each fix."""
        elif high_count > 0:
            approach_text = f"""With <b>{high_count} high-severity findings</b>, a structured remediation programme 
            should be initiated within the next 1-2 weeks. Assign ownership for each finding and establish clear 
            timelines. Consider addressing quick wins first to demonstrate progress while planning longer-term initiatives."""
        else:
            approach_text = """The findings identified are predominantly medium and low severity. These can be 
            addressed as part of normal security maintenance cycles. Consider grouping related findings to 
            improve efficiency and ensure changes are properly tested before deployment."""
        
        elements.append(Paragraph(approach_text, self.styles['BodyText']))
        
        return elements
    
    def _is_quick_win(self, severity: str, remediation: str) -> bool:
        """Determine if a finding is a quick win based on severity and remediation text."""
        quick_win_indicators = [
            'renew', 'update', 'enable', 'disable', 'configure', 'set',
            'change', 'modify', 'adjust', 'revoke', 'remove', 'add',
            'verify', 'check', 'review', 'ensure'
        ]
        
        long_term_indicators = [
            'migrate', 'replace', 'upgrade', 'infrastructure', 'architecture',
            'redesign', 'implement new', 'deploy', 'rollout', 'phase',
            'transition', 'reissue all', 'organization-wide', 'organisation-wide',
            'all certificates', 'all keys', 'enterprise', 'systematic'
        ]
        
        # Check for long-term indicators first
        for indicator in long_term_indicators:
            if indicator in remediation:
                return False
        
        # Check for quick-win indicators
        for indicator in quick_win_indicators:
            if indicator in remediation:
                return True
        
        # Default based on severity - critical/high often need more planning
        if severity in ['critical', 'high']:
            return False
        
        return True
    
    def _build_roadmap_table(self, findings: List[Dict[str, Any]]) -> List:
        """Build a remediation roadmap table."""
        elements = []
        
        if not findings:
            return elements
        
        table_data = [
            [Paragraph('<b>#</b>', self.styles['TableHeader']),
             Paragraph('<b>Finding</b>', self.styles['TableHeader']),
             Paragraph('<b>Remediation Action</b>', self.styles['TableHeader']),
             Paragraph('<b>Severity</b>', self.styles['TableHeader'])]
        ]
        
        for idx, finding in enumerate(findings, 1):
            rule_name = finding.get('rule_name', finding.get('title', 'Unknown'))
            if len(rule_name) > 40:
                rule_name = rule_name[:37] + '...'
            
            remediation = finding.get('remediation', 'Review and address')
            if len(remediation) > 70:
                remediation = remediation[:67] + '...'
            
            severity = finding.get('severity', 'info').upper()
            
            table_data.append([
                Paragraph(str(idx), self.styles['TableCell']),
                Paragraph(rule_name, self.styles['TableCell']),
                Paragraph(remediation, self.styles['TableCell']),
                Paragraph(severity, ParagraphStyle('SevCell', parent=self.styles['TableCell'],
                                                   textColor=colors.white, alignment=TA_CENTER,
                                                   fontName='Helvetica-Bold'))
            ])
        
        if len(table_data) > 1:
            roadmap_table = Table(table_data, colWidths=[0.4*inch, 2*inch, 3.4*inch, 0.8*inch])
            
            table_style = [
                ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['table_header']),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
            ]
            
            # Color severity column and alternate rows
            for row_idx in range(1, len(table_data)):
                severity_lower = findings[row_idx-1].get('severity', 'info').lower()
                severity_color = self.COLORS.get(severity_lower, self.COLORS['info'])
                
                table_style.append(('BACKGROUND', (-1, row_idx), (-1, row_idx), severity_color))
                
                # Alternate row background for other columns
                if row_idx % 2 == 0:
                    table_style.append(('BACKGROUND', (0, row_idx), (-2, row_idx), self.COLORS['table_alt']))
                else:
                    table_style.append(('BACKGROUND', (0, row_idx), (-2, row_idx), self.COLORS['white']))
            
            roadmap_table.setStyle(TableStyle(table_style))
            elements.append(roadmap_table)
        
        return elements
    
    def _build_appendix(self, metadata: Dict[str, Any],
                        collector_summaries: Dict[str, Any],
                        policy: Dict[str, Any],
                        document_assessment: Optional[Dict[str, Any]] = None,
                        section_num: int = 5) -> List:
        """Build the appendix section."""
        elements = []
        
        elements.append(Paragraph(f"{section_num}. Appendix", self.styles['SectionHeading']))
        elements.append(HRFlowable(width="100%", thickness=2, color=self.COLORS['primary']))
        elements.append(Spacer(1, 0.15*inch))
        
        # Scan Metadata
        elements.append(Paragraph(f"{section_num}.1 Assessment Metadata", self.styles['SubHeading']))
        
        meta_data = []
        if metadata.get('scan_timestamp'):
            meta_data.append(['Scan Timestamp', str(metadata['scan_timestamp'])])
        if metadata.get('policy_version'):
            meta_data.append(['Policy Version', str(metadata['policy_version'])])
        if metadata.get('total_certificates'):
            meta_data.append(['Total Certificates', str(metadata['total_certificates'])])
        if metadata.get('total_keys'):
            meta_data.append(['Total Keys', str(metadata['total_keys'])])
        if metadata.get('total_crls_checked'):
            meta_data.append(['CRLs Checked', str(metadata['total_crls_checked'])])
        if metadata.get('total_findings'):
            meta_data.append(['Total Findings', str(metadata['total_findings'])])
        
        if meta_data:
            meta_table = Table([[Paragraph(k, self.styles['TableCellBold']), 
                                Paragraph(v, self.styles['TableCell'])] for k, v in meta_data],
                              colWidths=[2*inch, 4.8*inch])
            meta_table.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
                ('BACKGROUND', (0, 0), (0, -1), self.COLORS['light_bg']),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ]))
            elements.append(meta_table)
        
        # Collector Summaries
        if collector_summaries:
            elements.append(Spacer(1, 0.15*inch))
            elements.append(Paragraph(f"{section_num}.2 Data Sources", self.styles['SubHeading']))
            
            source_data = []
            
            tls = collector_summaries.get('tls', {})
            if tls.get('enabled'):
                source_data.append(['TLS Scanner', 
                    f"{tls.get('endpoints_scanned', 0)} endpoints scanned, "
                    f"{tls.get('certificates_discovered', 0)} certificates discovered"])
            
            azure = collector_summaries.get('azure_keyvault', {})
            if azure.get('enabled'):
                source_data.append(['Azure Key Vault', 
                    f"{azure.get('total_vaults_successful', 0)} vaults accessed, "
                    f"{azure.get('total_certificates', 0)} certificates, "
                    f"{azure.get('total_keys', 0)} keys"])
            
            ejbca = collector_summaries.get('ejbca', {})
            if ejbca.get('enabled'):
                source_data.append(['EJBCA', 
                    f"{ejbca.get('total_servers_successful', 0)} servers connected, "
                    f"{ejbca.get('total_certificates', 0)} certificates"])
            
            luna = collector_summaries.get('luna_hsm', {})
            if luna.get('enabled'):
                source_data.append(['Luna HSM', 
                    f"{luna.get('total_hsms', 0)} HSMs, "
                    f"{luna.get('total_keys', 0)} keys, "
                    f"{luna.get('total_certificates', 0)} certificates"])
            
            crl = collector_summaries.get('crl', {})
            if crl.get('enabled'):
                source_data.append(['CRL Collector', 
                    f"{crl.get('total_crls_fetched', 0)} CRLs fetched"])
            
            file_scan = collector_summaries.get('file_scan', {})
            if file_scan.get('enabled'):
                source_data.append(['File Scanner', 
                    f"{file_scan.get('total_files_found', 0)} files found"])
            
            if source_data:
                source_table = Table([[Paragraph(k, self.styles['TableCellBold']), 
                                      Paragraph(v, self.styles['TableCell'])] for k, v in source_data],
                                    colWidths=[1.5*inch, 5.3*inch])
                source_table.setStyle(TableStyle([
                    ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
                    ('BACKGROUND', (0, 0), (0, -1), self.COLORS['light_bg']),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ]))
                elements.append(source_table)
        
        # Policy Details
        if policy:
            elements.append(Spacer(1, 0.15*inch))
            elements.append(Paragraph(f"{section_num}.3 Policy Configuration", self.styles['SubHeading']))
            
            policy_meta = policy.get('metadata', {})
            policy_data = [
                ['Policy Name', policy_meta.get('name', 'Unknown')],
            ]
            if policy_meta.get('description'):
                policy_data.append(['Description', policy_meta.get('description')])
            if policy_meta.get('category'):
                policy_data.append(['Category', policy_meta.get('category')])
            
            rules = policy.get('rules', [])
            if rules:
                policy_data.append(['Total Rules', str(len(rules))])
            
            policy_table = Table([[Paragraph(k, self.styles['TableCellBold']), 
                                  Paragraph(str(v), self.styles['TableCell'])] for k, v in policy_data],
                                colWidths=[1.5*inch, 5.3*inch])
            policy_table.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
                ('BACKGROUND', (0, 0), (0, -1), self.COLORS['light_bg']),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(policy_table)
            
            # Policy Rules Section
            if rules:
                elements.append(Spacer(1, 0.15*inch))
                elements.append(Paragraph(f"{section_num}.4 Policy Rules", self.styles['SubHeading']))
                elements.append(Paragraph(
                    f"The following {len(rules)} rules were evaluated during the assessment:",
                    self.styles['BodyText']
                ))
                
                # Build rules table
                rules_header = [[
                    Paragraph('<b>Rule ID</b>', ParagraphStyle('TH', fontSize=7, 
                             textColor=colors.white, fontName='Helvetica-Bold')),
                    Paragraph('<b>Rule Name</b>', ParagraphStyle('TH', fontSize=7, 
                             textColor=colors.white, fontName='Helvetica-Bold')),
                    Paragraph('<b>Severity</b>', ParagraphStyle('TH', fontSize=7, 
                             textColor=colors.white, fontName='Helvetica-Bold', alignment=TA_CENTER)),
                    Paragraph('<b>Category</b>', ParagraphStyle('TH', fontSize=7, 
                             textColor=colors.white, fontName='Helvetica-Bold'))
                ]]
                
                rules_rows = []
                extracted_severities = []  # Store extracted severity for styling
                for rule in rules:
                    # Handle different policy rule structures
                    rule_meta = rule.get('metadata', {})
                    
                    rule_id = rule.get('rule_id') or rule.get('id') or 'Unknown'
                    rule_name = rule_meta.get('name') or rule.get('name') or rule_id
                    severity = rule_meta.get('severity') or rule.get('severity') or 'info'
                    category = rule_meta.get('category') or rule.get('category') or 'general'
                    
                    # Store severity for styling later
                    extracted_severities.append(severity.lower())
                    
                    # Truncate if too long
                    if len(str(rule_id)) > 35:
                        rule_id = str(rule_id)[:32] + '...'
                    if len(str(rule_name)) > 40:
                        rule_name = str(rule_name)[:37] + '...'
                    
                    rules_rows.append([
                        Paragraph(str(rule_id), ParagraphStyle('TC', fontSize=7)),
                        Paragraph(str(rule_name), ParagraphStyle('TC', fontSize=7)),
                        Paragraph(str(severity).upper(), ParagraphStyle('TC', fontSize=7, 
                                 alignment=TA_CENTER, fontName='Helvetica-Bold')),
                        Paragraph(str(category).replace('_', ' ').replace('-', ' ').title(), ParagraphStyle('TC', fontSize=7))
                    ])
                
                rules_table_data = rules_header + rules_rows
                rules_table = Table(rules_table_data, 
                                   colWidths=[1.6*inch, 2.3*inch, 0.7*inch, 1.6*inch],
                                   repeatRows=1)
                
                rules_style = [
                    ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['table_header']),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 4),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]
                
                # Color severity column and alternate rows using extracted severities
                for row_idx in range(1, len(rules_table_data)):
                    severity_val = extracted_severities[row_idx - 1]
                    severity_color = self.COLORS.get(severity_val, self.COLORS['info'])
                    rules_style.append(('BACKGROUND', (2, row_idx), (2, row_idx), severity_color))
                    rules_style.append(('TEXTCOLOR', (2, row_idx), (2, row_idx), colors.white))
                    
                    # Alternate row background
                    if row_idx % 2 == 0:
                        rules_style.append(('BACKGROUND', (0, row_idx), (1, row_idx), self.COLORS['light_bg']))
                        rules_style.append(('BACKGROUND', (3, row_idx), (3, row_idx), self.COLORS['light_bg']))
                
                rules_table.setStyle(TableStyle(rules_style))
                elements.append(rules_table)
        
        # Document Assessment Details (if applicable)
        if document_assessment:
            elements.append(Spacer(1, 0.2*inch))
            elements.append(Paragraph(f"{section_num}.5 Document Assessment Details", self.styles['SubHeading']))
            
            template_data = [
                ['Document Name', document_assessment.get('filename', 'Unknown')],
                ['Document Type', document_assessment.get('document_type', 'Unknown').replace('_', ' ').title()],
                ['Template Used', document_assessment.get('template_used', 'Standard Template')],
                ['Assessment ID', document_assessment.get('assessment_id', 'Unknown')],
                ['Coverage Score', f"{document_assessment.get('coverage_score', 0):.1f}%"],
            ]
            
            # Add compliance frameworks
            compliance_scores = document_assessment.get('compliance_scores', {})
            if isinstance(compliance_scores, str):
                try:
                    compliance_scores = json.loads(compliance_scores)
                except:
                    compliance_scores = {}
            
            if compliance_scores:
                frameworks = ', '.join(sorted(compliance_scores.keys()))
                template_data.append(['Frameworks Assessed', frameworks])
            
            template_table = Table([[Paragraph(k, self.styles['TableCellBold']), 
                                    Paragraph(str(v), self.styles['TableCell'])] for k, v in template_data],
                                  colWidths=[2*inch, 4.8*inch])
            template_table.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
                ('BACKGROUND', (0, 0), (0, -1), self.COLORS['light_bg']),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ]))
            elements.append(template_table)
            
            # Framework compliance scores detail
            if compliance_scores:
                elements.append(Spacer(1, 0.1*inch))
                elements.append(Paragraph(f"{section_num}.6 Framework Compliance Scores", self.styles['SubHeading2']))
                
                framework_data = [[
                    Paragraph('<b>Framework</b>', self.styles['TableHeader']),
                    Paragraph('<b>Score</b>', self.styles['TableHeader']),
                    Paragraph('<b>Status</b>', self.styles['TableHeader'])
                ]]
                
                for framework, score in sorted(compliance_scores.items()):
                    status = "Compliant" if score >= 80 else "Partial" if score >= 60 else "Non-Compliant"
                    framework_data.append([
                        Paragraph(framework, self.styles['TableCell']),
                        Paragraph(f"{score:.1f}%", self.styles['TableCell']),
                        Paragraph(status, self.styles['TableCell'])
                    ])
                
                framework_table = Table(framework_data, colWidths=[2.5*inch, 1.5*inch, 2.8*inch])
                framework_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['table_header']),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ]))
                elements.append(framework_table)
        
        # Document footer
        elements.append(Spacer(1, 0.3*inch))
        elements.append(HRFlowable(width="100%", thickness=1, color=self.COLORS['border']))
        elements.append(Spacer(1, 0.1*inch))
        elements.append(Paragraph(
            f"<i>Report generated by {self.company_name} Cryptographic Asset Intelligence Platform (CAIP)</i>",
            ParagraphStyle('DocFooter', parent=self.styles['Footer'], fontSize=8, 
                          textColor=self.COLORS['text_secondary'])
        ))
        
        return elements
    
    def _add_page_header_footer(self, canvas, doc):
        """Add header and footer to each page."""
        canvas.saveState()
        
        # Header line
        canvas.setStrokeColor(self.COLORS['border'])
        canvas.setLineWidth(0.5)
        canvas.line(0.6*inch, A4[1] - 0.45*inch, A4[0] - 0.6*inch, A4[1] - 0.45*inch)
        
        # Footer
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(self.COLORS['text_secondary'])
        
        footer_text = f"{self.company_name} | PKI Security Assessment | Confidential"
        canvas.drawString(0.6*inch, 0.35*inch, footer_text)
        
        # Page number
        page_num = f"Page {doc.page}"
        canvas.drawRightString(A4[0] - 0.6*inch, 0.35*inch, page_num)
        
        # Footer line
        canvas.line(0.6*inch, 0.5*inch, A4[0] - 0.6*inch, 0.5*inch)
        
        canvas.restoreState()


    def generate_engagement_executive_report(self,
                                              engagement: Dict[str, Any],
                                              merged_crypto_data: Dict[str, Any],
                                              document_assessments: List[Dict[str, Any]],
                                              report_name: str,
                                              output_path: str,
                                              output_formats: List[str] = None) -> Dict[str, str]:
        """
        Generate executive summary report for an engagement with multiple crypto
        reports and document assessments combined.
    
        Args:
            engagement: Engagement data (customer_name, project_name, etc.)
            merged_crypto_data: Merged crypto scan data with findings, certificates, etc.
            document_assessments: List of document assessment data dicts
            report_name: Name for the report
            output_path: Full path where PDF will be saved (base path for multiple formats)
            output_formats: List of formats to generate ['pdf', 'docx']. Defaults to ['pdf']
        
        Returns:
            Dict mapping format to generated file path, e.g. {'pdf': '/path/to/report.pdf', 'docx': '/path/to/report.docx'}
        """
        if output_formats is None:
            output_formats = ['pdf']
        
        generated_files = {}
        
        try:
            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=0.6*inch,
                leftMargin=0.6*inch,
                topMargin=0.6*inch,
                bottomMargin=0.6*inch
            )
        
            story = []
        
            # Extract and analyze findings from crypto data
            findings = merged_crypto_data.get('findings', [])
            findings_analysis = self._analyze_findings(findings)
        
            # Extract metadata and policy
            metadata = merged_crypto_data.get('metadata', {})
            policy = merged_crypto_data.get('policy', {})
            collector_summaries = merged_crypto_data.get('collector_summaries', {})
        
            # Add engagement context to metadata
            metadata['customer_name'] = engagement.get('customer_name', '')
            metadata['project_name'] = engagement.get('project_name', '')
            metadata['engagement_id'] = engagement.get('engagement_id', '')
            metadata['lead_consultant'] = engagement.get('lead_consultant', '')
        
            has_document_assessments = len(document_assessments) > 0
            
            # Track section numbers properly
            section_num = 1
        
            # 1. Cover Page
            story.extend(self._build_cover_page(
                report_name, 
                'engagement', 
                metadata, 
                is_combined=has_document_assessments
            ))
            story.append(PageBreak())
        
            # 2. Executive Summary (Crypto Assets)
            story.extend(self._build_executive_summary(
                merged_crypto_data, findings_analysis, metadata, policy, section_num
            ))
            section_num += 1

            # 2.5 Governance Maturity Summary (CxO-focused document assessment overview)
            if document_assessments:
                story.append(PageBreak())
                story.extend(self._build_governance_maturity_summary(document_assessments, section_num))
                section_num += 1

            # 3. Document Assessment Sections (for each document) - with proper numbering
            if document_assessments:
                for i, doc_assessment in enumerate(document_assessments):
                    story.append(PageBreak())
                    # Each document gets its own properly numbered section
                    if len(document_assessments) == 1:
                        story.extend(self._build_document_assessment_section(doc_assessment, section_num))
                    else:
                        # Multiple documents - create subsections
                        story.extend(self._build_document_assessment_section_multi(
                            doc_assessment, section_num, i + 1, len(document_assessments)
                        ))
                
                section_num += 1  # Only increment once for all documents
                
                # Combined risk summary after all documents
                story.extend(self._build_combined_risk_summary(
                    findings_analysis, document_assessments[0], section_num
                ))
                section_num += 1
        
            story.append(PageBreak())
        
            # Key Findings Overview (Crypto)
            story.extend(self._build_key_findings_overview(findings_analysis, section_num))
            section_num += 1
        
            # Detailed Findings by Severity
            story.extend(self._build_detailed_findings(findings, policy, findings_analysis, section_num))
            section_num += 1
            story.append(PageBreak())
        
            # Remediation Roadmap
            story.extend(self._build_remediation_roadmap(findings, findings_analysis, section_num))
            section_num += 1
            story.append(PageBreak())
        
            # Appendix
            story.extend(self._build_appendix(
                metadata, collector_summaries, policy,
                document_assessment=document_assessments[0] if document_assessments else None,
                section_num=section_num
            ))
        
            # Build the PDF if requested
            if 'pdf' in output_formats:
                doc.build(story, onFirstPage=self._add_page_header_footer,
                         onLaterPages=self._add_page_header_footer)
                generated_files['pdf'] = output_path
                logger.info(f"Engagement executive PDF generated: {output_path}")
            
            # Build DOCX if requested
            if 'docx' in output_formats:
                # Prepare report data for DOCX generation
                report_data = self._prepare_report_data_for_docx(
                    engagement=engagement,
                    merged_crypto_data=merged_crypto_data,
                    document_assessments=document_assessments,
                    findings_analysis=findings_analysis,
                    metadata=metadata,
                    policy=policy,
                    report_name=report_name
                )
                
                # Generate DOCX path
                docx_path = output_path.replace('.pdf', '.docx')
                if not docx_path.endswith('.docx'):
                    docx_path = output_path + '.docx'
                
                # Generate DOCX
                docx_result = self._generate_docx(report_data, docx_path)
                if docx_result:
                    generated_files['docx'] = docx_result
                    logger.info(f"Engagement executive DOCX generated: {docx_result}")
            
            return generated_files
        
        except Exception as e:
            logger.error(f"Error generating engagement executive report: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    def _prepare_report_data_for_docx(self, engagement: Dict[str, Any],
                                       merged_crypto_data: Dict[str, Any],
                                       document_assessments: List[Dict[str, Any]],
                                       findings_analysis: Dict[str, Any],
                                       metadata: Dict[str, Any],
                                       policy: Dict[str, Any],
                                       report_name: str) -> Dict[str, Any]:
        """
        Prepare structured report data for DOCX generation.
        
        This creates a JSON-serializable structure that can be passed to the 
        Node.js DOCX generator script.
        """
        # Build findings by severity for export
        findings_by_severity = {}
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            findings_list = findings_analysis['by_severity'].get(severity, [])
            findings_by_severity[severity] = [{
                'rule_id': f.get('rule_id', ''),
                'rule_name': f.get('rule_name', ''),
                'category': f.get('category', 'general'),
                'severity': f.get('severity', severity),
                'message': f.get('message', ''),
                'recommendation': f.get('recommendation', ''),
                'entity_cn': f.get('entity_cn', ''),
                'entity_type': f.get('entity_type', ''),
                'details': {
                    'issuer': f.get('issuer_cn', f.get('issuer', '')),
                    'not_after': str(f.get('not_after', ''))[:10] if f.get('not_after') else '',
                    'algorithm': f.get('key_algorithm', f.get('algorithm', '')),
                    'key_size': f.get('key_size', ''),
                    'serial': f.get('serial_number', '')[:20] if f.get('serial_number') else ''
                }
            } for f in findings_list]
        
        # Build document assessment summaries
        doc_assessment_summaries = []
        for doc_assessment in document_assessments:
            summary = doc_assessment.get('summary', {})
            if isinstance(summary, str):
                try:
                    summary = json.loads(summary)
                except:
                    summary = {}
            
            findings = doc_assessment.get('findings', [])
            missing_items = [f for f in findings if f.get('status') == 'missing']
            partial_items = [f for f in findings if f.get('status') == 'partial']
            found_items = [f for f in findings if f.get('status') == 'found']
            
            compliance_scores = doc_assessment.get('compliance_scores', {})
            if isinstance(compliance_scores, str):
                try:
                    compliance_scores = json.loads(compliance_scores)
                except:
                    compliance_scores = {}
            
            doc_assessment_summaries.append({
                'filename': doc_assessment.get('filename', 'Unknown'),
                'document_type': doc_assessment.get('document_type', 'unknown').replace('_', ' ').title(),
                'coverage_score': doc_assessment.get('coverage_score', 0),
                'grade': summary.get('assessment_grade', self._calculate_doc_grade(doc_assessment.get('coverage_score', 0))),
                'elements_found': len(found_items),
                'elements_partial': len(partial_items),
                'elements_missing': len(missing_items),
                'compliance_scores': compliance_scores,
                'critical_gaps': summary.get('critical_gaps', []),
                'missing_elements': [{
                    'element_name': f.get('element_name', f.get('element', '')),
                    'compliance_refs': f.get('compliance_refs', []),
                    'recommendation': f.get('recommendation', self._get_element_recommendation(
                        f.get('element_name', f.get('element', '')), 'missing'))
                } for f in missing_items],
                'partial_elements': [{
                    'element_name': f.get('element_name', f.get('element', '')),
                    'matched_section': f.get('matched_section', ''),
                    'recommendation': f.get('recommendation', '')
                } for f in partial_items]
            })
        
        # Build strengths and concerns for posture indicators
        strengths = []
        concerns = []
        
        if findings_analysis['severity_counts'].get('critical', 0) == 0:
            strengths.append("No critical severity findings requiring immediate action")
        
        total_findings = sum(findings_analysis['severity_counts'].values())
        low_info_count = findings_analysis['severity_counts'].get('low', 0) + findings_analysis['severity_counts'].get('info', 0)
        if total_findings > 0 and low_info_count / total_findings > 0.5:
            strengths.append("Majority of findings are low severity or informational")
        
        critical_count = findings_analysis['severity_counts'].get('critical', 0)
        high_count = findings_analysis['severity_counts'].get('high', 0)
        medium_count = findings_analysis['severity_counts'].get('medium', 0)
        
        if critical_count > 0:
            concerns.append(f"{critical_count} critical finding(s) requiring immediate attention")
        if high_count > 0:
            concerns.append(f"{high_count} high severity finding(s) requiring prompt remediation")
        if medium_count > 5:
            concerns.append(f"{medium_count} medium severity findings indicating systemic issues")
        
        report_data = {
            'report_name': report_name,
            'generated_at': datetime.now().isoformat(),
            'engagement': {
                'customer_name': engagement.get('customer_name', ''),
                'project_name': engagement.get('project_name', ''),
                'engagement_id': engagement.get('engagement_id', ''),
                'lead_consultant': engagement.get('lead_consultant', '')
            },
            'executive_summary': {
                'total_findings': findings_analysis['total'],
                'severity_counts': findings_analysis['severity_counts'],
                'categories_affected': list(findings_analysis['by_category'].keys()),
                'unique_rules_triggered': len(findings_analysis['unique_rules'])
            },
            'findings_by_severity': findings_by_severity,
            'findings_by_category': {
                cat: [{
                    'rule_name': f.get('rule_name', ''),
                    'severity': f.get('severity', ''),
                    'entity_cn': f.get('entity_cn', '')
                } for f in findings_list]
                for cat, findings_list in findings_analysis['by_category'].items()
            },
            'document_assessments': doc_assessment_summaries,
            'posture_indicators': {
                'strengths': strengths,
                'concerns': concerns
            },
            'policy': {
                'name': policy.get('name', ''),
                'version': policy.get('version', ''),
                'rules_count': len(policy.get('rules', []))
            },
            'metadata': {
                'assessment_date': str(metadata.get('assessment_date', datetime.now().date())),
                'sources': list(metadata.get('sources', {}).keys()) if isinstance(metadata.get('sources'), dict) else []
            }
        }
        
        return report_data
    
    def _generate_docx(self, report_data: Dict[str, Any], output_path: str) -> Optional[str]:
        """
        Generate Word document from report data using Node.js docx library.
        
        Args:
            report_data: Structured report data from _prepare_report_data_for_docx
            output_path: Path where DOCX will be saved
            
        Returns:
            Path to generated DOCX file, or None if generation failed
        """
        import subprocess
        import tempfile
        
        try:
            # Write report data to temp JSON file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(report_data, f, indent=2, default=str)
                json_path = f.name
            
            # Path to the Node.js script (should be in same directory as this service)
            script_dir = os.path.dirname(os.path.abspath(__file__))
            script_path = os.path.join(script_dir, 'executive_report_docx.js')
            
            # Check if script exists
            if not os.path.exists(script_path):
                logger.warning(f"DOCX generator script not found at {script_path}")
                # Clean up temp file
                os.unlink(json_path)
                return None
            
            # Run Node.js script
            result = subprocess.run(
                ['node', script_path, json_path, output_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Clean up temp file
            os.unlink(json_path)
            
            if result.returncode != 0:
                logger.error(f"DOCX generation failed: {result.stderr}")
                return None
            
            if os.path.exists(output_path):
                return output_path
            else:
                logger.error("DOCX file was not created")
                return None
                
        except subprocess.TimeoutExpired:
            logger.error("DOCX generation timed out")
            return None
        except Exception as e:
            logger.error(f"Error generating DOCX: {e}")
            return None

    def _build_document_assessment_section_multi(self, document_assessment: Dict[str, Any],
                                                  section_num: int,
                                                  doc_index: int,
                                                  total_docs: int) -> List:
        """Build document assessment section for multiple documents with proper subsection numbering."""
        elements = []
        
        # First document gets the main section header
        if doc_index == 1:
            elements.append(Paragraph(f"{section_num}. Documentation Compliance Assessments", self.styles['SectionHeading']))
            elements.append(HRFlowable(width="100%", thickness=2, color=self.COLORS['primary']))
            elements.append(Spacer(1, 0.15*inch))
            
            intro_text = f"""This section presents findings from {total_docs} document compliance assessment(s) 
            conducted as part of this engagement. Each document was evaluated against industry-standard 
            governance requirements and regulatory frameworks."""
            elements.append(Paragraph(intro_text, self.styles['BodyText']))
        
        # Document subsection header
        doc_name = document_assessment.get('filename', f'Document {doc_index}')
        elements.append(Spacer(1, 0.15*inch))
        elements.append(Paragraph(f"{section_num}.{doc_index} {doc_name}", self.styles['SubHeading']))
        
        # Document details
        doc_data = [
            ['Document Type', document_assessment.get('document_type', 'Unknown').replace('_', ' ').title()],
            ['Assessment Date', str(document_assessment.get('created_at', 'Unknown'))[:10]],
        ]
        
        doc_table = Table([[Paragraph(k, self.styles['TableCellBold']), 
                           Paragraph(str(v), self.styles['TableCell'])] for k, v in doc_data],
                         colWidths=[2*inch, 4.8*inch])
        doc_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
            ('BACKGROUND', (0, 0), (0, -1), self.COLORS['light_bg']),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(doc_table)
        
        # Coverage metrics
        coverage_score = document_assessment.get('coverage_score', 0)
        summary = document_assessment.get('summary', {})
        if isinstance(summary, str):
            try:
                summary = json.loads(summary)
            except:
                summary = {}
        
        grade = summary.get('assessment_grade', self._calculate_doc_grade(coverage_score))
        elements_found = summary.get('elements_found', 0)
        elements_partial = summary.get('elements_partial', 0)
        elements_missing = summary.get('elements_missing', 0)
        
        elements.append(Spacer(1, 0.1*inch))
        
        # Compact metrics display
        grade_colors = {'A': self.COLORS['success'], 'B': self.COLORS['low'], 
                       'C': self.COLORS['medium'], 'D': self.COLORS['high'], 'F': self.COLORS['critical']}
        grade_color = grade_colors.get(grade, self.COLORS['info'])
        
        metrics_text = f"<b>Grade:</b> <font color=\"{grade_color.hexval()}\">{grade}</font> | <b>Coverage:</b> {coverage_score:.0f}% | <b>Found:</b> {elements_found} | <b>Partial:</b> {elements_partial} | <b>Missing:</b> {elements_missing}"
        elements.append(Paragraph(metrics_text, self.styles['BodyText']))
        
        # Compliance scores if available
        compliance_scores = document_assessment.get('compliance_scores', {})
        if isinstance(compliance_scores, str):
            try:
                compliance_scores = json.loads(compliance_scores)
            except:
                compliance_scores = {}
        
        if compliance_scores:
            scores_parts = []
            for k, v in sorted(compliance_scores.items()):
                if v >= 80:
                    color = self.COLORS['success']
                elif v >= 60:
                    color = self.COLORS['medium']
                else:
                    color = self.COLORS['critical']
                scores_parts.append(f"{k}: <font color=\"{color.hexval()}\">{v:.0f}%</font>")
            scores_text = "<b>Framework Scores:</b> " + ", ".join(scores_parts)
            elements.append(Paragraph(scores_text, self.styles['BodyText']))
        
        # Get and parse findings
        findings = document_assessment.get('findings', [])
        
        # Debug logging
        logger.info(f"Multi-doc assessment keys: {list(document_assessment.keys())}")
        logger.info(f"Multi-doc assessment has {len(findings)} findings")
        
        if not findings:
            elements.append(Spacer(1, 0.1*inch))
            elements.append(Paragraph("<i>No element-level findings data available for this document.</i>", 
                                     self.styles['BodyText']))
        else:
            # Parse JSON fields in findings if needed
            parsed_findings = []
            for f in findings:
                pf = dict(f)
                if 'compliance_refs_json' in pf and pf['compliance_refs_json']:
                    try:
                        pf['compliance_refs'] = json.loads(pf['compliance_refs_json'])
                    except:
                        pf['compliance_refs'] = []
                elif 'compliance_refs' not in pf:
                    pf['compliance_refs'] = []
                parsed_findings.append(pf)
            findings = parsed_findings
            
            # Group by status
            found_items = [f for f in findings if f.get('status') == 'found']
            partial_items = [f for f in findings if f.get('status') == 'partial']
            missing_items = [f for f in findings if f.get('status') == 'missing']
            
            # MISSING ELEMENTS TABLE
            if missing_items:
                elements.append(Spacer(1, 0.1*inch))
                elements.append(Paragraph(f"<b>Missing Elements ({len(missing_items)})</b>", 
                                         ParagraphStyle('MissingHdr', parent=self.styles['BodyText'],
                                                       textColor=self.COLORS['critical'], fontName='Helvetica-Bold')))
                
                missing_table_data = [
                    [Paragraph('<b>Element</b>', self.styles['TableHeader']),
                     Paragraph('<b>Compliance Refs</b>', self.styles['TableHeader']),
                     Paragraph('<b>Recommendation</b>', self.styles['TableHeader'])]
                ]
                
                for item in missing_items[:10]:  # Limit for multi-doc view
                    element_name = item.get('element_name', item.get('element', 'Unknown'))
                    compliance_refs = item.get('compliance_refs', [])
                    if isinstance(compliance_refs, list) and compliance_refs:
                        refs_text = ', '.join(str(r) for r in compliance_refs[:2])
                    else:
                        refs_text = self._infer_compliance_refs(element_name)
                    recommendation = item.get('recommendation') or self._get_element_recommendation(element_name, 'missing')
                    # Truncate long recommendations
                    if len(recommendation) > 80:
                        recommendation = recommendation[:77] + '...'
                    
                    missing_table_data.append([
                        Paragraph(element_name, self.styles['TableCell']),
                        Paragraph(refs_text, ParagraphStyle('RefCell', parent=self.styles['TableCell'], fontSize=7)),
                        Paragraph(recommendation, self.styles['TableCell'])
                    ])
                
                if len(missing_items) > 10:
                    missing_table_data.append([
                        Paragraph(f"<i>... +{len(missing_items)-10} more missing</i>", self.styles['TableCell']),
                        Paragraph('', self.styles['TableCell']),
                        Paragraph('', self.styles['TableCell'])
                    ])
                
                missing_table = Table(missing_table_data, colWidths=[2*inch, 1.2*inch, 3.6*inch])
                missing_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['critical']),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
                    ('BACKGROUND', (0, 1), (-1, -1), self.COLORS['critical_bg']),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 5),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                elements.append(missing_table)
            
            # PARTIAL ELEMENTS TABLE
            if partial_items:
                elements.append(Spacer(1, 0.1*inch))
                elements.append(Paragraph(f"<b>Partial Coverage ({len(partial_items)})</b>", 
                                         ParagraphStyle('PartialHdr', parent=self.styles['BodyText'],
                                                       textColor=self.COLORS['medium'], fontName='Helvetica-Bold')))
                
                partial_table_data = [
                    [Paragraph('<b>Element</b>', self.styles['TableHeader']),
                     Paragraph('<b>Found In</b>', self.styles['TableHeader']),
                     Paragraph('<b>Enhancement Needed</b>', self.styles['TableHeader'])]
                ]
                
                for item in partial_items[:8]:
                    element_name = item.get('element_name', item.get('element', 'Unknown'))
                    matched_section = item.get('matched_section') or '-'
                    if len(matched_section) > 30:
                        matched_section = matched_section[:27] + '...'
                    recommendation = item.get('recommendation') or 'Expand coverage'
                    if len(recommendation) > 60:
                        recommendation = recommendation[:57] + '...'
                    
                    partial_table_data.append([
                        Paragraph(element_name, self.styles['TableCell']),
                        Paragraph(matched_section, self.styles['TableCell']),
                        Paragraph(recommendation, self.styles['TableCell'])
                    ])
                
                if len(partial_items) > 8:
                    partial_table_data.append([
                        Paragraph(f"<i>... +{len(partial_items)-8} more partial</i>", self.styles['TableCell']),
                        Paragraph('', self.styles['TableCell']),
                        Paragraph('', self.styles['TableCell'])
                    ])
                
                partial_table = Table(partial_table_data, colWidths=[2*inch, 1.8*inch, 3*inch])
                partial_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['medium']),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
                    ('BACKGROUND', (0, 1), (-1, -1), self.COLORS['medium_bg']),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 5),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                elements.append(partial_table)
            
            # FOUND ELEMENTS - Compact summary
            if found_items:
                elements.append(Spacer(1, 0.1*inch))
                found_names = [f.get('element_name', f.get('element', ''))[:40] for f in found_items[:6]]
                found_text = f"<b>Fully Addressed ({len(found_items)}):</b> " + ', '.join(found_names)
                if len(found_items) > 6:
                    found_text += f" (+{len(found_items)-6} more)"
                elements.append(Paragraph(found_text, 
                                         ParagraphStyle('FoundSummary', parent=self.styles['BodyText'],
                                                       textColor=self.COLORS['success'])))
        
        # Critical gaps detailed guidance (for first/only document or most critical)
        critical_gaps = summary.get('critical_gaps', [])
        if critical_gaps and doc_index == 1:
            elements.append(Spacer(1, 0.1*inch))
            elements.append(Paragraph("<b>Priority Remediation Guidance:</b>", self.styles['BodyText']))
            
            for idx, gap in enumerate(critical_gaps[:3]):
                element = gap.get('element', 'Unknown')
                recommendation = gap.get('recommendation', self._get_detailed_gap_recommendation(element))
                if len(recommendation) > 150:
                    recommendation = recommendation[:147] + '...'
                elements.append(Paragraph(f"<b>{idx+1}. {element}:</b> {recommendation}", 
                                         ParagraphStyle('GapRec', parent=self.styles['BodyText'], 
                                                       fontSize=8, leftIndent=10, spaceBefore=4)))
        
        return elements

    def _build_engagement_cover_page(self,
                                        engagement: Dict[str, Any],
                                        report_name: str,
                                        metadata: Dict[str, Any]) -> List:
        """Build cover page for engagement report."""
        elements = []
    
        elements.append(Spacer(1, 1.5*inch))
    
        # Logo
        if self.logo_path and os.path.exists(self.logo_path):
            try:
                logo = Image(self.logo_path, width=2*inch, height=0.8*inch)
                logo.hAlign = 'CENTER'
                elements.append(logo)
                elements.append(Spacer(1, 0.5*inch))
            except:
                pass
    
        # Title
        elements.append(Paragraph("PKI Security Assessment", self.styles['CoverTitle']))
        elements.append(Paragraph("Executive Summary Report", self.styles['CoverSubtitle']))
        elements.append(Spacer(1, 0.3*inch))
    
        # Engagement details box
        elements.append(HRFlowable(width="60%", thickness=2, color=self.COLORS['primary']))
        elements.append(Spacer(1, 0.3*inch))
    
        # Customer and project
        elements.append(Paragraph(
            f"<b>{engagement.get('customer_name', 'Customer')}</b>",
            ParagraphStyle('CustomerName', parent=self.styles['CoverSubtitle'],
                            fontSize=18, textColor=self.COLORS['primary'])
        ))
        elements.append(Paragraph(
            engagement.get('project_name', 'Project'),
            self.styles['CoverSubtitle']
        ))
        elements.append(Spacer(1, 0.2*inch))
        elements.append(Paragraph(
            f"Engagement: {engagement.get('engagement_id', 'N/A')}",
            self.styles['CoverSubtitle']
        ))
    
        elements.append(Spacer(1, 0.5*inch))
        elements.append(HRFlowable(width="60%", thickness=2, color=self.COLORS['primary']))
    
        # Date
        elements.append(Spacer(1, 0.5*inch))
        report_date = datetime.datetime.now().strftime('%B %d, %Y')
        elements.append(Paragraph(f"Report Date: {report_date}", self.styles['CoverSubtitle']))
    
        # Consultant
        if engagement.get('lead_consultant'):
            elements.append(Paragraph(
                f"Lead Consultant: {engagement['lead_consultant']}",
                self.styles['CoverSubtitle']
            ))
    
        # Confidentiality notice
        elements.append(Spacer(1, 1*inch))
        elements.append(Paragraph(
            "<b>CONFIDENTIAL</b>",
            ParagraphStyle('Confidential', parent=self.styles['CoverSubtitle'],
                            textColor=self.COLORS['critical'], fontSize=12)
        ))
        elements.append(Paragraph(
            "This document contains proprietary and confidential information.",
            ParagraphStyle('ConfNotice', parent=self.styles['Footer'],
                            alignment=TA_CENTER)
        ))
    
        return elements

    def _build_engagement_overview(self,
                                    engagement: Dict[str, Any],
                                    findings_analysis: Dict[str, Any],
                                    document_assessments: List[Dict[str, Any]]) -> List:
        """Build engagement overview section."""
        elements = []
    
        elements.append(Paragraph("1. Engagement Overview", self.styles['SectionHeading']))
    
        # Engagement details table
        details = [
            ['Customer', engagement.get('customer_name', 'N/A')],
            ['Project', engagement.get('project_name', 'N/A')],
            ['Engagement ID', engagement.get('engagement_id', 'N/A')],
            ['Status', engagement.get('status', 'N/A')],
            ['Start Date', engagement.get('start_date', 'N/A')],
        ]
    
        if engagement.get('lead_consultant'):
            details.append(['Lead Consultant', engagement['lead_consultant']])
    
        if engagement.get('description'):
            details.append(['Description', engagement['description']])
    
        details_table = Table(
            [[Paragraph(f"<b>{k}</b>", self.styles['TableCell']),
                Paragraph(str(v), self.styles['TableCell'])] for k, v in details],
            colWidths=[2*inch, 4.8*inch]
        )
        details_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
            ('BACKGROUND', (0, 0), (0, -1), self.COLORS['light_bg']),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ]))
        elements.append(details_table)
        elements.append(Spacer(1, 0.3*inch))
    
        # Assessment scope summary
        elements.append(Paragraph("1.1 Assessment Scope", self.styles['SubHeading']))
    
        scope_text = f"""This assessment includes {findings_analysis['total']} cryptographic 
        asset findings across the PKI infrastructure"""
    
        if document_assessments:
            scope_text += f" and {len(document_assessments)} document compliance assessment(s)"
    
        scope_text += "."
    
        elements.append(Paragraph(scope_text, self.styles['BodyText']))
    
        return elements

    def _build_engagement_risk_summary(self,
                                        engagement: Dict[str, Any],
                                        findings_analysis: Dict[str, Any],
                                        document_assessments: List[Dict[str, Any]]) -> List:
        """Build combined risk summary for engagement."""
        elements = []
    
        elements.append(Paragraph("Combined Risk Summary", self.styles['SectionHeading']))
    
        # Calculate overall metrics
        crypto_critical = len(findings_analysis['by_severity'].get('critical', []))
        crypto_high = len(findings_analysis['by_severity'].get('high', []))
    
        doc_issues = 0
        avg_coverage = 0
        if document_assessments:
            for doc in document_assessments:
                # Count missing/partial items
                findings = doc.get('findings', [])
                doc_issues += len([f for f in findings if f.get('status') in ['missing', 'partial']])
            avg_coverage = sum(d.get('coverage_score', 0) for d in document_assessments) / len(document_assessments)
    
        # Summary metrics table
        metrics_data = [
            [Paragraph('<b>Metric</b>', self.styles['TableHeader']),
                Paragraph('<b>Crypto Assets</b>', self.styles['TableHeader']),
                Paragraph('<b>Documents</b>', self.styles['TableHeader']),
                Paragraph('<b>Combined</b>', self.styles['TableHeader'])]
        ]
    
        metrics_data.append([
            Paragraph('Critical/High Issues', self.styles['TableCell']),
            Paragraph(str(crypto_critical + crypto_high), self.styles['TableCell']),
            Paragraph(str(doc_issues), self.styles['TableCell']),
            Paragraph(str(crypto_critical + crypto_high + doc_issues), self.styles['TableCell'])
        ])
    
        metrics_data.append([
            Paragraph('Total Findings', self.styles['TableCell']),
            Paragraph(str(findings_analysis['total']), self.styles['TableCell']),
            Paragraph(str(sum(len(d.get('findings', [])) for d in document_assessments)), self.styles['TableCell']),
            Paragraph(str(findings_analysis['total'] + sum(len(d.get('findings', [])) for d in document_assessments)), self.styles['TableCell'])
        ])
    
        if document_assessments:
            metrics_data.append([
                Paragraph('Avg Document Coverage', self.styles['TableCell']),
                Paragraph('N/A', self.styles['TableCell']),
                Paragraph(f'{avg_coverage:.1f}%', self.styles['TableCell']),
                Paragraph(f'{avg_coverage:.1f}%', self.styles['TableCell'])
            ])
    
        metrics_table = Table(metrics_data, colWidths=[2.2*inch, 1.5*inch, 1.5*inch, 1.5*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['table_header']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['border']),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
        ]))
        elements.append(metrics_table)
    
        return elements

    def _build_engagement_appendix(self,
                                    engagement: Dict[str, Any],
                                    metadata: Dict[str, Any],
                                    collector_summaries: Dict[str, Any],
                                    policy: Dict[str, Any],
                                    document_assessments: List[Dict[str, Any]]) -> List:
        """Build appendix for engagement report."""
        elements = []
    
        elements.append(Paragraph("Appendix", self.styles['SectionHeading']))
    
        # A. Report Sources
        elements.append(Paragraph("A. Report Sources", self.styles['SubHeading']))
    
        source_reports = metadata.get('source_reports', [])
        if source_reports:
            for i, source in enumerate(source_reports, 1):
                elements.append(Paragraph(f"{i}. {source}", self.styles['BodyText']))
    
        # B. Document Assessments Summary
        if document_assessments:
            elements.append(Spacer(1, 0.2*inch))
            elements.append(Paragraph("B. Document Assessments Included", self.styles['SubHeading']))
        
            for i, doc in enumerate(document_assessments, 1):
                elements.append(Paragraph(
                    f"{i}. {doc.get('filename', 'Unknown')} ({doc.get('document_type', 'Unknown')})",
                    self.styles['BodyText']
                ))
    
        # C. Generation Details
        elements.append(Spacer(1, 0.2*inch))
        elements.append(Paragraph("C. Report Generation", self.styles['SubHeading']))
    
        gen_details = [
            f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Engagement: {engagement.get('engagement_id', 'N/A')}",
            f"Platform: {self.company_name} CAIP"
        ]
    
        for detail in gen_details:
            elements.append(Paragraph(detail, self.styles['BodyText']))
    
        return elements

    def _add_engagement_header_footer(self, canvas, doc):
        """Add header and footer for engagement reports."""
        canvas.saveState()
    
        # Header line
        canvas.setStrokeColor(self.COLORS['border'])
        canvas.setLineWidth(0.5)
        canvas.line(0.6*inch, A4[1] - 0.45*inch, A4[0] - 0.6*inch, A4[1] - 0.45*inch)
    
        # Footer
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(self.COLORS['text_secondary'])
    
        footer_text = f"{self.company_name} | Customer Engagement Report | Confidential"
        canvas.drawString(0.6*inch, 0.35*inch, footer_text)
    
        # Page number
        page_num = f"Page {doc.page}"
        canvas.drawRightString(A4[0] - 0.6*inch, 0.35*inch, page_num)
    
        # Footer line
        canvas.line(0.6*inch, 0.5*inch, A4[0] - 0.6*inch, 0.5*inch)
    
        canvas.restoreState()


def generate_executive_report_path(reports_folder: str, name: str) -> str:
    """Generate a standardized executive report file path."""
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    name_safe = name.replace(' ', '_').replace('/', '_')
    filename = f'{name_safe}_executive_{timestamp}.pdf'
    return os.path.join(reports_folder, filename)
