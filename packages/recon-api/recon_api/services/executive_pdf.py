"""
ExecutivePdfService — PDF executive report generation using reportlab.

Colours preserved from legacy for visual consistency.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

import structlog
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle, PageBreak,
)

logger = structlog.get_logger("recon.executive_pdf")

# Colour palette — preserved from legacy exactly
COLORS = {
    "primary": colors.HexColor("#00FF41"),
    "secondary": colors.HexColor("#FFB800"),
    "background": colors.HexColor("#0D1B2A"),
    "card_bg": colors.HexColor("#1f2937"),
    "border": colors.HexColor("#334155"),
    "text_primary": colors.HexColor("#E2E8F0"),
    "text_secondary": colors.HexColor("#94A3B8"),
    "critical": colors.HexColor("#FF4444"),
    "high": colors.HexColor("#FF8800"),
    "medium": colors.HexColor("#FFCC00"),
    "low": colors.HexColor("#44AAFF"),
    "success": colors.HexColor("#22C55E"),
    "light_bg": colors.HexColor("#1E293B"),
}

SEVERITY_COLORS = {
    "critical": COLORS["critical"],
    "high": COLORS["high"],
    "medium": COLORS["medium"],
    "low": COLORS["low"],
    "info": colors.HexColor("#888888"),
}


def _header_footer(canvas, doc, report_name: str) -> None:
    """Page header and footer callback."""
    canvas.saveState()
    # Header
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(colors.HexColor("#666666"))
    canvas.drawString(72, A4[1] - 50, report_name[:60])
    canvas.drawRightString(A4[0] - 72, A4[1] - 50, "0xRecon")
    # Footer
    canvas.setFont("Helvetica", 7)
    canvas.drawCentredString(A4[0] / 2, 40, f"Page {doc.page}")
    canvas.setFont("Helvetica-Oblique", 6)
    canvas.drawCentredString(
        A4[0] / 2, 28,
        "CONFIDENTIAL — This document contains sensitive security assessment data",
    )
    canvas.restoreState()


class ExecutivePdfService:
    def __init__(self, report_data: dict[str, Any]) -> None:
        self._data = report_data
        self._styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self) -> None:
        self._styles.add(ParagraphStyle(
            "SectionHeading",
            parent=self._styles["Heading1"],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.HexColor("#1a1a2e"),
        ))
        self._styles.add(ParagraphStyle(
            "SubHeading",
            parent=self._styles["Heading2"],
            fontSize=13,
            spaceAfter=8,
            textColor=colors.HexColor("#2d3748"),
        ))
        self._styles.add(ParagraphStyle(
            "BodyText2",
            parent=self._styles["BodyText"],
            fontSize=10,
            spaceAfter=6,
        ))
        self._styles.add(ParagraphStyle(
            "StatNumber",
            parent=self._styles["Normal"],
            fontSize=24,
            alignment=1,  # CENTER
            textColor=colors.HexColor("#1a1a2e"),
        ))

    def generate(self, output_path: str) -> str:
        """Generate PDF and write to output_path. Returns path."""
        report_name = self._data.get("report_name", "Executive Report")

        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72,
        )

        story: list = []
        self._add_cover_page(story)
        self._add_executive_summary(story)
        self._add_findings_breakdown(story)
        self._add_remediation_roadmap(story)
        self._add_technical_details(story)
        self._add_financial_impact(story)
        self._add_appendix(story)

        def on_page(canvas, doc_obj):
            _header_footer(canvas, doc_obj, report_name)

        doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
        logger.info("pdf_generated", path=output_path)
        return output_path

    def _add_cover_page(self, story: list) -> None:
        story.append(Spacer(1, 2 * inch))
        story.append(Paragraph(
            "0xRecon", ParagraphStyle(
                "CoverTitle", parent=self._styles["Title"],
                fontSize=42, alignment=1,
                textColor=colors.HexColor("#00FF41"),
            ),
        ))
        story.append(Spacer(1, 0.3 * inch))
        story.append(Paragraph(
            "Executive Report",
            ParagraphStyle("CoverSub", parent=self._styles["Title"],
                           fontSize=22, alignment=1),
        ))
        story.append(Spacer(1, inch))

        info_lines = [
            f"<b>Project:</b> {self._data.get('project_name', '—')}",
            f"<b>Report:</b> {self._data.get('report_name', '—')}",
            f"<b>Scan:</b> {self._data.get('scan_name', '—')}",
            f"<b>Generated:</b> {self._data.get('generated_at', '—')[:19]}",
        ]
        for line in info_lines:
            story.append(Paragraph(line, ParagraphStyle(
                "CoverInfo", parent=self._styles["Normal"],
                fontSize=12, alignment=1, spaceAfter=6,
            )))

        story.append(PageBreak())

    def _add_executive_summary(self, story: list) -> None:
        story.append(Paragraph("Executive Summary", self._styles["SectionHeading"]))
        summary = self._data.get("summary") or {}
        grade = summary.get("grade", "N/A")
        score = summary.get("health_score", 0)

        story.append(Paragraph(
            f"<b>Health Score: {score:.1f}/100  |  Grade: {grade}</b>",
            self._styles["BodyText2"],
        ))
        story.append(Paragraph(
            f"This assessment identified {summary.get('total_findings', 0)} findings "
            f"across {summary.get('total_certificates', 0)} certificates and "
            f"{summary.get('total_keys', 0)} keys.",
            self._styles["BodyText2"],
        ))
        story.append(Spacer(1, 0.2 * inch))

        # Severity table
        sev = summary.get("findings_by_severity") or {}
        if sev:
            data = [["Severity", "Count"]]
            for s in ["critical", "high", "medium", "low"]:
                count = sev.get(s, 0)
                if count > 0:
                    data.append([s.upper(), str(count)])
            if len(data) > 1:
                t = Table(data, colWidths=[200, 80])
                t.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("ALIGN", (1, 0), (1, -1), "CENTER"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                     [colors.HexColor("#f8f9fa"), colors.white]),
                ]))
                story.append(t)

        story.append(Spacer(1, 0.3 * inch))

    def _add_findings_breakdown(self, story: list) -> None:
        story.append(Paragraph("Findings Breakdown", self._styles["SectionHeading"]))
        findings = self._data.get("findings") or []

        if not findings:
            story.append(Paragraph(
                "No findings were identified.", self._styles["BodyText2"],
            ))
            return

        for severity in ["critical", "high", "medium", "low", "info"]:
            sev_findings = [
                f for f in findings
                if (f.get("severity") or "info").lower() == severity
            ]
            if not sev_findings:
                continue

            color = SEVERITY_COLORS.get(severity, colors.black)
            story.append(Paragraph(
                f'<font color="#{color.hexval()[2:]}">{severity.upper()} '
                f"({len(sev_findings)})</font>",
                self._styles["SubHeading"],
            ))

            for f in sev_findings[:10]:
                title = f.get("title") or f.get("rule_name") or "Finding"
                desc = f.get("description") or ""
                entity = f.get("entity_cn") or ""
                line = f"<b>{title}</b>"
                if entity:
                    line += f" ({entity})"
                story.append(Paragraph(line, self._styles["BodyText2"]))
                if desc:
                    story.append(Paragraph(
                        f"&nbsp;&nbsp;{desc[:200]}",
                        self._styles["BodyText2"],
                    ))

            story.append(Spacer(1, 0.15 * inch))

    def _add_remediation_roadmap(self, story: list) -> None:
        story.append(Paragraph("Remediation Roadmap", self._styles["SectionHeading"]))
        findings = self._data.get("findings") or []

        if not findings:
            story.append(Paragraph(
                "No remediation required.", self._styles["BodyText2"],
            ))
            return

        groups = [
            ("Immediate Action (Critical)",
             [f for f in findings if (f.get("severity") or "").lower() == "critical"]),
            ("Short-term (High Priority)",
             [f for f in findings if (f.get("severity") or "").lower() == "high"]),
            ("Planned Remediation",
             [f for f in findings
              if (f.get("severity") or "").lower() in ("medium", "low", "info")]),
        ]

        for group_name, group in groups:
            if not group:
                continue
            story.append(Paragraph(group_name, self._styles["SubHeading"]))
            for f in group[:10]:
                title = f.get("title") or "Action"
                rem = f.get("remediation") or "Review and address"
                story.append(Paragraph(
                    f"• <b>{title}</b>: {rem[:150]}",
                    self._styles["BodyText2"],
                ))

    def _add_technical_details(self, story: list) -> None:
        story.append(PageBreak())
        story.append(Paragraph("Technical Details", self._styles["SectionHeading"]))

        certs = self._data.get("certificates") or []
        keys = self._data.get("keys") or []

        story.append(Paragraph(
            f"<b>Certificates:</b> {len(certs)} discovered",
            self._styles["BodyText2"],
        ))
        story.append(Paragraph(
            f"<b>Keys:</b> {len(keys)} discovered",
            self._styles["BodyText2"],
        ))

        if certs:
            story.append(Spacer(1, 0.2 * inch))
            data = [["Subject CN", "Algorithm", "Key Size", "Status"]]
            for cert in certs[:15]:
                cn = str(
                    cert.get("subject_cn")
                    or (cert.get("subject") or {}).get("CN", "—")
                )[:35]
                algo = cert.get("key_algorithm") or cert.get("public_key_algorithm") or "—"
                size = str(cert.get("key_size") or cert.get("public_key_size") or "—")
                status = "Expired" if cert.get("is_expired") else "Valid"
                data.append([cn, algo, size, status])

            t = Table(data, colWidths=[180, 80, 60, 60])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.HexColor("#f8f9fa"), colors.white]),
            ]))
            story.append(t)

    def _add_financial_impact(self, story: list) -> None:
        fin = self._data.get("financial_impact")
        if not fin:
            return

        story.append(Spacer(1, 0.3 * inch))
        story.append(Paragraph("Financial Impact", self._styles["SectionHeading"]))

        arc = fin.get("annual_risk_cost") or {}
        if arc:
            cost = arc.get("total_annual_cost", 0)
            level = arc.get("risk_level", "—")
            story.append(Paragraph(
                f"<b>Annual Risk Cost:</b> £{cost:,} ({level} risk)",
                self._styles["BodyText2"],
            ))

        roi = fin.get("roi_analysis") or {}
        if roi:
            story.append(Paragraph(
                f"<b>Remediation Investment:</b> £{roi.get('remediation_investment', 0):,}",
                self._styles["BodyText2"],
            ))
            story.append(Paragraph(
                f"<b>Payback Period:</b> {roi.get('payback_months', '—')} months",
                self._styles["BodyText2"],
            ))
            story.append(Paragraph(
                f"<b>3-Year Net Benefit:</b> £{roi.get('roi_year3', 0):,}",
                self._styles["BodyText2"],
            ))

    def _add_appendix(self, story: list) -> None:
        story.append(PageBreak())
        story.append(Paragraph("Appendix", self._styles["SectionHeading"]))
        story.append(Paragraph(
            "<b>Assessment Methodology</b>",
            self._styles["SubHeading"],
        ))
        story.append(Paragraph(
            "This assessment was conducted using 0xRecon's automated "
            "cryptographic asset discovery and policy evaluation engine.",
            self._styles["BodyText2"],
        ))
        story.append(Spacer(1, 0.2 * inch))
        story.append(Paragraph(
            "<b>Disclaimer</b>",
            self._styles["SubHeading"],
        ))
        story.append(Paragraph(
            "Financial estimates are based on industry benchmarks and "
            "statistical models. Actual costs may vary. All values in GBP.",
            self._styles["BodyText2"],
        ))
