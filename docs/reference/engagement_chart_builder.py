"""
Engagement Chart Builder for DOCX Reports - WP2

Generates simple, professional charts for engagement executive summaries using ReportLab.

Approach:
- Uses ReportLab (already in codebase for PDF reports)
- Generates charts as PNG images
- Embed PNG images in DOCX (simple, reliable approach)
- Avoids DOCX native charts (complex XML, compatibility issues)

Charts:
- Certificate Inventory (pie: valid/expiring/expired)
- Expiration Timeline (bar: time buckets)
- Algorithm Distribution (bar: top algorithms)
- Key Size Distribution (bar: weak/valid/strong)
- Finding Severity (bar: critical/high/medium/low)
"""

import os
import logging
from typing import Dict, Any
from datetime import datetime
from pathlib import Path

from reportlab.graphics.shapes import Drawing, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPM
from reportlab.lib import colors as rl_colors

logger = logging.getLogger('caip.reporting.charts')


class EngagementChartBuilder:
    """Generates charts from merged engagement data."""

    COLORS = {
        'primary': rl_colors.HexColor('#003366'),
        'success': rl_colors.HexColor('#2E7D32'),
        'warning': rl_colors.HexColor('#F57C00'),
        'danger': rl_colors.HexColor('#C62828'),
        'info': rl_colors.HexColor('#0097A7'),
        'light': rl_colors.HexColor('#E0E0E0'),
        'dark': rl_colors.HexColor('#212121'),
    }

    def __init__(self, merged_data: Dict[str, Any], output_dir: str = '/tmp'):
        self.merged_data = merged_data
        self.output_dir = output_dir
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    def generate_all_charts(self) -> Dict[str, str]:
        """Generate all charts."""
        charts = {}
        try:
            self.logger.info("Generating engagement charts...")
            charts['certificate_inventory'] = self.generate_certificate_inventory_chart()
            charts['expiration_timeline'] = self.generate_expiration_timeline_chart()
            charts['algorithm_distribution'] = self.generate_algorithm_distribution_chart()
            charts['key_size_distribution'] = self.generate_key_size_distribution_chart()
            charts['finding_severity'] = self.generate_finding_severity_chart()
            self.logger.info(f"Generated {len(charts)} charts")
            return charts
        except Exception as e:
            self.logger.error(f"Error generating charts: {e}")
            raise

    def generate_certificate_inventory_chart(self) -> str:
        """Pie chart: certificate status."""
        certs = self.merged_data.get('certificates', [])
        valid = sum(1 for c in certs if not c.get('is_expired') and c.get('days_until_expiry', 999) >= 30)
        expiring = sum(1 for c in certs if not c.get('is_expired') and c.get('days_until_expiry', 999) < 30)
        expired = sum(1 for c in certs if c.get('is_expired'))

        drawing = Drawing(500, 350)
        pie = Pie()
        pie.data = [valid if valid else 1, expiring if expiring else 1, expired if expired else 1]
        pie.width = 250
        pie.height = 250
        pie.x = 125
        pie.y = 50
        pie.slices[0].fillColor = self.COLORS['success']
        pie.slices[1].fillColor = self.COLORS['warning']
        pie.slices[2].fillColor = self.COLORS['danger']
        drawing.add(pie)

        # Add title and legend
        title = String(250, 320, 'Certificate Status',
                      fontSize=12, fontName='Helvetica-Bold', textAnchor='middle')
        drawing.add(title)

        # Legend
        y = 40
        for color, label, count in [(self.COLORS['success'], 'Valid', valid),
                                      (self.COLORS['warning'], 'Expiring', expiring),
                                      (self.COLORS['danger'], 'Expired', expired)]:
            rect = __import__('reportlab.graphics.shapes', fromlist=['Rect']).Rect(20, y, 10, 10)
            rect.fillColor = color
            drawing.add(rect)
            legend = String(35, y+3, f'{label}: {count}', fontSize=9)
            drawing.add(legend)
            y -= 15

        return self._save_drawing(drawing, 'certificate_inventory')

    def generate_expiration_timeline_chart(self) -> str:
        """Bar chart: expiration timeline."""
        certs = self.merged_data.get('certificates', [])
        expired = sum(1 for c in certs if c.get('is_expired'))
        d0_7 = sum(1 for c in certs if 0 < c.get('days_until_expiry', 999) < 7)
        d7_30 = sum(1 for c in certs if 7 <= c.get('days_until_expiry', 999) < 30)
        d30_90 = sum(1 for c in certs if 30 <= c.get('days_until_expiry', 999) < 90)
        d90_plus = sum(1 for c in certs if c.get('days_until_expiry', 999) >= 90)

        drawing = Drawing(600, 350)
        chart = VerticalBarChart()
        chart.data = [[expired, d0_7, d7_30, d30_90, d90_plus]]
        chart.width = 450
        chart.height = 250
        chart.x = 80
        chart.y = 50
        chart.bars[0][0].fillColor = self.COLORS['danger']
        chart.bars[0][1].fillColor = self.COLORS['danger']
        chart.bars[0][2].fillColor = self.COLORS['warning']
        chart.bars[0][3].fillColor = self.COLORS['warning']
        chart.bars[0][4].fillColor = self.COLORS['success']
        chart.categoryAxis.categoryNames = ['Expired', '0-7d', '7-30d', '30-90d', '90+d']
        chart.categoryAxis.labels.fontSize = 8
        drawing.add(chart)

        title = String(300, 320, 'Expiration Timeline',
                      fontSize=12, fontName='Helvetica-Bold', textAnchor='middle')
        drawing.add(title)

        return self._save_drawing(drawing, 'expiration_timeline')

    def generate_algorithm_distribution_chart(self) -> str:
        """Bar chart: algorithms."""
        certs = self.merged_data.get('certificates', [])
        algo_counts = {}
        for cert in certs:
            algo = cert.get('signature_algorithm', 'Unknown')
            algo_counts[algo] = algo_counts.get(algo, 0) + 1

        top_algos = sorted(algo_counts.items(), key=lambda x: x[1], reverse=True)[:4]
        names = [a[0][:15] for a in top_algos]
        counts = [a[1] for a in top_algos]

        drawing = Drawing(600, 350)
        chart = VerticalBarChart()
        chart.data = [counts]
        chart.width = 450
        chart.height = 250
        chart.x = 80
        chart.y = 50

        for i in range(len(counts)):
            chart.bars[0][i].fillColor = self.COLORS['primary']

        chart.categoryAxis.categoryNames = names
        chart.categoryAxis.labels.fontSize = 8
        drawing.add(chart)

        title = String(300, 320, 'Algorithm Distribution',
                      fontSize=12, fontName='Helvetica-Bold', textAnchor='middle')
        drawing.add(title)

        return self._save_drawing(drawing, 'algorithm_distribution')

    def generate_key_size_distribution_chart(self) -> str:
        """Bar chart: key sizes."""
        certs = self.merged_data.get('certificates', [])
        weak = sum(1 for c in certs if c.get('key_size', 2048) < 2048)
        valid = sum(1 for c in certs if 2048 <= c.get('key_size', 2048) < 4096)
        strong = sum(1 for c in certs if c.get('key_size', 2048) >= 4096)

        drawing = Drawing(600, 350)
        chart = VerticalBarChart()
        chart.data = [[weak, valid, strong]]
        chart.width = 450
        chart.height = 250
        chart.x = 80
        chart.y = 50
        chart.bars[0][0].fillColor = self.COLORS['danger']
        chart.bars[0][1].fillColor = self.COLORS['warning']
        chart.bars[0][2].fillColor = self.COLORS['success']
        chart.categoryAxis.categoryNames = ['Weak', 'Valid', 'Strong']
        chart.categoryAxis.labels.fontSize = 9
        drawing.add(chart)

        title = String(300, 320, 'Key Size Distribution',
                      fontSize=12, fontName='Helvetica-Bold', textAnchor='middle')
        drawing.add(title)

        return self._save_drawing(drawing, 'key_size_distribution')

    def generate_finding_severity_chart(self) -> str:
        """Bar chart: finding severity."""
        findings = self.merged_data.get('findings', [])
        severity = {}
        for f in findings:
            sev = f.get('severity', 'info').lower()
            severity[sev] = severity.get(sev, 0) + 1

        critical = severity.get('critical', 0)
        high = severity.get('high', 0)
        medium = severity.get('medium', 0)
        low = severity.get('low', 0)

        drawing = Drawing(600, 350)
        chart = VerticalBarChart()
        chart.data = [[critical, high, medium, low]]
        chart.width = 450
        chart.height = 250
        chart.x = 80
        chart.y = 50
        chart.bars[0][0].fillColor = self.COLORS['danger']
        chart.bars[0][1].fillColor = self.COLORS['warning']
        chart.bars[0][2].fillColor = rl_colors.HexColor('#FFA726')
        chart.bars[0][3].fillColor = rl_colors.HexColor('#64B5F6')
        chart.categoryAxis.categoryNames = ['Critical', 'High', 'Medium', 'Low']
        chart.categoryAxis.labels.fontSize = 9
        drawing.add(chart)

        title = String(300, 320, 'Finding Severity',
                      fontSize=12, fontName='Helvetica-Bold', textAnchor='middle')
        drawing.add(title)

        return self._save_drawing(drawing, 'finding_severity')

    def _save_drawing(self, drawing: Drawing, chart_name: str) -> str:
        """Save chart to PNG."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"chart_{chart_name}_{timestamp}.png"
        filepath = os.path.join(self.output_dir, filename)

        try:
            renderPM.drawToFile(drawing, filepath, fmt='PNG', dpi=150)
            self.logger.debug(f"Chart saved: {filepath}")
            return filepath
        except Exception as e:
            self.logger.error(f"Error saving chart: {e}")
            raise


def generate_engagement_charts(merged_data: Dict[str, Any],
                              output_dir: str = '/tmp') -> Dict[str, str]:
    """Generate all engagement charts."""
    builder = EngagementChartBuilder(merged_data, output_dir)
    return builder.generate_all_charts()
