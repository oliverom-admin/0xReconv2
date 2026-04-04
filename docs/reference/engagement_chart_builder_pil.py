"""
Engagement Chart Builder using PIL/Pillow - Pure Python Chart Generation

Generates simple, professional charts for engagement executive summaries
using ONLY Pillow (PIL) - no ReportLab rendering needed.

This approach:
- Works without Cairo graphics library
- Creates PNG images directly
- Embeds cleanly in DOCX via python-docx
- No external dependencies beyond Pillow
"""

import os
import logging
from typing import Dict, Any
from datetime import datetime
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

logger = logging.getLogger('caip.reporting.charts_pil')


class EngagementChartBuilderPIL:
    """Generates charts from merged engagement data using PIL only."""

    # Colors (RGB tuples)
    COLORS = {
        'success': (46, 125, 50),      # Green
        'warning': (245, 124, 0),      # Orange
        'danger': (198, 40, 40),       # Red
        'primary': (0, 51, 102),       # Dark blue
        'info': (0, 151, 167),         # Cyan
        'light': (224, 224, 224),      # Light gray
        'dark': (33, 33, 33),          # Dark gray
        'white': (255, 255, 255),
        'black': (0, 0, 0),
        'gray': (128, 128, 128),
    }

    def __init__(self, merged_data: Dict[str, Any], output_dir: str = '/tmp'):
        self.merged_data = merged_data
        self.output_dir = output_dir
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    def generate_all_charts(self) -> Dict[str, str]:
        """Generate all charts."""
        charts = {}

        # Check if we have data
        certs = self.merged_data.get('certificates', [])
        findings = self.merged_data.get('findings', [])

        if not certs and not findings:
            self.logger.warning("No data available for charts - skipping")
            return charts

        try:
            self.logger.info("Generating charts with PIL...")

            if certs:
                try:
                    charts['certificate_inventory'] = self._create_certificate_inventory()
                except Exception as e:
                    self.logger.warning(f"Certificate inventory chart failed: {e}")

                try:
                    charts['expiration_timeline'] = self._create_expiration_timeline()
                except Exception as e:
                    self.logger.warning(f"Expiration timeline chart failed: {e}")

                try:
                    charts['algorithm_distribution'] = self._create_algorithm_distribution()
                except Exception as e:
                    self.logger.warning(f"Algorithm distribution chart failed: {e}")

                try:
                    charts['key_size_distribution'] = self._create_key_size_distribution()
                except Exception as e:
                    self.logger.warning(f"Key size distribution chart failed: {e}")

            if findings:
                try:
                    charts['finding_severity'] = self._create_finding_severity()
                except Exception as e:
                    self.logger.warning(f"Finding severity chart failed: {e}")

            self.logger.info(f"Generated {len(charts)} charts")
            return charts

        except Exception as e:
            self.logger.error(f"Error generating charts: {e}")
            return charts

    def _create_certificate_inventory(self) -> str:
        """Create certificate status pie chart."""
        certs = self.merged_data.get('certificates', [])
        valid = sum(1 for c in certs if not c.get('is_expired') and c.get('days_until_expiry', 999) >= 30)
        expiring = sum(1 for c in certs if not c.get('is_expired') and c.get('days_until_expiry', 999) < 30)
        expired = sum(1 for c in certs if c.get('is_expired'))

        # Create image
        img = Image.new('RGB', (500, 400), color=self.COLORS['white'])
        draw = ImageDraw.Draw(img)

        # Draw title
        draw.text((250, 20), "Certificate Status", fill=self.COLORS['black'], anchor='mm')

        # Draw legend
        y = 50
        data = [('Valid', valid, self.COLORS['success']),
                ('Expiring', expiring, self.COLORS['warning']),
                ('Expired', expired, self.COLORS['danger'])]

        for label, count, color in data:
            # Draw colored box
            draw.rectangle([(20, y), (40, y+20)], fill=color)
            # Draw label
            draw.text((50, y+10), f'{label}: {count}', fill=self.COLORS['black'], anchor='lm')
            y += 40

        # Simple pie visualization using segments
        self._draw_simple_pie(draw, 250, 220, 80, [valid, expiring, expired],
                            [self.COLORS['success'], self.COLORS['warning'], self.COLORS['danger']])

        return self._save_image(img, 'certificate_inventory')

    def _create_expiration_timeline(self) -> str:
        """Create expiration timeline bar chart."""
        certs = self.merged_data.get('certificates', [])
        data = {
            'Expired': sum(1 for c in certs if c.get('is_expired')),
            '0-7d': sum(1 for c in certs if 0 < c.get('days_until_expiry', 999) < 7),
            '7-30d': sum(1 for c in certs if 7 <= c.get('days_until_expiry', 999) < 30),
            '30-90d': sum(1 for c in certs if 30 <= c.get('days_until_expiry', 999) < 90),
            '90+d': sum(1 for c in certs if c.get('days_until_expiry', 999) >= 90),
        }

        return self._create_bar_chart('Expiration Timeline', data,
                                      [self.COLORS['danger'], self.COLORS['danger'],
                                       self.COLORS['warning'], self.COLORS['warning'],
                                       self.COLORS['success']])

    def _create_algorithm_distribution(self) -> str:
        """Create algorithm distribution bar chart."""
        certs = self.merged_data.get('certificates', [])
        algo_counts = {}
        for cert in certs:
            algo = cert.get('signature_algorithm', 'Unknown')
            algo_counts[algo] = algo_counts.get(algo, 0) + 1

        top_algos = dict(sorted(algo_counts.items(), key=lambda x: x[1], reverse=True)[:4])
        colors = [self.COLORS['primary']] * len(top_algos)

        return self._create_bar_chart('Algorithm Distribution', top_algos, colors)

    def _create_key_size_distribution(self) -> str:
        """Create key size distribution bar chart."""
        certs = self.merged_data.get('certificates', [])
        data = {
            'Weak': sum(1 for c in certs if c.get('key_size', 2048) < 2048),
            'Valid': sum(1 for c in certs if 2048 <= c.get('key_size', 2048) < 4096),
            'Strong': sum(1 for c in certs if c.get('key_size', 2048) >= 4096),
        }

        return self._create_bar_chart('Key Size Distribution', data,
                                      [self.COLORS['danger'], self.COLORS['warning'], self.COLORS['success']])

    def _create_finding_severity(self) -> str:
        """Create finding severity bar chart."""
        findings = self.merged_data.get('findings', [])
        data = {}
        for f in findings:
            sev = f.get('severity', 'info').lower()
            data[sev] = data.get(sev, 0) + 1

        severity_order = {'critical': self.COLORS['danger'], 'high': self.COLORS['warning'],
                         'medium': (255, 167, 38), 'low': (100, 181, 246)}

        ordered_data = {k: data.get(k, 0) for k in ['critical', 'high', 'medium', 'low']}
        colors = [severity_order[k] for k in ordered_data.keys()]

        return self._create_bar_chart('Finding Severity', ordered_data, colors)

    def _create_bar_chart(self, title: str, data: Dict[str, int], colors: list) -> str:
        """Create a generic bar chart."""
        img = Image.new('RGB', (600, 400), color=self.COLORS['white'])
        draw = ImageDraw.Draw(img)

        # Title
        draw.text((300, 20), title, fill=self.COLORS['black'], anchor='mm')

        # Calculate bar dimensions
        num_bars = len(data)
        bar_width = 350 // num_bars
        max_value = max(data.values()) if data.values() else 1
        scale = 250 / max_value

        # Draw bars
        x = 80
        for i, (label, value) in enumerate(data.items()):
            color = colors[i] if i < len(colors) else self.COLORS['primary']
            bar_height = int(value * scale)

            # Draw bar
            draw.rectangle([(x, 300 - bar_height), (x + bar_width - 5, 300)],
                          fill=color, outline=self.COLORS['gray'])

            # Draw value on bar
            if bar_height > 20:
                draw.text((x + bar_width // 2 - 5, 300 - bar_height // 2),
                         str(value), fill=self.COLORS['white'], anchor='mm')

            # Draw label
            draw.text((x + bar_width // 2 - 5, 320), label[:10],
                     fill=self.COLORS['black'], anchor='mm')

            x += bar_width

        return self._save_image(img, title.lower().replace(' ', '_'))

    def _draw_simple_pie(self, draw, center_x, center_y, radius, values, colors):
        """Draw simple pie chart visualization."""
        total = sum(values)
        if total == 0:
            return

        angle = 0
        for value, color in zip(values, colors):
            slice_angle = (value / total) * 360
            # Draw wedge as arc (simplified)
            draw.arc([(center_x - radius, center_y - radius),
                     (center_x + radius, center_y + radius)],
                    angle, angle + slice_angle, fill=color, width=2)
            angle += slice_angle

    def _save_image(self, img: Image.Image, chart_name: str) -> str:
        """Save PIL image as PNG."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"chart_{chart_name}_{timestamp}.png"
        filepath = os.path.join(self.output_dir, filename)

        try:
            img.save(filepath, 'PNG')
            self.logger.debug(f"Chart saved: {filepath}")
            return filepath
        except Exception as e:
            self.logger.error(f"Error saving chart: {e}")
            raise


def generate_engagement_charts_pil(merged_data: Dict[str, Any],
                                   output_dir: str = '/tmp') -> Dict[str, str]:
    """Generate all engagement charts using PIL."""
    builder = EngagementChartBuilderPIL(merged_data, output_dir)
    return builder.generate_all_charts()
