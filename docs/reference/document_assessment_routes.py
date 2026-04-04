"""
Document Assessment API Routes for CAIP

Flask routes for document assessment functionality.
These routes should be registered with the main Flask app.

Usage in app.py:
    from document_assessment_routes import register_document_assessment_routes
    register_document_assessment_routes(app)
"""

import os
import json
import logging
from datetime import datetime
from flask import request, jsonify, send_file, current_app
from werkzeug.utils import secure_filename
from functools import wraps

logger = logging.getLogger('caip.operational')

# Allowed file extensions
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'doc'}


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def register_document_assessment_routes(app, db_service, login_required, permission_required=None):
    """
    Register document assessment routes with the Flask app.
    
    Args:
        app: Flask application instance
        db_service: DatabaseService class
        login_required: Login required decorator
        permission_required: Optional permission decorator
    """
    
    # Import services (lazy import to avoid circular dependencies)
    from .document_assessment_service import (
        DocumentAssessmentService,
        DocumentType,
        ComplianceFramework
    )
    from .document_assessment_database import DocumentAssessmentDatabase
    
    # Ensure upload directory exists
    UPLOAD_FOLDER = app.config.get('UPLOAD_FOLDER', 'uploads')
    DOC_UPLOAD_FOLDER = os.path.join(UPLOAD_FOLDER, 'documents')
    os.makedirs(DOC_UPLOAD_FOLDER, exist_ok=True)
    
    # =========================================================================
    # DOCUMENT ASSESSMENT ENDPOINTS
    # =========================================================================
    
    @app.route('/api/v1/document-assessment/types', methods=['GET'])
    @login_required
    @permission_required('assessments:read')
    def get_document_types():
        """
        Get list of supported document types.
        
        Returns:
            List of document type definitions
        """
        try:
            types = DocumentAssessmentService.get_supported_document_types()
            return jsonify({'document_types': types}), 200
        except Exception as e:
            logger.error(f"Error getting document types: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/document-assessment/templates', methods=['GET'])
    @login_required
    @permission_required('assessments:read')
    def get_assessment_templates():
        """
        Get list of available assessment templates.
        
        Query params:
            document_type: Optional filter by document type
            
        Returns:
            List of template summaries
        """
        try:
            document_type = request.args.get('document_type')
            
            # Get built-in templates
            builtin = DocumentAssessmentService.list_available_templates()
            
            # Get custom templates from database
            custom = DocumentAssessmentDatabase.list_custom_templates(
                db_service, 
                document_type=document_type
            )
            
            # Filter builtin by type if specified
            if document_type:
                builtin = [t for t in builtin if t['document_type'] == document_type]
            
            return jsonify({
                'builtin_templates': builtin,
                'custom_templates': custom
            }), 200
            
        except Exception as e:
            logger.error(f"Error getting templates: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/document-assessment/assess', methods=['POST'])
    @login_required
    @permission_required('document_assessment:upload')
    def assess_document():
        """
        Upload and assess a document.
        
        Form data:
            file: Document file (PDF or DOCX)
            document_type: Optional document type override
            save_result: Whether to save result to database (default: true)
            
        Returns:
            Assessment results
        """
        try:
            # Check for file
            if 'file' not in request.files:
                return jsonify({'error': 'No file provided'}), 400
            
            file = request.files['file']
            
            if file.filename == '':
                return jsonify({'error': 'No file selected'}), 400
            
            if not allowed_file(file.filename):
                return jsonify({
                    'error': f'Invalid file type. Allowed types: {", ".join(ALLOWED_EXTENSIONS)}'
                }), 400
            
            # Save file temporarily
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            saved_filename = f"{timestamp}_{filename}"
            file_path = os.path.join(DOC_UPLOAD_FOLDER, saved_filename)
            file.save(file_path)
            
            logger.info(f"Document uploaded for assessment: {filename}")
            
            # Get optional parameters
            document_type_str = request.form.get('document_type')
            save_result = request.form.get('save_result', 'true').lower() == 'true'
            engagement_id = request.form.get('engagement_id')
            
            # Convert document type if provided
            document_type = None
            if document_type_str:
                try:
                    document_type = DocumentType(document_type_str)
                except ValueError:
                    return jsonify({
                        'error': f'Invalid document_type: {document_type_str}'
                    }), 400
            
            # Run assessment
            try:
                result = DocumentAssessmentService.assess_document(
                    file_path,
                    document_type=document_type
                )
            except ImportError as e:
                # Handle missing dependencies gracefully
                return jsonify({
                    'error': f'Missing dependency for document parsing: {str(e)}. '
                             'Please install PyMuPDF (pip install pymupdf) for PDF support '
                             'or python-docx (pip install python-docx) for DOCX support.'
                }), 500
            except Exception as e:
                logger.error(f"Assessment failed: {e}")
                # Clean up file on failure
                if os.path.exists(file_path):
                    os.remove(file_path)
                raise
            
            # Save to database if requested
            db_id = None
            if save_result:
                db_id = DocumentAssessmentDatabase.save_assessment(db_service, result, engagement_id)
            
            # Prepare response
            response_data = result.to_dict()
            if db_id:
                response_data['database_id'] = db_id
            
            # Clean up uploaded file after successful assessment
            # (or keep it if you want to retain uploaded documents)
            # os.remove(file_path)
            
            return jsonify(response_data), 200
            
        except Exception as e:
            logger.error(f"Error assessing document: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/document-assessment/assessments', methods=['GET'])
    @login_required
    @permission_required('assessments:read')
    def list_assessments():
        """
        List document assessments.
        
        Query params:
            document_type: Optional filter by document type
            limit: Max results (default 50)
            offset: Pagination offset (default 0)
            
        Returns:
            List of assessment summaries
        """
        try:
            document_type = request.args.get('document_type')
            engagement_id = request.args.get('engagement_id')
            limit = int(request.args.get('limit', 50))
            offset = int(request.args.get('offset', 0))
            
            # Use engagement-filtered query if engagement_id provided
            if engagement_id:
                assessments = DocumentAssessmentDatabase.list_assessments_by_engagement(
                    db_service,
                    engagement_id=engagement_id
                )
            else:
                assessments = DocumentAssessmentDatabase.list_assessments(
                    db_service,
                    document_type=document_type,
                    limit=limit,
                    offset=offset
                )
            
            return jsonify({
                'assessments': assessments,
                'limit': limit,
                'offset': offset
            }), 200
            
        except Exception as e:
            logger.error(f"Error listing assessments: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/document-assessment/assessments/<assessment_id>', methods=['GET'])
    @login_required
    @permission_required('assessments:read')
    def get_assessment(assessment_id):
        """
        Get a specific document assessment.
        
        Args:
            assessment_id: The assessment ID
            
        Returns:
            Full assessment details with findings
        """
        try:
            assessment = DocumentAssessmentDatabase.get_assessment(
                db_service, 
                assessment_id
            )
            
            if not assessment:
                return jsonify({'error': 'Assessment not found'}), 404
            
            return jsonify(assessment), 200
            
        except Exception as e:
            logger.error(f"Error getting assessment: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/document-assessment/assessments/<assessment_id>', methods=['DELETE'])
    @login_required
    @permission_required('assessments:delete')
    def delete_assessment(assessment_id):
        """
        Delete a document assessment.
        
        Args:
            assessment_id: The assessment ID
            
        Returns:
            Success message
        """
        try:
            deleted = DocumentAssessmentDatabase.delete_assessment(
                db_service, 
                assessment_id
            )
            
            if not deleted:
                return jsonify({'error': 'Assessment not found'}), 404
            
            return jsonify({'message': 'Assessment deleted successfully'}), 200
            
        except Exception as e:
            logger.error(f"Error deleting assessment: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/document-assessment/statistics', methods=['GET'])
    @login_required
    @permission_required('assessments:read')
    def get_assessment_statistics():
        """
        Get document assessment statistics.
        
        Returns:
            Statistics summary
        """
        try:
            stats = DocumentAssessmentDatabase.get_assessment_statistics(db_service)
            return jsonify(stats), 200
            
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return jsonify({'error': str(e)}), 500
    
    # =========================================================================
    # CUSTOM TEMPLATE ENDPOINTS
    # =========================================================================
    
    @app.route('/api/v1/document-assessment/templates/custom', methods=['POST'])
    @login_required
    @permission_required('assessments:create')
    def create_custom_template():
        """
        Create a custom assessment template.
        
        Request body:
            name: Template name
            document_type: Type of document
            description: Optional description
            version: Template version (default "1.0")
            template: Template definition with sections and elements
            
        Returns:
            Created template ID
        """
        try:
            data = request.get_json()
            
            required_fields = ['name', 'document_type', 'template']
            for field in required_fields:
                if field not in data:
                    return jsonify({'error': f'Missing required field: {field}'}), 400
            
            # Validate template structure
            template = data['template']
            if 'sections' not in template:
                return jsonify({'error': 'Template must contain sections array'}), 400
            
            from flask import session
            created_by = session.get('username', 'unknown')
            
            template_id = DocumentAssessmentDatabase.save_custom_template(
                db_service,
                name=data['name'],
                document_type=data['document_type'],
                template_json=template,
                description=data.get('description'),
                version=data.get('version', '1.0'),
                created_by=created_by
            )
            
            return jsonify({
                'message': 'Template created successfully',
                'template_id': template_id
            }), 201
            
        except Exception as e:
            logger.error(f"Error creating template: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/document-assessment/templates/custom/<int:template_id>', methods=['GET'])
    @login_required
    @permission_required('assessments:read')
    def get_custom_template(template_id):
        """
        Get a custom template by ID.
        
        Args:
            template_id: Database ID
            
        Returns:
            Template definition
        """
        try:
            template = DocumentAssessmentDatabase.get_custom_template(
                db_service, 
                template_id
            )
            
            if not template:
                return jsonify({'error': 'Template not found'}), 404
            
            return jsonify(template), 200
            
        except Exception as e:
            logger.error(f"Error getting template: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/document-assessment/templates/custom/<int:template_id>', methods=['DELETE'])
    @login_required
    @permission_required('assessments:delete')
    def delete_custom_template(template_id):
        """
        Delete a custom template.
        
        Args:
            template_id: Database ID
            
        Returns:
            Success message
        """
        try:
            deleted = DocumentAssessmentDatabase.delete_custom_template(
                db_service, 
                template_id
            )
            
            if not deleted:
                return jsonify({
                    'error': 'Template not found or is a builtin template'
                }), 404
            
            return jsonify({'message': 'Template deleted successfully'}), 200
            
        except Exception as e:
            logger.error(f"Error deleting template: {e}")
            return jsonify({'error': str(e)}), 500
    
    # =========================================================================
    # REPORT GENERATION ENDPOINTS
    # =========================================================================
    
    @app.route('/api/v1/document-assessment/assessments/<assessment_id>/report', methods=['GET'])
    @login_required
    @permission_required('assessments:read')
    def generate_assessment_report(assessment_id):
        """
        Generate a PDF report for an assessment.
        
        Args:
            assessment_id: The assessment ID
            
        Query params:
            format: Report format (pdf, html, json) - default pdf
            
        Returns:
            Report file or JSON
        """
        try:
            # Get assessment
            assessment = DocumentAssessmentDatabase.get_assessment(
                db_service, 
                assessment_id
            )
            
            if not assessment:
                return jsonify({'error': 'Assessment not found'}), 404
            
            format_type = request.args.get('format', 'pdf').lower()
            
            if format_type == 'json':
                return jsonify(assessment), 200
            
            elif format_type == 'html':
                # Generate HTML report
                html_content = _generate_html_report(assessment)
                return html_content, 200, {'Content-Type': 'text/html'}
            
            elif format_type == 'pdf':
                # Generate PDF report
                try:
                    from document_assessment_report_generator import DocumentAssessmentReportGenerator
                    
                    reports_folder = app.config.get('REPORTS_FOLDER', 'reports')
                    report_path = DocumentAssessmentReportGenerator.generate_pdf_report(
                        assessment,
                        output_dir=reports_folder
                    )
                    
                    return send_file(
                        report_path,
                        mimetype='application/pdf',
                        as_attachment=True,
                        download_name=f"document_assessment_{assessment_id}.pdf"
                    )
                except ImportError:
                    # Fallback to HTML if PDF generation not available
                    logger.warning("PDF generation not available, returning HTML")
                    html_content = _generate_html_report(assessment)
                    return html_content, 200, {'Content-Type': 'text/html'}
            
            else:
                return jsonify({
                    'error': f'Invalid format: {format_type}. Supported: pdf, html, json'
                }), 400
                
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/v1/document-assessment/assessments/<assessment_id>/report/save', methods=['POST'])
    @login_required
    @permission_required('reports:create')
    def save_assessment_report(assessment_id):
        """
        Generate and save an HTML report for an assessment to the reports folder.
        """
        try:
            # Get assessment
            assessment = DocumentAssessmentDatabase.get_assessment(
                db_service, 
                assessment_id
            )
            
            if not assessment:
                return jsonify({'error': 'Assessment not found'}), 404
            
            reports_folder = app.config.get('REPORTS_FOLDER', 'reports')
            os.makedirs(reports_folder, exist_ok=True)
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename_safe = (assessment.get('filename', 'document') or 'document').replace(' ', '_').replace('/', '_').rsplit('.', 1)[0]
            output_filename = f"doc_assessment_{filename_safe}_{timestamp}.html"
            output_path = os.path.join(reports_folder, output_filename)
            
            # Generate HTML report using existing function
            html_content = _generate_html_report(assessment)
            
            # Save to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"Saved document assessment report: {output_path}")
            
            return jsonify({
                'message': 'Document assessment report saved successfully',
                'filename': output_filename,
                'path': output_path
            }), 200
                
        except Exception as e:
            logger.error(f"Error saving report: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return jsonify({'error': str(e)}), 500
    

    def _generate_html_report(assessment: dict) -> str:
        """Generate HTML report from assessment data styled to match CAIP dashboard"""
        
        # Calculate statistics
        findings = assessment.get('findings', [])
        found_count = sum(1 for f in findings if f['status'] == 'found')
        partial_count = sum(1 for f in findings if f['status'] == 'partial')
        missing_count = sum(1 for f in findings if f['status'] == 'missing')
        total_findings = len(findings)
        
        # Grade styling
        grade = assessment.get('summary', {}).get('assessment_grade', 'N/A')
        grade_colors = {
            'A': '#10b981',
            'B': '#10b981',
            'C': '#f59e0b',
            'D': '#f59e0b',
            'F': '#ef4444'
        }
        grade_color = grade_colors.get(grade, '#64748b')
        
        # Build findings rows grouped by status
        def build_findings_rows(status_filter):
            filtered = [f for f in findings if f['status'] == status_filter]
            if not filtered:
                return ""
            
            rows = ""
            for finding in filtered:
                severity_colors = {
                    'critical': '#9b59b6',
                    'high': '#ef4444',
                    'medium': '#f59e0b',
                    'low': '#0ea5e9',
                    'info': '#94a3b8'
                }
                sev_color = severity_colors.get(finding['severity'], '#94a3b8')
                compliance_refs = ', '.join(finding.get('compliance_refs', []))
                confidence = finding.get('confidence', 0)
                confidence_pct = f"{confidence:.0%}" if isinstance(confidence, float) else f"{confidence}%"
                matched_section = finding.get('matched_section', 'N/A') or 'N/A'
                snippet = finding.get('matched_content_snippet', '')
                if snippet and len(snippet) > 100:
                    snippet = snippet[:100] + '...'
                
                rows += f"""
                <tr>
                    <td>
                        <div style="font-weight: 600; color: var(--text-primary);">{finding['element_name']}</div>
                        <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">{finding.get('element_id', '')}</div>
                    </td>
                    <td><span class="badge badge-{finding['severity']}">{finding['severity'].upper()}</span></td>
                    <td>
                        <div class="confidence-bar">
                            <div class="confidence-fill" style="width: {confidence_pct};"></div>
                        </div>
                        <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">{confidence_pct}</div>
                    </td>
                    <td style="font-size: 13px;">{matched_section}</td>
                    <td><code style="font-size: 11px; background: var(--content-bg); padding: 2px 6px; border-radius: 4px;">{compliance_refs}</code></td>
                    <td style="font-size: 13px; max-width: 300px;">{finding.get('recommendation', '')}</td>
                </tr>
                """
            return rows
        
        # Build compliance scores cards
        compliance_scores = assessment.get('compliance_scores', {})
        compliance_cards_html = ""
        for framework, score in compliance_scores.items():
            score_color = '#10b981' if score >= 80 else '#f59e0b' if score >= 60 else '#ef4444'
            compliance_cards_html += f"""
            <div class="compliance-card">
                <div class="compliance-framework">{framework}</div>
                <div class="compliance-score" style="color: {score_color};">{score:.1f}%</div>
            </div>
            """
        
        # Critical gaps
        critical_gaps = assessment.get('summary', {}).get('critical_gaps', [])
        critical_gaps_html = ""
        if critical_gaps:
            for gap in critical_gaps[:5]:
                critical_gaps_html += f"""
                <div class="gap-item">
                    <div class="gap-element">{gap.get('element', 'Unknown')}</div>
                    <div class="gap-recommendation">{gap.get('recommendation', '')}</div>
                </div>
                """
        
        # Document metadata
        doc_metadata = assessment.get('document_metadata', {})
        
        # Sections found - build tree structure
        sections_found = assessment.get('sections_found', [])
        
        def build_section_tree_html(sections):
            """Build a collapsible tree view of document sections"""
            if not sections:
                return '<p style="color: var(--text-muted);">No sections detected.</p>'
            
            # Group sections by level to build hierarchy
            # We'll process sequentially and track parent levels
            html_parts = ['<div class="tree-view"><ul>']
            current_level = 0
            open_uls = 0
            
            for i, section in enumerate(sections):
                level = section.get('level', 1)
                heading = section.get('heading', 'Untitled')
                mapped = section.get('mapped_element_id', '')
                confidence = section.get('mapping_confidence', 0) or 0
                
                # Determine status class based on mapping
                if mapped and confidence >= 0.5:
                    status_class = 'mapped'
                    status_icon = '🟢'
                elif mapped:
                    status_class = 'partial'
                    status_icon = '🟡'
                else:
                    status_class = 'unmapped'
                    status_icon = '⚪'
                
                # Check if this section has children (next section is deeper level)
                has_children = (i + 1 < len(sections) and sections[i + 1].get('level', 1) > level)
                
                # Close lists if we're going back up levels
                while current_level >= level and open_uls > 0:
                    html_parts.append('</ul></li>')
                    open_uls -= 1
                    current_level -= 1
                
                # Build the node HTML
                confidence_bar = ''
                if mapped:
                    conf_pct = int(confidence * 100)
                    confidence_bar = f'''
                        <div class="tree-confidence">
                            <div class="tree-confidence-fill" style="width: {conf_pct}%;"></div>
                        </div>'''
                
                mapped_badge = f'<span class="tree-mapping">→ {mapped}</span>' if mapped else ''
                
                if has_children:
                    # This is a parent node
                    html_parts.append(f'''
                    <li class="tree-node tree-parent {status_class}">
                        <div class="tree-node-content" onclick="toggleTreeNode(this)">
                            <span class="tree-toggle">▶</span>
                            <span class="tree-status">{status_icon}</span>
                            <span class="tree-heading">{heading}</span>
                            {mapped_badge}
                            {confidence_bar}
                        </div>
                        <ul class="tree-children">''')
                    open_uls += 1
                    current_level = level
                else:
                    # This is a leaf node
                    html_parts.append(f'''
                    <li class="tree-node tree-leaf {status_class}">
                        <div class="tree-node-content">
                            <span class="tree-toggle-placeholder"></span>
                            <span class="tree-status">{status_icon}</span>
                            <span class="tree-heading">{heading}</span>
                            {mapped_badge}
                            {confidence_bar}
                        </div>
                    </li>''')
            
            # Close any remaining open lists
            while open_uls > 0:
                html_parts.append('</ul></li>')
                open_uls -= 1
            
            html_parts.append('</ul></div>')
            return ''.join(html_parts)
        
        sections_tree_html = build_section_tree_html(sections_found)
        
        # Calculate section stats
        mapped_sections = sum(1 for s in sections_found if s.get('mapped_element_id'))
        unmapped_sections = len(sections_found) - mapped_sections
        
        # Build findings table sections
        missing_rows = build_findings_rows('missing')
        partial_rows = build_findings_rows('partial')
        found_rows = build_findings_rows('found')
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document Assessment Report - {assessment.get('filename', 'Unknown')}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        :root {{
            --sidebar-bg: #0f172a;
            --sidebar-hover: #1e293b;
            --sidebar-active: #0ea5e9;
            --sidebar-text: #94a3b8;
            --sidebar-text-active: #ffffff;
            --content-bg: #f8fafc;
            --card-bg: #ffffff;
            --border-color: #e2e8f0;
            --text-primary: #1e293b;
            --text-secondary: #64748b;
            --text-muted: #94a3b8;
            --accent: #0ea5e9;
            --accent-hover: #0284c7;
            --accent-light: #e0f2fe;
            --success: #10b981;
            --success-light: #d1fae5;
            --warning: #f59e0b;
            --warning-light: #fef3c7;
            --danger: #ef4444;
            --danger-light: #fee2e2;
            --info: #6366f1;
            --info-light: #e0e7ff;
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
            --radius-sm: 6px;
            --radius: 8px;
            --radius-lg: 12px;
            --radius-xl: 16px;
        }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--content-bg);
            min-height: 100vh;
            color: var(--text-primary);
            display: flex;
        }}

        /* Sidebar */
        .sidebar {{
            width: 280px;
            background: var(--sidebar-bg);
            min-height: 100vh;
            position: fixed;
            left: 0;
            top: 0;
            display: flex;
            flex-direction: column;
            z-index: 100;
        }}

        .sidebar-header {{
            padding: 24px 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        }}

        .sidebar-logo {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .sidebar-logo-icon {{
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, var(--accent) 0%, #6366f1 100%);
            border-radius: var(--radius);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
        }}

        .sidebar-logo-text {{
            color: var(--sidebar-text-active);
            font-size: 18px;
            font-weight: 700;
            letter-spacing: -0.025em;
        }}

        .sidebar-logo-subtitle {{
            color: var(--sidebar-text);
            font-size: 10px;
            font-weight: 500;
            letter-spacing: 0.03em;
            text-transform: uppercase;
            margin-top: 2px;
        }}

        .sidebar-nav {{
            flex: 1;
            padding: 16px 12px;
            overflow-y: auto;
        }}

        .sidebar-nav-section {{
            margin-bottom: 24px;
        }}

        .sidebar-nav-label {{
            color: var(--sidebar-text);
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            padding: 0 12px;
            margin-bottom: 8px;
        }}

        .sidebar-nav-item {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 16px;
            color: var(--sidebar-text);
            text-decoration: none;
            border-radius: var(--radius);
            font-size: 14px;
            font-weight: 500;
            transition: all 0.15s ease;
            cursor: pointer;
            margin-bottom: 4px;
        }}

        .sidebar-nav-item:hover {{
            background: var(--sidebar-hover);
            color: var(--sidebar-text-active);
        }}

        .sidebar-nav-item.active {{
            background: linear-gradient(135deg, var(--accent) 0%, #0284c7 100%);
            color: var(--sidebar-text-active);
            box-shadow: 0 4px 12px rgba(14, 165, 233, 0.3);
        }}

        .sidebar-nav-icon {{
            width: 20px;
            text-align: center;
        }}

        .sidebar-footer {{
            padding: 16px 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.08);
            color: var(--sidebar-text);
            font-size: 11px;
        }}

        /* Main Content */
        .main-content {{
            flex: 1;
            margin-left: 280px;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }}

        .top-banner {{
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: white;
            padding: 32px;
            box-shadow: var(--shadow-lg);
        }}

        .top-banner h1 {{
            font-size: 26px;
            font-weight: 700;
            margin-bottom: 8px;
            letter-spacing: -0.025em;
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .top-banner .metadata {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
            margin-top: 20px;
        }}

        .metadata-item {{
            background: rgba(255, 255, 255, 0.08);
            padding: 14px 16px;
            border-radius: var(--radius);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}

        .metadata-item strong {{
            display: block;
            opacity: 0.7;
            margin-bottom: 4px;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .content-area {{
            flex: 1;
            padding: 32px;
        }}

        /* Summary Cards Grid */
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 20px;
            margin-bottom: 32px;
        }}

        .summary-card {{
            background: var(--card-bg);
            border-radius: var(--radius-lg);
            padding: 24px;
            text-align: center;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
        }}

        .summary-card .value {{
            font-size: 42px;
            font-weight: 700;
            margin-bottom: 4px;
            line-height: 1;
        }}

        .summary-card .label {{
            font-size: 12px;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
        }}

        /* Cards */
        .card {{
            background: var(--card-bg);
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
            margin-bottom: 24px;
        }}

        .card-header {{
            padding: 20px 24px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}

        .card-header h2 {{
            font-size: 16px;
            font-weight: 700;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .card-body {{
            padding: 24px;
        }}

        /* Compliance Grid */
        .compliance-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
            gap: 16px;
        }}

        .compliance-card {{
            background: var(--content-bg);
            border-radius: var(--radius);
            padding: 20px;
            text-align: center;
            border: 1px solid var(--border-color);
        }}

        .compliance-framework {{
            font-size: 11px;
            font-weight: 700;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 8px;
        }}

        .compliance-score {{
            font-size: 28px;
            font-weight: 700;
        }}

        /* Tables */
        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th, td {{
            padding: 14px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}

        th {{
            background: var(--content-bg);
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-secondary);
            letter-spacing: 0.05em;
        }}

        tr:hover {{
            background: #fafbfc;
        }}

        /* Badges */
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.02em;
        }}

        .badge-critical {{ background: #f3e8ff; color: #9b59b6; }}
        .badge-high {{ background: var(--danger-light); color: var(--danger); }}
        .badge-medium {{ background: var(--warning-light); color: #b45309; }}
        .badge-low {{ background: var(--accent-light); color: var(--accent-hover); }}
        .badge-info {{ background: var(--info-light); color: var(--info); }}

        .badge-success {{ background: var(--success-light); color: var(--success); }}
        .badge-warning {{ background: var(--warning-light); color: var(--warning); }}
        .badge-danger {{ background: var(--danger-light); color: var(--danger); }}

        /* Confidence Bar */
        .confidence-bar {{
            width: 80px;
            height: 6px;
            background: var(--border-color);
            border-radius: 3px;
            overflow: hidden;
        }}

        .confidence-fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--accent) 0%, var(--success) 100%);
            border-radius: 3px;
        }}

        /* Section Items */
        .section-item {{
            padding: 10px 12px;
            border-bottom: 1px solid var(--border-color);
            font-size: 13px;
        }}

        .section-item:last-child {{
            border-bottom: none;
        }}

        .section-heading {{
            color: var(--text-primary);
            font-weight: 500;
        }}

        /* Tree View */
        .tree-view {{
            font-size: 13px;
        }}

        .tree-view ul {{
            list-style: none;
            padding-left: 0;
            margin: 0;
        }}

        .tree-view > ul > li {{
            border-left: 2px solid var(--border-color);
            margin-left: 8px;
        }}

        .tree-view > ul > li:last-child {{
            border-left-color: transparent;
        }}

        .tree-children {{
            padding-left: 20px;
            display: none;
            border-left: 2px solid var(--border-color);
            margin-left: 8px;
        }}

        .tree-children.expanded {{
            display: block;
        }}

        .tree-node {{
            position: relative;
        }}

        .tree-node-content {{
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 10px 12px;
            border-radius: var(--radius-sm);
            transition: background 0.15s ease;
            cursor: default;
        }}

        .tree-parent > .tree-node-content {{
            cursor: pointer;
        }}

        .tree-node-content:hover {{
            background: var(--content-bg);
        }}

        .tree-toggle {{
            width: 16px;
            height: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 10px;
            color: var(--text-muted);
            transition: transform 0.2s ease;
            flex-shrink: 0;
        }}

        .tree-parent.expanded > .tree-node-content .tree-toggle {{
            transform: rotate(90deg);
        }}

        .tree-toggle-placeholder {{
            width: 16px;
            flex-shrink: 0;
        }}

        .tree-status {{
            font-size: 10px;
            flex-shrink: 0;
        }}

        .tree-heading {{
            flex: 1;
            font-weight: 500;
            color: var(--text-primary);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}

        .tree-mapping {{
            font-size: 11px;
            color: var(--accent);
            background: var(--accent-light);
            padding: 2px 8px;
            border-radius: 10px;
            font-weight: 600;
            white-space: nowrap;
        }}

        .tree-confidence {{
            width: 50px;
            height: 4px;
            background: var(--border-color);
            border-radius: 2px;
            overflow: hidden;
            flex-shrink: 0;
        }}

        .tree-confidence-fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--warning) 0%, var(--success) 100%);
            border-radius: 2px;
        }}

        .tree-node.mapped > .tree-node-content {{
            background: rgba(16, 185, 129, 0.05);
        }}

        .tree-node.partial > .tree-node-content {{
            background: rgba(245, 158, 11, 0.05);
        }}

        .tree-node.unmapped > .tree-node-content {{
            background: transparent;
        }}

        .tree-node.mapped > .tree-node-content:hover {{
            background: rgba(16, 185, 129, 0.1);
        }}

        .tree-node.partial > .tree-node-content:hover {{
            background: rgba(245, 158, 11, 0.1);
        }}

        /* Tree toolbar */
        .tree-toolbar {{
            display: flex;
            gap: 12px;
            margin-bottom: 16px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border-color);
            align-items: center;
            flex-wrap: wrap;
        }}

        .tree-toolbar-btn {{
            padding: 6px 12px;
            font-size: 12px;
            font-weight: 600;
            border: 1px solid var(--border-color);
            background: var(--card-bg);
            border-radius: var(--radius-sm);
            cursor: pointer;
            transition: all 0.15s ease;
            color: var(--text-secondary);
        }}

        .tree-toolbar-btn:hover {{
            background: var(--content-bg);
            border-color: var(--accent);
            color: var(--accent);
        }}

        .tree-stats {{
            display: flex;
            gap: 16px;
            margin-left: auto;
            font-size: 12px;
        }}

        .tree-stat {{
            display: flex;
            align-items: center;
            gap: 6px;
            color: var(--text-secondary);
        }}

        .tree-stat-dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }}

        .tree-stat-dot.mapped {{ background: var(--success); }}
        .tree-stat-dot.partial {{ background: var(--warning); }}
        .tree-stat-dot.unmapped {{ background: var(--border-color); }}

        /* Gaps */
        .gap-item {{
            padding: 16px;
            background: var(--danger-light);
            border-radius: var(--radius);
            margin-bottom: 12px;
            border-left: 4px solid var(--danger);
        }}

        .gap-element {{
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 4px;
        }}

        .gap-recommendation {{
            font-size: 13px;
            color: var(--text-secondary);
        }}

        /* Status sections */
        .status-section {{
            margin-bottom: 32px;
        }}

        .status-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 2px solid var(--border-color);
        }}

        .status-header h3 {{
            font-size: 15px;
            font-weight: 700;
            color: var(--text-primary);
        }}

        .status-count {{
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 700;
            color: white;
        }}

        /* Two column layout */
        .two-col {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
        }}

        /* Print styles */
        @media print {{
            .sidebar {{
                display: none;
            }}
            .main-content {{
                margin-left: 0;
            }}
            .card {{
                box-shadow: none;
                border: 1px solid #ddd;
                page-break-inside: avoid;
            }}
        }}

        /* Responsive */
        @media (max-width: 1200px) {{
            .summary-grid {{
                grid-template-columns: repeat(3, 1fr);
            }}
            .two-col {{
                grid-template-columns: 1fr;
            }}
        }}

        @media (max-width: 768px) {{
            .sidebar {{
                display: none;
            }}
            .main-content {{
                margin-left: 0;
            }}
            .summary-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}
    </style>
</head>
<body>
    <!-- Sidebar -->
    <nav class="sidebar">
        <div class="sidebar-header">
            <div class="sidebar-logo">
                <div class="sidebar-logo-icon">📄</div>
                <div>
                    <div class="sidebar-logo-text">CAIP</div>
                    <div class="sidebar-logo-subtitle">Document Assessment</div>
                </div>
            </div>
        </div>
        
        <div class="sidebar-nav">
            <div class="sidebar-nav-section">
                <div class="sidebar-nav-label">Report Sections</div>
                <a href="#overview" class="sidebar-nav-item active">
                    <span class="sidebar-nav-icon">📊</span>
                    Overview
                </a>
                <a href="#compliance" class="sidebar-nav-item">
                    <span class="sidebar-nav-icon">✓</span>
                    Compliance Scores
                </a>
                <a href="#findings" class="sidebar-nav-item">
                    <span class="sidebar-nav-icon">🔍</span>
                    Assessment Findings
                </a>
                <a href="#structure" class="sidebar-nav-item">
                    <span class="sidebar-nav-icon">📑</span>
                    Document Structure
                </a>
                <a href="#metadata" class="sidebar-nav-item">
                    <span class="sidebar-nav-icon">ℹ️</span>
                    Document Metadata
                </a>
            </div>
            
            <div class="sidebar-nav-section">
                <div class="sidebar-nav-label">Quick Stats</div>
                <div style="padding: 12px 16px; color: var(--sidebar-text); font-size: 13px;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span>Found</span>
                        <span style="color: var(--success); font-weight: 600;">{found_count}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span>Partial</span>
                        <span style="color: var(--warning); font-weight: 600;">{partial_count}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between;">
                        <span>Missing</span>
                        <span style="color: var(--danger); font-weight: 600;">{missing_count}</span>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="sidebar-footer">
            <div>Assessment ID: {assessment.get('assessment_id', 'N/A')[:16]}</div>
            <div style="margin-top: 4px;">Generated by CAIP v1.0</div>
        </div>
    </nav>

    <!-- Main Content -->
    <main class="main-content">
        <div class="top-banner">
            <h1>📄 Document Assessment Report</h1>
            <div class="metadata">
                <div class="metadata-item">
                    <strong>File</strong>
                    {assessment.get('filename', 'Unknown')}
                </div>
                <div class="metadata-item">
                    <strong>Document Type</strong>
                    {assessment.get('document_type', 'Unknown').replace('_', ' ').title()}
                </div>
                <div class="metadata-item">
                    <strong>Assessed</strong>
                    {assessment.get('created_at', 'Unknown')}
                </div>
                <div class="metadata-item">
                    <strong>Template</strong>
                    {assessment.get('template_used', 'Default')}
                </div>
            </div>
        </div>

        <div class="content-area">
            <!-- Overview Section -->
            <section id="overview">
                <div class="summary-grid">
                    <div class="summary-card">
                        <div class="value" style="color: {grade_color};">{grade}</div>
                        <div class="label">Assessment Grade</div>
                    </div>
                    <div class="summary-card">
                        <div class="value" style="color: var(--accent);">{assessment.get('coverage_score', 0):.1f}%</div>
                        <div class="label">Coverage Score</div>
                    </div>
                    <div class="summary-card">
                        <div class="value" style="color: var(--success);">{found_count}</div>
                        <div class="label">Elements Found</div>
                    </div>
                    <div class="summary-card">
                        <div class="value" style="color: var(--warning);">{partial_count}</div>
                        <div class="label">Partial Coverage</div>
                    </div>
                    <div class="summary-card">
                        <div class="value" style="color: var(--danger);">{missing_count}</div>
                        <div class="label">Elements Missing</div>
                    </div>
                </div>

                {f'''
                <div class="card">
                    <div class="card-header">
                        <h2>⚠️ Critical Gaps</h2>
                    </div>
                    <div class="card-body">
                        {critical_gaps_html if critical_gaps_html else '<p style="color: var(--text-muted);">No critical gaps identified.</p>'}
                    </div>
                </div>
                ''' if critical_gaps else ''}
            </section>

            <!-- Compliance Section -->
            <section id="compliance">
                <div class="card">
                    <div class="card-header">
                        <h2>✓ Compliance Scores</h2>
                    </div>
                    <div class="card-body">
                        <div class="compliance-grid">
                            {compliance_cards_html if compliance_cards_html else '<p style="color: var(--text-muted);">No compliance scores available.</p>'}
                        </div>
                    </div>
                </div>
            </section>

            <!-- Findings Section -->
            <section id="findings">
                <div class="card">
                    <div class="card-header">
                        <h2>🔍 Assessment Findings</h2>
                        <span style="color: var(--text-muted); font-size: 14px;">{total_findings} total elements assessed</span>
                    </div>
                    <div class="card-body">
                        {f'''
                        <div class="status-section">
                            <div class="status-header">
                                <span class="status-count" style="background: var(--danger);">{missing_count}</span>
                                <h3>Missing Elements</h3>
                            </div>
                            <table>
                                <thead>
                                    <tr>
                                        <th>Element</th>
                                        <th>Severity</th>
                                        <th>Confidence</th>
                                        <th>Matched Section</th>
                                        <th>Compliance Refs</th>
                                        <th>Recommendation</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {missing_rows}
                                </tbody>
                            </table>
                        </div>
                        ''' if missing_rows else ''}
                        
                        {f'''
                        <div class="status-section">
                            <div class="status-header">
                                <span class="status-count" style="background: var(--warning);">{partial_count}</span>
                                <h3>Partial Coverage</h3>
                            </div>
                            <table>
                                <thead>
                                    <tr>
                                        <th>Element</th>
                                        <th>Severity</th>
                                        <th>Confidence</th>
                                        <th>Matched Section</th>
                                        <th>Compliance Refs</th>
                                        <th>Recommendation</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {partial_rows}
                                </tbody>
                            </table>
                        </div>
                        ''' if partial_rows else ''}
                        
                        {f'''
                        <div class="status-section">
                            <div class="status-header">
                                <span class="status-count" style="background: var(--success);">{found_count}</span>
                                <h3>Elements Found</h3>
                            </div>
                            <table>
                                <thead>
                                    <tr>
                                        <th>Element</th>
                                        <th>Severity</th>
                                        <th>Confidence</th>
                                        <th>Matched Section</th>
                                        <th>Compliance Refs</th>
                                        <th>Recommendation</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {found_rows}
                                </tbody>
                            </table>
                        </div>
                        ''' if found_rows else ''}
                        
                        {f'<p style="color: var(--text-muted); text-align: center; padding: 40px;">No findings recorded.</p>' if not findings else ''}
                    </div>
                </div>
            </section>

            <!-- Document Structure Section -->
            <section id="structure">
                <div class="card">
                    <div class="card-header">
                        <h2>📑 Document Structure</h2>
                        <span style="color: var(--text-muted); font-size: 14px;">{len(sections_found)} sections detected</span>
                    </div>
                    <div class="card-body">
                        <div class="tree-toolbar">
                            <button class="tree-toolbar-btn" onclick="expandAllTree()">Expand All</button>
                            <button class="tree-toolbar-btn" onclick="collapseAllTree()">Collapse All</button>
                            <button class="tree-toolbar-btn" onclick="expandMappedOnly()">Show Mapped Only</button>
                            <div class="tree-stats">
                                <div class="tree-stat">
                                    <span class="tree-stat-dot mapped"></span>
                                    <span>{mapped_sections} Mapped</span>
                                </div>
                                <div class="tree-stat">
                                    <span class="tree-stat-dot unmapped"></span>
                                    <span>{unmapped_sections} Unmapped</span>
                                </div>
                            </div>
                        </div>
                        <div style="max-height: 500px; overflow-y: auto;">
                            {sections_tree_html}
                        </div>
                    </div>
                </div>
            </section>

            <!-- Document Metadata Section -->
            <section id="metadata">
                <div class="card">
                    <div class="card-header">
                        <h2>ℹ️ Document Metadata</h2>
                    </div>
                    <div class="card-body">
                        <div class="two-col">
                            <div>
                                <table>
                                    <tr>
                                        <td style="font-weight: 600; width: 40%;">Filename</td>
                                        <td>{doc_metadata.get('filename', 'N/A')}</td>
                                    </tr>
                                    <tr>
                                        <td style="font-weight: 600;">File Type</td>
                                        <td>{doc_metadata.get('file_type', 'N/A').upper()}</td>
                                    </tr>
                                    <tr>
                                        <td style="font-weight: 600;">File Size</td>
                                        <td>{doc_metadata.get('file_size', 0):,} bytes</td>
                                    </tr>
                                    <tr>
                                        <td style="font-weight: 600;">Page Count</td>
                                        <td>{doc_metadata.get('page_count', 'N/A') or 'N/A'}</td>
                                    </tr>
                                    <tr>
                                        <td style="font-weight: 600;">Word Count</td>
                                        <td>{doc_metadata.get('word_count', 0):,}</td>
                                    </tr>
                                </table>
                            </div>
                            <div>
                                <table>
                                    <tr>
                                        <td style="font-weight: 600; width: 40%;">Detected Type</td>
                                        <td>{doc_metadata.get('detected_document_type', 'N/A')}</td>
                                    </tr>
                                    <tr>
                                        <td style="font-weight: 600;">Type Confidence</td>
                                        <td>{doc_metadata.get('document_type_confidence', 0):.0%}</td>
                                    </tr>
                                    <tr>
                                        <td style="font-weight: 600;">Version Detected</td>
                                        <td>{doc_metadata.get('version_detected', 'N/A') or 'N/A'}</td>
                                    </tr>
                                    <tr>
                                        <td style="font-weight: 600;">Date Detected</td>
                                        <td>{doc_metadata.get('date_detected', 'N/A') or 'N/A'}</td>
                                    </tr>
                                    <tr>
                                        <td style="font-weight: 600;">Organization</td>
                                        <td>{doc_metadata.get('organization_detected', 'N/A') or 'N/A'}</td>
                                    </tr>
                                </table>
                            </div>
                        </div>
                        <div style="margin-top: 20px; padding: 16px; background: var(--content-bg); border-radius: var(--radius); font-family: monospace; font-size: 12px; word-break: break-all;">
                            <strong>SHA-256:</strong> {doc_metadata.get('hash_sha256', 'N/A')}
                        </div>
                    </div>
                </div>
            </section>
        </div>
    </main>

    <script>
        // Smooth scrolling for nav links
        document.querySelectorAll('.sidebar-nav-item').forEach(link => {{
            link.addEventListener('click', function(e) {{
                const href = this.getAttribute('href');
                if (href && href.startsWith('#')) {{
                    e.preventDefault();
                    const target = document.querySelector(href);
                    if (target) {{
                        target.scrollIntoView({{ behavior: 'smooth' }});
                    }}
                    // Update active state
                    document.querySelectorAll('.sidebar-nav-item').forEach(l => l.classList.remove('active'));
                    this.classList.add('active');
                }}
            }});
        }});
        
        // Update active nav on scroll
        window.addEventListener('scroll', function() {{
            const sections = document.querySelectorAll('section[id]');
            let current = '';
            
            sections.forEach(section => {{
                const sectionTop = section.offsetTop;
                if (window.scrollY >= sectionTop - 100) {{
                    current = section.getAttribute('id');
                }}
            }});
            
            document.querySelectorAll('.sidebar-nav-item').forEach(link => {{
                link.classList.remove('active');
                if (link.getAttribute('href') === '#' + current) {{
                    link.classList.add('active');
                }}
            }});
        }});
        
        // Tree view functions
        function toggleTreeNode(element) {{
            const parent = element.closest('.tree-parent');
            if (parent) {{
                parent.classList.toggle('expanded');
                const children = parent.querySelector('.tree-children');
                if (children) {{
                    children.classList.toggle('expanded');
                }}
            }}
        }}
        
        function expandAllTree() {{
            document.querySelectorAll('.tree-parent').forEach(node => {{
                node.classList.add('expanded');
                const children = node.querySelector('.tree-children');
                if (children) children.classList.add('expanded');
            }});
        }}
        
        function collapseAllTree() {{
            document.querySelectorAll('.tree-parent').forEach(node => {{
                node.classList.remove('expanded');
                const children = node.querySelector('.tree-children');
                if (children) children.classList.remove('expanded');
            }});
        }}
        
        function expandMappedOnly() {{
            // First collapse all
            collapseAllTree();
            
            // Then expand only nodes that contain mapped items
            document.querySelectorAll('.tree-node.mapped, .tree-node.partial').forEach(node => {{
                // Expand all parent nodes
                let parent = node.parentElement;
                while (parent) {{
                    if (parent.classList.contains('tree-children')) {{
                        parent.classList.add('expanded');
                        const parentNode = parent.closest('.tree-parent');
                        if (parentNode) {{
                            parentNode.classList.add('expanded');
                        }}
                    }}
                    parent = parent.parentElement;
                }}
            }});
        }}
        
        // Auto-expand first level on load
        document.addEventListener('DOMContentLoaded', function() {{
            document.querySelectorAll('.tree-view > ul > .tree-parent').forEach(node => {{
                node.classList.add('expanded');
                const children = node.querySelector('.tree-children');
                if (children) children.classList.add('expanded');
            }});
        }});
    </script>
</body>
</html>"""
        
        return html
    
    logger.info("Document assessment routes registered")
