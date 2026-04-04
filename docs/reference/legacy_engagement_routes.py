"""
Engagement API Routes for CAIP

Flask routes for customer engagement and report grouping functionality.
These routes should be registered with the main Flask app.

Usage in app.py:
    from engagement_routes import register_engagement_routes
    register_engagement_routes(app, DatabaseService, login_required, permission_required)
"""

import os
import json
import logging
from datetime import datetime
from flask import request, jsonify, send_file, session

logger = logging.getLogger('caip.operational')

from caip_reporting_functions.executive_report_service import ExecutiveReportService


def register_engagement_routes(app, db_service, login_required, permission_required=None, vault_service=None):
    """
    Register engagement routes with the Flask app.

    Args:
        app: Flask application instance
        db_service: DatabaseService class
        login_required: Login required decorator
        permission_required: Optional permission decorator
        vault_service: Optional vault service (unified_vault or secret_service)
    """

    from caip_engagement_functions.engagement_service import EngagementService
    
    # =========================================================================
    # ENGAGEMENT CRUD ENDPOINTS
    # =========================================================================
    
    @app.route('/api/v1/engagements', methods=['GET'])
    @login_required
    @permission_required('engagements:read')
    def list_engagements():
        """
        List all engagements with optional filtering.
        
        Query params:
            status: Filter by status (Active, Completed, Archived)
            customer: Filter by customer name (partial match)
        """
        try:
            status = request.args.get('status')
            customer = request.args.get('customer')
            
            engagements = EngagementService.list_engagements(
                db_service,
                status=status,
                customer_name=customer
            )
            
            return jsonify({'engagements': engagements}), 200
            
        except Exception as e:
            logger.error(f"Error listing engagements: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/engagements', methods=['POST'])
    @login_required
    @permission_required('engagements:create')
    def create_engagement():
        """
        Create a new engagement and automatically issue certificates with deployment tracking.

        Returns per-step status array enabling UI to show progress and fail gracefully on critical step failure.

        Request body:
            customer_name: Required
            project_name: Required
            description: Optional
            start_date: Optional (defaults to today)
            lead_consultant: Optional

        Returns:
            Engagement details with 'steps' array showing deployment progress
            On critical failure: HTTP 500 with error and steps array
        """
        steps = []
        engagement_id_for_rollback = None

        try:
            data = request.json

            if not data.get('customer_name'):
                return jsonify({'error': 'customer_name is required'}), 400
            if not data.get('project_name'):
                return jsonify({'error': 'project_name is required'}), 400

            # Step 0: Create engagement record
            engagement = EngagementService.create_engagement(
                db_service,
                customer_name=data['customer_name'],
                project_name=data['project_name'],
                description=data.get('description'),
                start_date=data.get('start_date'),
                lead_consultant=data.get('lead_consultant')
            )
            engagement_id_for_rollback = engagement['engagement_id']
            steps.append({
                'id': 'engagement_record',
                'label': 'Engagement Record',
                'status': 'success',
                'detail': engagement['engagement_id'],
                'error': None
            })

            logger.info(f"Created engagement record: {engagement['engagement_id']}")

            # Steps 1-10: Create Engagement CA + Report Signing Cert via stepped method
            from caip_service_layer.certificate_service import CertificateService
            certificate_service = CertificateService(vault_service, db_service)

            cert_result = certificate_service.create_engagement_ca_stepped(
                engagement_id=engagement['engagement_id'],
                engagement_name=data['customer_name']
            )

            steps.extend(cert_result['steps'])
            logger.info(f"Engagement CA and signing certs created for {engagement['engagement_id']}")

            # Reload global vault instance to ensure in-memory cache stays synchronized
            try:
                from caip_service_layer.unified_vault_service import get_unified_vault_service
                global_vault = get_unified_vault_service()
                if global_vault and hasattr(global_vault, '_reload_vault'):
                    global_vault._reload_vault()
            except Exception as reload_err:
                logger.warning(f"Failed to reload global vault: {reload_err}")

            # Success: return engagement with steps
            response = engagement.copy()
            response['steps'] = steps

            return jsonify(response), 201

        except Exception as e:
            logger.error(f"Engagement creation failed: {e}", exc_info=True)

            # Rollback: delete engagement if it was created
            if engagement_id_for_rollback:
                try:
                    logger.info(f"Rolling back engagement {engagement_id_for_rollback}")
                    EngagementService.delete_engagement(db_service, engagement_id_for_rollback)
                    logger.info(f"Successfully rolled back engagement {engagement_id_for_rollback}")
                except Exception as rb_err:
                    logger.error(f"Rollback failed for {engagement_id_for_rollback}: {rb_err}", exc_info=True)

            # Build failed steps response
            failed_steps = getattr(e, 'steps', steps)  # steps from exception if available

            # Define all step definitions for skipped step tracking
            all_step_defs = [
                {'id': 'engagement_record', 'label': 'Engagement Record'},
                {'id': 'ca_key_gen', 'label': 'CA Key Generation'},
                {'id': 'ca_cert_sign', 'label': 'CA Certificate Signing'},
                {'id': 'ca_vault_store', 'label': 'CA Vault Storage'},
                {'id': 'ca_db_record', 'label': 'CA Database Record'},
                {'id': 'signing_cert_create', 'label': 'Report Signing Cert'},
                {'id': 'signing_vault_store', 'label': 'Signing Key Vault Storage'},
                {'id': 'signing_db_record', 'label': 'Signing Cert Database'},
            ]

            # Mark remaining steps as skipped
            executed_ids = {s['id'] for s in failed_steps}
            for step_def in all_step_defs:
                if step_def['id'] not in executed_ids:
                    failed_steps.append({
                        'id': step_def['id'],
                        'label': step_def['label'],
                        'status': 'skipped',
                        'detail': '',
                        'error': None
                    })

            return jsonify({'error': str(e), 'steps': failed_steps}), 500

    # =========================================================================
    # PHASE 3: ENGAGEMENT CA & REPORT SIGNING CERTIFICATE ENDPOINTS
    # =========================================================================

    def _get_certificate_by_engagement(table: str, engagement_id: str):
        """Generic certificate retrieval by engagement"""
        try:
            conn = db_service.get_connection()
            c = conn.cursor()
            c.execute(f'''
                SELECT certificate_pem, certificate_serial, subject, issuer,
                       issued_at, expires_at, status
                FROM {table}
                WHERE engagement_id = ? AND status = 'active'
            ''', (engagement_id,))
            row = c.fetchone()
            conn.close()

            if not row:
                return None

            return {
                'certificate_pem': row[0],
                'certificate_serial': row[1],
                'subject': row[2],
                'issuer': row[3],
                'issued_at': row[4],
                'expires_at': row[5],
                'status': row[6]
            }
        except Exception as e:
            logger.error(f"Failed to get cert from {table}: {e}")
            raise

    @app.route('/api/v1/engagements/<engagement_id>/ca', methods=['GET'])
    @login_required
    @permission_required('engagements:read')
    def get_engagement_ca(engagement_id):
        """Get Engagement CA certificate for an engagement"""
        try:
            cert = _get_certificate_by_engagement('engagement_ca_certificates', engagement_id)
            if not cert:
                return jsonify({'error': 'No Engagement CA found'}), 404
            return jsonify(cert), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/v1/engagements/<engagement_id>/report-signing-cert', methods=['GET'])
    @login_required
    @permission_required('engagements:read')
    def get_report_signing_cert(engagement_id):
        """Get Report Signing Certificate for an engagement"""
        try:
            cert = _get_certificate_by_engagement('report_signing_certificates', engagement_id)
            if not cert:
                return jsonify({'error': 'No Report Signing Cert found'}), 404
            return jsonify(cert), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/v1/ca/engagement-cas', methods=['GET'])
    @login_required
    @permission_required('engagements:read')
    def list_engagement_cas():
        """List all Engagement CA certificates"""
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            conn = db_service.get_connection()
            c = conn.cursor()
            c.execute('''
                SELECT ecc.engagement_id, ecc.certificate_pem, ecc.certificate_serial, ecc.subject, ecc.issuer,
                       ecc.issued_at, ecc.expires_at, ecc.status, e.customer_name, e.project_name
                FROM engagement_ca_certificates ecc
                LEFT JOIN engagements e ON ecc.engagement_id = e.engagement_id
                WHERE ecc.status = 'active'
                ORDER BY ecc.created_at DESC
            ''')
            rows = c.fetchall()
            conn.close()

            certs = []
            for row in rows:
                cert_pem = row[1]
                algorithm = 'Unknown'
                key_size = 'Unknown'

                # Extract algorithm and key size from PEM
                try:
                    cert_obj = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                    public_key = cert_obj.public_key()

                    # Determine algorithm
                    from cryptography.hazmat.primitives.asymmetric import rsa, ec
                    if isinstance(public_key, rsa.RSAPublicKey):
                        algorithm = 'RSA'
                        key_size = str(public_key.key_size)
                    elif isinstance(public_key, ec.EllipticCurvePublicKey):
                        algorithm = 'EC'
                        key_size = str(public_key.curve.key_size)
                except Exception:
                    pass

                certs.append({
                    'engagement_id': row[0],
                    'certificate_pem': row[1],
                    'certificate_serial': row[2],
                    'subject': row[3],
                    'issuer': row[4],
                    'issued_at': row[5],
                    'expires_at': row[6],
                    'status': row[7],
                    'algorithm': algorithm,
                    'key_size': key_size,
                    'customer_name': row[8],
                    'project_name': row[9]
                })

            return jsonify({'certificates': certs}), 200
        except Exception as e:
            logger.error(f"Failed to list Engagement CAs: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/v1/ca/report-signing-certs', methods=['GET'])
    @login_required
    @permission_required('engagements:read')
    def list_report_signing_certs():
        """List all Report Signing certificates"""
        try:
            conn = db_service.get_connection()
            c = conn.cursor()
            c.execute('''
                SELECT engagement_id, certificate_pem, certificate_serial, subject, issuer,
                       issued_at, expires_at, status
                FROM report_signing_certificates
                WHERE status = 'active'
                ORDER BY created_at DESC
            ''')
            rows = c.fetchall()
            conn.close()

            certs = []
            for row in rows:
                certs.append({
                    'engagement_id': row[0],
                    'certificate_pem': row[1],
                    'certificate_serial': row[2],
                    'subject': row[3],
                    'issuer': row[4],
                    'issued_at': row[5],
                    'expires_at': row[6],
                    'status': row[7]
                })

            return jsonify({'certificates': certs}), 200
        except Exception as e:
            logger.error(f"Failed to list Report Signing Certs: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/v1/engagements/<engagement_id>', methods=['GET'])
    @login_required
    @permission_required('engagements:read')
    def get_engagement(engagement_id):
        """Get engagement details including linked reports."""
        try:
            engagement = EngagementService.get_engagement(db_service, engagement_id)
            
            if not engagement:
                return jsonify({'error': 'Engagement not found'}), 404
            
            # Include linked reports
            engagement['reports'] = EngagementService.get_engagement_reports(
                db_service, engagement_id
            )
            
            # Include executive summaries
            engagement['executive_summaries'] = EngagementService.get_engagement_summaries(
                db_service, engagement_id
            )
            
            return jsonify(engagement), 200
            
        except Exception as e:
            logger.error(f"Error getting engagement: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/engagements/<engagement_id>', methods=['PUT'])
    @login_required
    @permission_required('engagements:update')
    def update_engagement(engagement_id):
        """Update engagement details."""
        try:
            data = request.json
            
            success = EngagementService.update_engagement(
                db_service,
                engagement_id,
                **data
            )
            
            if not success:
                return jsonify({'error': 'Engagement not found or no updates provided'}), 404
            
            return jsonify({'message': 'Engagement updated successfully'}), 200
            
        except Exception as e:
            logger.error(f"Error updating engagement: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/engagements/<engagement_id>', methods=['DELETE'])
    @login_required
    @permission_required('engagements:delete')
    def delete_engagement(engagement_id):
        """Delete engagement and all linked records with step tracking."""
        import time
        start_time = time.time()
        steps = []

        try:
            # Pre-count records for each table before deletion
            conn = db_service.get_connection()
            c = conn.cursor()

            # Get numeric_id for tables that use FK to engagements(id)
            c.execute('SELECT id FROM engagements WHERE engagement_id = ?', (engagement_id,))
            row = c.fetchone()
            if not row:
                conn.close()
                return jsonify({'error': 'Engagement not found'}), 404
            numeric_id = row[0]

            # Define deletion order with labels (matching engagement_service.py line 254+)
            deletion_order = [
                ('engagement_ca_certificates', 'Engagement CA Certificates'),
                ('report_signing_certificates', 'Report Signing Certificates'),
                ('engagement_dashboard_certificates', 'Dashboard Certificates'),
                ('collector_certificates', 'Collector Certificates'),
                ('certificate_audit_log', 'Certificate Audit Log'),
                ('certificate_registration_requests', 'Certificate Registration Requests'),
                ('certificate_revocation_list', 'Certificate Revocation List'),
                ('scan_logs', 'Scan Logs'),
                ('scans', 'Scans'),
                ('configurations', 'Configurations'),
                ('reassessments', 'Reassessments'),
                ('report_aggregations', 'Report Aggregations'),
                ('document_assessments', 'Document Assessments'),
                ('engagement_executive_summaries', 'Executive Summaries'),
                ('engagement_reports', 'Engagement Reports'),
                ('user_digital_identities', 'User Digital Identities'),
                ('engagements', 'Engagement Record'),
            ]

            # Count records for each table BEFORE deletion
            record_counts = {}
            try:
                # Special cases with complex WHERE clauses
                c.execute('''SELECT COUNT(*) FROM scan_logs WHERE scan_id IN
                             (SELECT id FROM scans WHERE engagement_id = ?)''',
                         (engagement_id,))
                record_counts['scan_logs'] = c.fetchone()[0]

                # Standard engagement_id references
                for table, label in deletion_order:
                    if table == 'scan_logs' or table == 'engagements':
                        continue

                    # Tables that use numeric_id FK to engagements(id)
                    if table in ['engagement_dashboard_certificates', 'collector_certificates', 'certificate_audit_log', 'certificate_registration_requests', 'certificate_revocation_list']:
                        c.execute(f'SELECT COUNT(*) FROM {table} WHERE engagement_id = ?', (numeric_id,))
                    else:
                        # These use engagement_id directly
                        c.execute(f'SELECT COUNT(*) FROM {table} WHERE engagement_id = ?', (engagement_id,))

                    record_counts[table] = c.fetchone()[0]
            finally:
                conn.close()

            # Execute deletion via EngagementService
            success = EngagementService.delete_engagement(db_service, engagement_id)

            if not success:
                return jsonify({'error': 'Engagement not found'}), 404

            # Build steps array based on counts
            for table, label in deletion_order:
                count = record_counts.get(table, 0)
                steps.append({
                    'id': table,
                    'label': label,
                    'table': table,
                    'count': count,
                    'status': 'success',
                    'error': None
                })

            # Add vault cleanup step
            steps.append({
                'id': 'vault_keys',
                'label': 'Vault Key Cleanup',
                'table': 'vault',
                'count': 0,
                'status': 'success',
                'error': None
            })

            execution_time_ms = int((time.time() - start_time) * 1000)

            return jsonify({
                'engagement_id': engagement_id,
                'status': 'success',
                'message': 'Engagement deleted successfully',
                'steps': steps,
                'summary': {
                    'total_records_deleted': sum(s.get('count', 0) for s in steps if s['status'] == 'success'),
                    'execution_time_ms': execution_time_ms
                }
            }), 200

        except Exception as e:
            logger.error(f"Error deleting engagement: {e}", exc_info=True)
            return jsonify({'error': str(e), 'steps': steps}), 500
    
    @app.route('/api/v1/engagements/<engagement_id>/associated-items', methods=['GET'])
    @login_required
    @permission_required('engagements:read')
    def get_engagement_associated_items(engagement_id):
        """
        Get all items directly associated with an engagement via engagement_id.
        
        Returns scans, configurations, reassessments, aggregations, 
        and document assessments that have this engagement_id set.
        """
        try:
            # Verify engagement exists
            engagement = EngagementService.get_engagement(db_service, engagement_id)
            if not engagement:
                return jsonify({'error': 'Engagement not found'}), 404
            
            # Get report summary from DatabaseService
            summary = db_service.get_engagement_report_summary(engagement_id)
            
            # Add document assessments
            from caip_document_assessment_functions.document_assessment_database import DocumentAssessmentDatabase
            doc_assessments = DocumentAssessmentDatabase.list_assessments_by_engagement(
                db_service, engagement_id
            )
            summary['document_assessments'] = doc_assessments
            summary['document_assessment_count'] = len(doc_assessments)
            
            return jsonify(summary), 200

        except Exception as e:
            logger.error(f"Error getting engagement associated items: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/v1/engagements/<engagement_id>/deletion-preview', methods=['GET'])
    @login_required
    @permission_required('engagements:read')
    def get_engagement_deletion_preview(engagement_id):
        """
        Get preview of all records that will be deleted before user confirms.

        Returns record counts for all tables that will be cascade-deleted.
        """
        try:
            # Verify engagement exists
            engagement = EngagementService.get_engagement(db_service, engagement_id)
            if not engagement:
                return jsonify({'error': 'Engagement not found'}), 404

            conn = db_service.get_connection()
            c = conn.cursor()

            # Get numeric_id for tables that use FK to engagements(id)
            c.execute('SELECT id FROM engagements WHERE engagement_id = ?', (engagement_id,))
            row = c.fetchone()
            if not row:
                conn.close()
                return jsonify({'error': 'Engagement not found'}), 404
            numeric_id = row[0]

            # Define deletion order (must match engagement_routes.py delete_engagement)
            deletion_order = [
                'engagement_ca_certificates',
                'report_signing_certificates',
                'engagement_dashboard_certificates',
                'collector_certificates',
                'certificate_audit_log',
                'certificate_registration_requests',
                'certificate_revocation_list',
                'scan_logs',
                'scans',
                'configurations',
                'reassessments',
                'report_aggregations',
                'document_assessments',
                'engagement_executive_summaries',
                'engagement_reports',
                'user_digital_identities',
            ]

            preview = {}
            total_records = 0

            try:
                # Count scan_logs (special case: FK to scans)
                c.execute('''SELECT COUNT(*) FROM scan_logs WHERE scan_id IN
                             (SELECT id FROM scans WHERE engagement_id = ?)''',
                         (engagement_id,))
                count = c.fetchone()[0]
                preview['scan_logs'] = count
                total_records += count

                # Count all other tables
                for table in deletion_order:
                    if table == 'scan_logs':
                        continue

                    # Tables that use numeric_id FK to engagements(id)
                    if table in ['engagement_dashboard_certificates', 'collector_certificates', 'certificate_audit_log', 'certificate_registration_requests', 'certificate_revocation_list']:
                        c.execute(f'SELECT COUNT(*) FROM {table} WHERE engagement_id = ?', (numeric_id,))
                    else:
                        # These use engagement_id directly
                        c.execute(f'SELECT COUNT(*) FROM {table} WHERE engagement_id = ?', (engagement_id,))

                    count = c.fetchone()[0]
                    preview[table] = count
                    total_records += count

                # Estimate vault keys (typically 2-3 per engagement)
                c.execute('SELECT COUNT(*) FROM engagement_ca_certificates WHERE engagement_id = ?', (engagement_id,))
                ca_certs = c.fetchone()[0]
                c.execute('SELECT COUNT(*) FROM report_signing_certificates WHERE engagement_id = ?', (engagement_id,))
                signing_certs = c.fetchone()[0]
                vault_keys = ca_certs + signing_certs  # 1 key per cert type

                preview['vault_keys'] = vault_keys
                total_records += vault_keys

            finally:
                conn.close()

            return jsonify({
                'engagement_id': engagement_id,
                'customer_name': engagement.get('customer_name', ''),
                'project_name': engagement.get('project_name', ''),
                'preview': preview,
                'summary': {
                    'total_records': total_records,
                    'total_vault_keys': vault_keys,
                    'warning_message': None
                }
            }), 200

        except Exception as e:
            logger.error(f"Error getting engagement deletion preview: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    # =========================================================================
    # REPORT LINKING ENDPOINTS
    # =========================================================================
    
    @app.route('/api/v1/engagements/<engagement_id>/reports', methods=['GET'])
    @login_required
    @permission_required('engagements:read')
    def get_engagement_reports(engagement_id):
        """Get all reports linked to an engagement."""
        try:
            include_exec_only = request.args.get('include_in_executive', 'false').lower() == 'true'
            
            reports = EngagementService.get_engagement_reports(
                db_service,
                engagement_id,
                include_in_executive_only=include_exec_only
            )
            
            return jsonify({'reports': reports}), 200
            
        except Exception as e:
            logger.error(f"Error getting engagement reports: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/engagements/<engagement_id>/reports', methods=['POST'])
    @login_required
    @permission_required('engagements:update')
    def add_report_to_engagement(engagement_id):
        """
        Link a report to an engagement.
        
        Request body:
            report_type: 'scan', 'reassessment', 'aggregation', 'document_assessment'
            report_reference_id: ID in the source table
            report_name: Display name
            report_path: Optional path to report file
            include_in_executive: Boolean (default true)
        """
        try:
            data = request.json
            
            if not data.get('report_type'):
                return jsonify({'error': 'report_type is required'}), 400
            if not data.get('report_reference_id'):
                return jsonify({'error': 'report_reference_id is required'}), 400
            if not data.get('report_name'):
                return jsonify({'error': 'report_name is required'}), 400
            
            link_id = EngagementService.add_report_to_engagement(
                db_service,
                engagement_id,
                report_type=data['report_type'],
                report_reference_id=data['report_reference_id'],
                report_name=data['report_name'],
                report_path=data.get('report_path'),
                include_in_executive=data.get('include_in_executive', True)
            )
            
            return jsonify({
                'id': link_id,
                'message': 'Report linked to engagement successfully'
            }), 201
            
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            logger.error(f"Error adding report to engagement: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/engagements/<engagement_id>/reports/<report_type>/<int:report_reference_id>', methods=['DELETE'])
    @login_required
    @permission_required('engagements:update')
    def remove_report_from_engagement(engagement_id, report_type, report_reference_id):
        """Remove a report link from an engagement."""
        try:
            success = EngagementService.remove_report_from_engagement(
                db_service,
                engagement_id,
                report_type,
                report_reference_id
            )
            
            if not success:
                return jsonify({'error': 'Report link not found'}), 404
            
            return jsonify({'message': 'Report removed from engagement'}), 200
            
        except Exception as e:
            logger.error(f"Error removing report from engagement: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/engagements/<engagement_id>/reports/<report_type>/<int:report_reference_id>/inclusion', methods=['PUT'])
    @login_required
    @permission_required('engagements:update')
    def update_report_inclusion(engagement_id, report_type, report_reference_id):
        """Update whether a report is included in executive summary."""
        try:
            data = request.json
            include = data.get('include_in_executive', True)
            
            success = EngagementService.update_report_inclusion(
                db_service,
                engagement_id,
                report_type,
                report_reference_id,
                include
            )
            
            if not success:
                return jsonify({'error': 'Report link not found'}), 404
            
            return jsonify({'message': 'Report inclusion updated'}), 200
            
        except Exception as e:
            logger.error(f"Error updating report inclusion: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/engagements/<engagement_id>/reports/reorder', methods=['PUT'])
    @login_required
    @permission_required('engagements:update')
    def reorder_engagement_reports(engagement_id):
        """
        Reorder reports within an engagement.
        
        Request body:
            report_order: List of {report_type, report_reference_id, display_order}
        """
        try:
            data = request.json
            report_order = data.get('report_order', [])
            
            if not report_order:
                return jsonify({'error': 'report_order is required'}), 400
            
            EngagementService.reorder_engagement_reports(
                db_service,
                engagement_id,
                report_order
            )
            
            return jsonify({'message': 'Reports reordered successfully'}), 200
            
        except Exception as e:
            logger.error(f"Error reordering reports: {e}")
            return jsonify({'error': str(e)}), 500
    
    # =========================================================================
    # EXECUTIVE SUMMARY ENDPOINTS
    # =========================================================================
    
    @app.route('/api/v1/engagements/<engagement_id>/executive-summary', methods=['POST'])
    @login_required
    @permission_required('reports:executive_summary')
    def generate_engagement_executive_summary(engagement_id):
        """
        Generate executive summary for an engagement.

        Request body:
            report_name: Optional custom name
            format: Optional format (pdf or docx, default: pdf)
        """
        try:

            data = request.json or {}
            report_name = data.get('report_name')
            summary_format = data.get('format', 'pdf').lower()
            
            # Get engagement
            engagement = EngagementService.get_engagement(db_service, engagement_id)
            if not engagement:
                return jsonify({'error': 'Engagement not found'}), 404
            
            # Get reports to include
            reports = EngagementService.get_engagement_reports(
                db_service,
                engagement_id,
                include_in_executive_only=True
            )
            
            if not reports:
                return jsonify({'error': 'No reports selected for executive summary'}), 400
            
            # Separate crypto and document reports
            crypto_reports = []
            document_reports = []
            
            for report in reports:
                report_data = EngagementService.get_report_data(
                    db_service,
                    report['report_type'],
                    report['report_reference_id']
                )
                
                if report_data:
                    if report['report_type'] == 'document_assessment':
                        document_reports.append({
                            'link': report,
                            'data': report_data
                        })
                    else:
                        crypto_reports.append({
                            'link': report,
                            'data': report_data
                        })
            
            # Generate the executive summary
            # This will need enhancement to executive_report_service.py
            # For now, use the first crypto report as base
            if not crypto_reports:
                return jsonify({'error': 'At least one crypto asset scan is required'}), 400
            
            # Merge crypto report findings
            merged_report_data = _merge_crypto_reports(crypto_reports)
            
            # Build document assessment list
            document_assessments = [d['data'] for d in document_reports]
            
            # Generate PDF
            reports_folder = app.config.get('REPORTS_FOLDER', 'reports')
            version = EngagementService.get_next_summary_version(db_service, engagement_id)
            
            if not report_name:
                report_name = f"{engagement['customer_name']} - {engagement['project_name']}"

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            file_extension = 'docx' if summary_format == 'docx' else 'pdf'
            filename = f"{engagement_id}_executive_v{version}_{timestamp}.{file_extension}"
            output_path = os.path.join(reports_folder, filename)

            # Initialize report service
            logo_path = os.path.join(os.path.dirname(__file__), 'Thales.png')
            if not os.path.exists(logo_path):
                logo_path = None

            # Route to appropriate service based on format
            if summary_format == 'docx':
                # Phase 2: Generate DOCX for engagement (merged data)
                logger.info(f"Generating DOCX engagement summary v{version}")
                from caip_reporting_functions.engagement_docx_builder import adapt_engagement_for_docx
                from caip_reporting_functions.executive_report_docx_service import ExecutiveReportDocxService

                # Adapt merged engagement data to DOCX service format
                adapted_data = adapt_engagement_for_docx(merged_report_data, {
                    'engagement_id': engagement_id,
                    'customer_name': engagement.get('customer_name', 'Organization'),
                    'project_name': engagement.get('project_name', 'Project'),
                    'document_assessments': document_assessments,  # Include document assessments
                })

                # Generate DOCX
                docx_service = ExecutiveReportDocxService(logo_path=logo_path)
                output_path = docx_service.generate_executive_report(
                    scan_data=adapted_data,
                    engagement_name=report_name,
                    organization_name=engagement.get('customer_name', report_name),
                    output_dir=reports_folder
                )
                logger.info(f"DOCX engagement summary generated: {output_path}")
            else:
                # Generate PDF (existing functionality)
                logger.info(f"Generating PDF engagement summary v{version}")
                exec_service = ExecutiveReportService(logo_path=logo_path)

                # Generate with multiple document assessments
                exec_service.generate_engagement_executive_report(
                    engagement=engagement,
                    merged_crypto_data=merged_report_data,
                    document_assessments=document_assessments,
                    report_name=report_name,
                    output_path=output_path
                )
            
            # Save record
            included_reports = [
                {'type': r['link']['report_type'], 'id': r['link']['report_reference_id'], 
                 'name': r['link']['report_name']}
                for r in crypto_reports + document_reports
            ]
            
            summary_id = EngagementService.save_executive_summary(
                db_service,
                engagement_id,
                output_path,
                included_reports,
                report_name=report_name,
                generated_by=session.get('username')
            )
            
            return jsonify({
                'id': summary_id,
                'version': version,
                'filename': filename,
                'path': output_path,
                'format': summary_format,
                'reports_included': len(included_reports),
                'message': f'Executive summary ({summary_format.upper()}) generated successfully'
            }), 201
            
        except Exception as e:
            logger.error(f"Error generating engagement executive summary: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/engagements/<engagement_id>/executive-summaries', methods=['GET'])
    @login_required
    @permission_required('engagements:read')
    def get_engagement_summaries(engagement_id):
        """Get all executive summaries for an engagement."""
        try:
            summaries = EngagementService.get_engagement_summaries(db_service, engagement_id)
            return jsonify({'summaries': summaries}), 200
            
        except Exception as e:
            logger.error(f"Error getting engagement summaries: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/engagements/<engagement_id>/executive-summaries/<int:summary_id>/download', methods=['GET'])
    @login_required
    @permission_required('reports:read')
    def download_engagement_summary(engagement_id, summary_id):
        """Download an executive summary PDF or DOCX."""
        try:
            summaries = EngagementService.get_engagement_summaries(db_service, engagement_id)
            summary = next((s for s in summaries if s['id'] == summary_id), None)

            if not summary:
                return jsonify({'error': 'Summary not found'}), 404

            if not summary.get('report_path') or not os.path.exists(summary['report_path']):
                return jsonify({'error': 'Summary file not found'}), 404

            # Detect format from file extension
            file_path = summary['report_path']
            file_ext = os.path.splitext(file_path)[1].lower()

            if file_ext == '.docx':
                mimetype = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            else:
                mimetype = 'application/pdf'

            return send_file(
                file_path,
                mimetype=mimetype,
                as_attachment=True,
                download_name=os.path.basename(file_path)
            )
            
        except Exception as e:
            logger.error(f"Error downloading engagement summary: {e}")
            return jsonify({'error': str(e)}), 500

    # =========================================================================
    # REPORT SELECTION ENDPOINTS (Selective Aggregation)
    # =========================================================================

    @app.route('/api/v1/engagements/<engagement_id>/reports/<int:report_id>/toggle-inclusion', methods=['PUT'])
    @login_required
    @permission_required('engagements:edit')
    def toggle_report_inclusion(engagement_id, report_id):
        """
        Toggle include_in_executive flag for a specific report in an engagement.

        This allows users to selectively include/exclude reports from executive
        summary generation without permanently removing them from the engagement.

        Request:
            PUT /api/v1/engagements/ENG-2025-001/reports/5/toggle-inclusion

        Response (200 OK):
            {
                "success": true,
                "report_id": 5,
                "include_in_executive": 1,
                "reports": [...]
            }

        Response (404):
            {"error": "Engagement not found"}
            or
            {"error": "Report not found in this engagement"}
        """
        try:
            # [1] Validate engagement exists
            engagement = EngagementService.get_engagement(db_service, engagement_id)
            if not engagement:
                return jsonify({'error': 'Engagement not found'}), 404

            # [2] Get the specific engagement_report record
            query = '''
                SELECT * FROM engagement_reports
                WHERE id = ? AND engagement_id = ?
            '''
            results = db_service.query(query, (report_id, engagement_id))

            if not results or len(results) == 0:
                return jsonify({'error': 'Report not found in this engagement'}), 404

            report_record = results[0]

            # [3] Toggle the flag (0 <-> 1)
            current_state = report_record.get('include_in_executive', 1)
            new_state = 1 - int(current_state)

            # [4] Update database
            update_query = '''
                UPDATE engagement_reports
                SET include_in_executive = ?
                WHERE id = ? AND engagement_id = ?
            '''
            db_service.execute(update_query, (new_state, report_id, engagement_id))

            # [5] Fetch updated report list to return to client
            updated_reports = EngagementService.get_engagement_reports(
                db_service,
                engagement_id
            )

            # [6] Format reports for response
            formatted_reports = []
            if updated_reports:
                for report in updated_reports:
                    formatted_reports.append({
                        'id': report.get('id'),
                        'report_name': report.get('report_name'),
                        'report_type': report.get('report_type'),
                        'include_in_executive': report.get('include_in_executive', 1),
                        'added_at': report.get('added_at')
                    })

            # [7] Return success response
            logger.info(f"Toggled report {report_id} inclusion to {new_state} in engagement {engagement_id}")
            return jsonify({
                'success': True,
                'report_id': report_id,
                'include_in_executive': new_state,
                'reports': formatted_reports
            }), 200

        except Exception as e:
            logger.error(f"Error toggling report inclusion: {str(e)}")
            return jsonify({'error': str(e)}), 500

    # =========================================================================
    # REPORT PACKAGE ENDPOINTS
    # =========================================================================
    
    @app.route('/api/v1/engagements/<engagement_id>/package', methods=['POST'])
    @login_required
    @permission_required('engagements:export')
    def generate_engagement_package(engagement_id):
        """
        Generate ZIP package with all engagement deliverables.
        
        Request body:
            include_individual_reports: Boolean (default true)
        """
        try:
            data = request.json or {}
            include_individual = data.get('include_individual_reports', True)
            
            reports_folder = app.config.get('REPORTS_FOLDER', 'reports')
            
            zip_path = EngagementService.generate_report_package(
                db_service,
                engagement_id,
                reports_folder,
                include_individual_reports=include_individual
            )
            
            return jsonify({
                'filename': os.path.basename(zip_path),
                'path': zip_path,
                'message': 'Report package generated successfully'
            }), 201
            
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            logger.error(f"Error generating engagement package: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/engagements/<engagement_id>/package/download', methods=['GET'])
    @login_required
    @permission_required('engagements:export')
    def download_engagement_package(engagement_id):
        """Download the latest engagement package ZIP."""
        try:
            import glob
            
            reports_folder = app.config.get('REPORTS_FOLDER', 'reports')
            pattern = os.path.join(reports_folder, f"{engagement_id}_*_package_*.zip")
            
            matching = glob.glob(pattern)
            if not matching:
                return jsonify({'error': 'No package found. Generate one first.'}), 404
            
            # Get most recent
            matching.sort(key=os.path.getmtime, reverse=True)
            zip_path = matching[0]
            
            return send_file(
                zip_path,
                mimetype='application/zip',
                as_attachment=True,
                download_name=os.path.basename(zip_path)
            )
            
        except Exception as e:
            logger.error(f"Error downloading engagement package: {e}")
            return jsonify({'error': str(e)}), 500
    
    # =========================================================================
    # AVAILABLE REPORTS ENDPOINT
    # =========================================================================
    
    @app.route('/api/v1/engagements/available-reports', methods=['GET'])
    @login_required
    @permission_required('engagements:read')
    def get_available_reports_for_engagement():
        """Get all available reports that can be linked to engagements.

        Query params:
            engagement_id: Optional. If provided, filters documents to only those linked to this engagement.
        """
        try:
            engagement_id = request.args.get('engagement_id')
            available = EngagementService.get_available_reports(db_service, engagement_id=engagement_id)
            return jsonify(available), 200

        except Exception as e:
            logger.error(f"Error getting available reports: {e}")
            return jsonify({'error': str(e)}), 500
    
    # =========================================================================
    # HELPER FUNCTIONS
    # =========================================================================
    
    def _merge_crypto_reports(crypto_reports: list) -> dict:
        """
        Merge multiple crypto asset reports into a single report structure.
        
        Combines findings, certificates, and metadata from multiple reports.
        """
        if not crypto_reports:
            return {}
        
        if len(crypto_reports) == 1:
            # Single report - use as-is
            return crypto_reports[0]['data'].get('report_data', crypto_reports[0]['data'])
        
        # Multiple reports - merge
        merged = {
            'findings': [],
            'certificates': [],
            'metadata': {
                'scan_name': 'Merged Engagement Report',
                'scan_type': 'engagement',
                'source_reports': []
            },
            'collector_summaries': {},
            'policy': None
        }
        
        seen_findings = set()  # For deduplication
        
        for report in crypto_reports:
            data = report['data'].get('report_data', report['data'])
            
            # Track source
            merged['metadata']['source_reports'].append(report['link']['report_name'])
            
            # Merge findings (deduplicate by finding ID + affected entity)
            for finding in data.get('findings', []):
                finding_key = f"{finding.get('id', '')}:{finding.get('title', '')}:{','.join(finding.get('affected_entities', []))}"
                if finding_key not in seen_findings:
                    seen_findings.add(finding_key)
                    merged['findings'].append(finding)
            
            # Merge certificates
            merged['certificates'].extend(data.get('certificates', []))
            
            # Use first policy encountered
            if not merged['policy'] and data.get('policy'):
                merged['policy'] = data['policy']
        
        return merged
    
    logger.info("Engagement routes registered")