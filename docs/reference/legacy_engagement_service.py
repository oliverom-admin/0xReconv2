"""
Engagement Service for CAIP

Manages customer engagements and report grouping for executive summary generation.
Provides:
- Engagement CRUD operations
- Report linking to engagements
- Multi-report executive summary aggregation
- Report package generation (ZIP with all deliverables)
"""

import os
import json
import logging
import zipfile
import sqlite3
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict

logger = logging.getLogger('caip.operational')


@dataclass
class EngagementReport:
    """Data model for a report linked to an engagement"""
    report_type: str  # 'scan', 'reassessment', 'aggregation', 'document_assessment'
    report_reference_id: int
    report_name: str
    report_path: Optional[str] = None
    include_in_executive: bool = True
    display_order: int = 0


class EngagementService:
    """
    Service for managing customer engagements and report aggregation.
    
    Follows existing CAIP service patterns for consistency.
    """
    
    # Valid report types that can be linked to engagements
    VALID_REPORT_TYPES = ['scan', 'reassessment', 'aggregation', 'document_assessment']
    
    # Engagement status options
    VALID_STATUSES = ['Active', 'Completed', 'Archived']
    
    @classmethod
    def generate_engagement_id(cls, db_service) -> str:
        """
        Generate a unique engagement ID in format ENG-YYYY-NNN.
        
        Args:
            db_service: DatabaseService class reference
            
        Returns:
            Unique engagement ID string
        """
        year = datetime.now().year
        
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            # Find the highest number for this year
            c.execute('''SELECT engagement_id FROM engagements 
                         WHERE engagement_id LIKE ? 
                         ORDER BY engagement_id DESC LIMIT 1''',
                     (f'ENG-{year}-%',))
            row = c.fetchone()
            
            if row:
                # Extract the number and increment
                last_id = row[0]
                try:
                    last_num = int(last_id.split('-')[2])
                    next_num = last_num + 1
                except (IndexError, ValueError):
                    next_num = 1
            else:
                next_num = 1
            
            return f'ENG-{year}-{next_num:03d}'
    
    # =========================================================================
    # ENGAGEMENT CRUD OPERATIONS
    # =========================================================================
    
    @classmethod
    def create_engagement(cls,
                          db_service,
                          customer_name: str,
                          project_name: str,
                          description: str = None,
                          start_date: str = None,
                          lead_consultant: str = None) -> Dict[str, Any]:
        """
        Create a new customer engagement.
        
        Args:
            db_service: DatabaseService class reference
            customer_name: Customer/client name
            project_name: Project or engagement name
            description: Optional description
            start_date: Optional start date (ISO format)
            lead_consultant: Optional lead consultant name
            
        Returns:
            Created engagement dict with engagement_id
        """
        engagement_id = cls.generate_engagement_id(db_service)
        
        if not start_date:
            start_date = datetime.now().strftime('%Y-%m-%d')
        
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO engagements 
                         (engagement_id, customer_name, project_name, description,
                          status, start_date, lead_consultant)
                         VALUES (?, ?, ?, ?, 'Active', ?, ?)''',
                     (engagement_id, customer_name, project_name, description,
                      start_date, lead_consultant))
            conn.commit()
            db_id = c.lastrowid
        
        logger.info(f"Created engagement {engagement_id} for customer {customer_name}")
        
        return {
            'id': db_id,
            'engagement_id': engagement_id,
            'customer_name': customer_name,
            'project_name': project_name,
            'description': description,
            'status': 'Active',
            'start_date': start_date,
            'lead_consultant': lead_consultant
        }
    
    @classmethod
    def get_engagement(cls, db_service, engagement_id: str) -> Optional[Dict[str, Any]]:
        """
        Get engagement by engagement_id.
        
        Args:
            db_service: DatabaseService class reference
            engagement_id: The engagement ID (e.g., 'ENG-2024-001')
            
        Returns:
            Engagement dict or None
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM engagements WHERE engagement_id = ?', (engagement_id,))
            row = c.fetchone()
            return db_service.dict_from_row(row)
    
    @classmethod
    def get_engagement_by_db_id(cls, db_service, db_id: int) -> Optional[Dict[str, Any]]:
        """
        Get engagement by database ID.
        
        Args:
            db_service: DatabaseService class reference
            db_id: Database primary key
            
        Returns:
            Engagement dict or None
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM engagements WHERE id = ?', (db_id,))
            row = c.fetchone()
            return db_service.dict_from_row(row)
    
    @classmethod
    def list_engagements(cls,
                         db_service,
                         status: str = None,
                         customer_name: str = None) -> List[Dict[str, Any]]:
        """
        List engagements with optional filtering.
        
        Args:
            db_service: DatabaseService class reference
            status: Optional status filter
            customer_name: Optional customer name filter
            
        Returns:
            List of engagement dicts with report counts
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            
            query = '''SELECT e.*, 
                              (SELECT COUNT(*) FROM engagement_reports er 
                               WHERE er.engagement_id = e.engagement_id) as report_count,
                              (SELECT COUNT(*) FROM engagement_executive_summaries es 
                               WHERE es.engagement_id = e.engagement_id) as summary_count
                       FROM engagements e
                       WHERE 1=1'''
            params = []
            
            if status:
                query += ' AND e.status = ?'
                params.append(status)
            
            if customer_name:
                query += ' AND e.customer_name LIKE ?'
                params.append(f'%{customer_name}%')
            
            query += ' ORDER BY e.created_at DESC'
            
            c.execute(query, params)
            return [db_service.dict_from_row(row) for row in c.fetchall()]
    
    @classmethod
    def update_engagement(cls,
                          db_service,
                          engagement_id: str,
                          **kwargs) -> bool:
        """
        Update engagement fields.
        
        Args:
            db_service: DatabaseService class reference
            engagement_id: The engagement ID
            **kwargs: Fields to update (customer_name, project_name, description,
                      status, start_date, end_date, lead_consultant)
                      
        Returns:
            True if updated, False if not found
        """
        allowed_fields = ['customer_name', 'project_name', 'description', 
                          'status', 'start_date', 'end_date', 'lead_consultant']
        
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields and v is not None}
        
        if not updates:
            return False
        
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            
            # Build update query
            set_clause = ', '.join([f'{k} = ?' for k in updates.keys()])
            set_clause += ', updated_at = CURRENT_TIMESTAMP'
            
            c.execute(f'UPDATE engagements SET {set_clause} WHERE engagement_id = ?',
                     list(updates.values()) + [engagement_id])
            conn.commit()
            
            return c.rowcount > 0
    
    @classmethod
    def delete_engagement(cls, db_service, engagement_id: str) -> bool:
        """
        Delete engagement and all linked reports, plus associated certificates and vault keys.

        Args:
            db_service: DatabaseService class reference
            engagement_id: The engagement ID

        Returns:
            True if deleted, False if not found
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()

            # Check exists and get numeric ID
            c.execute('SELECT id FROM engagements WHERE engagement_id = ?', (engagement_id,))
            row = c.fetchone()
            if not row:
                return False
            numeric_id = row[0]

            # Collect private_key_refs from certificate tables before deletion
            key_refs = []
            c.execute('SELECT private_key_ref FROM engagement_ca_certificates WHERE engagement_id = ?',
                     (engagement_id,))
            for row in c.fetchall():
                if row[0]:
                    key_refs.append(row[0])
            c.execute('SELECT private_key_ref FROM report_signing_certificates WHERE engagement_id = ?',
                     (engagement_id,))
            for row in c.fetchall():
                if row[0]:
                    key_refs.append(row[0])

            # Delete certificate records
            # Note: Some tables use numeric ID (engagement_id refs engagements(id))
            try:
                c.execute('DELETE FROM engagement_ca_certificates WHERE engagement_id = ?',
                         (engagement_id,))
                logger.debug(f"Deleted engagement_ca_certificates for {engagement_id}")
            except Exception as e:
                logger.error(f"FK error deleting engagement_ca_certificates: {e}", exc_info=True)
                raise

            try:
                c.execute('DELETE FROM report_signing_certificates WHERE engagement_id = ?',
                         (engagement_id,))
                logger.debug(f"Deleted report_signing_certificates for {engagement_id}")
            except Exception as e:
                logger.error(f"FK error deleting report_signing_certificates: {e}", exc_info=True)
                raise

            try:
                c.execute('DELETE FROM engagement_dashboard_certificates WHERE engagement_id = ?',
                         (numeric_id,))
                logger.debug(f"Deleted engagement_dashboard_certificates for {engagement_id}")
            except Exception as e:
                logger.error(f"FK error deleting engagement_dashboard_certificates: {e}", exc_info=True)
                raise

            try:
                c.execute('DELETE FROM collector_certificates WHERE engagement_id = ?',
                         (numeric_id,))
                logger.debug(f"Deleted collector_certificates for {engagement_id}")
            except Exception as e:
                logger.error(f"FK error deleting collector_certificates: {e}", exc_info=True)
                raise

            # Delete engagement-associated items (scans, configs, reassessments, aggregations, docs)
            # Delete scan_logs FIRST (FK constraint from scan_logs -> scans)
            try:
                c.execute('''DELETE FROM scan_logs WHERE scan_id IN
                             (SELECT id FROM scans WHERE engagement_id = ?)''',
                         (engagement_id,))
                logger.debug(f"Deleted scan_logs for {engagement_id}")
            except Exception as e:
                logger.error(f"FK error deleting scan_logs: {e}", exc_info=True)
                raise

            try:
                c.execute('DELETE FROM scans WHERE engagement_id = ?',
                         (engagement_id,))
                logger.debug(f"Deleted scans for {engagement_id}")
            except Exception as e:
                logger.error(f"FK error deleting scans: {e}", exc_info=True)
                raise

            try:
                c.execute('DELETE FROM configurations WHERE engagement_id = ?',
                         (engagement_id,))
                logger.debug(f"Deleted configurations for {engagement_id}")
            except Exception as e:
                logger.error(f"FK error deleting configurations: {e}", exc_info=True)
                raise

            try:
                c.execute('DELETE FROM reassessments WHERE engagement_id = ?',
                         (engagement_id,))
                logger.debug(f"Deleted reassessments for {engagement_id}")
            except Exception as e:
                logger.error(f"FK error deleting reassessments: {e}", exc_info=True)
                raise

            try:
                c.execute('DELETE FROM report_aggregations WHERE engagement_id = ?',
                         (engagement_id,))
                logger.debug(f"Deleted report_aggregations for {engagement_id}")
            except Exception as e:
                logger.error(f"FK error deleting report_aggregations: {e}", exc_info=True)
                raise

            try:
                c.execute('DELETE FROM document_assessments WHERE engagement_id = ?',
                         (engagement_id,))
                logger.debug(f"Deleted document_assessments for {engagement_id}")
            except Exception as e:
                logger.error(f"FK error deleting document_assessments: {e}", exc_info=True)
                raise

            # Delete related records
            try:
                c.execute('DELETE FROM engagement_executive_summaries WHERE engagement_id = ?',
                         (engagement_id,))
                logger.debug(f"Deleted engagement_executive_summaries for {engagement_id}")
            except Exception as e:
                logger.error(f"FK error deleting engagement_executive_summaries: {e}", exc_info=True)
                raise

            try:
                c.execute('DELETE FROM engagement_reports WHERE engagement_id = ?',
                         (engagement_id,))
                logger.debug(f"Deleted engagement_reports for {engagement_id}")
            except Exception as e:
                logger.error(f"FK error deleting engagement_reports: {e}", exc_info=True)
                raise

            # Delete certificate-related audit and request records (use numeric_id)
            try:
                c.execute('DELETE FROM certificate_audit_log WHERE engagement_id = ?',
                         (numeric_id,))
                logger.debug(f"Deleted certificate_audit_log for {engagement_id}")
            except Exception as e:
                logger.error(f"FK error deleting certificate_audit_log: {e}", exc_info=True)
                raise

            try:
                c.execute('DELETE FROM certificate_registration_requests WHERE engagement_id = ?',
                         (numeric_id,))
                logger.debug(f"Deleted certificate_registration_requests for {engagement_id}")
            except Exception as e:
                logger.error(f"FK error deleting certificate_registration_requests: {e}", exc_info=True)
                raise

            try:
                c.execute('DELETE FROM certificate_revocation_list WHERE engagement_id = ?',
                         (numeric_id,))
                logger.debug(f"Deleted certificate_revocation_list for {engagement_id}")
            except Exception as e:
                logger.error(f"FK error deleting certificate_revocation_list: {e}", exc_info=True)
                raise

            try:
                c.execute('DELETE FROM engagement_cas WHERE engagement_id = ?',
                         (numeric_id,))
                logger.debug(f"Deleted engagement_cas for {engagement_id}")
            except sqlite3.OperationalError as e:
                if 'no such table' in str(e):
                    logger.debug(f"engagement_cas table does not exist (OK)")
                else:
                    logger.error(f"FK error deleting engagement_cas: {e}", exc_info=True)
                    raise
            except Exception as e:
                logger.error(f"FK error deleting engagement_cas: {e}", exc_info=True)
                raise

            # Delete user_digital_identities (FK constraint to engagements)
            try:
                c.execute('DELETE FROM user_digital_identities WHERE engagement_id = ?',
                         (engagement_id,))
                logger.debug(f"Deleted user_digital_identities for {engagement_id}")
            except Exception as e:
                logger.error(f"FK error deleting user_digital_identities: {e}", exc_info=True)
                raise

            try:
                c.execute('DELETE FROM engagements WHERE engagement_id = ?',
                         (engagement_id,))
                logger.debug(f"Deleted engagements for {engagement_id}")
            except Exception as e:
                logger.error(f"FK error deleting engagements: {e}", exc_info=True)
                raise
            try:
                conn.commit()
            except Exception as e:
                logger.error(f"FK constraint error during engagement deletion: {e}", exc_info=True)
                raise

            # Delete private keys from vault (after DB commit, best-effort)
            if key_refs:
                try:
                    from caip_service_layer.unified_vault_service import get_unified_vault_service
                    vault = get_unified_vault_service()
                    if vault:
                        for key_ref in key_refs:
                            try:
                                vault.delete_key(key_ref)
                                logger.info(f"Deleted vault key: {key_ref}")
                            except Exception as e:
                                logger.warning(f"Could not delete vault key {key_ref}: {e}")
                except Exception as e:
                    logger.warning(f"Vault cleanup failed for engagement {engagement_id}: {e}")

            logger.info(f"Deleted engagement {engagement_id}")
            return True
    
    # =========================================================================
    # REPORT LINKING OPERATIONS
    # =========================================================================
    
    @classmethod
    def add_report_to_engagement(cls,
                                  db_service,
                                  engagement_id: str,
                                  report_type: str,
                                  report_reference_id: int,
                                  report_name: str,
                                  report_path: str = None,
                                  include_in_executive: bool = True) -> int:
        """
        Link a report to an engagement.
        
        Args:
            db_service: DatabaseService class reference
            engagement_id: The engagement ID
            report_type: Type of report ('scan', 'reassessment', 'aggregation', 'document_assessment')
            report_reference_id: ID in the source table
            report_name: Display name for the report
            report_path: Path to report file (optional)
            include_in_executive: Include in executive summary generation
            
        Returns:
            Database ID of the link record
            
        Raises:
            ValueError: If report_type is invalid or engagement doesn't exist
        """
        if report_type not in cls.VALID_REPORT_TYPES:
            raise ValueError(f"Invalid report_type: {report_type}. Must be one of {cls.VALID_REPORT_TYPES}")
        
        # Verify engagement exists
        engagement = cls.get_engagement(db_service, engagement_id)
        if not engagement:
            raise ValueError(f"Engagement {engagement_id} not found")
        
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            
            # Get next display order
            c.execute('''SELECT COALESCE(MAX(display_order), 0) + 1 
                         FROM engagement_reports WHERE engagement_id = ?''',
                     (engagement_id,))
            next_order = c.fetchone()[0]
            
            # Check for duplicate
            c.execute('''SELECT id FROM engagement_reports 
                         WHERE engagement_id = ? AND report_type = ? AND report_reference_id = ?''',
                     (engagement_id, report_type, report_reference_id))
            if c.fetchone():
                raise ValueError(f"Report already linked to engagement {engagement_id}")
            
            c.execute('''INSERT INTO engagement_reports 
                         (engagement_id, report_type, report_reference_id, report_name,
                          report_path, include_in_executive, display_order)
                         VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (engagement_id, report_type, report_reference_id, report_name,
                      report_path, 1 if include_in_executive else 0, next_order))
            conn.commit()
            
            logger.info(f"Added {report_type} report '{report_name}' to engagement {engagement_id}")
            return c.lastrowid
    
    @classmethod
    def remove_report_from_engagement(cls,
                                       db_service,
                                       engagement_id: str,
                                       report_type: str,
                                       report_reference_id: int) -> bool:
        """
        Remove a report link from an engagement.
        
        Args:
            db_service: DatabaseService class reference
            engagement_id: The engagement ID
            report_type: Type of report
            report_reference_id: ID in the source table
            
        Returns:
            True if removed, False if not found
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''DELETE FROM engagement_reports 
                         WHERE engagement_id = ? AND report_type = ? AND report_reference_id = ?''',
                     (engagement_id, report_type, report_reference_id))
            conn.commit()
            return c.rowcount > 0
    
    @classmethod
    def get_engagement_reports(cls,
                                db_service,
                                engagement_id: str,
                                include_in_executive_only: bool = False) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get all reports associated with and linked to an engagement with full details.

        Returns a grouped structure with full report metadata (status, last_run, run history, coverage_score, etc.)
        Includes both explicitly linked reports and all items directly associated with the engagement.

        Args:
            db_service: DatabaseService class reference
            engagement_id: The engagement ID
            include_in_executive_only: Only return reports marked for executive summary

        Returns:
            Dict with keys for each report type containing lists of detailed reports:
            {
                'scans': [...scan objects with runs...],
                'reassessments': [...reassessment objects...],
                'aggregations': [...aggregation objects...],
                'document_assessments': [...document assessment objects...]
            }
        """
        result = {
            'scans': [],
            'reassessments': [],
            'aggregations': [],
            'document_assessments': []
        }

        with db_service.get_connection_context() as conn:
            c = conn.cursor()

            # Get all associated scans with full details
            # LEFT JOIN with engagement_reports to get inclusion status for explicitly linked scans
            c.execute('''SELECT
                            COALESCE(er.id, s.id) as id, s.id as report_reference_id,
                            COALESCE(er.include_in_executive, 0) as include_in_executive,
                            COALESCE(er.display_order, s.id) as display_order,
                            er.added_at,
                            s.id as scan_id, s.name, s.status, s.last_run, s.report_path
                          FROM scans s
                          LEFT JOIN engagement_reports er ON er.report_reference_id = s.id
                              AND er.engagement_id = ? AND er.report_type = 'scan'
                          WHERE s.engagement_id = ?
                          ORDER BY COALESCE(er.display_order, s.id), er.added_at''',
                        (engagement_id, engagement_id))

            scans = []
            for row in c.fetchall():
                scan = db_service.dict_from_row(row)
                scan_id = scan['scan_id']

                # Get run history for this scan
                c.execute('''SELECT DISTINCT run_number, timestamp
                            FROM scan_logs
                            WHERE scan_id = ?
                            ORDER BY run_number DESC LIMIT 10''', (scan_id,))
                runs = [{'run_number': r[0], 'timestamp': r[1]} for r in c.fetchall()]
                scan['runs'] = runs if runs else [{'run_number': 1, 'timestamp': scan.get('last_run')}]
                scans.append(scan)

            result['scans'] = scans

            # Get all associated reassessments with full details
            c.execute('''SELECT
                            COALESCE(er.id, r.id) as id, r.id as report_reference_id,
                            COALESCE(er.include_in_executive, 0) as include_in_executive,
                            COALESCE(er.display_order, r.id) as display_order,
                            er.added_at,
                            r.id as reassessment_id, r.name, r.status, r.created_at, r.reassessed_report_path as report_path
                          FROM reassessments r
                          LEFT JOIN engagement_reports er ON er.report_reference_id = r.id
                              AND er.engagement_id = ? AND er.report_type = 'reassessment'
                          WHERE r.engagement_id = ?
                          ORDER BY COALESCE(er.display_order, r.id), er.added_at''',
                        (engagement_id, engagement_id))

            result['reassessments'] = [db_service.dict_from_row(row) for row in c.fetchall()]

            # Get all associated aggregations with full details
            c.execute('''SELECT
                            COALESCE(er.id, a.id) as id, a.id as report_reference_id,
                            COALESCE(er.include_in_executive, 0) as include_in_executive,
                            COALESCE(er.display_order, a.id) as display_order,
                            er.added_at,
                            a.id as aggregation_id, a.name, a.status, a.created_at, a.aggregated_report_path as report_path
                          FROM report_aggregations a
                          LEFT JOIN engagement_reports er ON er.report_reference_id = a.id
                              AND er.engagement_id = ? AND er.report_type = 'aggregation'
                          WHERE a.engagement_id = ?
                          ORDER BY COALESCE(er.display_order, a.id), er.added_at''',
                        (engagement_id, engagement_id))

            result['aggregations'] = [db_service.dict_from_row(row) for row in c.fetchall()]

            # Get all associated document assessments with full details
            c.execute('''SELECT
                            COALESCE(er.id, d.id) as id, d.id as report_reference_id,
                            COALESCE(er.include_in_executive, 0) as include_in_executive,
                            COALESCE(er.display_order, d.id) as display_order,
                            er.added_at,
                            d.id as doc_assessment_id, d.assessment_id, d.filename, d.document_type,
                            d.coverage_score, d.status, d.created_at
                          FROM document_assessments d
                          LEFT JOIN engagement_reports er ON er.report_reference_id = d.id
                              AND er.engagement_id = ? AND er.report_type = 'document_assessment'
                          WHERE d.engagement_id = ?
                          ORDER BY COALESCE(er.display_order, d.id), er.added_at''',
                        (engagement_id, engagement_id))

            result['document_assessments'] = [db_service.dict_from_row(row) for row in c.fetchall()]

        return result
    
    @classmethod
    def update_report_inclusion(cls,
                                 db_service,
                                 engagement_id: str,
                                 report_type: str,
                                 report_reference_id: int,
                                 include_in_executive: bool) -> bool:
        """
        Update whether a report is included in executive summary.
        
        Args:
            db_service: DatabaseService class reference
            engagement_id: The engagement ID
            report_type: Type of report
            report_reference_id: ID in the source table
            include_in_executive: New inclusion setting
            
        Returns:
            True if updated, False if not found
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''UPDATE engagement_reports 
                         SET include_in_executive = ?
                         WHERE engagement_id = ? AND report_type = ? AND report_reference_id = ?''',
                     (1 if include_in_executive else 0, engagement_id, report_type, report_reference_id))
            conn.commit()
            return c.rowcount > 0
    
    @classmethod
    def reorder_engagement_reports(cls,
                                    db_service,
                                    engagement_id: str,
                                    report_order: List[Dict[str, Any]]) -> bool:
        """
        Reorder reports within an engagement.
        
        Args:
            db_service: DatabaseService class reference
            engagement_id: The engagement ID
            report_order: List of dicts with 'report_type', 'report_reference_id', 'display_order'
            
        Returns:
            True if reordered successfully
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            
            for item in report_order:
                c.execute('''UPDATE engagement_reports 
                             SET display_order = ?
                             WHERE engagement_id = ? AND report_type = ? AND report_reference_id = ?''',
                         (item['display_order'], engagement_id, 
                          item['report_type'], item['report_reference_id']))
            
            conn.commit()
            return True
    
    # =========================================================================
    # EXECUTIVE SUMMARY OPERATIONS
    # =========================================================================
    
    @classmethod
    def get_next_summary_version(cls, db_service, engagement_id: str) -> int:
        """
        Get the next version number for an engagement executive summary.
        
        Args:
            db_service: DatabaseService class reference
            engagement_id: The engagement ID
            
        Returns:
            Next version number (1 if first summary)
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''SELECT COALESCE(MAX(version), 0) + 1 
                         FROM engagement_executive_summaries 
                         WHERE engagement_id = ?''',
                     (engagement_id,))
            return c.fetchone()[0]
    
    @classmethod
    def save_executive_summary(cls,
                                db_service,
                                engagement_id: str,
                                report_path: str,
                                included_reports: List[Dict[str, Any]],
                                report_name: str = None,
                                generated_by: str = None) -> int:
        """
        Save an executive summary record.
        
        Args:
            db_service: DatabaseService class reference
            engagement_id: The engagement ID
            report_path: Path to the generated PDF
            included_reports: List of reports included in the summary
            report_name: Optional custom report name
            generated_by: Username who generated it
            
        Returns:
            Database ID of the summary record
        """
        version = cls.get_next_summary_version(db_service, engagement_id)
        
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO engagement_executive_summaries 
                         (engagement_id, version, report_name, report_path,
                          included_reports_json, generated_by)
                         VALUES (?, ?, ?, ?, ?, ?)''',
                     (engagement_id, version, report_name, report_path,
                      json.dumps(included_reports), generated_by))
            conn.commit()
            
            logger.info(f"Saved executive summary v{version} for engagement {engagement_id}")
            return c.lastrowid
    
    @classmethod
    def get_engagement_summaries(cls,
                                  db_service,
                                  engagement_id: str) -> List[Dict[str, Any]]:
        """
        Get all executive summaries for an engagement.
        
        Args:
            db_service: DatabaseService class reference
            engagement_id: The engagement ID
            
        Returns:
            List of summary dicts ordered by version descending
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('''SELECT * FROM engagement_executive_summaries 
                         WHERE engagement_id = ?
                         ORDER BY version DESC''',
                     (engagement_id,))
            
            summaries = []
            for row in c.fetchall():
                summary = db_service.dict_from_row(row)
                summary['included_reports'] = json.loads(summary['included_reports_json'])
                summaries.append(summary)
            
            return summaries
    
    # =========================================================================
    # REPORT DATA RETRIEVAL (for executive summary generation)
    # =========================================================================
    
    @classmethod
    def get_report_data(cls,
                        db_service,
                        report_type: str,
                        report_reference_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve the full report data for a linked report.
        
        Args:
            db_service: DatabaseService class reference
            report_type: Type of report
            report_reference_id: ID in the source table
            
        Returns:
            Report data dict or None
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            
            if report_type == 'scan':
                c.execute('SELECT * FROM scans WHERE id = ?', (report_reference_id,))
                row = c.fetchone()
                if row:
                    scan = db_service.dict_from_row(row)
                    # Load report JSON if exists
                    if scan.get('report_path') and os.path.exists(scan['report_path']):
                        try:
                            with open(scan['report_path'], 'r') as f:
                                scan['report_data'] = json.load(f)
                        except Exception as e:
                            logger.warning(f"Could not load scan report: {e}")
                    return scan
                    
            elif report_type == 'reassessment':
                c.execute('SELECT * FROM reassessments WHERE id = ?', (report_reference_id,))
                row = c.fetchone()
                if row:
                    reassessment = db_service.dict_from_row(row)
                    if reassessment.get('report_data'):
                        try:
                            reassessment['report_data'] = json.loads(reassessment['report_data'])
                        except:
                            pass
                    return reassessment
                    
            elif report_type == 'aggregation':
                c.execute('SELECT * FROM report_aggregations WHERE id = ?', (report_reference_id,))
                row = c.fetchone()
                if row:
                    aggregation = db_service.dict_from_row(row)
                    if aggregation.get('report_data'):
                        try:
                            aggregation['report_data'] = json.loads(aggregation['report_data'])
                        except:
                            pass
                    return aggregation
                    
            elif report_type == 'document_assessment':
                c.execute('SELECT * FROM document_assessments WHERE id = ?', (report_reference_id,))
                row = c.fetchone()
                if row:
                    assessment = db_service.dict_from_row(row)
                    # Parse JSON fields
                    if assessment.get('compliance_scores_json'):
                        try:
                            assessment['compliance_scores'] = json.loads(assessment['compliance_scores_json'])
                        except:
                            assessment['compliance_scores'] = {}
                    if assessment.get('summary_json'):
                        try:
                            assessment['summary'] = json.loads(assessment['summary_json'])
                        except:
                            assessment['summary'] = {}
                    
                    # Get findings
                    c.execute('''SELECT * FROM document_assessment_findings 
                                 WHERE assessment_id = ?''',
                             (assessment['assessment_id'],))
                    assessment['findings'] = [db_service.dict_from_row(r) for r in c.fetchall()]
                    
                    return assessment
            
            return None
    
    # =========================================================================
    # REPORT PACKAGE GENERATION
    # =========================================================================
    
    @classmethod
    def generate_report_package(cls,
                                 db_service,
                                 engagement_id: str,
                                 reports_folder: str,
                                 include_individual_reports: bool = True) -> str:
        """
        Generate a ZIP package containing all engagement deliverables.
        
        Args:
            db_service: DatabaseService class reference
            engagement_id: The engagement ID
            reports_folder: Base reports folder path
            include_individual_reports: Include individual report PDFs
            
        Returns:
            Path to generated ZIP file
        """
        engagement = cls.get_engagement(db_service, engagement_id)
        if not engagement:
            raise ValueError(f"Engagement {engagement_id} not found")
        
        # Create ZIP filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_name = engagement['project_name'].replace(' ', '_').replace('/', '_')
        zip_filename = f"{engagement_id}_{safe_name}_package_{timestamp}.zip"
        zip_path = os.path.join(reports_folder, zip_filename)
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Add executive summaries
            summaries = cls.get_engagement_summaries(db_service, engagement_id)
            for summary in summaries:
                if summary.get('report_path') and os.path.exists(summary['report_path']):
                    arcname = f"Executive_Summaries/{os.path.basename(summary['report_path'])}"
                    zf.write(summary['report_path'], arcname)
            
            # Add individual reports if requested
            if include_individual_reports:
                reports = cls.get_engagement_reports(db_service, engagement_id)
                for report in reports:
                    if report.get('report_path') and os.path.exists(report['report_path']):
                        # Organize by type
                        type_folder = report['report_type'].replace('_', ' ').title().replace(' ', '_')
                        arcname = f"{type_folder}/{os.path.basename(report['report_path'])}"
                        zf.write(report['report_path'], arcname)
            
            # Add engagement metadata
            metadata = {
                'engagement_id': engagement_id,
                'customer_name': engagement['customer_name'],
                'project_name': engagement['project_name'],
                'status': engagement['status'],
                'start_date': engagement['start_date'],
                'end_date': engagement.get('end_date'),
                'lead_consultant': engagement.get('lead_consultant'),
                'generated_at': datetime.now().isoformat(),
                'reports_included': len(cls.get_engagement_reports(db_service, engagement_id)),
                'executive_summaries': len(summaries)
            }
            zf.writestr('engagement_metadata.json', json.dumps(metadata, indent=2))
        
        logger.info(f"Generated report package: {zip_path}")
        return zip_path
    
    # =========================================================================
    # UTILITY METHODS
    # =========================================================================
    
    @classmethod
    def get_available_reports(cls, db_service, engagement_id: str = None) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get available reports for an engagement.

        Args:
            db_service: DatabaseService class reference
            engagement_id: Optional engagement ID to filter documents linked to this engagement

        Returns:
            Dict with keys for each report type containing lists of available reports
        """
        available = {
            'scans': [],
            'reassessments': [],
            'aggregations': [],
            'document_assessments': []
        }

        with db_service.get_connection_context() as conn:
            c = conn.cursor()

            # Scans with all runs (not just latest)
            c.execute('''SELECT id, name, status, last_run, report_path
                         FROM scans WHERE report_path IS NOT NULL
                         ORDER BY name, last_run DESC''')
            scans = [db_service.dict_from_row(r) for r in c.fetchall()]

            # For each scan, get its run history from scan_logs
            for scan in scans:
                c.execute('''SELECT DISTINCT run_number, timestamp
                            FROM scan_logs
                            WHERE scan_id = ?
                            ORDER BY run_number DESC LIMIT 10''', (scan['id'],))
                runs = [{'run_number': r[0], 'timestamp': r[1]} for r in c.fetchall()]
                scan['runs'] = runs if runs else [{'run_number': 1, 'timestamp': scan['last_run']}]

            available['scans'] = scans

            # Reassessments
            c.execute('''SELECT id, name, status, created_at, reassessed_report_path as report_path
                         FROM reassessments
                         ORDER BY created_at DESC''')
            available['reassessments'] = [db_service.dict_from_row(r) for r in c.fetchall()]

            # Aggregations
            c.execute('''SELECT id, name, status, created_at, aggregated_report_path as report_path
                         FROM report_aggregations
                         ORDER BY created_at DESC''')
            available['aggregations'] = [db_service.dict_from_row(r) for r in c.fetchall()]

            # Document assessments - filter by engagement if provided
            if engagement_id:
                c.execute('''SELECT id, assessment_id, filename, document_type,
                                    coverage_score, status, created_at
                             FROM document_assessments
                             WHERE engagement_id = ?
                             ORDER BY created_at DESC''', (engagement_id,))
            else:
                c.execute('''SELECT id, assessment_id, filename, document_type,
                                    coverage_score, status, created_at
                             FROM document_assessments
                             ORDER BY created_at DESC''')
            available['document_assessments'] = [db_service.dict_from_row(r) for r in c.fetchall()]

        return available