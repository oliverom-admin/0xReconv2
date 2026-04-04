"""
Database Extensions for Document Assessment

Provides database table creation and CRUD operations for document assessments.
This module extends the existing DatabaseService with document assessment capabilities.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger('caip.operational')


class DocumentAssessmentDatabase:
    """
    Database operations for document assessments.
    
    Extends the existing DatabaseService pattern for document-specific operations.
    """
    
    @classmethod
    def init_document_assessment_tables(cls, db_service):
        """
        Initialize document assessment tables.
        
        Call this from DatabaseService.init_db() to create required tables.
        
        Args:
            db_service: DatabaseService class reference
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            
            # Document assessments table
            c.execute('''CREATE TABLE IF NOT EXISTS document_assessments
                         (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          assessment_id TEXT UNIQUE NOT NULL,
                          filename TEXT NOT NULL,
                          file_type TEXT NOT NULL,
                          file_size INTEGER,
                          file_hash TEXT,
                          page_count INTEGER,
                          word_count INTEGER,
                          document_type TEXT NOT NULL,
                          document_type_confidence REAL,
                          version_detected TEXT,
                          date_detected TEXT,
                          organization_detected TEXT,
                          template_used TEXT,
                          coverage_score REAL,
                          compliance_scores_json TEXT,
                          summary_json TEXT,
                          status TEXT DEFAULT 'Completed',
                          assessed_by TEXT,
                          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
            
            # Document assessment findings table
            c.execute('''CREATE TABLE IF NOT EXISTS document_assessment_findings
                         (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          assessment_id TEXT NOT NULL,
                          finding_id TEXT NOT NULL,
                          element_id TEXT NOT NULL,
                          element_name TEXT NOT NULL,
                          status TEXT NOT NULL,
                          severity TEXT NOT NULL,
                          confidence REAL,
                          matched_section TEXT,
                          matched_content_snippet TEXT,
                          compliance_refs_json TEXT,
                          recommendation TEXT,
                          details_json TEXT,
                          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                          FOREIGN KEY(assessment_id) REFERENCES document_assessments(assessment_id))''')
            
            # Document sections table (for detailed section mapping)
            c.execute('''CREATE TABLE IF NOT EXISTS document_sections
                         (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          assessment_id TEXT NOT NULL,
                          heading TEXT NOT NULL,
                          level INTEGER,
                          mapped_element_id TEXT,
                          mapping_confidence REAL,
                          content_preview TEXT,
                          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                          FOREIGN KEY(assessment_id) REFERENCES document_assessments(assessment_id))''')
            
            # Custom document templates table (user-defined templates)
            c.execute('''CREATE TABLE IF NOT EXISTS document_templates
                         (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          name TEXT UNIQUE NOT NULL,
                          document_type TEXT NOT NULL,
                          version TEXT,
                          description TEXT,
                          frameworks_json TEXT,
                          template_json TEXT NOT NULL,
                          is_builtin INTEGER DEFAULT 0,
                          created_by TEXT,
                          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
            
            # Create indexes for performance
            c.execute('''CREATE INDEX IF NOT EXISTS idx_doc_assess_filename 
                         ON document_assessments(filename)''')
            c.execute('''CREATE INDEX IF NOT EXISTS idx_doc_assess_type 
                         ON document_assessments(document_type)''')
            c.execute('''CREATE INDEX IF NOT EXISTS idx_doc_findings_assessment 
                         ON document_assessment_findings(assessment_id)''')
            c.execute('''CREATE INDEX IF NOT EXISTS idx_doc_findings_status 
                         ON document_assessment_findings(status)''')
            c.execute('''CREATE INDEX IF NOT EXISTS idx_doc_sections_assessment 
                         ON document_sections(assessment_id)''')
            
            conn.commit()
            logger.info("Document assessment tables initialized")
            
            # Migrate existing tables to add new columns (safe for existing databases)
            cls._migrate_document_assessments_table(db_service)
    
    @classmethod
    def _migrate_document_assessments_table(cls, db_service):
        """
        Add missing columns to existing document_assessments table.
        Safe to run multiple times - checks if columns exist before adding.
        """
        new_columns = [
            ('page_count', 'INTEGER'),
            ('word_count', 'INTEGER'),
            ('version_detected', 'TEXT'),
            ('date_detected', 'TEXT'),
            ('organization_detected', 'TEXT'),
            ('engagement_id', 'TEXT REFERENCES engagements(engagement_id)')
        ]
        
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            
            # Get existing columns
            c.execute("PRAGMA table_info(document_assessments)")
            existing_columns = {row[1] for row in c.fetchall()}
            
            # Add missing columns
            for col_name, col_type in new_columns:
                if col_name not in existing_columns:
                    try:
                        c.execute(f'ALTER TABLE document_assessments ADD COLUMN {col_name} {col_type}')
                        logger.info(f"Added column {col_name} to document_assessments table")
                    except Exception as e:
                        logger.debug(f"Column {col_name} may already exist: {e}")
            
            conn.commit()
            
            # Create engagement index if engagement_id column exists
            if 'engagement_id' in existing_columns or ('engagement_id', 'TEXT REFERENCES engagements(engagement_id)') in new_columns:
                try:
                    c.execute('CREATE INDEX IF NOT EXISTS idx_doc_assess_engagement ON document_assessments(engagement_id)')
                    conn.commit()
                except Exception as e:
                    logger.debug(f"Engagement index may already exist: {e}")
    
    @classmethod
    def save_assessment(cls, db_service, assessment_result, engagement_id: str = None) -> int:
        """
        Save a document assessment result to the database.
        
        Args:
            db_service: DatabaseService class reference
            assessment_result: DocumentAssessmentResult object
            engagement_id: Optional engagement ID to associate with
            
        Returns:
            Database ID of the created assessment
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            
            # Insert main assessment record
            # Insert main assessment record
            c.execute('''INSERT INTO document_assessments 
                         (assessment_id, filename, file_type, file_size, file_hash,
                          page_count, word_count, document_type, document_type_confidence,
                          version_detected, date_detected, organization_detected,
                          template_used, coverage_score, compliance_scores_json, summary_json, status, engagement_id)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                     (assessment_result.assessment_id,
                      assessment_result.document_metadata.filename,
                      assessment_result.document_metadata.file_type,
                      assessment_result.document_metadata.file_size,
                      assessment_result.document_metadata.hash_sha256,
                      assessment_result.document_metadata.page_count,
                      assessment_result.document_metadata.word_count,
                      assessment_result.document_type.value,
                      assessment_result.document_metadata.document_type_confidence,
                      assessment_result.document_metadata.version_detected,
                      assessment_result.document_metadata.date_detected,
                      assessment_result.document_metadata.organization_detected,
                      assessment_result.template_used,
                      assessment_result.coverage_score,
                      json.dumps(assessment_result.compliance_scores),
                      json.dumps(assessment_result.summary),
                      'Completed',
                      engagement_id))
            
            assessment_db_id = c.lastrowid
            
            # Insert findings
            for finding in assessment_result.findings:
                c.execute('''INSERT INTO document_assessment_findings
                             (assessment_id, finding_id, element_id, element_name,
                              status, severity, confidence, matched_section,
                              matched_content_snippet, compliance_refs_json,
                              recommendation, details_json)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                         (assessment_result.assessment_id,
                          finding.finding_id,
                          finding.element_id,
                          finding.element_name,
                          finding.status,
                          finding.severity.value,
                          finding.confidence,
                          finding.matched_section,
                          finding.matched_content_snippet,
                          json.dumps(finding.compliance_refs),
                          finding.recommendation,
                          json.dumps(finding.details)))
            
            # Insert sections
            for section in assessment_result.sections_found:
                content_preview = section.content[:500] if section.content else None
                c.execute('''INSERT INTO document_sections
                             (assessment_id, heading, level, mapped_element_id,
                              mapping_confidence, content_preview)
                             VALUES (?, ?, ?, ?, ?, ?)''',
                         (assessment_result.assessment_id,
                          section.heading,
                          section.level,
                          section.mapped_element_id,
                          section.mapping_confidence,
                          content_preview))
            
            conn.commit()
            logger.info(f"Saved document assessment {assessment_result.assessment_id}")
            return assessment_db_id
    
    @classmethod
    def get_assessment(cls, db_service, assessment_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a document assessment by assessment_id.
        
        Args:
            db_service: DatabaseService class reference
            assessment_id: The assessment ID
            
        Returns:
            Assessment dict with findings and sections, or None
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            
            # Get main assessment
            c.execute('SELECT * FROM document_assessments WHERE assessment_id = ?',
                     (assessment_id,))
            row = c.fetchone()
            
            if not row:
                return None
            
            assessment = db_service.dict_from_row(row)
            assessment['compliance_scores'] = json.loads(assessment['compliance_scores_json'])
            assessment['summary'] = json.loads(assessment['summary_json'])
            
            # Reconstruct document_metadata nested dict for report compatibility
            assessment['document_metadata'] = {
                'filename': assessment.get('filename'),
                'file_type': assessment.get('file_type', 'unknown'),
                'file_size': assessment.get('file_size', 0),
                'page_count': assessment.get('page_count'),
                'word_count': assessment.get('word_count', 0),
                'detected_document_type': assessment.get('document_type'),
                'document_type_confidence': assessment.get('document_type_confidence', 0),
                'version_detected': assessment.get('version_detected'),
                'date_detected': assessment.get('date_detected'),
                'organization_detected': assessment.get('organization_detected'),
                'hash_sha256': assessment.get('file_hash')
            }
            
            # Get findings
            c.execute('''SELECT * FROM document_assessment_findings 
                         WHERE assessment_id = ? ORDER BY id''',
                     (assessment_id,))
            findings = []
            for finding_row in c.fetchall():
                finding = db_service.dict_from_row(finding_row)
                finding['compliance_refs'] = json.loads(finding['compliance_refs_json'])
                finding['details'] = json.loads(finding['details_json'])
                findings.append(finding)
            assessment['findings'] = findings
            
            # Get sections (as sections_found for report compatibility)
            c.execute('''SELECT * FROM document_sections 
                         WHERE assessment_id = ? ORDER BY id''',
                     (assessment_id,))
            sections = [db_service.dict_from_row(row) for row in c.fetchall()]
            assessment['sections_found'] = sections
            # Also keep 'sections' for backward compatibility
            assessment['sections'] = sections
            
            return assessment
    
    @classmethod
    def get_assessment_by_db_id(cls, db_service, db_id: int) -> Optional[Dict[str, Any]]:
        """
        Get a document assessment by database ID.
        
        Args:
            db_service: DatabaseService class reference
            db_id: Database ID
            
        Returns:
            Assessment dict or None
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('SELECT assessment_id FROM document_assessments WHERE id = ?',
                     (db_id,))
            row = c.fetchone()
            
            if not row:
                return None
            
            return cls.get_assessment(db_service, row[0])
    
    @classmethod
    def list_assessments(cls, db_service, 
                        document_type: str = None,
                        limit: int = 50,
                        offset: int = 0) -> List[Dict[str, Any]]:
        """
        List document assessments with optional filtering.
        
        Args:
            db_service: DatabaseService class reference
            document_type: Optional filter by document type
            limit: Maximum results to return
            offset: Offset for pagination
            
        Returns:
            List of assessment summary dicts (including findings counts and summary)
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            
            if document_type:
                c.execute('''SELECT id, assessment_id, filename, file_type, document_type,
                                    coverage_score, summary_json, status, created_at
                             FROM document_assessments
                             WHERE document_type = ?
                             ORDER BY created_at DESC
                             LIMIT ? OFFSET ?''',
                         (document_type, limit, offset))
            else:
                c.execute('''SELECT id, assessment_id, filename, file_type, document_type,
                                    coverage_score, summary_json, status, created_at
                             FROM document_assessments
                             ORDER BY created_at DESC
                             LIMIT ? OFFSET ?''',
                         (limit, offset))
            
            assessments = []
            for row in c.fetchall():
                assessment = db_service.dict_from_row(row)
                
                # Parse summary JSON
                if assessment.get('summary_json'):
                    assessment['summary'] = json.loads(assessment['summary_json'])
                else:
                    assessment['summary'] = {}
                
                # Get findings counts for this assessment
                c.execute('''SELECT status, COUNT(*) as count
                             FROM document_assessment_findings
                             WHERE assessment_id = ?
                             GROUP BY status''',
                         (assessment['assessment_id'],))
                findings_counts = {row[0]: row[1] for row in c.fetchall()}
                
                assessment['findings_found'] = findings_counts.get('found', 0)
                assessment['findings_partial'] = findings_counts.get('partial', 0)
                assessment['findings_missing'] = findings_counts.get('missing', 0)
                assessment['findings_total'] = sum(findings_counts.values())
                
                assessments.append(assessment)
            
            return assessments
    
    @classmethod
    def list_assessments_by_engagement(cls, db_service, engagement_id: str = None) -> List[Dict[str, Any]]:
        """
        List document assessments filtered by engagement.
        
        Args:
            db_service: DatabaseService class reference
            engagement_id: If provided, filter to this engagement only.
                          If None, returns all assessments.
        
        Returns:
            List of assessment summary dicts
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            
            if engagement_id:
                c.execute('''SELECT id, assessment_id, filename, file_type, document_type,
                                    coverage_score, summary_json, status, engagement_id, created_at
                             FROM document_assessments
                             WHERE engagement_id = ?
                             ORDER BY created_at DESC''',
                         (engagement_id,))
            else:
                c.execute('''SELECT id, assessment_id, filename, file_type, document_type,
                                    coverage_score, summary_json, status, engagement_id, created_at
                             FROM document_assessments
                             ORDER BY created_at DESC''')
            
            assessments = []
            for row in c.fetchall():
                assessment = db_service.dict_from_row(row)
                
                # Parse summary JSON
                if assessment.get('summary_json'):
                    assessment['summary'] = json.loads(assessment['summary_json'])
                else:
                    assessment['summary'] = {}
                
                assessments.append(assessment)
            
            return assessments
    
    @classmethod
    def get_assessment_statistics(cls, db_service) -> Dict[str, Any]:
        """
        Get overall statistics for document assessments.
        
        Args:
            db_service: DatabaseService class reference
            
        Returns:
            Statistics dict
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            
            # Total assessments
            c.execute('SELECT COUNT(*) FROM document_assessments')
            total = c.fetchone()[0]
            
            # By document type
            c.execute('''SELECT document_type, COUNT(*) as count
                         FROM document_assessments
                         GROUP BY document_type''')
            by_type = {row[0]: row[1] for row in c.fetchall()}
            
            # Average coverage score
            c.execute('SELECT AVG(coverage_score) FROM document_assessments')
            avg_coverage = c.fetchone()[0] or 0
            
            # Findings by status
            c.execute('''SELECT status, COUNT(*) as count
                         FROM document_assessment_findings
                         GROUP BY status''')
            findings_by_status = {row[0]: row[1] for row in c.fetchall()}
            
            # Findings by severity
            c.execute('''SELECT severity, COUNT(*) as count
                         FROM document_assessment_findings
                         GROUP BY severity''')
            findings_by_severity = {row[0]: row[1] for row in c.fetchall()}
            
            return {
                'total_assessments': total,
                'assessments_by_type': by_type,
                'average_coverage_score': round(avg_coverage, 1),
                'findings_by_status': findings_by_status,
                'findings_by_severity': findings_by_severity
            }
    
    @classmethod
    def delete_assessment(cls, db_service, assessment_id: str) -> bool:
        """
        Delete a document assessment and related records.
        
        Args:
            db_service: DatabaseService class reference
            assessment_id: The assessment ID to delete
            
        Returns:
            True if deleted, False if not found
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            
            # Check exists
            c.execute('SELECT id FROM document_assessments WHERE assessment_id = ?',
                     (assessment_id,))
            if not c.fetchone():
                return False
            
            # Delete related records
            c.execute('DELETE FROM document_sections WHERE assessment_id = ?',
                     (assessment_id,))
            c.execute('DELETE FROM document_assessment_findings WHERE assessment_id = ?',
                     (assessment_id,))
            c.execute('DELETE FROM document_assessments WHERE assessment_id = ?',
                     (assessment_id,))
            
            conn.commit()
            logger.info(f"Deleted document assessment {assessment_id}")
            return True
    
    # =========================================================================
    # CUSTOM TEMPLATE OPERATIONS
    # =========================================================================
    
    @classmethod
    def save_custom_template(cls, db_service,
                            name: str,
                            document_type: str,
                            template_json: Dict[str, Any],
                            description: str = None,
                            version: str = "1.0",
                            created_by: str = None) -> int:
        """
        Save a custom document assessment template.
        
        Args:
            db_service: DatabaseService class reference
            name: Template name
            document_type: Type of document
            template_json: Template definition
            description: Optional description
            version: Template version
            created_by: Username who created it
            
        Returns:
            Database ID of created template
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            
            frameworks = template_json.get('frameworks', [])
            
            c.execute('''INSERT INTO document_templates
                         (name, document_type, version, description,
                          frameworks_json, template_json, is_builtin, created_by)
                         VALUES (?, ?, ?, ?, ?, ?, 0, ?)''',
                     (name, document_type, version, description,
                      json.dumps(frameworks), json.dumps(template_json), created_by))
            
            conn.commit()
            return c.lastrowid
    
    @classmethod
    def get_custom_template(cls, db_service, template_id: int) -> Optional[Dict[str, Any]]:
        """
        Get a custom template by ID.
        
        Args:
            db_service: DatabaseService class reference
            template_id: Database ID
            
        Returns:
            Template dict or None
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM document_templates WHERE id = ?', (template_id,))
            row = c.fetchone()
            
            if not row:
                return None
            
            template = db_service.dict_from_row(row)
            template['frameworks'] = json.loads(template['frameworks_json'])
            template['template'] = json.loads(template['template_json'])
            return template
    
    @classmethod
    def list_custom_templates(cls, db_service,
                             document_type: str = None) -> List[Dict[str, Any]]:
        """
        List custom templates.
        
        Args:
            db_service: DatabaseService class reference
            document_type: Optional filter by document type
            
        Returns:
            List of template summary dicts
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            
            if document_type:
                c.execute('''SELECT id, name, document_type, version, description,
                                    frameworks_json, is_builtin, created_at
                             FROM document_templates
                             WHERE document_type = ?
                             ORDER BY name''',
                         (document_type,))
            else:
                c.execute('''SELECT id, name, document_type, version, description,
                                    frameworks_json, is_builtin, created_at
                             FROM document_templates
                             ORDER BY name''')
            
            templates = []
            for row in c.fetchall():
                template = db_service.dict_from_row(row)
                template['frameworks'] = json.loads(template['frameworks_json'])
                templates.append(template)
            
            return templates
    
    @classmethod
    def delete_custom_template(cls, db_service, template_id: int) -> bool:
        """
        Delete a custom template.
        
        Args:
            db_service: DatabaseService class reference
            template_id: Database ID
            
        Returns:
            True if deleted, False if not found or is builtin
        """
        with db_service.get_connection_context() as conn:
            c = conn.cursor()
            
            # Check exists and is not builtin
            c.execute('SELECT is_builtin FROM document_templates WHERE id = ?',
                     (template_id,))
            row = c.fetchone()
            
            if not row:
                return False
            
            if row[0] == 1:
                logger.warning(f"Cannot delete builtin template {template_id}")
                return False
            
            c.execute('DELETE FROM document_templates WHERE id = ?', (template_id,))
            conn.commit()
            return True
