"""
Asset Context API Routes for CAIP

Flask routes for asset context enrichment functionality.
These routes should be registered with the main Flask app.

Usage in app.py:
    from asset_context_routes import register_context_routes
    register_context_routes(app, DatabaseService, login_required, permission_required)
"""

import json
import logging
from flask import request, jsonify

logger = logging.getLogger('caip.operational')


def register_context_routes(app, db_service, login_required, permission_required):
    """
    Register asset context routes with the Flask app.

    Args:
        app: Flask application instance
        db_service: DatabaseService class
        login_required: Login required decorator
        permission_required: Permission required decorator
    """
    
    from .asset_context_service import AssetContextService
    
    # =========================================================================
    # CONTEXT CRUD ENDPOINTS
    # =========================================================================
    
    @app.route('/api/v1/engagements/<engagement_id>/context', methods=['GET'])
    @login_required
    @permission_required('engagement_context:read')
    def get_engagement_context(engagement_id):
        """
        Get all context data for an engagement.
        
        Returns:
            List of context records for all assets in the engagement
        """
        try:
            context_data = AssetContextService.get_engagement_context(
                db_service,
                engagement_id
            )
            
            return jsonify({
                'engagement_id': engagement_id,
                'context_count': len(context_data),
                'context_data': context_data
            }), 200
            
        except Exception as e:
            logger.error(f"Error getting engagement context: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/engagements/<engagement_id>/context/<asset_id>', methods=['GET'])
    @login_required
    @permission_required('engagement_context:read')
    def get_asset_context(engagement_id, asset_id):
        """
        Get context for a specific asset.
        
        Returns:
            Context record for the asset or 404 if not found
        """
        try:
            context = AssetContextService.get_context(
                db_service,
                engagement_id,
                asset_id
            )
            
            if not context:
                return jsonify({'error': 'Context not found'}), 404
            
            return jsonify(context), 200
            
        except Exception as e:
            logger.error(f"Error getting asset context: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/engagements/<engagement_id>/context', methods=['POST'])
    @login_required
    @permission_required('engagement_context:update')
    def upsert_asset_context(engagement_id):
        """
        Create or update context for an asset.
        
        Request body:
            asset_id: Required - unique asset identifier
            asset_type: Required - 'certificate' or 'key'
            asset_name: Optional - display name
            source: Optional - asset source
            business_unit: Optional - organisational unit
            business_function: Optional - Critical, Important, Standard, Unknown
            data_classification: Optional - Restricted, Confidential, Internal, Public
            dependencies: Optional - None, Low (1-2), Medium (3-5), High (5+)
            migration_path: Optional - Clear, Uncertain, Blocked
            compliance_scope: Optional - comma-separated list of frameworks
            owner: Optional - technical owner
            notes: Optional
        """
        try:
            data = request.json
            
            if not data.get('asset_id'):
                return jsonify({'error': 'asset_id is required'}), 400
            if not data.get('asset_type'):
                return jsonify({'error': 'asset_type is required'}), 400
            
            result = AssetContextService.upsert_context(
                db_service,
                engagement_id=engagement_id,
                asset_id=data['asset_id'],
                asset_type=data['asset_type'],
                asset_name=data.get('asset_name'),
                source=data.get('source'),
                business_unit=data.get('business_unit'),
                business_function=data.get('business_function'),
                data_classification=data.get('data_classification'),
                dependencies=data.get('dependencies'),
                migration_path=data.get('migration_path'),
                compliance_scope=data.get('compliance_scope'),
                owner=data.get('owner'),
                notes=data.get('notes')
            )
            
            return jsonify(result), 200 if result.get('operation') == 'updated' else 201
            
        except Exception as e:
            logger.error(f"Error upserting asset context: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/engagements/<engagement_id>/context/<asset_id>', methods=['DELETE'])
    @login_required
    @permission_required('engagement_context:delete')
    def delete_asset_context(engagement_id, asset_id):
        """
        Delete context for a specific asset.
        """
        try:
            result = AssetContextService.delete_context(
                db_service,
                engagement_id,
                asset_id
            )
            
            return jsonify(result), 200
            
        except Exception as e:
            logger.error(f"Error deleting asset context: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/v1/engagements/<engagement_id>/context', methods=['DELETE'])
    @login_required
    @permission_required('engagement_context:delete')
    def delete_engagement_context(engagement_id):
        """
        Delete all context data for an engagement.
        """
        try:
            result = AssetContextService.delete_context(
                db_service,
                engagement_id
            )
            
            return jsonify(result), 200
            
        except Exception as e:
            logger.error(f"Error deleting engagement context: {e}")
            return jsonify({'error': str(e)}), 500
    
    # =========================================================================
    # BULK IMPORT ENDPOINT
    # =========================================================================
    
    @app.route('/api/v1/engagements/<engagement_id>/context/import', methods=['POST'])
    @login_required
    @permission_required('engagement_context:create')
    def import_context_data(engagement_id):
        """
        Import context data from embedded dashboard export.
        
        Accepts JSON export file from pki_report.html context enrichment tab.
        
        Request body: The full JSON export from the embedded dashboard
        """
        try:
            import_data = request.json
            
            # Debug logging
            logger.info(f"Import request for engagement: {engagement_id}")
            logger.info(f"import_data type: {type(import_data)}")
            logger.info(f"import_data keys: {list(import_data.keys()) if import_data else 'None'}")
            logger.info(f"context_data length: {len(import_data.get('context_data', [])) if import_data else 0}")
            
            if not import_data:
                return jsonify({'error': 'No import data provided'}), 400
            
            result = AssetContextService.import_context_data(
                db_service,
                engagement_id,
                import_data
            )
            
            logger.info(f"Import result: {result}")
            
            if not result.get('success'):
                return jsonify(result), 400
            
            return jsonify(result), 200
            
        except Exception as e:
            logger.error(f"Error importing context data: {e}")
            return jsonify({'error': str(e)}), 500
    
    # =========================================================================
    # STATISTICS ENDPOINT
    # =========================================================================
    
    @app.route('/api/v1/engagements/<engagement_id>/context/statistics', methods=['GET'])
    @login_required
    @permission_required('engagement_context:read')
    def get_context_statistics(engagement_id):
        """
        Get context enrichment statistics for an engagement.
        
        Returns:
            Statistics including counts by business unit, criticality, etc.
        """
        try:
            stats = AssetContextService.get_context_statistics(
                db_service,
                engagement_id
            )
            
            return jsonify(stats), 200
            
        except Exception as e:
            logger.error(f"Error getting context statistics: {e}")
            return jsonify({'error': str(e)}), 500
    
    # =========================================================================
    # UTILITY ENDPOINTS
    # =========================================================================
    
    @app.route('/api/v1/context/options', methods=['GET'])
    @login_required
    @permission_required('engagement_context:read')
    def get_context_options():
        """
        Get valid options for context fields.

        Useful for populating dropdowns in the UI.
        """
        return jsonify({
            'business_units': AssetContextService.VALID_BUSINESS_UNITS,
            'business_functions': AssetContextService.VALID_BUSINESS_FUNCTIONS,
            'data_classifications': AssetContextService.VALID_DATA_CLASSIFICATIONS,
            'dependencies': AssetContextService.VALID_DEPENDENCIES,
            'migration_paths': AssetContextService.VALID_MIGRATION_PATHS,
            'compliance_scopes': AssetContextService.VALID_COMPLIANCE_SCOPES
        }), 200

    # =========================================================================
    # ORG-WIDE ENRICHMENT ENDPOINT
    # =========================================================================

    @app.route('/api/v1/context/enrich', methods=['POST'])
    @login_required
    @permission_required('engagement_context:update')
    def enrich_asset_org_wide():
        """
        Create or update org-wide context for an asset (engagement_id = NULL).

        Used by dashboard enrichment modal for assets not tied to a specific engagement.

        Request body:
            asset_id: Required - unique asset identifier
            asset_type: Required - 'certificate' or 'key'
            business_unit: Optional
            business_function: Optional
            data_classification: Optional
            dependencies: Optional
            migration_path: Optional
            compliance_scope: Optional
            owner: Optional
            notes: Optional
            override_enabled: Optional
            override_score: Optional
            override_reason: Optional
            excluded: Optional
            exclusion_reason: Optional
        """
        try:
            from flask import session

            data = request.json

            if not data.get('asset_id'):
                return jsonify({'error': 'asset_id is required'}), 400
            if not data.get('asset_type'):
                return jsonify({'error': 'asset_type is required'}), 400

            # Get current user for audit trail
            changed_by = session.get('username', 'unknown')

            result = AssetContextService.upsert_context(
                db_service,
                engagement_id=None,  # NULL for org-wide
                asset_id=data['asset_id'],
                asset_type=data['asset_type'],
                asset_name=data.get('asset_name'),
                source=data.get('source'),
                business_unit=data.get('business_unit'),
                business_function=data.get('business_function'),
                data_classification=data.get('data_classification'),
                dependencies=data.get('dependencies'),
                migration_path=data.get('migration_path'),
                compliance_scope=data.get('compliance_scope'),
                owner=data.get('owner'),
                notes=data.get('notes'),
                override_enabled=data.get('override_enabled'),
                override_score=data.get('override_score'),
                override_phase=None,  # Will be computed from score
                override_reason=data.get('override_reason'),
                excluded=data.get('excluded'),
                exclusion_reason=data.get('exclusion_reason'),
                changed_by=changed_by
            )

            return jsonify(result), 200 if result.get('operation') == 'updated' else 201

        except Exception as e:
            logger.error(f"Error upserting org-wide asset context: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/v1/context/enrich/<asset_id>', methods=['GET'])
    @login_required
    @permission_required('engagement_context:read')
    def get_org_wide_context(asset_id):
        """
        Get org-wide context for an asset (engagement_id = NULL).
        """
        try:
            # Retrieve org-wide context
            context = AssetContextService.get_context(
                db_service,
                engagement_id=None,  # NULL for org-wide
                asset_id=asset_id
            )

            if not context:
                return jsonify({'error': 'Context not found'}), 404

            return jsonify(context), 200

        except Exception as e:
            logger.error(f"Error retrieving org-wide context: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/v1/context/enrich/<asset_id>', methods=['DELETE'])
    @login_required
    @permission_required('engagement_context:delete')
    def delete_org_wide_context(asset_id):
        """
        Delete org-wide context for an asset (clears enrichment).
        """
        try:
            # Delete org-wide context
            result = AssetContextService.delete_context(
                db_service,
                engagement_id=None,  # NULL for org-wide
                asset_id=asset_id
            )

            return jsonify(result), 200

        except Exception as e:
            logger.error(f"Error deleting org-wide context: {e}")
            return jsonify({'error': str(e)}), 500

    # =========================================================================
    # MERGED ENRICHMENT ENDPOINTS (Priority: Manual > Inferred > None)
    # =========================================================================

    @app.route('/api/v1/enrichment/merged/<asset_id>', methods=['GET'])
    @login_required
    @permission_required('engagement_context:read')
    def get_merged_enrichment(asset_id):
        """
        Get merged enrichment data with priority: manual override > inferred > None

        Query parameters:
            engagement_id: Optional - if provided, returns engagement-specific enrichment

        Returns:
            Dict with all 19 extracted_* fields including:
            - field_name: The value (manual or inferred)
            - field_name_source: 'manual', 'inferred', or 'none'
            - field_name_confidence: Confidence score (1.0 for manual, <1.0 for inferred, 0.0 for none)
        """
        try:
            engagement_id = request.args.get('engagement_id')

            merged = AssetContextService.get_merged_enrichment(
                db_service,
                asset_id=asset_id,
                engagement_id=engagement_id
            )

            if not merged:
                return jsonify({'error': 'No enrichment data found'}), 404

            return jsonify({
                'success': True,
                'asset_id': asset_id,
                'engagement_id': engagement_id,
                'enrichment': merged
            }), 200

        except Exception as e:
            logger.error(f"Error getting merged enrichment for {asset_id}: {e}")
            return jsonify({'error': str(e)}), 500

    logger.info("Asset context routes registered")
