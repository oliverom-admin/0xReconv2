"""
Enrichment Routes - API endpoints for bulk asset enrichment operations

Endpoints:
- GET /api/v1/assets/enrichment/list - Query assets with enrichment data
- PUT /api/v1/assets/enrichment/save - Save bulk enrichment changes
- POST /api/v1/assets/enrichment/undo/{operation_id} - Undo operation (Phase 1.1)
- GET /api/v1/assets/enrichment/history - Get operation history (Phase 1.1)

All routes require:
- Authentication (@login_required)
- Permission: engagement_admin
"""

from flask import request, jsonify
from typing import Dict, List, Any
import logging
from caip_service_layer.enrichment_service import EnrichmentService

logger = logging.getLogger('caip.enrichment')


def register_enrichment_routes(app, db_service, login_required, permission_required):
    """
    Register enrichment routes with Flask app.

    Args:
        app: Flask application instance
        db_service: DatabaseService class reference
        login_required: Authentication decorator
        permission_required: Authorization decorator
    """

    @app.route('/api/v1/assets/enrichment/list', methods=['GET'])
    @login_required
    @permission_required('inventory:read_certificates')
    def get_enrichment_list():
        """
        GET /api/v1/assets/enrichment/list

        Query assets with enrichment data (inferred + manual).

        Query Parameters:
        - engagement_id: str (required) - Engagement to query
        - page: int (default 1) - Page number
        - limit: int (default 100, max 500) - Items per page
        - source: str (optional) - Filter by integration name (comma-separated)
        - confidence_min: float (optional) - Min discovery confidence (0.0-1.0)
        - confidence_max: float (optional) - Max discovery confidence (0.0-1.0)
        - enrichment_status: str (optional) - not_enriched, partial, or complete
        - sort_by: str (default 'confidence') - confidence, source, last_seen, or default

        Returns:
        {
          "assets": [
            {
              "asset_id": "...",
              "integration_name": "...",
              "inferred": { ... },     # Auto-discovered metadata
              "manual": { ... },       # User-provided enrichment
              "inventory": { ... },    # Temporal data
              "enrichment_status": "...",
              "enrichment_completeness": 0.85
            },
            ...
          ],
          "pagination": {
            "total": 2341,
            "page": 1,
            "pages": 24,
            "per_page": 100
          }
        }
        """
        try:
            # Get and validate query parameters
            engagement_id = request.args.get('engagement_id')
            if not engagement_id:
                return jsonify({'error': 'engagement_id required'}), 400

            page = request.args.get('page', 1, type=int)
            limit = request.args.get('limit', 100, type=int)

            # Validate and clamp pagination
            if limit > 500:
                limit = 500
            if page < 1:
                page = 1

            # Get filter parameters
            source = request.args.get('source')
            confidence_min = request.args.get('confidence_min', type=float)
            confidence_max = request.args.get('confidence_max', type=float)
            enrichment_status = request.args.get('enrichment_status')
            sort_by = request.args.get('sort_by', 'confidence')

            # Call service to get assets
            result = EnrichmentService.get_enrichment_list(
                db_service=db_service,
                engagement_id=engagement_id,
                page=page,
                limit=limit,
                filters={
                    'source': source,
                    'confidence_min': confidence_min,
                    'confidence_max': confidence_max,
                    'enrichment_status': enrichment_status
                },
                sort_by=sort_by
            )

            return jsonify(result), 200

        except Exception as e:
            logger.error(f"Error getting enrichment list: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/v1/assets/enrichment/save', methods=['PUT'])
    @login_required
    @permission_required('inventory:update_context')
    def save_enrichment():
        """
        PUT /api/v1/assets/enrichment/save

        Save bulk enrichment changes to asset_context with audit trail.

        Request Body:
        {
          "engagement_id": "ENG-2024-001",
          "operations": [
            {
              "asset_id": "fingerprint_abc123",
              "updates": {
                "business_unit": "IT Operations",
                "business_function": "Critical",
                "data_classification": "Restricted",
                "dependencies": "High (5+)",
                "compliance_scope": ["PCI-DSS", "NIS2"],
                "migration_path": "Clear",
                "owner": "alice.johnson@company.com"
              }
            },
            { ... }
          ]
        }

        Returns:
        {
          "success": true,
          "updated_count": 23,
          "assets_updated": [
            "fingerprint_abc123",
            "fingerprint_xyz789",
            ...
          ],
          "operation_id": "op-20260223-120530-a1b2c3d4",
          "timestamp": "2026-02-23T12:05:30.123456+00:00",
          "validation_warnings": [
            {
              "asset_id": "fingerprint_bad",
              "field": "business_unit",
              "warning": "Invalid business_unit: BadValue"
            },
            ...
          ]
        }
        """
        try:
            data = request.get_json()
            engagement_id = data.get('engagement_id')
            operations = data.get('operations', [])

            # Validate request
            if not engagement_id:
                return jsonify({'error': 'engagement_id required'}), 400
            if not operations or not isinstance(operations, list):
                return jsonify({'error': 'operations array required'}), 400

            # Get authenticated user from session or headers
            user_id = request.headers.get('X-User-ID', 'system')

            # Call service to save enrichment
            result = EnrichmentService.save_enrichment(
                db_service=db_service,
                engagement_id=engagement_id,
                operations=operations,
                changed_by=user_id
            )

            return jsonify(result), 200

        except Exception as e:
            logger.error(f"Error saving enrichment: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/v1/assets/enrichment/undo/<operation_id>', methods=['POST'])
    @login_required
    @permission_required('inventory:update_context')
    def undo_enrichment_operation(operation_id):
        """
        POST /api/v1/assets/enrichment/undo/{operation_id}

        Revert a previous bulk enrichment operation.
        DEFERRED to Phase 1.1 (v1.1 release).

        Query Parameters:
        - engagement_id: str (required)

        Returns:
        {
          "success": false,
          "message": "Undo functionality deferred to Phase 1.1 (v1.1 release)"
        }
        """
        try:
            engagement_id = request.args.get('engagement_id')
            if not engagement_id:
                return jsonify({'error': 'engagement_id required'}), 400

            user_id = request.headers.get('X-User-ID', 'system')

            result = EnrichmentService.undo_operation(
                db_service=db_service,
                engagement_id=engagement_id,
                operation_id=operation_id,
                reverted_by=user_id
            )

            return jsonify(result), 200 if result.get('success') else 501

        except Exception as e:
            logger.error(f"Error undoing enrichment operation: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/v1/assets/enrichment/history', methods=['GET'])
    @login_required
    @permission_required('inventory:read_certificates')
    def get_enrichment_history():
        """
        GET /api/v1/assets/enrichment/history

        Get history of bulk enrichment operations for potential undo.
        DEFERRED to Phase 1.1 (v1.1 release).

        Query Parameters:
        - engagement_id: str (required)
        - limit: int (default 20, max 100)

        Returns:
        {
          "history": []  # Empty (deferred implementation)
        }
        """
        try:
            engagement_id = request.args.get('engagement_id')
            if not engagement_id:
                return jsonify({'error': 'engagement_id required'}), 400

            limit = request.args.get('limit', 20, type=int)
            limit = min(limit, 100)  # Cap at 100

            history = EnrichmentService.get_operation_history(
                db_service=db_service,
                engagement_id=engagement_id,
                limit=limit
            )

            return jsonify({'history': history}), 200

        except Exception as e:
            logger.error(f"Error getting enrichment history: {e}")
            return jsonify({'error': str(e)}), 500
