"""
Asset Relationship API Routes for CAIP - Phase 4

Flask routes for asset relationship and dependency analysis.
These routes provide access to:
- Blast radius calculations
- Dependency graphs
- CA hierarchy trees
- Relationship traversal

Usage in app.py:
    from relationship_routes import register_relationship_routes
    register_relationship_routes(app, login_required, permission_required)
"""

import json
import logging
from flask import request, jsonify

logger = logging.getLogger('caip.operational')


def register_relationship_routes(app, login_required, permission_required):
    """
    Register asset relationship routes with the Flask app.

    Args:
        app: Flask application instance
        login_required: Login required decorator
        permission_required: Permission required decorator
    """

    from .relationship_service import RelationshipService

    # =========================================================================
    # RELATIONSHIP QUERY ENDPOINTS
    # =========================================================================

    @app.route('/api/v1/assets/<asset_id>/relationships', methods=['GET'])
    @login_required
    @permission_required('asset:read')
    def get_asset_relationships(asset_id):
        """
        Get all relationships for an asset (upstream + downstream).

        Query parameters:
            - direction: 'both' (default), 'parent', or 'child'
            - type: Optional relationship type filter (e.g., 'ca_to_cert')

        Returns:
            {
                'asset_id': str,
                'upstream_dependencies': List[Dict],  # Assets this depends on
                'downstream_dependents': List[Dict]   # Assets that depend on this
            }
        """
        try:
            direction = request.args.get('direction', 'both').lower()
            rel_type = request.args.get('type', None)

            if direction not in ['both', 'parent', 'child']:
                return jsonify({'error': 'Invalid direction (must be both, parent, or child)'}), 400

            from database_service import DatabaseService

            result = {
                'asset_id': asset_id,
                'upstream_dependencies': [],
                'downstream_dependents': []
            }

            if direction in ['both', 'parent']:
                result['upstream_dependencies'] = DatabaseService.get_parent_relationships(
                    asset_id, rel_type
                )

            if direction in ['both', 'child']:
                result['downstream_dependents'] = DatabaseService.get_child_relationships(
                    asset_id, rel_type
                )

            return jsonify(result), 200

        except Exception as e:
            logger.error(f"Error getting asset relationships: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/v1/assets/<asset_id>/blast-radius', methods=['GET'])
    @login_required
    @permission_required('asset:read')
    def get_blast_radius(asset_id):
        """
        Calculate blast radius for an asset.

        Determines how many downstream assets would be affected if this asset fails.

        Query parameters:
            - max_depth: Maximum traversal depth (default 5, max 10)

        Returns:
            {
                'asset_id': str,
                'dependent_count': int,
                'dependent_assets': List[Dict],
                'max_depth_reached': int,
                'relationship_paths': List[List[str]]
            }
        """
        try:
            max_depth = request.args.get('max_depth', 5, type=int)

            # Validate and limit max_depth
            if max_depth < 1:
                return jsonify({'error': 'max_depth must be >= 1'}), 400
            if max_depth > 10:
                max_depth = 10  # Hard limit for performance

            blast_radius = RelationshipService.get_blast_radius(asset_id, max_depth)

            # Add asset_id for context
            blast_radius['asset_id'] = asset_id

            return jsonify(blast_radius), 200

        except Exception as e:
            logger.error(f"Error calculating blast radius: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/v1/assets/<asset_id>/dependency-summary', methods=['GET'])
    @login_required
    @permission_required('asset:read')
    def get_dependency_summary(asset_id):
        """
        Get comprehensive dependency summary for an asset.

        Combines upstream dependencies, downstream dependents, and auto-calculated
        dependency level in a single response.

        Returns:
            {
                'asset_id': str,
                'upstream_dependencies': List[Dict],
                'downstream_dependents': List[Dict],
                'blast_radius': int,
                'dependency_level': str  # 'None', 'Low (1-2)', 'Medium (3-5)', 'High (5+)'
            }
        """
        try:
            summary = RelationshipService.get_dependency_summary(asset_id)
            return jsonify(summary), 200

        except Exception as e:
            logger.error(f"Error getting dependency summary: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/v1/assets/<asset_id>/ca-hierarchy', methods=['GET'])
    @login_required
    @permission_required('asset:read')
    def get_ca_hierarchy(asset_id):
        """
        Build CA hierarchy tree starting from the given certificate.

        Recursively builds the certificate chain showing:
        - Direct issued certificates
        - Intermediate CAs and their issued certificates
        - Total certificate count

        Query parameters:
            - max_depth: Maximum recursion depth (default 5, max 10)

        Returns:
            {
                'ca_id': str,
                'issued_certificates': List[str],
                'intermediate_cas': List[Dict],  # Recursive hierarchy
                'total_certificates': int
            }
        """
        try:
            max_depth = request.args.get('max_depth', 5, type=int)

            # Validate and limit max_depth
            if max_depth < 1:
                return jsonify({'error': 'max_depth must be >= 1'}), 400
            if max_depth > 10:
                max_depth = 10  # Hard limit for performance

            hierarchy = RelationshipService.get_ca_hierarchy(asset_id, max_depth)
            return jsonify(hierarchy), 200

        except Exception as e:
            logger.error(f"Error building CA hierarchy: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/v1/assets/<asset_id>/auto-dependency-level', methods=['GET'])
    @login_required
    @permission_required('asset:read')
    def get_auto_dependency_level(asset_id):
        """
        Get auto-calculated dependency level for an asset.

        Maps blast radius to standardized dependency categories:
        - None: 0 dependents
        - Low (1-2): 1-2 dependents
        - Medium (3-5): 3-5 dependents
        - High (5+): 6+ dependents

        Returns:
            {
                'asset_id': str,
                'dependency_level': str,
                'dependent_count': int
            }
        """
        try:
            dep_level = RelationshipService.calculate_dependency_level(asset_id)
            blast_radius = RelationshipService.get_blast_radius(asset_id, max_depth=3)

            return jsonify({
                'asset_id': asset_id,
                'dependency_level': dep_level,
                'dependent_count': blast_radius['dependent_count']
            }), 200

        except Exception as e:
            logger.error(f"Error calculating dependency level: {e}")
            return jsonify({'error': str(e)}), 500

    # =========================================================================
    # RELATIONSHIP MANAGEMENT ENDPOINTS
    # =========================================================================

    @app.route('/api/v1/relationships', methods=['POST'])
    @login_required
    @permission_required('relationship:create')
    def create_relationship():
        """
        Create a new asset relationship.

        Request body:
            parent_id: Parent asset ID
            parent_type: Type of parent ('certificate' or 'key')
            child_id: Child asset ID
            child_type: Type of child ('certificate' or 'key')
            relationship_type: Type of relationship (ca_to_cert, cert_to_cert, etc.)
            confidence: Confidence score 0.0-1.0 (default 1.0)
            source: Source of relationship discovery
            metadata: Optional metadata dict

        Returns:
            {
                'success': bool,
                'parent_id': str,
                'child_id': str,
                'relationship_type': str
            }
        """
        try:
            from database_service import DatabaseService

            data = request.get_json() or {}

            # Validate required fields
            required = ['parent_id', 'parent_type', 'child_id', 'child_type', 'relationship_type']
            missing = [f for f in required if f not in data]
            if missing:
                return jsonify({'error': f'Missing required fields: {", ".join(missing)}'}), 400

            # Validate types
            for type_field in ['parent_type', 'child_type']:
                if data[type_field] not in ['certificate', 'key']:
                    return jsonify({'error': f'{type_field} must be "certificate" or "key"'}), 400

            # Validate confidence
            confidence = data.get('confidence', 1.0)
            if not (0.0 <= confidence <= 1.0):
                return jsonify({'error': 'confidence must be between 0.0 and 1.0'}), 400

            success = DatabaseService.upsert_relationship(
                parent_id=data['parent_id'],
                parent_type=data['parent_type'],
                child_id=data['child_id'],
                child_type=data['child_type'],
                relationship_type=data['relationship_type'],
                confidence=confidence,
                source=data.get('source'),
                metadata=data.get('metadata')
            )

            if success:
                return jsonify({
                    'success': True,
                    'parent_id': data['parent_id'],
                    'child_id': data['child_id'],
                    'relationship_type': data['relationship_type']
                }), 201

            return jsonify({'error': 'Failed to create relationship'}), 500

        except Exception as e:
            logger.error(f"Error creating relationship: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/v1/relationships', methods=['DELETE'])
    @login_required
    @permission_required('relationship:delete')
    def delete_relationship():
        """
        Delete an asset relationship.

        Query parameters:
            - parent_id: Parent asset ID
            - child_id: Child asset ID
            - relationship_type: Type of relationship

        Returns:
            {
                'success': bool,
                'parent_id': str,
                'child_id': str,
                'relationship_type': str
            }
        """
        try:
            from database_service import DatabaseService

            parent_id = request.args.get('parent_id')
            child_id = request.args.get('child_id')
            rel_type = request.args.get('relationship_type')

            if not all([parent_id, child_id, rel_type]):
                return jsonify({
                    'error': 'Required parameters: parent_id, child_id, relationship_type'
                }), 400

            success = DatabaseService.delete_relationship(
                parent_id=parent_id,
                child_id=child_id,
                relationship_type=rel_type
            )

            if success:
                return jsonify({
                    'success': True,
                    'parent_id': parent_id,
                    'child_id': child_id,
                    'relationship_type': rel_type
                }), 200

            return jsonify({'error': 'Relationship not found'}), 404

        except Exception as e:
            logger.error(f"Error deleting relationship: {e}")
            return jsonify({'error': str(e)}), 500
