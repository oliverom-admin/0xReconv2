"""
Relationship Service - Graph analysis for asset dependencies.

Provides methods to:
- Calculate blast radius (how many assets depend on this one)
- Find dependent assets (downstream impact)
- Auto-calculate dependency count for scoring
- Build CA hierarchy trees for visualization
"""

from typing import List, Dict, Set
from database_service import DatabaseService
import logging

logger = logging.getLogger('caip.relationships')


class RelationshipService:
    """Service for analyzing asset relationship graph"""

    @classmethod
    def get_blast_radius(cls, asset_id: str, max_depth: int = 5) -> Dict:
        """
        Calculate how many assets would be affected if this asset fails.

        Performs breadth-first search to find all dependent assets.

        Args:
            asset_id: The asset to analyze
            max_depth: Maximum traversal depth (default 5)

        Returns:
            {
                'dependent_count': int,
                'dependent_assets': List[Dict],
                'max_depth_reached': int,
                'relationship_paths': List[List[str]]
            }
        """
        visited = set()
        dependent_assets = []
        relationship_paths = []
        max_depth_reached = 0

        def traverse(current_id: str, current_path: List[str], depth: int):
            nonlocal max_depth_reached

            if depth > max_depth or current_id in visited:
                return

            visited.add(current_id)
            max_depth_reached = max(max_depth_reached, depth)

            # Get children (assets that depend on current asset)
            children = DatabaseService.get_child_relationships(current_id)

            for child in children:
                child_id = child['child_asset_id']
                child_type = child['child_asset_type']
                rel_type = child['relationship_type']

                dependent_assets.append({
                    'asset_id': child_id,
                    'asset_type': child_type,
                    'relationship_type': rel_type,
                    'depth': depth + 1,
                    'confidence': child.get('confidence', 1.0)
                })

                new_path = current_path + [f"{child_id} ({rel_type})"]
                relationship_paths.append(new_path)

                # Recurse
                traverse(child_id, new_path, depth + 1)

        # Start traversal
        traverse(asset_id, [asset_id], 0)

        return {
            'dependent_count': len(dependent_assets),
            'dependent_assets': dependent_assets,
            'max_depth_reached': max_depth_reached,
            'relationship_paths': relationship_paths[:10]
        }

    @classmethod
    def calculate_dependency_level(cls, asset_id: str) -> str:
        """
        Auto-calculate dependency level for AssetContextService.

        Maps blast radius to dependency levels:
        - None: 0 dependents
        - Low (1-2): 1-2 dependents
        - Medium (3-5): 3-5 dependents
        - High (5+): 6+ dependents

        Args:
            asset_id: The asset to analyze

        Returns:
            One of: 'None', 'Low (1-2)', 'Medium (3-5)', 'High (5+)'
        """
        blast_radius = cls.get_blast_radius(asset_id, max_depth=3)
        count = blast_radius['dependent_count']

        if count == 0:
            return 'None'
        elif count <= 2:
            return 'Low (1-2)'
        elif count <= 5:
            return 'Medium (3-5)'
        else:
            return 'High (5+)'

    @classmethod
    def get_ca_hierarchy(cls, ca_id: str, max_depth: int = 5) -> Dict:
        """
        Build CA hierarchy tree for visualization.

        Recursively traverses CA->cert relationships to build hierarchy.

        Args:
            ca_id: The CA certificate fingerprint to analyze
            max_depth: Maximum recursion depth

        Returns:
            {
                'ca_id': str,
                'issued_certificates': List[str],
                'intermediate_cas': List[Dict],
                'total_certificates': int
            }
        """
        children = DatabaseService.get_child_relationships(ca_id)

        issued_certs = []
        intermediate_cas = []
        total_count = len(children)

        for child in children:
            child_id = child['child_asset_id']
            rel_type = child.get('relationship_type', '')

            # Only process ca_to_cert relationships
            if rel_type != 'ca_to_cert':
                continue

            # Check if child is also a CA (has issued certificates)
            grandchildren = DatabaseService.get_child_relationships(child_id)
            grandchildren_ca = [gc for gc in grandchildren if gc.get('relationship_type') == 'ca_to_cert']

            if grandchildren_ca and max_depth > 1:
                # Child is intermediate CA - recurse
                sub_hierarchy = cls.get_ca_hierarchy(child_id, max_depth - 1)
                intermediate_cas.append(sub_hierarchy)
                total_count += sub_hierarchy['total_certificates']
            else:
                # Child is leaf certificate
                issued_certs.append(child_id)

        return {
            'ca_id': ca_id,
            'issued_certificates': issued_certs,
            'intermediate_cas': intermediate_cas,
            'total_certificates': total_count
        }

    @classmethod
    def get_dependency_summary(cls, asset_id: str) -> Dict:
        """
        Get comprehensive dependency summary for an asset.

        Includes both upstream (parents) and downstream (children) relationships.

        Args:
            asset_id: The asset to analyze

        Returns:
            {
                'asset_id': str,
                'upstream_dependencies': List[Dict],
                'downstream_dependents': List[Dict],
                'blast_radius': int,
                'dependency_level': str
            }
        """
        parents = DatabaseService.get_parent_relationships(asset_id)
        blast_radius = cls.get_blast_radius(asset_id, max_depth=3)

        return {
            'asset_id': asset_id,
            'upstream_dependencies': parents,
            'downstream_dependents': blast_radius['dependent_assets'],
            'blast_radius': blast_radius['dependent_count'],
            'dependency_level': cls.calculate_dependency_level(asset_id)
        }

    @classmethod
    def auto_calculate_dependencies_for_context(cls, asset_id: str) -> str:
        """
        Auto-populate dependencies field based on relationship graph.

        This method is called from AssetContextService to automatically
        populate the 'dependencies' field based on actual relationship counts.

        Args:
            asset_id: The asset to analyze

        Returns:
            Dependency level string: 'None', 'Low (1-2)', 'Medium (3-5)', or 'High (5+)'
        """
        try:
            return cls.calculate_dependency_level(asset_id)
        except Exception as e:
            logger.error(f"Error calculating dependency level for {asset_id}: {e}")
            return 'None'
