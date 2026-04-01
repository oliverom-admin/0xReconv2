# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: caip_service_layer/scoring_service.py
# Copied: 2026-04-01
# Used in: Phase 9 — Scoring, Aggregation, PQC Detection
#
# When porting logic from this file:
#   - Rewrite using the new stack (FastAPI, asyncpg, python-pkcs11, httpx)
#   - Remove all Flask/SQLite/PyKCS11/requests dependencies
#   - Remove all caip_* naming conventions
#   - Fix any bare except: or except Exception: pass blocks
#   - Add proper async/await patterns
#   - Do not copy — port deliberately
# =============================================================================

"""
Scoring Service for CAIP

Provides algorithmic risk scoring for assessment findings.
Calculates weighted scores based on asset context (criticality, exposure, 
data classification) and generates priority queues for remediation planning.

Phase 1: Core Scoring Engine
- WeightFactors: Multipliers derived from asset context
- ScoredFinding: Extended finding with weighted scoring
- ScoringEngine: Core calculation logic

Phase 2: Aggregation Engine
- AssessmentScore: Aggregate metrics, grades, and priority queue
- AggregationEngine: Composite score calculations, health index, grading
- SeverityBreakdown: Per-severity metrics

Design Principles:
1. Works without context (defaults to 1.0 multipliers)
2. Does not modify existing RuleResult - creates new ScoredFinding
3. All weights are configurable via class attributes
4. Effort estimates derived from rule category/remediation type
5. Health index provides 0-100 "cryptographic health" metric
6. Grades (A+ to F) provide executive-friendly summary
"""

import logging
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone

from caip_service_layer.environment_inference_service import EnvironmentInferenceService

logger = logging.getLogger('caip.scoring')

# Module availability flag (for conditional imports)
SCORING_AVAILABLE = True


# =============================================================================
# CONFIGURATION: Weight Mappings
# =============================================================================

# These map asset context values to weight multipliers.
# Higher weight = higher priority for remediation.
# 
# Logic: A critical, internet-facing asset with restricted data should have
# findings weighted MORE heavily than a development, isolated asset.

CRITICALITY_WEIGHTS = {
    # Maps business_function from AssetContextService
    'Critical': 2.0,        # Mission-critical systems - double the weight
    'Important': 1.5,       # Business-important - 50% increase
    'Standard': 1.0,        # Normal priority - baseline
    'Unknown': 1.0,         # Unknown treated as standard (safe default)
    None: 1.0,              # Missing context - baseline
}

EXPOSURE_WEIGHTS = {
    # Maps network exposure (derived from source or explicit context)
    'internet_facing': 1.8,  # Publicly accessible - high multiplier
    'dmz': 1.4,              # DMZ/perimeter - elevated
    'internal': 1.0,         # Internal network - baseline
    'isolated': 0.6,         # Air-gapped/isolated - reduced priority
    None: 1.0,               # Unknown - assume internal (baseline)
}

DATA_CLASSIFICATION_WEIGHTS = {
    # Maps data_classification from AssetContextService
    'Restricted': 1.5,       # Highly sensitive data
    'Confidential': 1.3,     # Business confidential
    'Internal': 1.0,         # Internal use only - baseline
    'Public': 0.8,           # Public data - slightly reduced
    None: 1.0,               # Unknown - baseline
}

COMPLIANCE_WEIGHTS = {
    # Applied when asset is in scope for specific frameworks
    # These are additive bonuses, not multipliers
    'PCI-DSS': 0.2,          # +20% if PCI in scope
    'DORA': 0.2,             # +20% if DORA in scope
    'NIS2': 0.15,            # +15% if NIS2 in scope
    'CNSA 2.0': 0.25,        # +25% if CNSA 2.0 (PQC) in scope
    'SOX': 0.1,              # +10% if SOX in scope
    'HIPAA': 0.15,           # +15% if HIPAA in scope
    'GDPR': 0.1,             # +10% if GDPR in scope
}

RECENCY_WEIGHTS = {
    # Applied based on certificate expiry proximity
    # Certificates expiring soon get higher weight
    'expires_30_days': 1.5,   # Expiring within 30 days - urgent
    'expires_90_days': 1.2,   # Expiring within 90 days - elevated
    'expires_365_days': 1.0,  # Expiring within year - baseline
    'long_lived': 0.9,        # >1 year expiry - slightly reduced
    None: 1.0,                # Unknown - baseline
}

DEPENDENCY_WEIGHTS = {
    # Applied based on blast radius / number of dependent assets
    # Assets affecting many other systems get higher priority
    'None': 0.8,              # Isolated assets - lower priority
    'Low (1-2)': 1.0,         # 1-2 dependents - baseline
    'Medium (3-5)': 1.3,      # 3-5 dependents - elevated
    'High (5+)': 1.6,         # 6+ dependents - urgent
    None: 1.0,                # Unknown - baseline
}

ENVIRONMENT_WEIGHTS = {
    # Applied based on deployment environment
    # Production issues are more urgent than development
    'production': 1.5,        # Production - high priority
    'staging': 1.1,           # Pre-production - moderate elevation
    'development': 0.7,       # Development - lower priority
    'testing': 0.6,           # Testing - lowest priority
    'unknown': 1.0,           # Unknown - safe default
    None: 1.0,                # Unknown - baseline
}

# Effort estimates for remediation (1-10 scale)
# Used to calculate priority score: weighted_score / effort
# Lower effort + high risk = higher priority (better ROI)
EFFORT_ESTIMATES = {
    # By category (from rule metadata)
    'certificate-expiry': 2,           # Simple reissue
    'certificate-validation': 2,       # Reissue with correct params
    'cryptographic-strength': 3,       # May need key regeneration
    'hash-algorithm': 3,               # Reissue with new algorithm
    'key-strength': 4,                 # Key rotation required
    'key-management': 4,               # Policy/process change
    'protocol-security': 5,            # TLS config change
    'tls-configuration': 5,            # Server reconfiguration
    'crl-validation': 3,               # CA/CRL infrastructure
    'pqc-readiness': 6,                # Algorithm migration
    'algorithm-migration': 7,          # Significant change
    'infrastructure': 8,               # Major infrastructure work
    'default': 3,                      # Unknown - assume moderate
}

# Severity to base score mapping (if not provided in rule)
SEVERITY_BASE_SCORES = {
    'critical': 9.0,
    'high': 7.0,
    'medium': 5.0,
    'low': 3.0,
    'info': 1.0,
}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class WeightFactors:
    """
    Weight multipliers derived from asset context.

    Each factor is a multiplier (typically 0.5 to 2.0).
    Combined weight is the product of all factors.

    Example:
        Critical (2.0) × Internet-facing (1.8) × Restricted (1.5) × High-Dependencies (1.6) = 8.64x multiplier

    A finding with base_risk_score of 9.0 would become:
        weighted_score = 9.0 × 8.64 = 77.76
    """
    criticality: float = 1.0
    exposure: float = 1.0
    data_classification: float = 1.0
    compliance_bonus: float = 0.0  # Additive, not multiplicative
    recency: float = 1.0
    dependency: float = 1.0  # Blast radius multiplier
    environment: float = 1.0  # NEW: Environment type multiplier
    
    @property
    def combined(self) -> float:
        """
        Calculate combined weight multiplier.

        Formula: (criticality × exposure × data_classification × recency × dependency × environment) + compliance_bonus

        The compliance bonus is added after multiplication to give frameworks
        an additive boost rather than compounding effect.
        """
        base = self.criticality * self.exposure * self.data_classification * self.recency * self.dependency * self.environment
        return base + self.compliance_bonus
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'criticality': self.criticality,
            'exposure': self.exposure,
            'data_classification': self.data_classification,
            'compliance_bonus': self.compliance_bonus,
            'recency': self.recency,
            'dependency': self.dependency,
            'environment': self.environment,
            'combined': self.combined
        }


@dataclass
class ScoredFinding:
    """
    Extended finding with weighted scoring applied.
    
    This wraps the original RuleResult data and adds:
    - weight_factors: The multipliers used
    - weighted_score: base_risk_score × combined_weight
    - effort_estimate: Estimated remediation effort (1-10)
    - priority_score: weighted_score / effort (higher = fix first)
    - confidence: Rule evaluation confidence (0-1)
    
    The priority_score represents "bang for buck" - findings with high
    risk reduction per unit effort should be fixed first.
    """
    # Original finding fields (from RuleResult)
    rule_id: str
    rule_name: str
    triggered: bool
    severity: str
    title: str
    description: str
    remediation: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    compliance_impact: str = ""
    category: str = ""
    
    # Scoring fields
    base_risk_score: float = 0.0
    weight_factors: WeightFactors = field(default_factory=WeightFactors)
    weighted_score: float = 0.0
    effort_estimate: int = 3
    priority_score: float = 0.0
    confidence: float = 1.0
    
    # Context reference (for traceability)
    asset_id: str = ""
    asset_context_applied: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            # Original fields
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'triggered': self.triggered,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'remediation': self.remediation,
            'evidence': self.evidence,
            'compliance_impact': self.compliance_impact,
            'category': self.category,
            
            # Scoring fields
            'risk_score': self.base_risk_score,  # Alias for HTML template compatibility
            'base_risk_score': self.base_risk_score,
            'weight_factors': self.weight_factors.to_dict(),
            'weighted_score': round(self.weighted_score, 2),
            'effort_estimate': self.effort_estimate,
            'priority_score': round(self.priority_score, 2),
            'confidence': self.confidence,
            
            # Context reference
            'asset_id': self.asset_id,
            'asset_context_applied': self.asset_context_applied
        }
    
    @classmethod
    def from_rule_result(cls, rule_result, **kwargs) -> 'ScoredFinding':
        """
        Create ScoredFinding from a RuleResult object.
        
        Args:
            rule_result: RuleResult object (or dict with same fields)
            **kwargs: Additional scoring fields to set
            
        Returns:
            ScoredFinding with base fields populated
        """
        # Handle both RuleResult objects and dicts
        if hasattr(rule_result, 'to_dict'):
            data = rule_result.to_dict()
        elif isinstance(rule_result, dict):
            data = rule_result
        else:
            raise ValueError(f"Expected RuleResult or dict, got {type(rule_result)}")
        
        return cls(
            rule_id=data.get('rule_id', ''),
            rule_name=data.get('rule_name', ''),
            triggered=data.get('triggered', False),
            severity=data.get('severity', 'medium'),
            title=data.get('title', ''),
            description=data.get('description', ''),
            remediation=data.get('remediation', ''),
            evidence=data.get('evidence', {}),
            compliance_impact=data.get('compliance_impact', ''),
            category=data.get('category', ''),
            base_risk_score=data.get('risk_score', 0.0),
            **kwargs
        )


# =============================================================================
# SCORING ENGINE
# =============================================================================

class ScoringEngine:
    """
    Core scoring calculation engine.
    
    Responsibilities:
    1. Calculate weight factors from asset context
    2. Apply weights to findings to produce weighted scores
    3. Estimate remediation effort from rule metadata
    4. Calculate priority scores (weighted_score / effort)
    
    Usage:
        engine = ScoringEngine()
        
        # Score a single finding
        scored = engine.score_finding(rule_result, asset_context)
        
        # Score a batch with contexts
        contexts = {'cert-001': {'business_function': 'Critical'}, ...}
        scored_batch = engine.score_findings_batch(findings, contexts)
    
    Design:
    - Works without context (uses default weights of 1.0)
    - Does not modify input RuleResult objects
    - All configuration via class attributes (can be overridden)
    """
    
    def __init__(self,
                 criticality_weights: Dict[str, float] = None,
                 exposure_weights: Dict[str, float] = None,
                 data_classification_weights: Dict[str, float] = None,
                 compliance_weights: Dict[str, float] = None,
                 recency_weights: Dict[str, float] = None,
                 dependency_weights: Dict[str, float] = None,
                 environment_weights: Dict[str, float] = None,
                 effort_estimates: Dict[str, int] = None):
        """
        Initialize scoring engine with optional custom weight mappings.

        Args:
            criticality_weights: Override CRITICALITY_WEIGHTS
            exposure_weights: Override EXPOSURE_WEIGHTS
            data_classification_weights: Override DATA_CLASSIFICATION_WEIGHTS
            compliance_weights: Override COMPLIANCE_WEIGHTS
            recency_weights: Override RECENCY_WEIGHTS
            dependency_weights: Override DEPENDENCY_WEIGHTS
            environment_weights: Override ENVIRONMENT_WEIGHTS
            effort_estimates: Override EFFORT_ESTIMATES
        """
        self.criticality_weights = criticality_weights or CRITICALITY_WEIGHTS
        self.exposure_weights = exposure_weights or EXPOSURE_WEIGHTS
        self.data_classification_weights = data_classification_weights or DATA_CLASSIFICATION_WEIGHTS
        self.compliance_weights = compliance_weights or COMPLIANCE_WEIGHTS
        self.recency_weights = recency_weights or RECENCY_WEIGHTS
        self.dependency_weights = dependency_weights or DEPENDENCY_WEIGHTS
        self.environment_weights = environment_weights or ENVIRONMENT_WEIGHTS
        self.effort_estimates = effort_estimates or EFFORT_ESTIMATES
    
    # =========================================================================
    # WEIGHT CALCULATION
    # =========================================================================
    
    def calculate_weight_factors(self, 
                                  asset_context: Dict[str, Any] = None,
                                  asset_data: Dict[str, Any] = None) -> WeightFactors:
        """
        Calculate weight factors from asset context and data.
        
        Args:
            asset_context: Context from AssetContextService, may include:
                - business_function: Critical, Important, Standard, Unknown
                - data_classification: Restricted, Confidential, Internal, Public
                - compliance_scope: Comma-separated list of frameworks
                - exposure: internet_facing, dmz, internal, isolated
            asset_data: The asset itself (certificate, key), used for:
                - days_until_expiration: For recency weight
                - source: To infer exposure if not in context
                
        Returns:
            WeightFactors with all multipliers calculated
        """
        context = asset_context or {}
        data = asset_data or {}
        
        # 1. Criticality weight (from business_function)
        business_function = context.get('business_function')
        criticality = self.criticality_weights.get(
            business_function, 
            self.criticality_weights.get(None, 1.0)
        )
        
        # 2. Exposure weight
        # First check explicit context, then infer from source
        exposure_value = context.get('exposure')
        if not exposure_value:
            exposure_value = self._infer_exposure_from_source(data.get('source', ''))
        exposure = self.exposure_weights.get(
            exposure_value,
            self.exposure_weights.get(None, 1.0)
        )
        
        # 3. Data classification weight
        data_class = context.get('data_classification')
        data_classification = self.data_classification_weights.get(
            data_class,
            self.data_classification_weights.get(None, 1.0)
        )
        
        # 4. Compliance bonus (additive)
        compliance_scope = context.get('compliance_scope', '')
        compliance_bonus = self._calculate_compliance_bonus(compliance_scope)
        
        # 5. Recency weight (from expiry)
        days_until_expiry = data.get('days_until_expiration')
        if days_until_expiry is None:
            # Try to calculate from not_after
            days_until_expiry = self._calculate_days_until_expiry(data.get('not_after'))
        recency = self._get_recency_weight(days_until_expiry)

        # 6. Dependency weight (from blast radius)
        dependencies = context.get('dependencies', 'None')
        dependency = self.dependency_weights.get(
            dependencies,
            self.dependency_weights.get(None, 1.0)
        )

        # 7. Environment weight (from context, Phase 2 inferred fields, or source inference)
        # Priority: explicit context > Phase 2 inferred fields > source-based inference
        environment_type = context.get('environment_type')
        environment_confidence = None

        if not environment_type:
            # Try Phase 2 inferred fields from NormalisedKey/NormalisedCertificate
            environment_type = data.get('inferred_environment_type')
            environment_confidence = data.get('inferred_discovery_confidence')

        if not environment_type:
            # Fallback to source-based inference if not explicit or inferred
            inference = EnvironmentInferenceService.infer_from_source_string(
                data.get('source', '')
            )
            environment_type = inference.get('environment_type', 'unknown')
            environment_confidence = inference.get('discovery_confidence')

        environment = self.environment_weights.get(
            environment_type,
            self.environment_weights.get(None, 1.0)
        )

        # Log the environment classification for debugging
        if environment_confidence is not None:
            logger.debug(
                f"Environment classification for {data.get('fingerprint_sha256', 'unknown')}: "
                f"{environment_type} (confidence: {environment_confidence})"
            )

        return WeightFactors(
            criticality=criticality,
            exposure=exposure,
            data_classification=data_classification,
            compliance_bonus=compliance_bonus,
            recency=recency,
            dependency=dependency,
            environment=environment
        )
    
    def _infer_exposure_from_source(self, source: str) -> Optional[str]:
        """
        Infer exposure level from asset source string.
        
        Logic:
        - TLS scans are typically internet-facing or DMZ
        - Azure Key Vault is typically internal (cloud)
        - Luna HSM is typically isolated (on-prem HSM)
        - File scans are typically internal
        
        This is a heuristic - explicit context overrides this.
        """
        if not source:
            return None
            
        source_lower = source.lower()
        
        if 'tls' in source_lower:
            # TLS endpoints could be internet-facing
            # Conservative: assume DMZ unless we know better
            return 'dmz'
        elif 'azure' in source_lower:
            return 'internal'  # Cloud but private
        elif 'luna' in source_lower or 'hsm' in source_lower:
            return 'isolated'  # HSMs are typically isolated
        elif 'ejbca' in source_lower:
            return 'internal'  # CA infrastructure
        elif 'file' in source_lower:
            return 'internal'  # File system scans
        
        return None
    
    def _calculate_compliance_bonus(self, compliance_scope: str) -> float:
        """
        Calculate additive compliance bonus from scope string.
        
        Args:
            compliance_scope: Comma-separated list of frameworks
                e.g., "PCI-DSS, DORA, CNSA 2.0"
                
        Returns:
            Sum of applicable compliance bonuses
        """
        if not compliance_scope:
            return 0.0
        
        bonus = 0.0
        frameworks = [f.strip() for f in compliance_scope.split(',')]
        
        for framework in frameworks:
            if framework in self.compliance_weights:
                bonus += self.compliance_weights[framework]
        
        return bonus
    
    def _calculate_days_until_expiry(self, not_after: Any) -> Optional[int]:
        """
        Calculate days until expiry from not_after field.
        
        Args:
            not_after: Expiry date (string ISO format or datetime)
            
        Returns:
            Days until expiry, or None if cannot calculate
        """
        if not not_after:
            return None
            
        try:
            if isinstance(not_after, str):
                # Parse ISO format
                expiry = datetime.fromisoformat(not_after.replace('Z', '+00:00'))
            elif isinstance(not_after, datetime):
                expiry = not_after
            else:
                return None
            
            # Calculate days
            now = datetime.now(timezone.utc) if expiry.tzinfo else datetime.now()
            delta = expiry - now
            return delta.days
            
        except Exception as e:
            logger.debug(f"Could not calculate days until expiry: {e}")
            return None
    
    def _get_recency_weight(self, days_until_expiry: Optional[int]) -> float:
        """
        Get recency weight based on days until expiry.
        
        Args:
            days_until_expiry: Days until certificate/key expires
            
        Returns:
            Recency weight multiplier
        """
        if days_until_expiry is None:
            return self.recency_weights.get(None, 1.0)
        
        if days_until_expiry <= 30:
            return self.recency_weights.get('expires_30_days', 1.5)
        elif days_until_expiry <= 90:
            return self.recency_weights.get('expires_90_days', 1.2)
        elif days_until_expiry <= 365:
            return self.recency_weights.get('expires_365_days', 1.0)
        else:
            return self.recency_weights.get('long_lived', 0.9)
    
    # =========================================================================
    # EFFORT ESTIMATION
    # =========================================================================
    
    def estimate_effort(self, 
                        category: str = None,
                        rule_id: str = None,
                        remediation: str = None) -> int:
        """
        Estimate remediation effort for a finding.
        
        Uses rule category as primary indicator, with fallbacks to
        rule_id patterns and remediation text analysis.
        
        Args:
            category: Rule category (e.g., 'cryptographic-strength')
            rule_id: Rule identifier (for pattern matching)
            remediation: Remediation text (for keyword analysis)
            
        Returns:
            Effort estimate (1-10 scale)
        """
        # 1. Try category lookup (most reliable)
        if category:
            category_lower = category.lower().replace(' ', '-')
            if category_lower in self.effort_estimates:
                return self.effort_estimates[category_lower]
        
        # 2. Try rule_id pattern matching
        if rule_id:
            rule_lower = rule_id.lower()
            
            # Check for known patterns
            if 'expir' in rule_lower:
                return self.effort_estimates.get('certificate-expiry', 2)
            elif 'sha1' in rule_lower or 'md5' in rule_lower or 'hash' in rule_lower:
                return self.effort_estimates.get('hash-algorithm', 3)
            elif 'key' in rule_lower and 'size' in rule_lower:
                return self.effort_estimates.get('key-strength', 4)
            elif 'tls' in rule_lower or 'protocol' in rule_lower:
                return self.effort_estimates.get('protocol-security', 5)
            elif 'pqc' in rule_lower or 'quantum' in rule_lower:
                return self.effort_estimates.get('pqc-readiness', 6)
        
        # 3. Try remediation text analysis
        if remediation:
            remediation_lower = remediation.lower()
            
            if 'reissue' in remediation_lower or 'renew' in remediation_lower:
                return 2  # Simple reissue
            elif 'rotate' in remediation_lower:
                return 4  # Key rotation
            elif 'upgrade' in remediation_lower or 'migrate' in remediation_lower:
                return 6  # Algorithm/protocol upgrade
            elif 'infrastructure' in remediation_lower or 'redesign' in remediation_lower:
                return 8  # Major change
        
        # 4. Default
        return self.effort_estimates.get('default', 3)
    
    # =========================================================================
    # SCORING
    # =========================================================================
    
    def score_finding(self,
                      rule_result,
                      asset_context: Dict[str, Any] = None,
                      asset_data: Dict[str, Any] = None) -> ScoredFinding:
        """
        Apply weighted scoring to a single finding.
        
        Args:
            rule_result: RuleResult object or dict with finding data
            asset_context: Context from AssetContextService (optional)
            asset_data: The asset itself for additional context (optional)
            
        Returns:
            ScoredFinding with weighted scores calculated
        """
        # Convert to ScoredFinding (preserves original data)
        scored = ScoredFinding.from_rule_result(rule_result)
        
        # Get base risk score (from rule or severity mapping)
        if scored.base_risk_score == 0.0:
            scored.base_risk_score = SEVERITY_BASE_SCORES.get(
                scored.severity.lower(), 5.0
            )
        
        # Calculate weight factors
        weights = self.calculate_weight_factors(asset_context, asset_data)
        scored.weight_factors = weights
        scored.asset_context_applied = asset_context is not None
        
        # Calculate weighted score
        scored.weighted_score = scored.base_risk_score * weights.combined
        
        # Cap weighted score at 100 (prevents runaway scores)
        scored.weighted_score = min(scored.weighted_score, 100.0)
        
        # Estimate effort
        scored.effort_estimate = self.estimate_effort(
            category=scored.category,
            rule_id=scored.rule_id,
            remediation=scored.remediation
        )
        
        # Calculate priority score (weighted_score / effort)
        # Higher priority = higher weighted score, lower effort
        if scored.effort_estimate > 0:
            scored.priority_score = scored.weighted_score / scored.effort_estimate
        else:
            scored.priority_score = scored.weighted_score
        
        # Extract asset_id from evidence if available
        if 'asset_id' in scored.evidence:
            scored.asset_id = scored.evidence['asset_id']
        elif 'fingerprint_sha256' in scored.evidence:
            scored.asset_id = scored.evidence['fingerprint_sha256']
        elif 'subject_cn' in scored.evidence:
            scored.asset_id = scored.evidence['subject_cn']
        
        return scored
    
    def score_findings_batch(self,
                             findings: List,
                             asset_contexts: Dict[str, Dict[str, Any]] = None,
                             asset_data_map: Dict[str, Dict[str, Any]] = None) -> List[ScoredFinding]:
        """
        Apply weighted scoring to a batch of findings.
        
        Args:
            findings: List of RuleResult objects or dicts
            asset_contexts: Dict mapping asset_id -> context dict
            asset_data_map: Dict mapping asset_id -> asset data dict
            
        Returns:
            List of ScoredFinding objects with weighted scores
        """
        contexts = asset_contexts or {}
        data_map = asset_data_map or {}
        scored_findings = []
        
        for finding in findings:
            # Determine asset_id to look up context
            asset_id = self._extract_asset_id(finding)
            
            # Get context and data for this asset
            context = contexts.get(asset_id, {}) if asset_id else {}
            data = data_map.get(asset_id, {}) if asset_id else {}
            
            # Score the finding
            scored = self.score_finding(finding, context, data)
            if asset_id:
                scored.asset_id = asset_id
            
            scored_findings.append(scored)
        
        return scored_findings
    
    def _extract_asset_id(self, finding) -> Optional[str]:
        """
        Extract asset_id from a finding for context lookup.
        
        Checks evidence dict for common identifier fields.
        """
        # Handle both objects and dicts
        if hasattr(finding, 'evidence'):
            evidence = finding.evidence
        elif isinstance(finding, dict):
            evidence = finding.get('evidence', {})
        else:
            return None
        
        # Try common identifier fields
        for field in ['asset_id', 'fingerprint_sha256', 'subject_cn', 'key_id', 'id']:
            if field in evidence and evidence[field]:
                return str(evidence[field])
        
        return None


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def create_default_scoring_engine() -> ScoringEngine:
    """
    Create a scoring engine with default configuration.
    
    Returns:
        ScoringEngine with default weight mappings
    """
    return ScoringEngine()


def score_finding_simple(rule_result,
                         business_function: str = None,
                         data_classification: str = None,
                         exposure: str = None) -> ScoredFinding:
    """
    Convenience function to score a single finding with simple context.
    
    Args:
        rule_result: RuleResult object or dict
        business_function: Critical, Important, Standard, Unknown
        data_classification: Restricted, Confidential, Internal, Public
        exposure: internet_facing, dmz, internal, isolated
        
    Returns:
        ScoredFinding with weighted scores
    """
    engine = ScoringEngine()
    context = {}
    
    if business_function:
        context['business_function'] = business_function
    if data_classification:
        context['data_classification'] = data_classification
    if exposure:
        context['exposure'] = exposure
    
    return engine.score_finding(rule_result, context if context else None)


# =============================================================================
# PHASE 2: AGGREGATION ENGINE
# =============================================================================

# Grade thresholds - maps health index ranges to letter grades
# Health index is 0-100 (100 = perfect cryptographic health)
GRADE_THRESHOLDS = {
    'A+': 95,
    'A': 90,
    'B+': 85,
    'B': 80,
    'C+': 70,
    'C': 60,
    'D': 50,
    'F': 0
}

GRADE_DESCRIPTIONS = {
    'A+': 'Excellent cryptographic posture with minimal risk exposure',
    'A': 'Strong cryptographic posture with very low risk exposure',
    'B+': 'Good cryptographic posture with minor areas for improvement',
    'B': 'Acceptable cryptographic posture with some areas needing attention',
    'C+': 'Below average posture requiring planned remediation',
    'C': 'Significant issues identified requiring remediation planning',
    'D': 'Poor cryptographic posture with high risk exposure',
    'F': 'Critical issues requiring immediate attention'
}


@dataclass
class SeverityBreakdown:
    """
    Metrics breakdown for a single severity level.
    
    Provides both count and weighted exposure for each severity,
    enabling both "how many" and "how bad" analysis.
    """
    count: int = 0
    total_base_score: float = 0.0
    total_weighted_score: float = 0.0
    average_weight: float = 0.0
    highest_priority_finding: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'count': self.count,
            'total_base_score': round(self.total_base_score, 2),
            'total_weighted_score': round(self.total_weighted_score, 2),
            'average_weight': round(self.average_weight, 2),
            'highest_priority_finding': self.highest_priority_finding
        }


@dataclass
class AssessmentScore:
    """
    Aggregated assessment scoring summary.
    
    Provides:
    - Overall health index (0-100, higher = better)
    - Letter grade (A+ to F)
    - Total risk exposure (sum of weighted scores)
    - Breakdown by severity
    - Priority queue (top findings to fix first)
    - Metadata for reporting
    
    The health index represents "cryptographic health" where:
    - 100 = No findings, perfect health
    - 0 = Maximum possible exposure reached
    
    Formula:
        health_index = 100 × (1 - (total_exposure / max_possible_exposure))
    """
    # Overall metrics
    total_findings: int = 0
    triggered_findings: int = 0
    total_base_exposure: float = 0.0
    total_weighted_exposure: float = 0.0
    
    # Health and grading
    health_index: float = 100.0
    grade: str = 'A+'
    grade_description: str = ''
    
    # Asset context
    total_assets_assessed: int = 0
    assets_with_context: int = 0
    context_coverage_percent: float = 0.0
    
    # Risk exposure metrics (new)
    assets_at_risk: int = 0
    assets_at_risk_percent: float = 0.0
    compliant_assets: int = 0
    compliance_percent: float = 0.0
    max_possible_exposure: float = 0.0
    risk_exposure_percent: float = 0.0
    
    # Severity breakdown
    critical: SeverityBreakdown = field(default_factory=SeverityBreakdown)
    high: SeverityBreakdown = field(default_factory=SeverityBreakdown)
    medium: SeverityBreakdown = field(default_factory=SeverityBreakdown)
    low: SeverityBreakdown = field(default_factory=SeverityBreakdown)
    info: SeverityBreakdown = field(default_factory=SeverityBreakdown)
    
    # Priority queue (top N findings to fix first)
    priority_queue: List[Dict[str, Any]] = field(default_factory=list)
    
    # Metadata
    assessment_timestamp: str = ''
    scoring_version: str = '1.0'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'total_findings': self.total_findings,
            'triggered_findings': self.triggered_findings,
            'total_base_exposure': round(self.total_base_exposure, 2),
            'total_weighted_exposure': round(self.total_weighted_exposure, 2),
            'health_index': round(self.health_index, 1),
            'grade': self.grade,
            'grade_description': self.grade_description,
            'total_assets_assessed': self.total_assets_assessed,
            'assets_with_context': self.assets_with_context,
            'context_coverage_percent': round(self.context_coverage_percent, 1),
            'assets_at_risk': self.assets_at_risk,
            'assets_at_risk_percent': round(self.assets_at_risk_percent, 1),
            'compliant_assets': self.compliant_assets,
            'compliance_percent': round(self.compliance_percent, 1),
            'max_possible_exposure': round(self.max_possible_exposure, 2),
            'risk_exposure_percent': round(self.risk_exposure_percent, 1),
            'severity_breakdown': {
                'critical': self.critical.to_dict(),
                'high': self.high.to_dict(),
                'medium': self.medium.to_dict(),
                'low': self.low.to_dict(),
                'info': self.info.to_dict()
            },
            'priority_queue': self.priority_queue,
            'assessment_timestamp': self.assessment_timestamp,
            'scoring_version': self.scoring_version
        }
    
    def get_executive_summary(self) -> Dict[str, Any]:
        """
        Generate executive-friendly summary for reports.
        
        Returns condensed metrics suitable for executive dashboards
        and PDF reports.
        """
        # Determine trend indicator based on severity distribution
        if self.critical.count > 0:
            risk_trend = 'critical_attention'
        elif self.high.count > 5:
            risk_trend = 'needs_attention'
        elif self.health_index >= 80:
            risk_trend = 'healthy'
        else:
            risk_trend = 'monitor'
        
        return {
            'grade': self.grade,
            'grade_description': self.grade_description,
            'health_index': round(self.health_index, 1),
            'health_index_display': f"{self.health_index:.0f}%",
            'risk_trend': risk_trend,
            'key_metrics': [
                {
                    'label': 'Critical Issues',
                    'value': self.critical.count,
                    'status': 'danger' if self.critical.count > 0 else 'success'
                },
                {
                    'label': 'High Severity',
                    'value': self.high.count,
                    'status': 'warning' if self.high.count > 3 else 'success'
                },
                {
                    'label': 'Total Findings',
                    'value': self.triggered_findings,
                    'status': 'info'
                },
                {
                    'label': 'Risk Exposure',
                    'value': f"{self.total_weighted_exposure:.0f}",
                    'status': 'warning' if self.total_weighted_exposure > 100 else 'success'
                }
            ],
            'top_priorities': [
                {
                    'rank': item.get('rank'),
                    'title': item.get('title'),
                    'asset': item.get('asset_id') or item.get('asset_name', 'Unknown'),
                    'priority_score': item.get('priority_score')
                }
                for item in self.priority_queue[:5]
            ],
            'remediation_summary': {
                'immediate_action': self.critical.count,
                'short_term': self.high.count,
                'planned': self.medium.count + self.low.count
            }
        }


class AggregationEngine:
    """
    Aggregates scored findings into assessment summary.
    
    Responsibilities:
    1. Calculate total and per-severity exposure metrics
    2. Compute health index (0-100)
    3. Assign letter grade (A+ to F)
    4. Generate priority queue (top N findings by priority_score)
    
    Usage:
        engine = AggregationEngine()
        
        # Aggregate scored findings
        score = engine.aggregate(scored_findings, total_assets=150)
        
        # Get executive summary
        summary = score.get_executive_summary()
        
        # Access priority queue
        for item in score.priority_queue:
            print(f"Fix: {item['title']} (priority: {item['priority_score']})")
    
    Health Index Formula:
        max_possible = total_assets × max_score_per_asset (default 100)
        exposure_ratio = total_weighted_exposure / max_possible
        health_index = 100 × (1 - exposure_ratio)
        
    This means:
        - 0 findings = 100% health
        - Exposure equal to max_possible = 0% health
        - Linear interpolation between
    """
    
    def __init__(self,
                 grade_thresholds: Dict[str, int] = None,
                 grade_descriptions: Dict[str, str] = None,
                 max_score_per_asset: float = 100.0):
        """
        Initialize aggregation engine.
        
        Args:
            grade_thresholds: Override GRADE_THRESHOLDS
            grade_descriptions: Override GRADE_DESCRIPTIONS
            max_score_per_asset: Maximum possible weighted score per asset
                                 Used for health index calculation
        """
        self.grade_thresholds = grade_thresholds or GRADE_THRESHOLDS
        self.grade_descriptions = grade_descriptions or GRADE_DESCRIPTIONS
        self.max_score_per_asset = max_score_per_asset
    
    def aggregate(self,
                  scored_findings: List[ScoredFinding],
                  total_assets: int = None,
                  assets_with_context: int = None) -> AssessmentScore:
        """
        Aggregate scored findings into assessment summary.
        
        Args:
            scored_findings: List of ScoredFinding objects from ScoringEngine
            total_assets: Total number of assets assessed (for health index)
                         If None, uses count of unique asset_ids in findings
            assets_with_context: Number of assets that had context applied
                                If None, counts from findings
        
        Returns:
            AssessmentScore with all metrics calculated
        """
        score = AssessmentScore()
        score.assessment_timestamp = datetime.now(timezone.utc).isoformat()
        
        # Filter to triggered findings only for metrics
        triggered = [f for f in scored_findings if f.triggered]
        
        score.total_findings = len(scored_findings)
        score.triggered_findings = len(triggered)
        
        # Calculate total assets if not provided
        if total_assets is not None:
            score.total_assets_assessed = total_assets
        else:
            # Count unique asset_ids
            unique_assets = set()
            for f in scored_findings:
                if f.asset_id:
                    unique_assets.add(f.asset_id)
            score.total_assets_assessed = len(unique_assets) if unique_assets else len(triggered)
        
        # Count assets with context
        if assets_with_context is not None:
            score.assets_with_context = assets_with_context
        else:
            score.assets_with_context = sum(1 for f in triggered if f.asset_context_applied)
        
        # Calculate context coverage
        if score.total_assets_assessed > 0:
            score.context_coverage_percent = (
                score.assets_with_context / score.total_assets_assessed
            ) * 100
        
        # Aggregate by severity
        severity_map = {
            'critical': score.critical,
            'high': score.high,
            'medium': score.medium,
            'low': score.low,
            'info': score.info
        }
        
        for finding in triggered:
            severity = finding.severity.lower()
            breakdown = severity_map.get(severity, score.medium)  # Default to medium
            
            breakdown.count += 1
            breakdown.total_base_score += finding.base_risk_score
            breakdown.total_weighted_score += finding.weighted_score
            
            score.total_base_exposure += finding.base_risk_score
            score.total_weighted_exposure += finding.weighted_score
        
        # Calculate average weights per severity
        for breakdown in severity_map.values():
            if breakdown.count > 0 and breakdown.total_base_score > 0:
                breakdown.average_weight = (
                    breakdown.total_weighted_score / breakdown.total_base_score
                )
        
        # Calculate assets at risk (assets with triggered findings)
        assets_with_findings = set()
        for finding in triggered:
            if finding.asset_id:
                assets_with_findings.add(finding.asset_id)
        
        score.assets_at_risk = len(assets_with_findings)
        score.compliant_assets = max(0, score.total_assets_assessed - score.assets_at_risk)
        
        # Calculate percentages
        if score.total_assets_assessed > 0:
            score.assets_at_risk_percent = (score.assets_at_risk / score.total_assets_assessed) * 100
            score.compliance_percent = (score.compliant_assets / score.total_assets_assessed) * 100
        else:
            score.assets_at_risk_percent = 0.0
            score.compliance_percent = 100.0
        
        # Calculate max possible exposure and risk exposure percentage
        # Max exposure = total_assets × max_score_per_asset (default 100)
        score.max_possible_exposure = score.total_assets_assessed * self.max_score_per_asset
        if score.max_possible_exposure > 0:
            score.risk_exposure_percent = (score.total_weighted_exposure / score.max_possible_exposure) * 100
        else:
            score.risk_exposure_percent = 0.0
        
        # Calculate assets at risk (unique assets with triggered findings)
        assets_with_findings = set()
        for finding in triggered:
            # Try multiple fields to identify the asset
            asset_id = finding.asset_id
            if not asset_id and finding.evidence:
                asset_id = (
                    finding.evidence.get('fingerprint_sha256') or
                    finding.evidence.get('subject_cn') or
                    finding.evidence.get('key_id') or
                    finding.evidence.get('serial_number')
                )
            if asset_id:
                assets_with_findings.add(asset_id)
        
        score.assets_at_risk = len(assets_with_findings)
        score.compliant_assets = max(0, score.total_assets_assessed - score.assets_at_risk)
        
        # Calculate percentages
        if score.total_assets_assessed > 0:
            score.assets_at_risk_percent = (score.assets_at_risk / score.total_assets_assessed) * 100
            score.compliance_percent = (score.compliant_assets / score.total_assets_assessed) * 100
        else:
            score.assets_at_risk_percent = 0.0
            score.compliance_percent = 100.0
        
        # Calculate max possible exposure and risk exposure percentage
        score.max_possible_exposure = score.total_assets_assessed * self.max_score_per_asset
        if score.max_possible_exposure > 0:
            score.risk_exposure_percent = (score.total_weighted_exposure / score.max_possible_exposure) * 100
        else:
            score.risk_exposure_percent = 0.0
        
        # Calculate health index using blended model (severity + compliance)
        score.health_index = self.calculate_health_index(
            critical_count=score.critical.count,
            high_count=score.high.count,
            medium_count=score.medium.count,
            low_count=score.low.count,
            info_count=score.info.count,
            total_assets=score.total_assets_assessed,
            compliant_assets=score.compliant_assets
        )
        
        # Assign grade
        score.grade = self._get_grade(score.health_index)
        score.grade_description = self.grade_descriptions.get(
            score.grade,
            'Assessment complete'
        )
        
        # Generate priority queue
        score.priority_queue = self.generate_priority_queue(triggered, top_n=10)
        
        # Set highest priority finding per severity
        for severity, breakdown in severity_map.items():
            severity_findings = [f for f in triggered if f.severity.lower() == severity]
            if severity_findings:
                top_finding = max(severity_findings, key=lambda f: f.priority_score)
                breakdown.highest_priority_finding = {
                    'rule_id': top_finding.rule_id,
                    'title': top_finding.title,
                    'asset_id': top_finding.asset_id,
                    'priority_score': round(top_finding.priority_score, 2)
                }
        
        return score
    
    def calculate_health_index(self,
                               critical_count: int = 0,
                               high_count: int = 0,
                               medium_count: int = 0,
                               low_count: int = 0,
                               info_count: int = 0,
                               total_assets: int = 0,
                               compliant_assets: int = 0) -> float:
        """
        Calculate health index (0-100, higher = better) using a blended model.
        
        This combines severity-based penalties with compliance ratio to provide
        a more balanced view that accounts for both the nature of findings and
        the proportion of compliant assets.
        
        Formula:
            severity_health = 100 - penalty (capped at 0-100)
            compliance_health = (compliant_assets / total_assets) × 100
            health_index = (severity_health × 0.4) + (compliance_health × 0.6)
        
        Penalty weights:
        - Critical: 20 points per finding
        - High: 5 points per finding
        - Medium: 2 points per finding
        - Low: 0.5 points per finding
        - Info: 0 points (informational)
        
        The 40/60 weighting prioritises compliance ratio while still heavily
        penalising critical/high severity findings.
        
        Examples:
            - 100 assets, 80 compliant, no findings: (100×0.4) + (80×0.6) = 88%
            - 100 assets, 80 compliant, 2 critical: (60×0.4) + (80×0.6) = 72%
            - 46 assets, 22 compliant, 5 high: (75×0.4) + (48×0.6) = 59%
        
        Args:
            critical_count: Number of critical severity findings
            high_count: Number of high severity findings
            medium_count: Number of medium severity findings
            low_count: Number of low severity findings
            info_count: Number of info severity findings (no penalty)
            total_assets: Total number of assets assessed
            compliant_assets: Number of assets without findings
            
        Returns:
            Health index between 0 and 100
        """
        # Severity penalty weights
        PENALTY_CRITICAL = 20.0
        PENALTY_HIGH = 5.0
        PENALTY_MEDIUM = 2.0
        PENALTY_LOW = 0.5
        PENALTY_INFO = 0.0
        
        # Calculate severity-based health (original model)
        penalty = (
            (critical_count * PENALTY_CRITICAL) +
            (high_count * PENALTY_HIGH) +
            (medium_count * PENALTY_MEDIUM) +
            (low_count * PENALTY_LOW) +
            (info_count * PENALTY_INFO)
        )
        severity_health = max(0.0, min(100.0, 100.0 - penalty))
        
        # Calculate compliance-based health
        if total_assets > 0:
            compliance_health = (compliant_assets / total_assets) * 100.0
        else:
            compliance_health = 100.0  # No assets = assume healthy
        
        # Blend the two metrics (40% severity, 60% compliance)
        SEVERITY_WEIGHT = 0.4
        COMPLIANCE_WEIGHT = 0.6
        
        health_index = (severity_health * SEVERITY_WEIGHT) + (compliance_health * COMPLIANCE_WEIGHT)
        
        return max(0.0, min(100.0, health_index))
    
    def _get_grade(self, health_index: float) -> str:
        """
        Map health index to letter grade.
        
        Args:
            health_index: Health index (0-100)
            
        Returns:
            Letter grade (A+ to F)
        """
        # Sort thresholds descending
        sorted_grades = sorted(
            self.grade_thresholds.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        for grade, threshold in sorted_grades:
            if health_index >= threshold:
                return grade
        
        return 'F'  # Below all thresholds
    
    def generate_priority_queue(self,
                                 scored_findings: List[ScoredFinding],
                                 top_n: int = 10) -> List[Dict[str, Any]]:
        """
        Generate priority queue sorted by ROI (risk reduction per effort).
        
        Priority Score = weighted_score / effort_estimate
        
        Higher priority_score = fix this first (more bang for buck)
        
        Args:
            scored_findings: List of ScoredFinding objects
            top_n: Number of top findings to return
            
        Returns:
            List of priority queue items (dicts) with rank
        """
        # Filter to triggered findings only
        triggered = [f for f in scored_findings if f.triggered]
        
        if not triggered:
            return []
        
        # Sort by priority_score descending
        sorted_findings = sorted(
            triggered,
            key=lambda f: f.priority_score,
            reverse=True
        )
        
        # Build priority queue with rank
        queue = []
        for i, finding in enumerate(sorted_findings[:top_n]):
            queue.append({
                'rank': i + 1,
                'rule_id': finding.rule_id,
                'rule_name': finding.rule_name,
                'title': finding.title,
                'severity': finding.severity,
                'asset_id': finding.asset_id,
                'asset_name': finding.evidence.get('subject_cn') or finding.evidence.get('name', ''),
                'base_risk_score': round(finding.base_risk_score, 2),
                'weighted_score': round(finding.weighted_score, 2),
                'weight_applied': round(finding.weight_factors.combined, 2),
                'effort_estimate': finding.effort_estimate,
                'priority_score': round(finding.priority_score, 2),
                'remediation': finding.remediation,
                'context_applied': finding.asset_context_applied
            })
        
        return queue
    
    def get_remediation_roadmap(self,
                                 scored_findings: List[ScoredFinding],
                                 phases: int = 3) -> Dict[str, Any]:
        """
        Generate a phased remediation roadmap.
        
        Divides findings into phases based on priority:
        - Phase 1 (Immediate): Critical + top high priority
        - Phase 2 (Short-term): Remaining high + top medium
        - Phase 3 (Planned): Remaining medium + low
        
        Args:
            scored_findings: List of ScoredFinding objects
            phases: Number of phases (default 3)
            
        Returns:
            Roadmap dict with phases and estimated effort
        """
        triggered = [f for f in scored_findings if f.triggered]
        sorted_findings = sorted(triggered, key=lambda f: f.priority_score, reverse=True)
        
        # Separate by severity first
        critical = [f for f in sorted_findings if f.severity.lower() == 'critical']
        high = [f for f in sorted_findings if f.severity.lower() == 'high']
        medium = [f for f in sorted_findings if f.severity.lower() == 'medium']
        low = [f for f in sorted_findings if f.severity.lower() in ('low', 'info')]
        
        roadmap = {
            'total_findings': len(triggered),
            'total_effort': sum(f.effort_estimate for f in triggered),
            'phases': []
        }
        
        # Phase 1: All critical + top 50% of high
        phase1_findings = critical + high[:len(high)//2 + 1]
        if phase1_findings:
            roadmap['phases'].append({
                'phase': 1,
                'name': 'Immediate Action',
                'timeframe': '0-30 days',
                'findings_count': len(phase1_findings),
                'effort_estimate': sum(f.effort_estimate for f in phase1_findings),
                'risk_reduction': sum(f.weighted_score for f in phase1_findings),
                'items': [
                    {
                        'title': f.title,
                        'asset': f.asset_id or f.evidence.get('subject_cn', ''),
                        'priority_score': round(f.priority_score, 2)
                    }
                    for f in phase1_findings[:10]  # Top 10 per phase
                ]
            })
        
        # Phase 2: Remaining high + top 50% of medium
        phase2_findings = high[len(high)//2 + 1:] + medium[:len(medium)//2 + 1]
        if phase2_findings:
            roadmap['phases'].append({
                'phase': 2,
                'name': 'Short-term Remediation',
                'timeframe': '30-90 days',
                'findings_count': len(phase2_findings),
                'effort_estimate': sum(f.effort_estimate for f in phase2_findings),
                'risk_reduction': sum(f.weighted_score for f in phase2_findings),
                'items': [
                    {
                        'title': f.title,
                        'asset': f.asset_id or f.evidence.get('subject_cn', ''),
                        'priority_score': round(f.priority_score, 2)
                    }
                    for f in phase2_findings[:10]
                ]
            })
        
        # Phase 3: Remaining medium + all low
        phase3_findings = medium[len(medium)//2 + 1:] + low
        if phase3_findings:
            roadmap['phases'].append({
                'phase': 3,
                'name': 'Planned Remediation',
                'timeframe': '90+ days',
                'findings_count': len(phase3_findings),
                'effort_estimate': sum(f.effort_estimate for f in phase3_findings),
                'risk_reduction': sum(f.weighted_score for f in phase3_findings),
                'items': [
                    {
                        'title': f.title,
                        'asset': f.asset_id or f.evidence.get('subject_cn', ''),
                        'priority_score': round(f.priority_score, 2)
                    }
                    for f in phase3_findings[:10]
                ]
            })
        
        return roadmap


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_default_aggregation_engine() -> AggregationEngine:
    """
    Create an aggregation engine with default configuration.
    
    Returns:
        AggregationEngine with default grade thresholds
    """
    return AggregationEngine()


def score_and_aggregate(findings: List,
                        asset_contexts: Dict[str, Dict] = None,
                        total_assets: int = None) -> Tuple[List[ScoredFinding], AssessmentScore]:
    """
    Convenience function to score findings and aggregate in one call.
    
    Args:
        findings: List of RuleResult objects or dicts
        asset_contexts: Dict mapping asset_id -> context dict
        total_assets: Total assets assessed (for health index)
        
    Returns:
        Tuple of (scored_findings, assessment_score)
    """
    # Score findings
    scoring_engine = ScoringEngine()
    scored_findings = scoring_engine.score_findings_batch(findings, asset_contexts)
    
    # Aggregate
    aggregation_engine = AggregationEngine()
    assessment_score = aggregation_engine.aggregate(
        scored_findings,
        total_assets=total_assets
    )
    
    return scored_findings, assessment_score
