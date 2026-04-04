"""
Policy Assessment Service Layer for CAIP

Centralizes policy assessment operations to eliminate code duplication.
Provides standardized methods for:
- Converting model objects to assessment-ready dictionaries
- Evaluating assets against policy rules
- Aggregating findings from multiple asset types
- Algorithmic scoring with weighted prioritization (Phase 3)

Previously duplicated code locations consolidated here:
- _scan_orchestrator.py _phase_7_policy_assessment() 
- _scan_orchestrator.py _convert_*_to_dicts() methods
"""

import datetime
import logging
from typing import Dict, List, Any, Optional, Tuple

from .rule_assessment import UnifiedAssessor, RuleResult
from caip_scanning_functions.models import (
    CertificateInfo,
    AzureKeyVaultKeyInfo,
    KeyInfo,
    TLSScanResult,
    CRLInfo,
    ScanResults
)

# Import scoring service (Phase 3)
try:
    from caip_service_layer.scoring_service import (
        ScoringEngine,
        AggregationEngine,
        ScoredFinding,
        AssessmentScore
    )
    SCORING_AVAILABLE = True
except ImportError:
    SCORING_AVAILABLE = False

logger = logging.getLogger('caip.operational')


class PolicyAssessmentService:
    """
    Centralized policy assessment operations service.
    
    Provides standardized methods for:
    - Converting model objects to dictionaries for rule evaluation
    - Assessing individual assets or batches against policy
    - Aggregating findings across asset types
    - Algorithmic scoring with context-aware weighting (Phase 3)
    """
    
    # =========================================================================
    # CERTIFICATE CONVERSION FOR ASSESSMENT
    # =========================================================================
    
    @staticmethod
    def certificate_to_assessment_dict(cert: CertificateInfo) -> Dict[str, Any]:
        """
        Convert CertificateInfo object to dictionary for rule evaluation.
        
        This provides the full set of fields needed for policy assessment,
        including computed fields like days_until_expiration.
        
        Args:
            cert: CertificateInfo object to convert
            
        Returns:
            Dictionary suitable for rule evaluation
        """
        # Helper to handle both datetime and string dates
        def to_iso_string(date_val):
            if date_val is None:
                return None
            if isinstance(date_val, str):
                return date_val
            if hasattr(date_val, 'isoformat'):
                return date_val.isoformat()
            return str(date_val)
        
        # Calculate certificate validity days and expiration
        certificate_validity_days = 0
        days_until_expiration = 0
        
        try:
            # Parse dates
            if isinstance(cert.not_after, str):
                not_after = datetime.datetime.fromisoformat(cert.not_after.replace('Z', '+00:00'))
            else:
                not_after = cert.not_after
            
            if isinstance(cert.not_before, str):
                not_before = datetime.datetime.fromisoformat(cert.not_before.replace('Z', '+00:00'))
            else:
                not_before = cert.not_before
            
            # Calculate validity period in days
            if not_after and not_before:
                certificate_validity_days = (not_after - not_before).days
            
            # Calculate days until expiration
            if not_after:
                now = datetime.datetime.now(datetime.timezone.utc) if not_after.tzinfo else datetime.datetime.now()
                days_until_expiration = (not_after - now).days
        except Exception as e:
            logger.debug(f"Could not calculate certificate validity days: {e}")
        
        
        # Extract extensions with safe fallbacks
        san_list = getattr(cert, 'san', []) if hasattr(cert, 'san') else []
        key_usage = getattr(cert, 'key_usage', []) if hasattr(cert, 'key_usage') else []
        extended_key_usage = getattr(cert, 'extended_key_usage', []) if hasattr(cert, 'extended_key_usage') else []
        ocsp_responders = getattr(cert, 'ocsp_responders', []) if hasattr(cert, 'ocsp_responders') else []
        crl_distribution_points = getattr(cert, 'crl_distribution_points', []) if hasattr(cert, 'crl_distribution_points') else []

        # Check certificate properties
        is_self_signed = getattr(cert, 'is_self_signed', False)
        is_ca = getattr(cert, 'is_ca', False)
        trusted_issuer_available = (
            getattr(cert, 'is_root_ca', False) or
            (cert.issuer.get('commonName', '').lower() != 'unknown' if cert.issuer else False)
        )

        # Computed field: Certificate has revocation checking support (OCSP or CRL)
        ocsp_or_crl_implemented = (len(ocsp_responders) > 0) or (len(crl_distribution_points) > 0)

        return {
            'id': cert.unique_id,
            'subject_cn': cert.subject.get('commonName', 'Unknown') if cert.subject else 'Unknown',
            'issuer_cn': cert.issuer.get('commonName', 'Unknown') if cert.issuer else 'Unknown',
            'signature_algorithm': cert.signature_algorithm,
            'public_key_algorithm': cert.public_key_algorithm,
            'public_key_size': cert.public_key_size,
            'key_curve': getattr(cert, 'key_curve', None),
            'not_before': to_iso_string(cert.not_before),
            'not_after': to_iso_string(cert.not_after),
            'serial_number': cert.serial_number,
            'source': cert.source,
            'is_root_ca': getattr(cert, 'is_root_ca', False),
            'is_intermediate_ca': getattr(cert, 'is_intermediate_ca', False),
            'crl_distribution_points': getattr(cert, 'crl_distribution_points', []),
            'extensions': getattr(cert, 'extensions', {}),
            'certificate_validity_days': certificate_validity_days,
            'days_until_expiration': days_until_expiration,
            'is_self_signed': is_self_signed,
            'is_ca': is_ca,
            'san': san_list,
            'san_count': len(san_list),
            'key_usage': key_usage,
            'extended_key_usage': extended_key_usage,
            'ocsp_responders': ocsp_responders,
            'trusted_issuer_available': trusted_issuer_available,
            # Revocation checking capability - computed field (policy rules reference this)
            'ocsp_or_crl_implemented': ocsp_or_crl_implemented,
            # PQC Analysis fields for rule evaluation
            'pqc_analysis': getattr(cert, 'pqc_analysis', None),
            'is_pqc': cert.pqc_analysis.get('is_pqc', False) if hasattr(cert, 'pqc_analysis') and cert.pqc_analysis else False,
            'is_hybrid': cert.pqc_analysis.get('is_hybrid', False) if hasattr(cert, 'pqc_analysis') and cert.pqc_analysis else False,
            'pqc_algorithm': cert.pqc_analysis.get('pqc_algorithm') if hasattr(cert, 'pqc_analysis') and cert.pqc_analysis else None,
            'migration_status': cert.pqc_analysis.get('migration_status', 'unknown') if hasattr(cert, 'pqc_analysis') and cert.pqc_analysis else 'needs_migration',
        }
    
    @staticmethod
    def certificates_to_assessment_dicts(certs: List[CertificateInfo]) -> List[Dict[str, Any]]:
        """
        Convert a list of CertificateInfo objects to assessment dictionaries.
        
        Args:
            certs: List of CertificateInfo objects
            
        Returns:
            List of dictionary representations for rule evaluation
        """
        return [
            PolicyAssessmentService.certificate_to_assessment_dict(cert)
            for cert in certs
        ]
    
    # =========================================================================
    # TLS RESULT CONVERSION FOR ASSESSMENT
    # =========================================================================
    
    @staticmethod
    def tls_result_to_assessment_dict(tls_result: TLSScanResult) -> Dict[str, Any]:
        """
        Convert TLSScanResult object to dictionary for rule evaluation.

        IMPORTANT: This returns the TLS endpoint info. The actual certificates
        in certificate_chain are assessed separately via certificate_to_assessment_dict()
        to ensure all certificate fields (including ocsp_or_crl_implemented) are available.

        Args:
            tls_result: TLSScanResult object to convert

        Returns:
            Dictionary suitable for rule evaluation
        """
        return {
            'id': f"{tls_result.host}:{tls_result.port}",
            'host': tls_result.host,
            'port': tls_result.port,
            'supported_protocols': tls_result.supported_protocols,
            'certificate_chain': [
                c.subject.get('commonName', 'Unknown') if c.subject else 'Unknown'
                for c in tls_result.certificate_chain
            ],
            'tls_library': getattr(tls_result, 'tls_library', None),
            'tls_version': getattr(tls_result, 'tls_version', None),
        }
    
    @staticmethod
    def tls_results_to_assessment_dicts(tls_results: List[TLSScanResult]) -> List[Dict[str, Any]]:
        """
        Convert a list of TLSScanResult objects to assessment dictionaries.
        
        Args:
            tls_results: List of TLSScanResult objects
            
        Returns:
            List of dictionary representations for rule evaluation
        """
        return [
            PolicyAssessmentService.tls_result_to_assessment_dict(tls_result)
            for tls_result in tls_results
        ]
    
    # =========================================================================
    # KEY CONVERSION FOR ASSESSMENT
    # =========================================================================
    
    @staticmethod
    def key_to_assessment_dict(key: Any) -> Dict[str, Any]:
        """
        Convert a key object to dictionary for rule evaluation.
        
        Handles both AzureKeyVaultKeyInfo and generic KeyInfo objects.
        
        Args:
            key: Key object (AzureKeyVaultKeyInfo, KeyInfo, or similar)
            
        Returns:
            Dictionary suitable for rule evaluation
        """
        # Handle AzureKeyVaultKeyInfo
        if isinstance(key, AzureKeyVaultKeyInfo):
            return {
                'id': key.key_id,
                'name': key.name,
                'label': key.label,
                'key_type': key.key_type,
                'key_size': key.key_size,
                'key_curve': key.key_curve,
                'key_operations': key.key_operations,
                'enabled': key.enabled,
                'created_on': key.created_on,
                'updated_on': key.updated_on,
                'expires_on': key.expires_on,
                'not_before': key.not_before,
                'hsm_backed': key.hsm_backed,
                'managed': key.managed,
                'source': key.source,
                'vault_url': key.vault_url,
                'tenancy_name': key.tenancy_name,
                'service_principal_name': key.service_principal_name,
                'tags': key.tags,
                'recovery_level': key.recovery_level,
                'pqc_analysis': getattr(key, 'pqc_analysis', None),
            }
        
        # Handle generic KeyInfo or dict-like objects
        if hasattr(key, '__dict__'):
            return {k: v for k, v in key.__dict__.items() if not k.startswith('_')}
        
        # Already a dict
        if isinstance(key, dict):
            return key
        
        # Fallback
        return {'id': str(key)}
    
    @staticmethod
    def keys_to_assessment_dicts(keys: List[Any]) -> List[Dict[str, Any]]:
        """
        Convert a list of key objects to assessment dictionaries.
        
        Args:
            keys: List of key objects
            
        Returns:
            List of dictionary representations for rule evaluation
        """
        return [
            PolicyAssessmentService.key_to_assessment_dict(key)
            for key in keys
        ]
    
    # =========================================================================
    # CRL CONVERSION FOR ASSESSMENT
    # =========================================================================
    
    @staticmethod
    def crl_to_assessment_dict(crl: CRLInfo, source_url: str = None) -> Dict[str, Any]:
        """
        Convert CRLInfo object to dictionary for rule evaluation.
        
        Args:
            crl: CRLInfo object to convert
            source_url: Optional source URL for identification
            
        Returns:
            Dictionary suitable for rule evaluation
        """
        return {
            'id': source_url or crl.source_url,
            'source_url': source_url or crl.source_url,
            'issuer': crl.issuer,
            'this_update': crl.this_update,
            'next_update': crl.next_update,
            'total_revoked': crl.total_revoked,
            'signature_algorithm': crl.signature_algorithm,
            'is_stale': crl.is_stale,
        }
    
    # =========================================================================
    # SCAN RESULTS ASSESSMENT (for model objects)
    # =========================================================================
    
    @staticmethod
    def assess_scan_results(scan_results: ScanResults,
                            policy: Dict[str, Any]) -> Tuple[List[RuleResult], Dict[str, Any]]:
        """
        Assess ScanResults model against a policy.
        
        Args:
            scan_results: ScanResults object containing all scan data
            policy: Policy dictionary (v2.0 format)
            
        Returns:
            Tuple of:
                - List of triggered RuleResult objects
                - Assessment summary dict
                
        Raises:
            ValueError: If policy fails to load
        """
        assessor = UnifiedAssessor()
        
        if not assessor.load_policy(policy):
            raise ValueError("Failed to load policy")
        
        findings = []
        summary = {
            'certificates_assessed': 0,
            'keys_assessed': 0,
            'tls_endpoints_assessed': 0,
            'crls_assessed': 0,
            'total_findings': 0
        }
        
        # Assess certificates - prefer normalised data if available
        if scan_results.normalised_certificates:
            summary['certificates_assessed'] = len(scan_results.normalised_certificates)
            cert_dicts = scan_results.normalised_certificates
            cert_results = assessor.assess_batch(cert_dicts, asset_type='certificate')
            for asset_id, results in cert_results.items():
                findings.extend([r for r in results if r.triggered])
        elif scan_results.certificates:
            summary['certificates_assessed'] = len(scan_results.certificates)
            cert_dicts = PolicyAssessmentService.certificates_to_assessment_dicts(
                scan_results.certificates
            )
            cert_results = assessor.assess_batch(cert_dicts, asset_type='certificate')
            for asset_id, results in cert_results.items():
                findings.extend([r for r in results if r.triggered])
        
        # Assess TLS results
        if scan_results.tls_results:
            summary['tls_endpoints_assessed'] = len(scan_results.tls_results)
            tls_dicts = PolicyAssessmentService.tls_results_to_assessment_dicts(
                scan_results.tls_results
            )
            tls_results = assessor.assess_batch(tls_dicts, asset_type='tls_endpoint')
            for asset_id, results in tls_results.items():
                findings.extend([r for r in results if r.triggered])
        
        # Assess keys - prefer normalised data if available
        if scan_results.normalised_keys:
            summary['keys_assessed'] = len(scan_results.normalised_keys)
            key_dicts = scan_results.normalised_keys
            key_results = assessor.assess_batch(key_dicts, asset_type='key')
            for asset_id, results in key_results.items():
                findings.extend([r for r in results if r.triggered])
        elif scan_results.azure_keys:
            summary['keys_assessed'] = len(scan_results.azure_keys)
            key_dicts = PolicyAssessmentService.keys_to_assessment_dicts(
                scan_results.azure_keys
            )
            key_results = assessor.assess_batch(key_dicts, asset_type='key')
            for asset_id, results in key_results.items():
                findings.extend([r for r in results if r.triggered])
        
        # Assess CRLs
        if scan_results.crls:
            summary['crls_assessed'] = len(scan_results.crls)
            for url, crl in scan_results.crls.items():
                crl_dict = PolicyAssessmentService.crl_to_assessment_dict(crl, url)
                crl_results = assessor.assess_crl(crl_dict)
                findings.extend([r for r in crl_results if r.triggered])
        
        summary['total_findings'] = len(findings)
        
        return findings, summary
    
    # =========================================================================
    # CERTIFICATE BATCH ASSESSMENT
    # =========================================================================
    
    @staticmethod
    def assess_certificates(certs: List[CertificateInfo],
                           policy: Dict[str, Any]) -> List[RuleResult]:
        """
        Assess a list of certificates against a policy.
        
        Args:
            certs: List of CertificateInfo objects
            policy: Policy dictionary (v2.0 format)
            
        Returns:
            List of triggered RuleResult objects
            
        Raises:
            ValueError: If policy fails to load
        """
        assessor = UnifiedAssessor()
        if not assessor.load_policy(policy):
            raise ValueError("Failed to load policy")
        
        cert_dicts = PolicyAssessmentService.certificates_to_assessment_dicts(certs)
        findings = []
        
        cert_results = assessor.assess_batch(cert_dicts, asset_type='certificate')
        for asset_id, results in cert_results.items():
            findings.extend([r for r in results if r.triggered])
        
        return findings
    
    @staticmethod
    def assess_single_certificate(cert: CertificateInfo,
                                   policy: Dict[str, Any]) -> List[RuleResult]:
        """
        Assess a single certificate against a policy.
        
        Args:
            cert: CertificateInfo object
            policy: Policy dictionary (v2.0 format)
            
        Returns:
            List of rule results (both triggered and not triggered)
        """
        assessor = UnifiedAssessor()
        if not assessor.load_policy(policy):
            raise ValueError("Failed to load policy")
        
        cert_dict = PolicyAssessmentService.certificate_to_assessment_dict(cert)
        return assessor.assess_certificate(cert_dict)

    # =========================================================================
    # RAW REPORT DATA ASSESSMENT (for reassessment and aggregation)
    # =========================================================================
    
    @staticmethod
    def assess_report_data(report_data: Dict[str, Any], 
                           policy: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Assess raw report data (dicts) against a policy.
        
        Used for reassessment and aggregation where data comes from 
        existing JSON reports rather than fresh ScanResults objects.
        
        Unlike assess_scan_results() which expects model objects,
        this method works directly with dictionary data from JSON reports.
        
        Args:
            report_data: Dictionary containing:
                - certificates: List of certificate dicts
                - keys: List of key dicts  
                - azure_keys: List of Azure key dicts (optional)
                - tls_results: List of TLS scan result dicts (optional)
                - crls: Dict mapping URL to CRL info dicts (optional)
                - file_scan: List of file scan result dicts (optional)
            policy: Policy dictionary (v2.0 format)
            
        Returns:
            Tuple of:
                - List of triggered finding dictionaries (already serialized)
                - Assessment summary dict with counts

        Raises:
            ValueError: If policy fails to load
        """
        # DEBUG: Entry point tracing
        logger.info("[SERVICE] assess_report_data() called")
        logger.debug(f"[SERVICE] policy object type: {type(policy)}")
        logger.debug(f"[SERVICE] policy is None: {policy is None}")

        # Initialize the assessor
        assessor = UnifiedAssessor()

        if not assessor.load_policy(policy):
            logger.error("[SERVICE] FAILED to load policy into assessor!")
            raise ValueError("Failed to load policy - check policy format and rule definitions")

        logger.info("[SERVICE] Policy loaded successfully into assessor")
        
        findings_list = []
        summary = {
            'certificates_assessed': 0,
            'keys_assessed': 0,
            'tls_endpoints_assessed': 0,
            'crls_assessed': 0,
            'files_assessed': 0,
            'total_findings': 0
        }
        
        # Assess certificates
        certificates = report_data.get('certificates', [])
        if certificates:
            summary['certificates_assessed'] = len(certificates)
            for cert_dict in certificates:
                if isinstance(cert_dict, dict):
                    results = assessor.assess_certificate(cert_dict)
                    
                    # Inject certificate identification into each finding's evidence
                    for result in results:
                        if isinstance(result, dict):
                            evidence = result.get('evidence', {})
                        else:
                            evidence = getattr(result, 'evidence', {})
                        
                        # Add subject_cn
                        if 'subject_cn' not in evidence:
                            subject = cert_dict.get('subject', {})
                            if isinstance(subject, dict):
                                evidence['subject_cn'] = subject.get('commonName', 'Unknown')
                            else:
                                evidence['subject_cn'] = str(subject) if subject else 'Unknown'
                        
                        # Add source_integration
                        if 'source_integration' not in evidence:
                            evidence['source_integration'] = cert_dict.get('source_integration', '')
                        
                        # Add asset_id for fallback
                        if 'asset_id' not in evidence:
                            evidence['asset_id'] = cert_dict.get('fingerprint_sha256') or cert_dict.get('serial_number', '')
                        
                        if isinstance(result, dict):
                            result['evidence'] = evidence
                        else:
                            result.evidence = evidence
                    
                    findings_list.extend(results)
        
        # Assess keys (both regular and azure_keys)
        keys = report_data.get('keys', [])
        azure_keys = report_data.get('azure_keys', [])
        all_keys = keys + azure_keys
        if all_keys:
            summary['keys_assessed'] = len(all_keys)
            for key_dict in all_keys:
                if isinstance(key_dict, dict):
                    results = assessor.assess_key(key_dict)
                    findings_list.extend(results)
        
        # Assess TLS results
        tls_results = report_data.get('tls_results', [])
        if tls_results:
            summary['tls_endpoints_assessed'] = len(tls_results)
            for tls_dict in tls_results:
                if isinstance(tls_dict, dict):
                    results = assessor.assess_tls_endpoint(tls_dict)
                    findings_list.extend(results)
        
        # Assess CRLs
        crls = report_data.get('crls', {})
        if crls:
            summary['crls_assessed'] = len(crls)
            for crl_url, crl_info in crls.items():
                if isinstance(crl_info, dict):
                    # Add URL to CRL info for identification
                    crl_with_url = dict(crl_info)
                    crl_with_url['source_url'] = crl_url
                    results = assessor.assess_crl(crl_with_url)
                    findings_list.extend(results)
        
        # Assess file scan results
        file_results = report_data.get('file_scan', [])
        if file_results:
            summary['files_assessed'] = len(file_results)
            for file_dict in file_results:
                if isinstance(file_dict, dict):
                    results = assessor.assess_file(file_dict)
                    findings_list.extend(results)
        
        # Filter to triggered findings and convert to dicts
        triggered_findings = []
        for finding in findings_list:
            if finding.triggered:
                triggered_findings.append(finding.to_dict())
        
        summary['total_findings'] = len(triggered_findings)
        
        return triggered_findings, summary
    
    # =========================================================================
    # PHASE 3: ASSESSMENT WITH ALGORITHMIC SCORING
    # =========================================================================
    
    @staticmethod
    def assess_report_data_with_scoring(
        report_data: Dict[str, Any],
        policy: Dict[str, Any],
        asset_contexts: Dict[str, Dict[str, Any]] = None,
        enable_scoring: bool = True,
        db_service = None,
        engagement_id: str = None
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any], Optional['AssessmentScore']]:
        """
        Assess report data with algorithmic scoring applied.
        
        This extends assess_report_data() by adding weighted scoring based on
        asset context (criticality, exposure, data classification). Returns
        scored findings with priority queue for remediation planning.
        
        Args:
            report_data: Dictionary containing asset data (certificates, keys, etc.)
            policy: Policy dictionary (v2.0 format)
            asset_contexts: Optional dict mapping asset_id -> context dict
                           If None and db_service/engagement_id provided,
                           contexts will be loaded from database
            enable_scoring: Whether to apply algorithmic scoring (default True)
            db_service: Optional DatabaseService for loading contexts
            engagement_id: Optional engagement ID for loading contexts
            
        Returns:
            Tuple of:
                - List of finding dictionaries (with scoring if enabled)
                - Assessment summary dict with counts
                - AssessmentScore object (if scoring enabled, else None)
                
        Raises:
            ValueError: If policy fails to load
            ImportError: If scoring requested but scoring_service not available
        """
        # First, run the standard assessment
        findings, summary = PolicyAssessmentService.assess_report_data(
            report_data, policy
        )
        
        # If scoring not enabled, return standard results
        if not enable_scoring:
            return findings, summary, None
        
        # Check scoring availability
        if not SCORING_AVAILABLE:
            logger.warning("Scoring requested but scoring_service not available. "
                          "Returning unscored results.")
            return findings, summary, None
        
        # Load contexts if not provided but db_service and engagement_id are
        if asset_contexts is None and db_service is not None and engagement_id:
            asset_contexts = PolicyAssessmentService._load_contexts_from_db(
                db_service, engagement_id
            )
        
        # Build asset data map for recency calculations
        asset_data_map = PolicyAssessmentService._build_asset_data_map(report_data)
        
        # Calculate total assets for health index
        total_assets = (
            len(report_data.get('certificates', [])) +
            len(report_data.get('keys', [])) +
            len(report_data.get('azure_keys', []))
        )
        
        # Score findings
        scoring_engine = ScoringEngine()
        scored_findings = scoring_engine.score_findings_batch(
            findings,  # These are already dicts from assess_report_data
            asset_contexts=asset_contexts or {},
            asset_data_map=asset_data_map
        )
        
        # Aggregate scores
        aggregation_engine = AggregationEngine()
        assessment_score = aggregation_engine.aggregate(
            scored_findings,
            total_assets=total_assets,
            assets_with_context=len(asset_contexts) if asset_contexts else 0
        )
        
        # Convert scored findings to dicts
        scored_findings_dicts = [sf.to_dict() for sf in scored_findings if sf.triggered]
        
        # Update summary with scoring info
        summary['scoring_applied'] = True
        summary['health_index'] = assessment_score.health_index
        summary['grade'] = assessment_score.grade
        summary['total_weighted_exposure'] = assessment_score.total_weighted_exposure
        
        return scored_findings_dicts, summary, assessment_score
    
    @staticmethod
    def _load_contexts_from_db(db_service, engagement_id: str) -> Dict[str, Dict[str, Any]]:
        """
        Load asset contexts from database for an engagement.
        
        Args:
            db_service: DatabaseService class reference
            engagement_id: Engagement ID
            
        Returns:
            Dict mapping asset_id -> context dict
        """
        try:
            from .asset_context_service import AssetContextService
            
            contexts = AssetContextService.get_engagement_context(
                db_service, engagement_id
            )
            
            # Convert list to lookup dict
            return {
                ctx['asset_id']: ctx
                for ctx in contexts
                if ctx.get('asset_id')
            }
        except Exception as e:
            logger.warning(f"Failed to load contexts from database: {e}")
            return {}
    
    @staticmethod
    def _build_asset_data_map(report_data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """
        Build asset data map for scoring (provides recency data, source, etc.).
        
        Args:
            report_data: Report data containing certificates, keys, etc.
            
        Returns:
            Dict mapping asset_id -> asset data dict
        """
        asset_map = {}
        
        # Map certificates (supports both raw and normalised formats)
        for cert in report_data.get('certificates', []):
            if isinstance(cert, dict):
                asset_id = (
                    cert.get('fingerprint_sha256') or 
                    cert.get('serial_number') or
                    cert.get('id')
                )
                if asset_id:
                    asset_map[asset_id] = cert
                
                # Also map by subject_cn for fallback matching
                # Handle both nested subject dict and flat subject_cn field
                subject_cn = cert.get('subject_cn')
                if not subject_cn:
                    subject = cert.get('subject', {})
                    if isinstance(subject, dict):
                        subject_cn = subject.get('commonName')
                
                if subject_cn:
                    asset_map[subject_cn] = cert    
        
        return asset_map
    
    @staticmethod
    def score_existing_findings(
        findings: List[Dict[str, Any]],
        asset_contexts: Dict[str, Dict[str, Any]] = None,
        asset_data_map: Dict[str, Dict[str, Any]] = None,
        total_assets: int = None
    ) -> Tuple[List[Dict[str, Any]], 'AssessmentScore']:
        """
        Apply scoring to existing findings (already assessed).
        
        Useful for re-scoring findings with updated contexts or
        applying scoring to findings loaded from a previous assessment.
        
        Args:
            findings: List of finding dictionaries
            asset_contexts: Dict mapping asset_id -> context dict
            asset_data_map: Dict mapping asset_id -> asset data dict
            total_assets: Total assets for health index calculation
            
        Returns:
            Tuple of:
                - List of scored finding dictionaries
                - AssessmentScore object
                
        Raises:
            ImportError: If scoring_service not available
        """
        if not SCORING_AVAILABLE:
            raise ImportError("scoring_service not available")
        
        # Score findings
        scoring_engine = ScoringEngine()
        scored_findings = scoring_engine.score_findings_batch(
            findings,
            asset_contexts=asset_contexts or {},
            asset_data_map=asset_data_map or {}
        )
        
        # Aggregate
        aggregation_engine = AggregationEngine()
        assessment_score = aggregation_engine.aggregate(
            scored_findings,
            total_assets=total_assets or len(findings)
        )
        
        # Convert to dicts
        scored_dicts = [sf.to_dict() for sf in scored_findings if sf.triggered]
        
        return scored_dicts, assessment_score
    
    @staticmethod
    def get_priority_queue(
        findings: List[Dict[str, Any]],
        asset_contexts: Dict[str, Dict[str, Any]] = None,
        top_n: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Generate priority queue from findings.
        
        Quick method to get "what to fix first" without full aggregation.
        
        Args:
            findings: List of finding dictionaries
            asset_contexts: Optional context for weighting
            top_n: Number of top priorities to return
            
        Returns:
            List of priority queue items (highest priority first)
        """
        if not SCORING_AVAILABLE:
            # Fallback: sort by severity and risk_score
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
            sorted_findings = sorted(
                findings,
                key=lambda f: (
                    severity_order.get(f.get('severity', 'medium').lower(), 2),
                    -f.get('risk_score', 0)
                )
            )
            return [
                {
                    'rank': i + 1,
                    'rule_id': f.get('rule_id'),
                    'title': f.get('title'),
                    'severity': f.get('severity'),
                    'risk_score': f.get('risk_score'),
                    'remediation': f.get('remediation')
                }
                for i, f in enumerate(sorted_findings[:top_n])
            ]
        
        # Use scoring engine
        scoring_engine = ScoringEngine()
        scored = scoring_engine.score_findings_batch(findings, asset_contexts)
        
        aggregation_engine = AggregationEngine()
        return aggregation_engine.generate_priority_queue(scored, top_n=top_n)
    
    # =========================================================================
    # POLICY VALIDATION
    # =========================================================================
    
    @staticmethod
    def load_and_validate_policy(policy: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Validate a policy can be loaded successfully.
        
        Useful for pre-validation before assessment operations.
        
        Args:
            policy: Policy dictionary to validate
            
        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        try:
            assessor = UnifiedAssessor()
            if assessor.load_policy(policy):
                return True, None
            else:
                return False, "Policy failed to load - check format and rule definitions"
        except Exception as e:
            return False, f"Policy validation error: {str(e)}"
    
    # =========================================================================
    # SCORING AVAILABILITY CHECK
    # =========================================================================
    
    @staticmethod
    def is_scoring_available() -> bool:
        """
        Check if algorithmic scoring is available.
        
        Returns:
            True if scoring_service is importable
        """
        return SCORING_AVAILABLE
