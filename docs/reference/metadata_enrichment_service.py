"""
Metadata Enrichment Service

Provides modular, optional metadata capture for discovered assets.
Separate from core discovery to allow:
- Toggling via UI configuration
- Running as async process
- Reusing across all collectors
- Adding new metadata types without scanner changes

Usage:
    # In ScanOrchestrator phase
    enricher = MetadataEnrichmentService.get_enricher('tls')
    enriched_result = enricher.enrich(result.to_dict(), config)
"""

import logging
from typing import Dict, List, Any, Optional
from caip_service_layer.environment_inference_service import EnvironmentInferenceService

logger = logging.getLogger(__name__)


class MetadataEnrichmentService:
    """Factory service for creating appropriate enrichers by collector type"""

    @classmethod
    def get_enricher(cls, collector_type: str) -> 'BaseEnricher':
        """
        Get enricher for collector type

        Args:
            collector_type: 'tls', 'ejbca', 'azure', 'luna', 'crl'

        Returns:
            Enricher instance
        """
        enrichers = {
            'tls': TLSMetadataEnricher,
            'tls_security': TLSSecurityEnricher,          # Phase 1.5 NEW
            'tls_revocation': TLSRevocationEnricher,      # Phase 1.5 NEW
            'ejbca': EJBCAMetadataEnricher,
            'azure': AzureMetadataEnricher,
            'luna': LunaMetadataEnricher,
            'crl': NoOpEnricher,
        }
        enricher_class = enrichers.get(collector_type, NoOpEnricher)
        return enricher_class()

    @classmethod
    def enrich_assets(cls, collector_type: str, assets: List[Dict],
                     config: Dict) -> List[Dict]:
        """
        Enrich a list of assets with metadata

        Args:
            collector_type: Type of collector ('tls', 'ejbca', etc.)
            assets: List of asset dicts
            config: Enrichment configuration (from scan config)

        Returns:
            Assets with metadata added
        """
        if not config.get('enabled', False):
            return assets  # Pass through unchanged

        enricher = cls.get_enricher(collector_type)
        enriched = []

        for asset in assets:
            try:
                enriched_asset = enricher.enrich(asset, config)
                enriched.append(enriched_asset)
            except Exception as e:
                logger.warning(f"Enrichment error for {collector_type}: {e}")
                enriched.append(asset)  # Return original if enrichment fails

        return enriched


class BaseEnricher:
    """Base class for all enrichers"""

    def enrich(self, asset: Dict, config: Dict) -> Dict:
        """
        Enrich a single asset

        Args:
            asset: Asset dict (raw from collector)
            config: Enrichment configuration

        Returns:
            Asset with metadata fields added
        """
        raise NotImplementedError


class TLSMetadataEnricher(BaseEnricher):
    """Enriches TLS scan results with environment metadata"""

    def enrich(self, tls_result: Dict, config: Dict) -> Dict:
        """
        Enrich TLS result with environment metadata

        Args:
            tls_result: TLSScanResult dict with host, port, certificate_chain
            config: {
                'capture_environment': bool,
                'capture_tls_context': bool,  # Future
                'capture_headers': bool,       # Future
                'capture_vulnerabilities': bool # Future
            }

        Returns:
            tls_result with environment_metadata added
        """
        # Extract environment from hostname/port if enabled
        logger.info(f"[TLSMetadataEnricher] enrich called with capture_environment={config.get('capture_environment', False)}")
        if config.get('capture_environment', False):
            logger.info(f"[TLSMetadataEnricher] tls_result keys: {list(tls_result.keys())}")

            # Try multiple field names for hostname/port (different collectors use different names)
            host = tls_result.get('host') or tls_result.get('found_at_destination') or tls_result.get('hostname')
            port = tls_result.get('port') or tls_result.get('found_on_port')
            ip = tls_result.get('ip') or tls_result.get('ip_address')

            logger.info(f"[TLSMetadataEnricher] Building scan_data for {host}:{port}")

            # Build scan_data from TLS context
            scan_data = {
                'source': 'tls_scan',
                'hostname': host,
                'port': port,
                'ip': ip
            }

            # Get first cert from chain for additional signals
            if tls_result.get('certificate_chain') and len(tls_result['certificate_chain']) > 0:
                first_cert = tls_result['certificate_chain'][0]
                cert_dict = first_cert if isinstance(first_cert, dict) else (
                    first_cert.__dict__ if hasattr(first_cert, '__dict__') else {}
                )

                # Add cryptographic properties (try multiple field names)
                scan_data['public_key_size'] = cert_dict.get('public_key_size')
                scan_data['public_key_algorithm'] = cert_dict.get('public_key_algorithm')
                scan_data['issuer_dn'] = cert_dict.get('issuer') or cert_dict.get('issuer_cn')
                scan_data['is_self_signed'] = cert_dict.get('is_self_signed', False)
                # Normalised certs use 'certificate_validity_days'; check it first
                scan_data['validity_days'] = cert_dict.get('certificate_validity_days') or cert_dict.get('validity_days')
                scan_data['subject_cn'] = cert_dict.get('subject_cn') or cert_dict.get('subject', {}).get('commonName')
                scan_data['signature_algorithm'] = cert_dict.get('signature_algorithm')
                scan_data['key_curve'] = cert_dict.get('key_curve')
                scan_data['is_ca'] = cert_dict.get('is_ca', False)

                logger.info(f"[TLSMetadataEnricher] Extracted cert fields: public_key_size={scan_data.get('public_key_size')}, is_self_signed={scan_data.get('is_self_signed')}, validity_days={scan_data.get('validity_days')}")

            # Call multi-signal orchestrator
            logger.info(f"[TLSMetadataEnricher] Calling infer_from_scan_data with scan_data keys: {list(scan_data.keys())}")
            env_metadata = EnvironmentInferenceService.infer_from_scan_data(
                scan_data=scan_data,
                asset_type='certificate'
            )
            logger.info(f"[TLSMetadataEnricher] Got env_metadata with keys: {list(env_metadata.keys()) if env_metadata else 'None'}")

            # Add to result
            tls_result['environment_metadata'] = env_metadata
        else:
            logger.info(f"[TLSMetadataEnricher] capture_environment is False, skipping enrichment")

        # NEW: Extract metadata fields from certificate data
        if config.get('capture_enrichment', False):
            logger.info(f"[TLSMetadataEnricher] Extracting enrichment metadata")

            # Use first certificate from chain, or full tls_result as fallback
            cert_data = tls_result
            if tls_result.get('certificate_chain') and len(tls_result['certificate_chain']) > 0:
                first_cert = tls_result['certificate_chain'][0]
                cert_data = first_cert if isinstance(first_cert, dict) else (
                    first_cert.__dict__ if hasattr(first_cert, '__dict__') else tls_result
                )

            # Extract all metadata fields using unified methods
            extracted_metadata = {
                'identity': EnvironmentInferenceService.extract_identity_fields(cert_data),
                'purpose': EnvironmentInferenceService.extract_purpose_fields(cert_data),
                'crypto': EnvironmentInferenceService.extract_crypto_fields(cert_data),
                'ha': EnvironmentInferenceService.extract_ha_fields(cert_data)
            }

            tls_result['extracted_enrichment'] = extracted_metadata
            logger.info(f"[TLSMetadataEnricher] Added extracted_enrichment with keys: {list(extracted_metadata.keys())}")

        # Future: TLS context enrichment (ciphers, compression, ALPN)
        if config.get('capture_tls_context', False):
            # TODO: Extract cipher details, compression, protocol range
            pass

        # Future: Header analysis
        if config.get('capture_headers', False):
            # TODO: Extract Server header, CDN detection, HTTP/2 support
            pass

        # Future: Vulnerability assessment
        if config.get('capture_vulnerabilities', False):
            # TODO: Detect CRIME, DROWN, weak ciphers
            pass

        return tls_result


class EJBCAMetadataEnricher(BaseEnricher):
    """Enriches EJBCA certificates with environment metadata"""

    def enrich(self, cert: Dict, config: Dict) -> Dict:
        """
        Enrich EJBCA certificate with environment inference and metadata extraction

        Args:
            cert: Certificate dict from EJBCA
            config: Enrichment configuration
        """
        if config.get('capture_environment', False):
            # Build scan_data from EJBCA certificate fields
            issuer_cn = cert.get('issuer_cn', '')
            subject_cn = cert.get('subject_cn', '')
            ca_name = cert.get('ca_name', '')

            scan_data = {
                'source': ca_name or 'ejbca',
                'issuer_cn': issuer_cn,
                'subject_cn': subject_cn,
                'issuer_dn': cert.get('issuer_dn', issuer_cn),
                # Leverage EJBCA's rich metadata for cryptographic signals
                'public_key_algorithm': cert.get('public_key_algorithm'),
                'public_key_size': cert.get('public_key_size'),
                # Normalised certs use 'certificate_validity_days' (from NormalisedCertificate dataclass line 193)
                # Check certificate_validity_days first (normalised field), then fallback to validity_days (raw field)
                'validity_days': cert.get('certificate_validity_days') or cert.get('validity_days'),
                'is_self_signed': cert.get('is_self_signed', False),
                'certificate_profile': cert.get('certificate_profile'),  # EJBCA-specific
                'ca_name': ca_name
            }

            # Call multi-signal orchestrator for environment inference
            env_metadata = EnvironmentInferenceService.infer_from_scan_data(
                scan_data=scan_data,
                asset_type='certificate'
            )

            # Add to normalised_data if present
            if 'normalised_data' in cert:
                cert['normalised_data']['environment_metadata'] = env_metadata
            else:
                # Or store directly
                cert['environment_metadata'] = env_metadata

        # NEW: Extract metadata fields from certificate data (independent of environment config)
        if config.get('capture_enrichment', False):
            # Use either normalised_data (if present) or raw cert data
            cert_data = cert.get('normalised_data', cert)

            extracted_metadata = {
                'identity': EnvironmentInferenceService.extract_identity_fields(cert_data),
                'purpose': EnvironmentInferenceService.extract_purpose_fields(cert_data),
                'crypto': EnvironmentInferenceService.extract_crypto_fields(cert_data),
                'ha': EnvironmentInferenceService.extract_ha_fields(cert_data)
            }

            # Store directly at cert level (will be flattened by normalisation layer)
            cert['extracted_enrichment'] = extracted_metadata

        return cert


class AzureMetadataEnricher(BaseEnricher):
    """Enriches Azure Key Vault certificates and keys with environment metadata"""

    def enrich(self, asset: Dict, config: Dict) -> Dict:
        """
        Enrich Azure KV certificate or key

        Args:
            asset: Certificate or Key dict from Azure
            config: Enrichment configuration
        """
        if config.get('capture_environment', False):
            # Build scan_data from Azure context
            tags = asset.get('tags', {})
            scan_data = {
                'source': 'azure_keyvault',
                'azure_tags': tags,  # Preserve high-confidence tag signal
                'vault_name': asset.get('vault_name'),
                'key_name': asset.get('name'),
                # Leverage Azure metadata for additional signals
                'key_type': asset.get('key_type'),
                'key_size': asset.get('key_size'),
                'key_ops': asset.get('key_ops')
            }

            # Call multi-signal orchestrator (will prioritize azure_tags)
            env_metadata = EnvironmentInferenceService.infer_from_scan_data(
                scan_data=scan_data,
                asset_type='key'
            )

            # Add to normalised_data if present
            if 'normalised_data' in asset:
                asset['normalised_data']['environment_metadata'] = env_metadata
            else:
                # Or store directly
                asset['environment_metadata'] = env_metadata

        # NEW: Extract metadata fields from certificate data (independent of environment config)
        if config.get('capture_enrichment', False):
            # Use either normalised_data (if present) or raw certificate data
            cert_data = asset.get('normalised_data', asset)

            # Only extract if this is a certificate (has certificate-specific fields)
            if cert_data.get('subject') or cert_data.get('extended_key_usage'):
                extracted_metadata = {
                    'identity': EnvironmentInferenceService.extract_identity_fields(cert_data),
                    'purpose': EnvironmentInferenceService.extract_purpose_fields(cert_data),
                    'crypto': EnvironmentInferenceService.extract_crypto_fields(cert_data),
                    'ha': EnvironmentInferenceService.extract_ha_fields(cert_data)
                }

                # Store directly at asset level (will be flattened by normalisation layer)
                asset['extracted_enrichment'] = extracted_metadata

        return asset


class LunaMetadataEnricher(BaseEnricher):
    """Enriches Luna HSM keys with environment metadata"""

    def enrich(self, key: Dict, config: Dict) -> Dict:
        """
        Enrich Luna HSM key

        Args:
            key: Key dict from Luna
            config: Enrichment configuration
        """
        if config.get('capture_environment', False):
            # Build scan_data from Luna HSM context
            partition = key.get('partition', '')
            key_label = key.get('key_label', '')

            scan_data = {
                'source': 'luna_hsm',
                'partition': partition,
                'key_label': key_label,
                # Leverage Luna metadata for cryptographic signals
                'key_type': key.get('key_type'),
                'key_size': key.get('key_size'),
                'key_usage': key.get('key_usage'),
                'extractable': key.get('extractable')
            }

            # Call multi-signal orchestrator
            env_metadata = EnvironmentInferenceService.infer_from_scan_data(
                scan_data=scan_data,
                asset_type='key'
            )

            # Add to normalised_data if present
            if 'normalised_data' in key:
                key['normalised_data']['environment_metadata'] = env_metadata
            else:
                # Or store directly
                key['environment_metadata'] = env_metadata

        return key


class NoOpEnricher(BaseEnricher):
    """No-op enricher for collectors without metadata support"""

    def enrich(self, asset: Dict, config: Dict) -> Dict:
        """Pass through unchanged"""
        return asset


class TLSSecurityEnricher(BaseEnricher):
    """
    Enriches TLS results with cryptographic security analysis.

    Analyzes:
    - Signature algorithm weakness (MD5, SHA1 detection)
    - Public key strength (RSA <2048, weak curves)
    - PQC readiness (hybrid vs pure vs legacy)
    - Risk scoring for each dimension
    """

    # Risk thresholds for signature algorithms
    WEAK_SIGNATURE_ALGORITHMS = {
        'md5WithRSAEncryption': {'risk': 'CRITICAL', 'score': 0.95},
        'md5WithDSA': {'risk': 'CRITICAL', 'score': 0.95},
        'sha1WithRSAEncryption': {'risk': 'CRITICAL', 'score': 0.85},
        'sha1WithDSA': {'risk': 'CRITICAL', 'score': 0.85},
        'sha1WithECDSA': {'risk': 'HIGH', 'score': 0.75},
        'dsa': {'risk': 'HIGH', 'score': 0.70},
    }

    # Risk thresholds for key algorithms and sizes
    WEAK_KEY_ALGORITHMS = {
        'RSA': {
            512: {'risk': 'CRITICAL', 'score': 0.95, 'broken': True, 'break_year': 1999},
            768: {'risk': 'CRITICAL', 'score': 0.90, 'broken': True, 'break_year': 2009},
            1024: {'risk': 'CRITICAL', 'score': 0.80, 'vulnerable': True, 'break_year': 2020},
            2048: {'risk': 'LOW', 'score': 0.1, 'safe_until': 2030},
            3072: {'risk': 'LOW', 'score': 0.05, 'safe_until': 2040},
            4096: {'risk': 'LOW', 'score': 0.05, 'safe_until': 2050},
        },
        'ECDSA': {
            256: {'risk': 'LOW', 'score': 0.1, 'equivalent_rsa': 3072},
            384: {'risk': 'LOW', 'score': 0.05, 'equivalent_rsa': 7680},
            521: {'risk': 'LOW', 'score': 0.02, 'equivalent_rsa': 15360},
        },
        'DSA': {
            1024: {'risk': 'CRITICAL', 'score': 0.85, 'vulnerable': True},
            2048: {'risk': 'HIGH', 'score': 0.60, 'aging': True},
        }
    }

    QUANTUM_THREAT_YEAR = 2035
    CNSA_TRANSITION_DEADLINE = 2030

    def enrich(self, result_dict: Dict, config: Dict) -> Dict:
        """
        Enrich TLS result with security analysis.

        Args:
            result_dict: Certificate dict with cryptographic fields
            config: Enrichment configuration dict

        Returns:
            result_dict with security analysis fields added
        """
        if not config.get('capture_security_analysis', False):
            return result_dict

        try:
            # Priority 1: Signature algorithm analysis
            result_dict['signature_algorithm_analysis'] = \
                self._analyze_signature_algorithm(
                    result_dict.get('signature_algorithm'),
                    result_dict.get('not_after')
                )

            # Priority 2: Key strength analysis
            result_dict['key_strength_analysis'] = \
                self._analyze_key_strength(
                    result_dict.get('public_key_algorithm'),
                    result_dict.get('public_key_size'),
                    result_dict.get('key_curve')
                )

            # Priority 3: PQC readiness analysis
            result_dict['pqc_readiness'] = \
                self._analyze_pqc_readiness(
                    result_dict.get('pqc_analysis'),
                    result_dict.get('is_pqc'),
                    result_dict.get('is_hybrid'),
                    result_dict.get('not_before'),
                    result_dict.get('not_after'),
                    result_dict.get('migration_status')
                )

        except Exception as e:
            logger.warning(f"Security enrichment error: {e}")
            # Continue with partial enrichment

        return result_dict

    def _analyze_signature_algorithm(self, sig_algo: str,
                                     not_after: str) -> Dict[str, Any]:
        """
        Analyze signature algorithm for cryptographic weakness.

        Args:
            sig_algo: Signature algorithm name (e.g., 'sha256WithRSAEncryption')
            not_after: Certificate expiration date (ISO format)

        Returns:
            Dict with algorithm analysis and risk assessment
        """
        if not sig_algo:
            return {
                'algorithm': 'unknown',
                'risk_level': 'UNKNOWN',
                'risk_score': 0.5
            }

        algo_lower = sig_algo.lower()

        # Check against weak algorithm list
        for weak_algo, weak_info in self.WEAK_SIGNATURE_ALGORITHMS.items():
            if weak_algo.lower() in algo_lower:
                return {
                    'algorithm': sig_algo,
                    'is_weak': True,
                    'risk_level': weak_info['risk'],
                    'risk_score': weak_info['score'],
                    'requires_remediation': True,
                    'reason': f"{weak_algo} is cryptographically broken or weak",
                    'remediation': 'Reissue certificate with SHA256 or better'
                }

        # Safe/modern algorithms
        return {
            'algorithm': sig_algo,
            'is_weak': False,
            'risk_level': 'LOW',
            'risk_score': 0.1,
            'requires_remediation': False,
            'reason': 'Modern, cryptographically sound signature algorithm'
        }

    def _analyze_key_strength(self, pub_key_algo: str,
                             pub_key_size: int,
                             key_curve: str) -> Dict[str, Any]:
        """
        Analyze public key strength and vulnerability.

        Args:
            pub_key_algo: Public key algorithm (e.g., 'RSAPublicKey', 'EllipticCurvePublicKey')
            pub_key_size: Key size in bits (e.g., 2048, 256)
            key_curve: EC curve name if applicable (e.g., 'secp256r1')

        Returns:
            Dict with key strength analysis and risk assessment
        """
        if not pub_key_algo:
            return {
                'algorithm': 'unknown',
                'risk_level': 'UNKNOWN',
                'risk_score': 0.5
            }

        # Normalize algorithm name (remove leading underscore and 'PublicKey' suffix)
        algo = pub_key_algo.lstrip('_').replace('PublicKey', '').strip()

        # Map common class names to algorithm names
        algo_map = {
            'RSA': 'RSA',
            'EllipticCurve': 'ECDSA',
            'DSA': 'DSA',
            'Ed25519': 'EdDSA',
            'Ed448': 'EdDSA'
        }
        algo = algo_map.get(algo, algo)  # Use mapped name if available

        # Get risk thresholds for this algorithm
        if algo not in self.WEAK_KEY_ALGORITHMS:
            return {
                'algorithm': algo,
                'key_size': pub_key_size,
                'risk_level': 'UNKNOWN',
                'risk_score': 0.5,
                'message': f'Unknown key algorithm: {algo}'
            }

        algo_thresholds = self.WEAK_KEY_ALGORITHMS[algo]

        # For RSA/DSA: analyze by key size
        if algo in ['RSA', 'DSA'] and pub_key_size:
            if pub_key_size in algo_thresholds:
                threshold_info = algo_thresholds[pub_key_size]
            else:
                # Find closest size in thresholds
                available_sizes = sorted(algo_thresholds.keys())
                closest_size = min(available_sizes,
                                 key=lambda x: abs(x - pub_key_size))
                threshold_info = dict(algo_thresholds[closest_size])
                threshold_info['actual_key_size'] = pub_key_size
                threshold_info['closest_reference_size'] = closest_size

            is_weak = threshold_info.get('risk') in ['CRITICAL', 'HIGH']
            is_broken = threshold_info.get('broken', False)
            is_vulnerable = threshold_info.get('vulnerable', False)

            return {
                'algorithm': algo,
                'key_size': pub_key_size,
                'risk_level': threshold_info.get('risk', 'UNKNOWN'),
                'risk_score': threshold_info.get('score', 0.5),
                'is_broken': is_broken,
                'is_vulnerable': is_vulnerable,
                'requires_remediation': is_weak,
                'safe_until': threshold_info.get('safe_until'),
                'break_year': threshold_info.get('break_year'),
                'remediation': self._key_remediation(algo, pub_key_size),
                'reason': self._key_risk_reason(algo, pub_key_size, threshold_info)
            }

        # For ECDSA: analyze by curve
        elif algo == 'ECDSA' and key_curve:
            # Try exact match first
            if key_curve in algo_thresholds:
                curve_info = algo_thresholds[key_curve]
                return {
                    'algorithm': algo,
                    'key_curve': key_curve,
                    'key_size': pub_key_size,  # Include the actual key size
                    'risk_level': curve_info.get('risk', 'LOW'),
                    'risk_score': curve_info.get('score', 0.1),
                    'requires_remediation': False,
                    'equivalent_rsa_bits': curve_info.get('equivalent_rsa'),
                    'reason': 'ECDSA with secure curve'
                }
            else:
                # Unknown curve - conservative estimate
                return {
                    'algorithm': algo,
                    'key_curve': key_curve,
                    'key_size': pub_key_size,  # Include the actual key size
                    'risk_level': 'MEDIUM',
                    'risk_score': 0.5,
                    'message': f'Unknown ECDSA curve: {key_curve}'
                }

        return {
            'algorithm': algo,
            'risk_level': 'MEDIUM',
            'risk_score': 0.5,
            'message': 'Unable to determine key strength'
        }

    def _key_remediation(self, algo: str, key_size: int) -> str:
        """Get remediation advice for weak key"""
        if algo == 'RSA':
            if key_size < 2048:
                return 'Reissue with RSA 2048+ or switch to ECDSA 256+'
            else:
                return 'Monitor, no immediate action required'
        elif algo == 'DSA':
            return 'Migrate away from DSA, use RSA 2048+ or ECDSA'
        return 'Consult security team for remediation'

    def _key_risk_reason(self, algo: str, key_size: int,
                        threshold_info: Dict) -> str:
        """Generate human-readable risk reason"""
        if threshold_info.get('broken'):
            return f'{algo} {key_size} is cryptographically broken'
        elif threshold_info.get('vulnerable'):
            return f'{algo} {key_size} is vulnerable to known attacks'
        elif threshold_info.get('aging'):
            return f'{algo} {key_size} is aging and should be phased out'
        else:
            return f'{algo} {key_size} is acceptable'

    def _analyze_pqc_readiness(self, pqc_analysis: Dict,
                              is_pqc: bool,
                              is_hybrid: bool,
                              not_before: str,
                              not_after: str,
                              migration_status: str) -> Dict[str, Any]:
        """
        Analyze post-quantum cryptography readiness.

        Args:
            pqc_analysis: Full PQC analysis dict from TLS scanner
            is_pqc: Boolean - is this a PQC certificate
            is_hybrid: Boolean - is this a hybrid cert
            not_before: Certificate valid from (ISO format)
            not_after: Certificate expires (ISO format)
            migration_status: Migration status string

        Returns:
            Dict with PQC readiness assessment
        """
        from datetime import datetime, timedelta

        # Calculate certificate lifetime
        lifetime_days = 0
        try:
            if not_before and not_after:
                before = datetime.fromisoformat(
                    not_before.replace('Z', '+00:00') if 'Z' in not_before else not_before
                )
                after = datetime.fromisoformat(
                    not_after.replace('Z', '+00:00') if 'Z' in not_after else not_after
                )
                lifetime_days = (after - before).days
        except Exception as e:
            logger.debug(f"Error calculating PQC lifetime: {e}")

        # Determine PQC status
        pqc_status = 'not_pqc'
        if is_hybrid:
            pqc_status = 'hybrid'
        elif is_pqc:
            pqc_status = 'pqc_only'

        # Get quantum threat timeline
        quantum_threat = 'post-2035'
        if pqc_analysis and isinstance(pqc_analysis, dict):
            quantum_threat = pqc_analysis.get('quantum_threat_timeline', 'post-2035')

        # Calculate migration urgency
        migration_urgency = 'HIGH'
        if is_hybrid:
            migration_urgency = 'MEDIUM'
        elif is_pqc:
            migration_urgency = 'LOW'

        # Calculate target migration date (2 years before CNSA deadline)
        target_date = None
        try:
            current_year = datetime.now().year
            years_to_deadline = max(0, self.CNSA_TRANSITION_DEADLINE - current_year - 2)
            target_date = (datetime.now() + timedelta(days=365*years_to_deadline)).isoformat()
        except Exception as e:
            logger.debug(f"Error calculating target migration date: {e}")

        # Determine harvest-now-decrypt-later risk
        hndy_risk = 'HIGH' if not is_hybrid else 'LOW'
        if is_pqc:
            hndy_risk = 'RESOLVED'

        return {
            'is_pqc': is_pqc,
            'is_hybrid': is_hybrid,
            'pqc_status': pqc_status,
            'quantum_threat_timeline': quantum_threat,
            'harvest_now_decrypt_later_risk': hndy_risk,
            'certificate_lifetime_days': lifetime_days,
            'cnsa_deadline_year': self.CNSA_TRANSITION_DEADLINE,
            'migration_urgency': migration_urgency,
            'target_migration_date': target_date,
            'pqc_readiness_score': self._pqc_score(is_pqc, is_hybrid),
            'recommendation': self._pqc_recommendation(is_pqc, is_hybrid)
        }

    def _pqc_score(self, is_pqc: bool, is_hybrid: bool) -> float:
        """Calculate PQC readiness score (0.0-1.0)"""
        if is_hybrid:
            return 0.95  # Excellent - hybrid is best state
        elif is_pqc:
            return 0.85  # Good - PQC only, but client compatibility risk
        else:
            return 0.3   # Poor - needs migration

    def _pqc_recommendation(self, is_pqc: bool, is_hybrid: bool) -> str:
        """Generate PQC migration recommendation"""
        if is_hybrid:
            return 'Hybrid certificate deployed. Excellent for quantum transition. Monitor client compatibility.'
        elif is_pqc:
            return 'PQC-only certificate deployed. Monitor client compatibility. Consider hybrid for broader support.'
        else:
            return 'Issue hybrid certificate (RSA + CRYSTALS-Kyber or similar) to begin quantum transition.'


class TLSRevocationEnricher(BaseEnricher):
    """
    Enriches TLS results with revocation status metadata.

    This enricher is async/optional - can be run in background.
    Checks for presence of CRL and OCSP URLs.
    Full validation deferred to async task.
    """

    def enrich(self, result_dict: Dict, config: Dict) -> Dict:
        """
        Add revocation metadata to result.

        Note: Actual revocation checking (network calls) can be run async.
        This just prepares the metadata and flags what needs checking.

        Args:
            result_dict: Certificate dict
            config: Configuration dict

        Returns:
            result_dict with revocation_status field added
        """
        crls = result_dict.get('crl_distribution_points', [])
        ocsp = result_dict.get('ocsp_responders', [])

        result_dict['revocation_status'] = {
            'crl_urls_present': len(crls) > 0,
            'ocsp_urls_present': len(ocsp) > 0,
            'crl_count': len(crls),
            'ocsp_count': len(ocsp),
            'validation_enabled': config.get('check_revocation', False),
            'validation_status': 'not_checked',
            'note': 'Revocation checking can be enabled in scan configuration'
        }

        # If revocation checking enabled, would do network calls here
        # For Phase 1.5, just flag presence and defer actual checking
        if config.get('check_revocation', False):
            result_dict['revocation_status']['note'] = 'Revocation checking configured (async)'

        return result_dict
