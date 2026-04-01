# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: caip_service_layer/environment_inference_service.py
# Copied: 2026-04-01
# Used in: Phase 10 — Inventory and Enrichment
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
Environment Inference Service

Centralized service for inferring environment metadata from various sources.
Used by collectors during asset discovery to auto-populate environment_type,
service_name, and application_name fields.

Confidence Scoring:
- 0.9-1.0: Explicit tags/metadata (Azure tags, EJBCA CA properties)
- 0.6-0.8: Hostname patterns with environment keywords
- 0.4-0.5: Port-based inference, source string analysis
- 0.0-0.3: Low confidence guesses (fallback logic)
"""

import logging
from typing import Dict, Any, Optional

logger = logging.getLogger('caip.environment_inference')


class EnvironmentInferenceService:
    """Infers environment metadata from TLS scans, tags, hostnames, and source strings"""

    # Environment type validation
    VALID_ENVIRONMENT_TYPES = [
        'production',
        'staging',
        'development',
        'testing',
        'unknown'
    ]

    # Signal weights for fusion (higher weight = more trust)
    SIGNAL_WEIGHTS = {
        'azure_tags': 1.2,              # Highest trust (explicit tags)
        'issuer_patterns': 1.1,         # High trust (public CAs reliable)
        'infrastructure_tier': 1.0,     # Medium trust
        'cryptographic_properties': 1.0,
        'source_string': 0.9,           # Lower trust (pattern matching)
        'sync_patterns': 0.8,           # TODO: Phase 2 (activity history sync detection)
        'activity_patterns': 0.7,       # TODO: Phase 2 (requires activity history)
        'relationship_analysis': 0.7,   # ✅ IMPLEMENTED Phase 1
        'ha_analysis': 0.90,            # ✅ Phase 3: HA clustering high indicator
        'purpose_analysis': 0.85,       # ✅ Phase 3: Certificate role explicit
        'identity_analysis': 0.80,      # ✅ Phase 3: Service patterns reliable
        'crypto_analysis': 0.75         # ✅ Phase 3: Key strength explicit
    }

    MAX_FUSED_CONFIDENCE = 0.95  # Cap to preserve uncertainty

    @classmethod
    def infer_from_source_string(cls, source: str) -> Dict[str, Any]:
        """
        Infer environment from source string (TLS, EJBCA, etc.)

        Args:
            source: Source string from asset (e.g., "TLS", "Luna HSM: hsm-prod")

        Returns:
            {
                'environment_type': str,
                'discovery_method': str,
                'discovery_confidence': float
            }
        """
        source_lower = source.lower() if source else ''

        # Explicit environment markers in source string
        if any(marker in source_lower for marker in ['production', 'prod']):
            return {
                'environment_type': 'production',
                'discovery_method': 'source-string-pattern',
                'discovery_confidence': 0.7
            }
        elif any(marker in source_lower for marker in ['staging', 'stage', 'uat']):
            return {
                'environment_type': 'staging',
                'discovery_method': 'source-string-pattern',
                'discovery_confidence': 0.7
            }
        elif any(marker in source_lower for marker in ['development', 'dev']):
            return {
                'environment_type': 'development',
                'discovery_method': 'source-string-pattern',
                'discovery_confidence': 0.7
            }
        elif any(marker in source_lower for marker in ['test', 'testing', 'qa']):
            return {
                'environment_type': 'testing',
                'discovery_method': 'source-string-pattern',
                'discovery_confidence': 0.7
            }

        # High-confidence collector-based inference
        if 'luna hsm' in source_lower:
            return {
                'environment_type': 'production',
                'discovery_method': 'collector-type-inference',
                'discovery_confidence': 0.6  # HSMs typically production
            }

        # Conservative default
        return {
            'environment_type': 'unknown',
            'discovery_method': 'source-string-pattern',
            'discovery_confidence': 0.0
        }

    @classmethod
    def infer_from_tls_scan(cls, host: str, port: int, cert_subject: Dict[str, str]) -> Dict[str, Any]:
        """
        Infer environment from TLS scan metadata (hostname, port, certificate).

        Args:
            host: Hostname or IP
            port: Port number
            cert_subject: Certificate subject dict

        Returns:
            {
                'environment_type': str,
                'service_name': str,
                'application_name': str,
                'discovery_method': str,
                'discovery_confidence': float
            }
        """
        result = {
            'environment_type': 'unknown',
            'service_name': None,
            'application_name': None,
            'discovery_method': 'tls-scan-inference',
            'discovery_confidence': 0.4  # Base confidence for TLS inference
        }

        host_lower = host.lower()

        # Environment detection from hostname
        if any(marker in host_lower for marker in ['prod', 'production']):
            result['environment_type'] = 'production'
            result['discovery_confidence'] = 0.7  # Higher confidence for explicit names
        elif any(marker in host_lower for marker in ['dev', 'development']):
            result['environment_type'] = 'development'
            result['discovery_confidence'] = 0.7
        elif any(marker in host_lower for marker in ['stage', 'staging', 'uat']):
            result['environment_type'] = 'staging'
            result['discovery_confidence'] = 0.7
        elif any(marker in host_lower for marker in ['test', 'testing', 'qa']):
            result['environment_type'] = 'testing'
            result['discovery_confidence'] = 0.7
        elif port == 443:
            # Port 443 with no explicit environment marker → likely production
            result['environment_type'] = 'production'
            result['discovery_confidence'] = 0.5

        # Service inference from port
        port_to_service = {
            443: 'https-web',
            8443: 'https-app',
            636: 'ldaps',
            3389: 'rdp-tls',
            5986: 'winrm-https',
            8080: 'http-alt',
            9443: 'management-https'
        }

        if port in port_to_service:
            result['service_name'] = port_to_service[port]
        else:
            result['service_name'] = f'port-{port}'

        # Service name from hostname pattern
        # Example: payment-api.prod.example.com → service_name = payment-api
        parts = host_lower.split('.')
        if len(parts) >= 2:
            potential_service = parts[0]
            # Common service naming patterns
            if any(keyword in potential_service for keyword in ['api', 'service', 'app', 'web', 'portal']):
                result['service_name'] = potential_service
                result['discovery_confidence'] = 0.6

        # Application name from certificate CN
        try:
            cn = cert_subject.get('commonName', '')
            if cn and not cn.startswith('*'):
                # Extract application from CN if it's not a wildcard
                app_name = cn.split('.')[0]
                result['application_name'] = app_name
        except Exception as e:
            logger.debug(f"Error extracting application name from CN: {e}")

        return result

    @classmethod
    def infer_from_azure_tags(cls, tags: Dict[str, str]) -> Dict[str, Any]:
        """
        Extract environment metadata from Azure Key Vault tags.

        Args:
            tags: Azure resource tags dict

        Returns:
            {
                'environment_type': str or None,
                'service_name': str or None,
                'application_name': str or None,
                'discovery_method': str,
                'discovery_confidence': float
            }
        """
        result = {
            'environment_type': None,
            'service_name': None,
            'application_name': None,
            'discovery_method': 'azure-tags',
            'discovery_confidence': 0.9  # High confidence for explicit tags
        }

        if not tags:
            result['discovery_confidence'] = 0.0
            return result

        # Common tag names for environment
        env_tag_names = ['environment', 'env', 'Environment', 'Env']
        for tag_name in env_tag_names:
            if tag_name in tags:
                env_value = tags[tag_name].lower()
                if env_value in cls.VALID_ENVIRONMENT_TYPES:
                    result['environment_type'] = env_value
                elif 'prod' in env_value:
                    result['environment_type'] = 'production'
                elif 'dev' in env_value:
                    result['environment_type'] = 'development'
                elif 'stage' in env_value or 'uat' in env_value:
                    result['environment_type'] = 'staging'
                elif 'test' in env_value or 'qa' in env_value:
                    result['environment_type'] = 'testing'
                break

        # Service/application tags
        service_tag_names = ['service', 'Service', 'application', 'Application', 'app', 'App']
        for tag_name in service_tag_names:
            if tag_name in tags:
                if 'service' in tag_name.lower():
                    result['service_name'] = tags[tag_name]
                else:
                    result['application_name'] = tags[tag_name]

        return result

    @classmethod
    def infer_from_cryptographic_properties(cls, cert_data: Dict) -> Optional[Dict]:
        """
        Infer environment from cryptographic properties.

        Analyzes key size, algorithm, validity period, extensions to infer environment.
        - Production: RSA 2048+, long validity (2+ years), critical extensions
        - Testing: RSA 1024, short validity (<90 days), basic constraints
        - Development: Self-signed, localhost CNs, very short validity (<30 days)

        Args:
            cert_data: Certificate/key data dict with cryptographic properties

        Returns:
            {
                'signal_type': 'cryptographic_properties',
                'environment_type': str,
                'confidence': float (0.4-0.7),
                'signal_details': {...}
            }
            or None if signal cannot be computed
        """
        try:
            key_size = cert_data.get('public_key_size')
            algorithm = cert_data.get('public_key_algorithm', '').lower()
            validity_days = cert_data.get('validity_days') or cert_data.get('certificate_validity_days') or 0
            is_self_signed = cert_data.get('is_self_signed', False)

            # Ensure validity_days is numeric (not None)
            if validity_days is None:
                validity_days = 0

            if not key_size or not algorithm:
                return None  # Missing required data

            signal_details = {
                'key_size': key_size,
                'algorithm': algorithm,
                'validity_days': validity_days,
                'is_self_signed': is_self_signed
            }

            # Development: Self-signed, very short validity (<30 days)
            if is_self_signed and validity_days < 30:
                return {
                    'signal_type': 'cryptographic_properties',
                    'environment_type': 'development',
                    'confidence': 0.7,
                    'signal_details': signal_details
                }

            # Development: Very short validity (<7 days)
            if validity_days < 7:
                return {
                    'signal_type': 'cryptographic_properties',
                    'environment_type': 'development',
                    'confidence': 0.6,
                    'signal_details': signal_details
                }

            # Testing: Weak RSA (1024), short validity (<90 days)
            if 'rsa' in algorithm and key_size == 1024 and validity_days < 90:
                return {
                    'signal_type': 'cryptographic_properties',
                    'environment_type': 'testing',
                    'confidence': 0.6,
                    'signal_details': signal_details
                }

            # Production: RSA 2048+, long validity (2+ years = 730 days)
            if 'rsa' in algorithm and key_size >= 2048 and validity_days >= 730:
                return {
                    'signal_type': 'cryptographic_properties',
                    'environment_type': 'production',
                    'confidence': 0.6,
                    'signal_details': signal_details
                }

            # Production: ECC P-256+, long validity (2+ years = 730 days)
            # ECC key sizes: P-256=256, P-384=384, P-521=521
            if 'ecc' in algorithm or 'ec' in algorithm:
                if key_size >= 256 and validity_days >= 730:
                    return {
                        'signal_type': 'cryptographic_properties',
                        'environment_type': 'production',
                        'confidence': 0.6,
                        'signal_details': signal_details
                    }
                # ECC with short validity is testing/development
                if key_size >= 128 and validity_days < 90:
                    env_type = 'testing' if validity_days >= 30 else 'development'
                    return {
                        'signal_type': 'cryptographic_properties',
                        'environment_type': env_type,
                        'confidence': 0.5,
                        'signal_details': signal_details
                    }

            # Generic check: Any key >127 bits with 2+ year validity = production
            if key_size > 127 and validity_days >= 730:
                return {
                    'signal_type': 'cryptographic_properties',
                    'environment_type': 'production',
                    'confidence': 0.5,
                    'signal_details': signal_details
                }

            # No confident inference possible
            return None

        except Exception as e:
            logger.warning(f"Cryptographic properties signal failed: {e}")
            return None

    @classmethod
    def infer_from_infrastructure_tier(cls, hostname: str = None, port: int = None, ip: str = None) -> Optional[Dict]:
        """
        Infer environment from infrastructure tier (hostname, port, IP).

        Analyzes network tier, port conventions, IP ranges to infer environment.
        - Production: Standard ports (443, 8443), public IPs, prod/prd in hostname
        - Staging: Non-standard ports, private IPs, stg/stage in hostname
        - Development: High ports (8000+), localhost/127.0.0.1, dev in hostname

        Args:
            hostname: Hostname or domain name
            port: Port number
            ip: IP address

        Returns:
            {
                'signal_type': 'infrastructure_tier',
                'environment_type': str,
                'confidence': float (0.5-0.8),
                'signal_details': {...}
            }
            or None if signal cannot be computed
        """
        try:
            signal_details = {
                'hostname': hostname,
                'port': port,
                'ip': ip
            }

            if not hostname and not port and not ip:
                return None  # No data available

            environment_scores = {}

            # Infrastructure analysis
            if hostname:
                hostname_lower = hostname.lower()

                # Production markers
                if any(m in hostname_lower for m in ['prod', 'production', 'www']):
                    environment_scores['production'] = 0.7
                # Staging markers
                elif any(m in hostname_lower for m in ['stage', 'staging', 'uat', 'stg']):
                    environment_scores['staging'] = 0.7
                # Development markers
                elif any(m in hostname_lower for m in ['dev', 'development', 'localhost']):
                    environment_scores['development'] = 0.7
                # Testing markers
                elif any(m in hostname_lower for m in ['test', 'testing', 'qa']):
                    environment_scores['testing'] = 0.7

            # Port-based inference
            if port:
                if port in [443, 8443, 636]:  # Standard secure ports → production likely
                    environment_scores.setdefault('production', 0.0)
                    environment_scores['production'] = max(environment_scores['production'], 0.5)
                elif port in [8000, 8001, 8008, 8080]:  # High ports → development likely
                    environment_scores.setdefault('development', 0.0)
                    environment_scores['development'] = max(environment_scores['development'], 0.5)
                elif port > 8000:  # Very high ports → development
                    environment_scores.setdefault('development', 0.0)
                    environment_scores['development'] = max(environment_scores['development'], 0.4)

            # IP-based inference
            if ip:
                if any(ip.startswith(m) for m in ['127.', '192.168.', '10.', '172.16']):  # Private/localhost
                    environment_scores.setdefault('development', 0.0)
                    environment_scores['development'] = max(environment_scores['development'], 0.5)

            if environment_scores:
                environment_type = max(environment_scores.keys(), key=lambda k: environment_scores[k])
                confidence = environment_scores[environment_type]
                return {
                    'signal_type': 'infrastructure_tier',
                    'environment_type': environment_type,
                    'confidence': confidence,
                    'signal_details': signal_details
                }

            return None

        except Exception as e:
            logger.warning(f"Infrastructure tier signal failed: {e}")
            return None

    @classmethod
    def infer_from_issuer_patterns(cls, issuer_dn: str = None, ca_chain: list = None) -> Optional[Dict]:
        """
        Infer environment from issuer DN and CA hierarchy.

        Analyzes issuer DN and CA chain for environment indicators.
        - Production: Public CAs (DigiCert, Let's Encrypt Prod), org-validated
        - Testing: Internal CAs with "Test" in DN, Let's Encrypt Staging
        - Development: Self-signed, "Dev" in issuer CN

        Args:
            issuer_dn: Issuer distinguished name
            ca_chain: List of issuer DNs in chain

        Returns:
            {
                'signal_type': 'issuer_patterns',
                'environment_type': str,
                'confidence': float (0.6-0.9),
                'signal_details': {...}
            }
            or None if signal cannot be computed
        """
        try:
            if not issuer_dn and not ca_chain:
                return None

            # Handle issuer_dn as dict (X.509 DN object) or string
            if isinstance(issuer_dn, dict):
                # Extract CN from dict (e.g., {'commonName': 'Some CA'})
                issuer_str = issuer_dn.get('commonName', str(issuer_dn))
            else:
                issuer_str = issuer_dn or ''

            issuer_lower = issuer_str.lower()
            signal_details = {
                'issuer_dn': issuer_str,
                'ca_chain_length': len(ca_chain) if ca_chain else 0
            }

            # Self-signed certificate → likely development
            if 'self-signed' in issuer_lower:
                return {
                    'signal_type': 'issuer_patterns',
                    'environment_type': 'development',
                    'confidence': 0.7,
                    'signal_details': signal_details
                }

            # Let's Encrypt indicators (check before general dev/test markers)
            if 'let\'s encrypt' in issuer_lower or 'letsencrypt' in issuer_lower:
                if 'staging' in issuer_lower or 'fake' in issuer_lower:
                    return {
                        'signal_type': 'issuer_patterns',
                        'environment_type': 'testing',
                        'confidence': 0.8,
                        'signal_details': signal_details
                    }
                else:
                    return {
                        'signal_type': 'issuer_patterns',
                        'environment_type': 'production',
                        'confidence': 0.8,
                        'signal_details': signal_details
                    }

            # Public CAs (high confidence for production)
            public_cas = ['digicert', 'comodo', 'entrust', 'sectigo', 'globalsign', 'verisign', 'thawte', 'geotrust']
            if any(ca in issuer_lower for ca in public_cas):
                return {
                    'signal_type': 'issuer_patterns',
                    'environment_type': 'production',
                    'confidence': 0.85,
                    'signal_details': signal_details
                }

            # Development markers in issuer (after CA checks to avoid false positives)
            if any(m in issuer_lower for m in [' dev', ' test', ' qa', 'local', '-dev-']):
                return {
                    'signal_type': 'issuer_patterns',
                    'environment_type': 'development',
                    'confidence': 0.7,
                    'signal_details': signal_details
                }

            # Fallback: Internal/unknown CA (not public, not dev/test marked)
            # Most internal CAs are used for production or staging
            # Default to production with moderate confidence (0.5)
            if issuer_str:  # Has some issuer data
                return {
                    'signal_type': 'issuer_patterns',
                    'environment_type': 'production',
                    'confidence': 0.5,
                    'signal_details': signal_details
                }

            return None

        except Exception as e:
            logger.warning(f"Issuer patterns signal failed: {e}")
            return None

    @classmethod
    def infer_from_relationship_analysis(cls, cert_data: Dict = None,
                                        relationship_data: Dict = None) -> Optional[Dict]:
        """
        Infer environment from certificate dependency context.

        Leverages RelationshipService to determine how many other assets
        depend on this certificate, indicating likely production vs development.

        Signals:
        - High blast radius (6+ dependents) → High confidence production
        - Low blast radius (0 dependents, end-entity) → Moderate confidence development
        - New CA with no issuances → No signal (insufficient data)

        Args:
            cert_data: Certificate data dict (optional, for CA detection)
            relationship_data: Dict from RelationshipService with:
                - dependent_count: int, number of dependent certificates
                - dependency_level: str, e.g. "High (5+)"
                - blast_radius: int (same as dependent_count, redundant but explicit)

        Returns:
            {
                'signal_type': 'relationship_analysis',
                'environment_type': str,
                'confidence': float,
                'signal_details': {...}
            }
            or None if insufficient data
        """
        try:
            if not relationship_data:
                return None

            # Require dependent_count to be present
            if 'dependent_count' not in relationship_data:
                return None

            dependent_count = relationship_data.get('dependent_count')
            dependency_level = relationship_data.get('dependency_level', 'None')
            blast_radius = relationship_data.get('blast_radius', 0)

            # Signal 1: Production - certificates with high dependency (5+ dependents)
            # Scaling confidence with count: 5 deps = 0.55, 10 deps = 0.70, 15+ deps = 0.80, capped at 0.85
            if dependent_count >= 5:
                base_confidence = 0.55  # Start at 0.55 (>0.5) for 5 deps
                count_bonus = min((dependent_count - 5) * 0.05, 0.30)  # Max +0.30 for higher counts
                confidence = min(base_confidence + count_bonus, 0.85)

                return {
                    'signal_type': 'relationship_analysis',
                    'environment_type': 'production',
                    'confidence': confidence,
                    'signal_details': {
                        'dependent_count': dependent_count,
                        'blast_radius': blast_radius,
                        'dependency_level': dependency_level,
                        'reasoning': f'Production-grade: {dependent_count} dependent services'
                    }
                }

            # Signal 2: Development - isolated end-entity certificates with no dependents
            # Only if NOT a CA (CAs with zero dependents are just new, not development)
            if dependent_count == 0:
                # Check if this is a CA (from cert_data)
                if cert_data:
                    basic_constraints = cert_data.get('basic_constraints', {})
                    is_ca = basic_constraints.get('ca', False)

                    # Only flag as development if it's NOT a CA
                    if not is_ca:
                        return {
                            'signal_type': 'relationship_analysis',
                            'environment_type': 'development',
                            'confidence': 0.6,
                            'signal_details': {
                                'dependent_count': 0,
                                'reasoning': 'Isolated end-entity certificate (development indicator)'
                            }
                        }
                else:
                    # Without cert_data, assume end-entity if no dependents
                    return {
                        'signal_type': 'relationship_analysis',
                        'environment_type': 'development',
                        'confidence': 0.6,
                        'signal_details': {
                            'dependent_count': 0,
                            'reasoning': 'Isolated certificate (development indicator)'
                        }
                    }

            # No signal: insufficient data
            # - 1-4 dependents: unclear if development or non-critical production
            # - CA with no issuances: not yet issued, no signal
            return None

        except Exception as e:
            logger.warning(f"Relationship analysis signal failed: {e}")
            return None

    @classmethod
    def infer_from_identity_analysis(cls, cert_data: Dict = None,
                                     extracted_identity: Dict = None) -> Optional[Dict]:
        """
        Infer environment from service identity patterns (service name, tier, cloud, region).

        Analyzes CN-extracted identity fields to infer production vs development based on:
        - SaaS domains (high production indicator)
        - Cloud provider presence (azure, aws, gcp)
        - Service tier keywords (api, web, db = production; test, dev = development)
        - Naming patterns (staging, test, dev prefixes)

        Args:
            cert_data: Certificate data dict (optional, for fallback extraction)
            extracted_identity: Dict from extract_identity_fields() with:
                - service_name, organization, cloud_provider, region, service_tier, domain_type

        Returns:
            {
                'signal_type': 'identity_analysis',
                'environment_type': str,
                'confidence': float (0.55-0.75),
                'signal_details': {...}
            }
            or None if insufficient data
        """
        try:
            if extracted_identity is None and cert_data:
                extracted_identity = cls.extract_identity_fields(cert_data)

            if not extracted_identity or not extracted_identity.get('service_name'):
                return None

            service_name = (extracted_identity.get('service_name') or '').lower()
            organization = (extracted_identity.get('organization') or '').lower()
            cloud_provider = extracted_identity.get('cloud_provider')
            region = extracted_identity.get('region')
            service_tier = extracted_identity.get('service_tier')
            domain_type = extracted_identity.get('domain_type', 'internal')

            # Base confidence
            confidence = 0.55

            # SaaS domain boost → production
            if domain_type == 'saas':
                confidence = 0.75
                return {
                    'signal_type': 'identity_analysis',
                    'environment_type': 'production',
                    'confidence': confidence,
                    'signal_details': {
                        'service_name': service_name,
                        'domain_type': domain_type,
                        'reasoning': f'SaaS domain indicator ({domain_type})'
                    }
                }

            # Cloud provider → production
            if cloud_provider:
                confidence = 0.65
                return {
                    'signal_type': 'identity_analysis',
                    'environment_type': 'production',
                    'confidence': confidence,
                    'signal_details': {
                        'service_name': service_name,
                        'cloud_provider': cloud_provider,
                        'region': region,
                        'reasoning': f'Cloud provider detected: {cloud_provider}'
                    }
                }

            # Production service tiers (api, web, db, cache, queue)
            if service_tier in ['api', 'web', 'database', 'cache', 'queue']:
                confidence = 0.60
                return {
                    'signal_type': 'identity_analysis',
                    'environment_type': 'production',
                    'confidence': confidence,
                    'signal_details': {
                        'service_name': service_name,
                        'service_tier': service_tier,
                        'reasoning': f'Production service tier: {service_tier}'
                    }
                }

            # Development patterns (dev, test, staging in service name)
            dev_patterns = ['dev', 'test', 'local', 'sandbox', 'temp']
            if any(pattern in service_name for pattern in dev_patterns):
                confidence = 0.65
                env_type = 'development' if any(p in service_name for p in ['dev', 'test', 'local']) else 'staging'
                if 'staging' in service_name:
                    env_type = 'staging'
                    confidence = 0.70

                return {
                    'signal_type': 'identity_analysis',
                    'environment_type': env_type,
                    'confidence': confidence,
                    'signal_details': {
                        'service_name': service_name,
                        'reasoning': f'{env_type.capitalize()} pattern detected in service name'
                    }
                }

            # Staging patterns
            if 'staging' in service_name:
                return {
                    'signal_type': 'identity_analysis',
                    'environment_type': 'staging',
                    'confidence': 0.70,
                    'signal_details': {
                        'service_name': service_name,
                        'reasoning': 'Staging pattern detected in service name'
                    }
                }

            # Default internal domain (no patterns) → production
            return {
                'signal_type': 'identity_analysis',
                'environment_type': 'production',
                'confidence': 0.55,
                'signal_details': {
                    'service_name': service_name,
                    'organization': organization,
                    'reasoning': 'Internal domain, conservative production estimate'
                }
            }

        except Exception as e:
            logger.warning(f"Identity analysis signal failed: {e}")
            return None

    @classmethod
    def infer_from_purpose_analysis(cls, cert_data: Dict = None,
                                    extracted_purpose: Dict = None) -> Optional[Dict]:
        """
        Infer environment from certificate purpose and role (TLS server, CA tier, criticality).

        Analyzes purpose fields to infer production vs development based on:
        - TLS Server with public CA → high production confidence
        - TLS Server with long validity (3+ years) → production
        - Code signing, Email protection → production
        - Client certificates → staging/development
        - Short-lived certs (<1 year) → development

        Args:
            cert_data: Certificate data dict (optional, for fallback extraction)
            extracted_purpose: Dict from extract_purpose_fields() with:
                - primary_purpose, ca_tier, issuing_organization, criticality_tier, data_residency

        Returns:
            {
                'signal_type': 'purpose_analysis',
                'environment_type': str,
                'confidence': float (0.55-0.80),
                'signal_details': {...}
            }
            or None if insufficient data
        """
        try:
            if extracted_purpose is None and cert_data:
                extracted_purpose = cls.extract_purpose_fields(cert_data)

            if not extracted_purpose:
                return None

            primary_purpose = extracted_purpose.get('primary_purpose')
            ca_tier = extracted_purpose.get('ca_tier')
            criticality_tier = extracted_purpose.get('criticality_tier', 'standard')
            issuing_organization = extracted_purpose.get('issuing_organization')

            # TLS Server certificates
            if primary_purpose == 'TLS Server':
                # Public CA + any criticality → high production
                if ca_tier == 'public':
                    confidence = 0.80
                    return {
                        'signal_type': 'purpose_analysis',
                        'environment_type': 'production',
                        'confidence': confidence,
                        'signal_details': {
                            'primary_purpose': primary_purpose,
                            'ca_tier': ca_tier,
                            'criticality_tier': criticality_tier,
                            'reasoning': f'Public CA TLS Server certificate'
                        }
                    }

                # Internal CA, criticality-based
                if criticality_tier == 'critical':
                    confidence = 0.75
                    return {
                        'signal_type': 'purpose_analysis',
                        'environment_type': 'production',
                        'confidence': confidence,
                        'signal_details': {
                            'primary_purpose': primary_purpose,
                            'criticality_tier': criticality_tier,
                            'reasoning': 'Critical validity (3+ years) TLS Server'
                        }
                    }

                if criticality_tier == 'high':
                    confidence = 0.65
                    return {
                        'signal_type': 'purpose_analysis',
                        'environment_type': 'production',
                        'confidence': confidence,
                        'signal_details': {
                            'primary_purpose': primary_purpose,
                            'criticality_tier': criticality_tier,
                            'reasoning': 'High validity (1-3 years) TLS Server'
                        }
                    }

                # Short-lived TLS Server → development
                if criticality_tier == 'standard':
                    confidence = 0.60
                    return {
                        'signal_type': 'purpose_analysis',
                        'environment_type': 'development',
                        'confidence': confidence,
                        'signal_details': {
                            'primary_purpose': primary_purpose,
                            'criticality_tier': criticality_tier,
                            'reasoning': 'Short-lived (<1 year) TLS Server'
                        }
                    }

            # Code signing → production
            if primary_purpose == 'Code Signing':
                confidence = 0.70 if criticality_tier == 'critical' else 0.60
                return {
                    'signal_type': 'purpose_analysis',
                    'environment_type': 'production',
                    'confidence': confidence,
                    'signal_details': {
                        'primary_purpose': primary_purpose,
                        'reasoning': 'Code signing certificate'
                    }
                }

            # TLS Client → staging
            if primary_purpose == 'TLS Client':
                confidence = 0.55
                return {
                    'signal_type': 'purpose_analysis',
                    'environment_type': 'staging',
                    'confidence': confidence,
                    'signal_details': {
                        'primary_purpose': primary_purpose,
                        'reasoning': 'TLS Client certificate'
                    }
                }

            # Other purposes (Email, OCSP, Time Stamping)
            if primary_purpose:
                confidence = 0.60
                return {
                    'signal_type': 'purpose_analysis',
                    'environment_type': 'production',
                    'confidence': confidence,
                    'signal_details': {
                        'primary_purpose': primary_purpose,
                        'reasoning': f'{primary_purpose} certificate'
                    }
                }

            # Insufficient data
            return None

        except Exception as e:
            logger.warning(f"Purpose analysis signal failed: {e}")
            return None

    @classmethod
    def infer_from_crypto_analysis(cls, cert_data: Dict = None,
                                   extracted_crypto: Dict = None) -> Optional[Dict]:
        """
        Infer environment from cryptographic strength and PQC migration status.

        Analyzes key algorithm and size to infer production vs development based on:
        - RSA-4096 / ECC-256+ (strong) → production
        - RSA-2048 / ECC-160+ (moderate) → production
        - RSA-1024 (weak) → development
        - Weak algorithms → development

        Args:
            cert_data: Certificate data dict (optional, for fallback extraction)
            extracted_crypto: Dict from extract_crypto_fields() with:
                - crypto_strength, pqc_migration_needed, key_algorithm, key_size

        Returns:
            {
                'signal_type': 'crypto_analysis',
                'environment_type': str,
                'confidence': float (0.55-0.65),
                'signal_details': {...}
            }
            or None if insufficient data
        """
        try:
            if extracted_crypto is None and cert_data:
                extracted_crypto = cls.extract_crypto_fields(cert_data)

            if not extracted_crypto:
                return None

            crypto_strength = extracted_crypto.get('crypto_strength', 'unknown')
            key_algorithm = extracted_crypto.get('key_algorithm')
            key_size = extracted_crypto.get('key_size')

            if not key_algorithm or not key_size:
                return None

            # Strong crypto → production
            if crypto_strength == 'strong':
                # RSA-4096, ECC-256+ get 0.65; RSA-2048 gets 0.60
                if key_size >= 4096 or (key_algorithm and 'ECC' in key_algorithm and key_size >= 256):
                    confidence = 0.65
                else:
                    confidence = 0.60
                return {
                    'signal_type': 'crypto_analysis',
                    'environment_type': 'production',
                    'confidence': confidence,
                    'signal_details': {
                        'key_algorithm': key_algorithm,
                        'key_size': key_size,
                        'crypto_strength': crypto_strength,
                        'reasoning': f'{key_algorithm}-{key_size} ({crypto_strength})'
                    }
                }

            # Moderate crypto → production (acceptable standard)
            if crypto_strength == 'moderate':
                confidence = 0.58
                return {
                    'signal_type': 'crypto_analysis',
                    'environment_type': 'staging',
                    'confidence': confidence,
                    'signal_details': {
                        'key_algorithm': key_algorithm,
                        'key_size': key_size,
                        'crypto_strength': crypto_strength,
                        'reasoning': f'{key_algorithm}-{key_size} (moderate strength)'
                    }
                }

            # Weak crypto → development
            if crypto_strength == 'weak':
                confidence = 0.55
                return {
                    'signal_type': 'crypto_analysis',
                    'environment_type': 'development',
                    'confidence': confidence,
                    'signal_details': {
                        'key_algorithm': key_algorithm,
                        'key_size': key_size,
                        'crypto_strength': crypto_strength,
                        'reasoning': f'{key_algorithm}-{key_size} (weak - deprecated)'
                    }
                }

            # Unknown strength
            return None

        except Exception as e:
            logger.warning(f"Crypto analysis signal failed: {e}")
            return None

    @classmethod
    def infer_from_ha_analysis(cls, cert_data: Dict = None,
                               extracted_ha: Dict = None) -> Optional[Dict]:
        """
        Infer environment from High Availability and clustering patterns.

        Analyzes SAN patterns to detect clustering/replication, indicating production infrastructure:
        - 3+ replicated nodes → high production confidence
        - 2 replicated nodes → moderate production confidence
        - Single node → development

        Args:
            cert_data: Certificate data dict (optional, for fallback extraction)
            extracted_ha: Dict from extract_ha_fields() with:
                - ha_enabled, replication_count, san_base_name, is_replicated

        Returns:
            {
                'signal_type': 'ha_analysis',
                'environment_type': str,
                'confidence': float (0.55-0.70),
                'signal_details': {...}
            }
            or None if insufficient data
        """
        try:
            if extracted_ha is None and cert_data:
                extracted_ha = cls.extract_ha_fields(cert_data)

            if not extracted_ha:
                return None

            ha_enabled = extracted_ha.get('ha_enabled', False)
            replication_count = extracted_ha.get('replication_count', 0)
            san_base_name = extracted_ha.get('san_base_name')
            is_replicated = extracted_ha.get('is_replicated', False)

            # HA enabled → production
            if ha_enabled and replication_count >= 2:
                # 2 nodes = 0.65, 3+ nodes = 0.70 (capped)
                if replication_count >= 3:
                    confidence = 0.70
                else:
                    confidence = 0.65
                return {
                    'signal_type': 'ha_analysis',
                    'environment_type': 'production',
                    'confidence': confidence,
                    'signal_details': {
                        'ha_enabled': ha_enabled,
                        'replication_count': replication_count,
                        'san_base_name': san_base_name,
                        'reasoning': f'{replication_count}-node HA cluster'
                    }
                }

            # Single node or no replication → development
            if not ha_enabled or replication_count <= 1:
                confidence = 0.55
                return {
                    'signal_type': 'ha_analysis',
                    'environment_type': 'development',
                    'confidence': confidence,
                    'signal_details': {
                        'ha_enabled': ha_enabled,
                        'replication_count': replication_count,
                        'reasoning': 'Single node, no HA clustering'
                    }
                }

            # Insufficient data
            return None

        except Exception as e:
            logger.warning(f"HA analysis signal failed: {e}")
            return None

    @classmethod
    def fuse_signals(cls, signals: list, weights: Dict = None) -> Dict:
        """
        Fuse multiple signals using weighted confidence voting.

        Combines signals with confidence-weighted voting, capping final confidence at 0.95
        to preserve uncertainty.

        Args:
            signals: List of signal dicts with environment_type and confidence
            weights: Optional custom signal weights (default: SIGNAL_WEIGHTS)

        Returns:
            {
                'environment_type': str,
                'confidence': float (capped at 0.95),
                'signal_breakdown': [
                    {
                        'signal_type': str,
                        'environment_type': str,
                        'confidence': float,
                        'details': dict
                    }
                ],
                'fusion_method': 'confidence_weighted_voting'
            }
        """
        try:
            if weights is None:
                weights = cls.SIGNAL_WEIGHTS

            # Filter out None/failed signals
            valid_signals = [s for s in signals if s is not None]

            if not valid_signals:
                logger.warning("All inference signals failed, using fallback")
                return {
                    'environment_type': 'unknown',
                    'confidence': 0.0,
                    'discovery_method': 'fallback',
                    'signal_breakdown': []
                }

            # Confidence-weighted voting
            environment_scores = {}
            signal_breakdown = []

            for signal in valid_signals:
                signal_type = signal.get('signal_type', 'unknown')
                env = signal.get('environment_type', 'unknown')
                conf = signal.get('confidence', 0.0)
                weight = weights.get(signal_type, 1.0)

                # Accumulate score
                weighted_conf = conf * weight
                environment_scores[env] = environment_scores.get(env, 0.0) + weighted_conf

                # Record in breakdown
                signal_breakdown.append({
                    'signal_type': signal_type,
                    'environment_type': env,
                    'confidence': conf,
                    'details': signal.get('signal_details', {})
                })

            # Select highest score
            winning_env = max(environment_scores.keys(), key=lambda k: environment_scores[k])

            # Calculate fused confidence (average, capped at MAX_FUSED_CONFIDENCE)
            total_weighted_confidence = sum(environment_scores.values())
            avg_confidence = total_weighted_confidence / len(valid_signals)
            fused_confidence = min(avg_confidence, cls.MAX_FUSED_CONFIDENCE)

            logger.debug(f"Fused signals: {winning_env} (confidence={fused_confidence:.2f}, signals={len(valid_signals)})")

            return {
                'environment_type': winning_env,
                'confidence': fused_confidence,
                'signal_breakdown': signal_breakdown,
                'fusion_method': 'confidence_weighted_voting'
            }

        except Exception as e:
            logger.error(f"Signal fusion failed: {e}")
            return {
                'environment_type': 'unknown',
                'confidence': 0.0,
                'discovery_method': 'fusion-error',
                'signal_breakdown': []
            }

    @classmethod
    def infer_from_scan_data(cls, scan_data: Dict, asset_type: str = 'certificate') -> Dict:
        """
        Orchestrator method for multi-signal environment inference.

        Calls all applicable signal methods and fuses results using weighted voting.

        Args:
            scan_data: Dict with source, hostname, port, cert data, tags, etc.
            asset_type: 'certificate' or 'key'

        Returns:
            {
                'environment_type': str,
                'service_name': str or None,
                'application_name': str or None,
                'discovery_method': 'multi_signal_fusion',
                'discovery_confidence': float,
                'signal_breakdown': [...]
            }
        """
        try:
            signals = []

            # Source string signal (always try)
            if scan_data.get('source'):
                source_signal = cls.infer_from_source_string(scan_data['source'])
                if source_signal:
                    source_signal['signal_type'] = 'source_string'
                    signals.append(source_signal)

            # Issuer patterns signal
            if scan_data.get('issuer_dn'):
                issuer_signal = cls.infer_from_issuer_patterns(
                    issuer_dn=scan_data.get('issuer_dn'),
                    ca_chain=scan_data.get('ca_chain')
                )
                if issuer_signal:
                    signals.append(issuer_signal)

            # Cryptographic properties signal (for certificates)
            if asset_type == 'certificate' and scan_data.get('public_key_size'):
                crypto_signal = cls.infer_from_cryptographic_properties(scan_data)
                if crypto_signal:
                    signals.append(crypto_signal)

            # Infrastructure tier signal (for TLS scans)
            if scan_data.get('hostname') or scan_data.get('port') or scan_data.get('ip'):
                infra_signal = cls.infer_from_infrastructure_tier(
                    hostname=scan_data.get('hostname'),
                    port=scan_data.get('port'),
                    ip=scan_data.get('ip')
                )
                if infra_signal:
                    signals.append(infra_signal)

            # Azure tags signal (highest priority, preserve high weight)
            if scan_data.get('azure_tags'):
                azure_signal = cls.infer_from_azure_tags(scan_data['azure_tags'])
                if azure_signal and azure_signal.get('environment_type'):
                    azure_signal['signal_type'] = 'azure_tags'
                    # Convert discovery_confidence to confidence for fusion
                    if 'discovery_confidence' in azure_signal and 'confidence' not in azure_signal:
                        azure_signal['confidence'] = azure_signal.pop('discovery_confidence')
                    azure_signal['signal_details'] = {
                        'tag_source': 'azure_tags',
                        'tags': scan_data.get('azure_tags', {})
                    }
                    signals.append(azure_signal)

            # Relationship analysis signal (if relationship data available)
            # This signal requires dependency context which is typically available
            # during inventory sync when RelationshipService has been populated.
            # For ad-hoc TLS scans, this will be None and skipped.
            if scan_data.get('relationship_data'):
                rel_signal = cls.infer_from_relationship_analysis(
                    cert_data=scan_data,  # Pass cert data for CA detection
                    relationship_data=scan_data.get('relationship_data')
                )
                if rel_signal:
                    signals.append(rel_signal)
                    logger.debug(f"Relationship analysis signal added: {rel_signal['environment_type']} "
                               f"(confidence={rel_signal['confidence']:.2f})")

            # Phase 3: Metadata analysis signals (leverage extracted metadata)
            # These 4 signals convert extracted metadata into environment inference
            if asset_type == 'certificate':
                # Extract metadata once, reuse for all 4 signals
                extracted_identity = cls.extract_identity_fields(scan_data) if scan_data else {}
                extracted_purpose = cls.extract_purpose_fields(scan_data) if scan_data else {}
                extracted_crypto = cls.extract_crypto_fields(scan_data) if scan_data else {}
                extracted_ha = cls.extract_ha_fields(scan_data) if scan_data else {}

                # Identity analysis (service patterns)
                if extracted_identity:
                    identity_signal = cls.infer_from_identity_analysis(extracted_identity=extracted_identity)
                    if identity_signal:
                        signals.append(identity_signal)
                        logger.debug(f"Identity analysis signal added: {identity_signal['environment_type']} "
                                   f"(confidence={identity_signal['confidence']:.2f})")

                # Purpose analysis (certificate role)
                if extracted_purpose:
                    purpose_signal = cls.infer_from_purpose_analysis(extracted_purpose=extracted_purpose)
                    if purpose_signal:
                        signals.append(purpose_signal)
                        logger.debug(f"Purpose analysis signal added: {purpose_signal['environment_type']} "
                                   f"(confidence={purpose_signal['confidence']:.2f})")

                # Crypto analysis (key strength)
                if extracted_crypto:
                    crypto_signal = cls.infer_from_crypto_analysis(extracted_crypto=extracted_crypto)
                    if crypto_signal:
                        signals.append(crypto_signal)
                        logger.debug(f"Crypto analysis signal added: {crypto_signal['environment_type']} "
                                   f"(confidence={crypto_signal['confidence']:.2f})")

                # HA analysis (clustering)
                if extracted_ha:
                    ha_signal = cls.infer_from_ha_analysis(extracted_ha=extracted_ha)
                    if ha_signal:
                        signals.append(ha_signal)
                        logger.debug(f"HA analysis signal added: {ha_signal['environment_type']} "
                                   f"(confidence={ha_signal['confidence']:.2f})")

                # Store extracted metadata in result for dashboard/API
                scan_data['extracted_metadata'] = {
                    'identity': extracted_identity,
                    'purpose': extracted_purpose,
                    'crypto': extracted_crypto,
                    'ha': extracted_ha
                }

            # Fuse all signals
            if signals:
                fused = cls.fuse_signals(signals)
                fused['discovery_method'] = 'multi_signal_fusion'
                fused['discovery_confidence'] = fused.pop('confidence', 0.0)  # Rename 'confidence' to 'discovery_confidence'
                fused['service_name'] = scan_data.get('service_name')
                fused['application_name'] = scan_data.get('application_name')
                return fused
            else:
                # No signals succeeded, return fallback
                logger.info("No signals succeeded, returning fallback")
                return {
                    'environment_type': 'unknown',
                    'service_name': scan_data.get('service_name'),
                    'application_name': scan_data.get('application_name'),
                    'discovery_method': 'no-signals',
                    'discovery_confidence': 0.0,
                    'signal_breakdown': []
                }

        except Exception as e:
            logger.error(f"Scan data inference orchestrator failed: {e}")
            return {
                'environment_type': 'unknown',
                'service_name': scan_data.get('service_name'),
                'application_name': scan_data.get('application_name'),
                'discovery_method': 'orchestrator-error',
                'discovery_confidence': 0.0,
                'signal_breakdown': []
            }

    @classmethod
    def extract_identity_fields(cls, cert_data: Dict) -> Dict[str, Any]:
        """
        Extract service identity fields from certificate CN.
        Works with any collector (TLS, EJBCA, Azure, Luna) - all use unified schema.

        Extracts: service_name, organization, cloud_provider, region, service_tier, domain_type

        Args:
            cert_data: Certificate data dict with 'subject_cn' field

        Returns:
            {
                'service_name': str or None,
                'organization': str or None,
                'cloud_provider': str or None,
                'region': str or None,
                'service_tier': str or None,
                'domain_type': str or None
            }

        Confidence: 85-95% for most fields (CN is explicit, structured data)
        """
        try:
            cn = cert_data.get('subject_cn', '').lower()
            if not cn:
                return {}

            parts = cn.split('.')

            # Extract service name (first segment)
            service_name = parts[0] if len(parts) > 0 else None

            # Extract organization (second segment)
            organization = parts[1] if len(parts) > 1 else None

            # Cloud provider detection
            cloud_providers = ['az', 'aws', 'gcp', 'azure']
            cloud_provider = None
            for part in parts:
                if part in cloud_providers or part.startswith('az') or part.startswith('aws'):
                    cloud_provider = 'azure' if 'az' in part else part
                    break

            # Region extraction
            region_patterns = ['eu', 'us', 'us-east', 'us-west', 'ap', 'au']
            region = None
            for part in parts:
                if part in region_patterns:
                    region = part
                    break

            # Service tier extraction
            tier_keywords = {
                'app': 'application',
                'web': 'web',
                'api': 'api',
                'db': 'database',
                'cache': 'cache',
                'queue': 'queue'
            }
            service_tier = None
            for part in parts:
                if part in tier_keywords:
                    service_tier = tier_keywords[part]
                    break

            # Domain type (SaaS vs Internal)
            saas_tlds = ['saas', 'keyfactorsaas']
            domain_type = 'saas' if any(tld in cn for tld in saas_tlds) else 'internal'

            return {
                'service_name': service_name,
                'organization': organization,
                'cloud_provider': cloud_provider,
                'region': region,
                'service_tier': service_tier,
                'domain_type': domain_type
            }
        except Exception as e:
            logger.warning(f"Identity field extraction failed: {e}")
            return {}

    @classmethod
    def extract_purpose_fields(cls, cert_data: Dict) -> Dict[str, Any]:
        """
        Extract purpose and role fields from certificate extensions and issuer.
        Works with any collector - all use unified schema.

        Extracts: primary_purpose, ca_tier, issuing_organization, criticality_tier, data_residency

        Args:
            cert_data: Certificate data dict with 'extended_key_usage', 'issuer', 'certificate_validity_days'

        Returns:
            {
                'primary_purpose': str or None,
                'ca_tier': str or None,
                'issuing_organization': str or None,
                'criticality_tier': str,
                'data_residency': str or None
            }

        Confidence: 90-100% for most fields (extensions are explicit, X.509 standard)
        """
        try:
            # Purpose from Extended Key Usage
            eku_to_purpose = {
                'serverauth': 'TLS Server',
                'clientauth': 'TLS Client',
                'codesigning': 'Code Signing',
                'emailprotection': 'Email Protection',
                'timestamping': 'Time Stamping',
                'ocspsigning': 'OCSP Responder'
            }

            primary_purpose = None
            eku_list = cert_data.get('extended_key_usage', [])
            if eku_list:
                # Parse EKU (can be string or object representation)
                eku_str = str(eku_list[0]).lower()
                for key, value in eku_to_purpose.items():
                    if key in eku_str:
                        primary_purpose = value
                        break

            # CA tier from issuer
            issuer = cert_data.get('issuer', {})
            issuer_cn = cert_data.get('issuer_cn', '').lower()

            public_cas = [
                'digicert', 'comodo', 'entrust', 'sectigo',
                'globalsign', 'verisign', 'thawte', 'geotrust', 'letsencrypt'
            ]
            is_public_ca = any(ca in issuer_cn for ca in public_cas)
            ca_tier = 'public' if is_public_ca else 'internal'

            # Issuing organization
            issuing_organization = issuer.get('organizationName')

            # Criticality from validity period
            validity_days = cert_data.get('certificate_validity_days', 0)
            if validity_days >= 1095:  # 3+ years
                criticality_tier = 'critical'
            elif validity_days >= 365:  # 1+ year
                criticality_tier = 'high'
            else:
                criticality_tier = 'standard'

            # Data residency from country code
            data_residency = issuer.get('countryName')

            return {
                'primary_purpose': primary_purpose,
                'ca_tier': ca_tier,
                'issuing_organization': issuing_organization,
                'criticality_tier': criticality_tier,
                'data_residency': data_residency
            }
        except Exception as e:
            logger.warning(f"Purpose field extraction failed: {e}")
            return {}

    @classmethod
    def extract_crypto_fields(cls, cert_data: Dict) -> Dict[str, Any]:
        """
        Extract cryptographic strength and PQC migration status.
        Works with any collector - all use unified schema.

        Extracts: crypto_strength, pqc_migration_needed, key_algorithm, key_size

        Args:
            cert_data: Certificate data dict with 'public_key_algorithm' and 'public_key_size'

        Returns:
            {
                'crypto_strength': str,
                'pqc_migration_needed': bool,
                'key_algorithm': str,
                'key_size': int
            }

        Confidence: 95-100% (cryptographic standards are explicit, well-defined)
        """
        try:
            algo = cert_data.get('public_key_algorithm', '').upper()
            key_size = cert_data.get('public_key_size', 0)

            if not algo or not key_size:
                return {}

            # Crypto strength assessment
            crypto_strength = 'unknown'

            if 'RSA' in algo:
                if key_size >= 2048:
                    crypto_strength = 'strong'
                elif key_size == 1024:
                    crypto_strength = 'weak'
                else:
                    crypto_strength = 'moderate'
            elif 'ECC' in algo or 'EC' in algo:
                if key_size >= 256:
                    crypto_strength = 'strong'
                elif key_size >= 160:
                    crypto_strength = 'moderate'
                else:
                    crypto_strength = 'weak'

            # PQC migration needed for classical algorithms
            pqc_migration_needed = algo in ['RSA', 'DSA', 'ECDSA']

            return {
                'crypto_strength': crypto_strength,
                'pqc_migration_needed': pqc_migration_needed,
                'key_algorithm': algo,
                'key_size': key_size,
                'signature_algorithm': cert_data.get('signature_algorithm'),
                'signature_algorithm_analysis': cert_data.get('signature_algorithm_analysis'),
                'migration_urgency': cert_data.get('pqc_readiness', {}).get('migration_urgency')
            }
        except Exception as e:
            logger.warning(f"Crypto field extraction failed: {e}")
            return {}

    @classmethod
    def extract_ha_fields(cls, cert_data: Dict) -> Dict[str, Any]:
        """
        Extract High Availability and clustering information from SANs.
        Works with any collector - all use unified schema.

        Extracts: ha_enabled, replication_count, san_base_name, is_replicated

        Args:
            cert_data: Certificate data dict with 'san' field (list of SANs)

        Returns:
            {
                'ha_enabled': bool,
                'replication_count': int,
                'san_base_name': str or None,
                'is_replicated': bool
            }

        Confidence: 95% (SAN patterns are explicit, structured data)
        """
        try:
            import re

            san_list = cert_data.get('san', [])
            if not san_list:
                return {
                    'ha_enabled': False,
                    'replication_count': 0,
                    'san_base_name': None,
                    'is_replicated': False
                }

            # Parse SANs (can be string or object representation)
            san_strings = []
            for san in san_list:
                # Extract domain name from string representation
                san_str = str(san).lower()
                if "value='" in san_str:
                    # Format: <DNSName(value='domain.com')>
                    match = re.search(r"value='([^']+)'", san_str)
                    if match:
                        san_strings.append(match.group(1))
                else:
                    san_strings.append(san_str)

            # Detect clustering (numbered nodes: ra0, ra1, ra2, etc.)
            numbered_nodes = []
            base_names = []

            for san in san_strings:
                # Extract base name (remove trailing numbers)
                match = re.match(r'([a-z0-9-]+?)(\d+)?\.', san)
                if match:
                    base = match.group(1)
                    num = match.group(2)
                    base_names.append(base)
                    if num:
                        numbered_nodes.append(san)

            ha_enabled = len(numbered_nodes) >= 2  # 2+ numbered nodes = HA cluster
            san_base_name = base_names[0] if base_names else None
            is_replicated = len(san_strings) > 1

            return {
                'ha_enabled': ha_enabled,
                'replication_count': len(san_strings),
                'san_base_name': san_base_name,
                'is_replicated': is_replicated
            }
        except Exception as e:
            logger.warning(f"HA field extraction failed: {e}")
            return {}

    @classmethod
    def validate_environment_type(cls, env_type: str) -> bool:
        """Validate environment type is recognized"""
        return env_type in cls.VALID_ENVIRONMENT_TYPES
