# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: caip_reporting_functions/cbom_export_service.py
# Copied: 2026-04-01
# Used in: Phase 13 — CBOM, Reassessments, Aggregations
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
CycloneDX CBOM Export Service for CAIP

Exports CAIP scan results to CycloneDX 1.6+ CBOM (Cryptographic Bill of Materials) format.

This service:
- Converts certificates to crypto-asset components
- Converts keys (Azure Key Vault, HSM) to related-crypto-material components
- Extracts and deduplicates algorithm components
- Includes TLS protocol information as protocol components
- Builds dependency relationships between certificates and algorithms
- Provides detection evidence with occurrence metadata

CycloneDX Specification: https://cyclonedx.org/
CBOM Use Case: https://cyclonedx.org/capabilities/cbom/

References:
- CycloneDX 1.6 JSON Schema
- draft-ietf-scitt-cbom (CBOM specification)
"""

import json
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Set, Tuple
from pathlib import Path

logger = logging.getLogger('caip.cbom_export')


class CBOMExportService:
    """
    CycloneDX CBOM (Cryptographic Bill of Materials) Export Service.
    
    Exports CAIP scan results to CycloneDX 1.6+ format supporting:
    - Certificates as crypto-asset components (assetType: certificate)
    - Keys as related-crypto-material components (assetType: related-crypto-material)
    - Algorithms with OID references (assetType: algorithm)
    - TLS protocols as protocol components (assetType: protocol)
    - Dependencies between certificates and algorithms
    - Detection evidence with source/location metadata
    
    Usage:
        cbom = CBOMExportService.export_scan_results(
            certificates=report_data['certificates'],
            keys=report_data['keys'],
            metadata={'engagement_name': 'Volvo Q4 Assessment'}
        )
        CBOMExportService.save_to_json(cbom, 'output/cbom.json')
    """
    
    SPEC_VERSION = "1.6"
    BOM_FORMAT = "CycloneDX"
    
    # =========================================================================
    # OID MAPPINGS - Signature Algorithms
    # =========================================================================
    
    SIGNATURE_ALGORITHM_OIDS = {
        # RSA variants
        'sha1WithRSAEncryption': '1.2.840.113549.1.1.5',
        'sha256WithRSAEncryption': '1.2.840.113549.1.1.11',
        'sha384WithRSAEncryption': '1.2.840.113549.1.1.12',
        'sha512WithRSAEncryption': '1.2.840.113549.1.1.13',
        'RSASSA-PSS': '1.2.840.113549.1.1.10',
        'rsaEncryption': '1.2.840.113549.1.1.1',
        # ECDSA variants
        'ecdsa-with-SHA1': '1.2.840.10045.4.1',
        'ecdsa-with-SHA256': '1.2.840.10045.4.3.2',
        'ecdsa-with-SHA384': '1.2.840.10045.4.3.3',
        'ecdsa-with-SHA512': '1.2.840.10045.4.3.4',
        # Edwards curve
        'Ed25519': '1.3.101.112',
        'ED25519': '1.3.101.112',
        'Ed448': '1.3.101.113',
        'ED448': '1.3.101.113',
        # DSA
        'dsa-with-sha1': '1.2.840.10040.4.3',
        'dsa-with-sha224': '2.16.840.1.101.3.4.3.1',
        'dsa-with-sha256': '2.16.840.1.101.3.4.3.2',
        # PQC - ML-DSA (Dilithium)
        'ML-DSA-44': '2.16.840.1.101.3.4.3.17',
        'ML-DSA-65': '2.16.840.1.101.3.4.3.18',
        'ML-DSA-87': '2.16.840.1.101.3.4.3.19',
        # PQC - SLH-DSA (SPHINCS+)
        'SLH-DSA-SHA2-128s': '2.16.840.1.101.3.4.3.20',
        'SLH-DSA-SHA2-128f': '2.16.840.1.101.3.4.3.21',
        'SLH-DSA-SHA2-192s': '2.16.840.1.101.3.4.3.22',
        'SLH-DSA-SHA2-192f': '2.16.840.1.101.3.4.3.23',
        'SLH-DSA-SHA2-256s': '2.16.840.1.101.3.4.3.24',
        'SLH-DSA-SHA2-256f': '2.16.840.1.101.3.4.3.25',
        'SLH-DSA-SHAKE-128s': '2.16.840.1.101.3.4.3.26',
        'SLH-DSA-SHAKE-128f': '2.16.840.1.101.3.4.3.27',
        'SLH-DSA-SHAKE-192s': '2.16.840.1.101.3.4.3.28',
        'SLH-DSA-SHAKE-192f': '2.16.840.1.101.3.4.3.29',
        'SLH-DSA-SHAKE-256s': '2.16.840.1.101.3.4.3.30',
        'SLH-DSA-SHAKE-256f': '2.16.840.1.101.3.4.3.31',
        # Hybrid composites
        'ECDSA-P256-ML-DSA-44': '2.16.840.1.114027.80.8.1.1',
        'ECDSA-P384-ML-DSA-65': '2.16.840.1.114027.80.8.1.2',
        'ECDSA-P521-ML-DSA-87': '2.16.840.1.114027.80.8.1.3',
    }
    
    # =========================================================================
    # OID MAPPINGS - Public Key Algorithms
    # =========================================================================
    
    KEY_ALGORITHM_OIDS = {
        'RSA': '1.2.840.113549.1.1.1',
        'rsaEncryption': '1.2.840.113549.1.1.1',
        'EC': '1.2.840.10045.2.1',
        'id-ecPublicKey': '1.2.840.10045.2.1',
        'ECDSA': '1.2.840.10045.2.1',
        # Named curves
        'secp256r1': '1.2.840.10045.3.1.7',
        'P-256': '1.2.840.10045.3.1.7',
        'prime256v1': '1.2.840.10045.3.1.7',
        'secp384r1': '1.3.132.0.34',
        'P-384': '1.3.132.0.34',
        'secp521r1': '1.3.132.0.35',
        'P-521': '1.3.132.0.35',
        # Edwards curves
        'Ed25519': '1.3.101.112',
        'Ed448': '1.3.101.113',
        'X25519': '1.3.101.110',
        'X448': '1.3.101.111',
        # PQC - ML-KEM (Kyber)
        'ML-KEM-512': '2.16.840.1.101.3.4.4.1',
        'ML-KEM-768': '2.16.840.1.101.3.4.4.2',
        'ML-KEM-1024': '2.16.840.1.101.3.4.4.3',
    }
    
    # =========================================================================
    # TLS PROTOCOL MAPPINGS
    # =========================================================================
    
    TLS_PROTOCOL_INFO = {
        'TLSv1.0': {'version': '1.0', 'oid': None, 'deprecated': True},
        'TLSv1.1': {'version': '1.1', 'oid': None, 'deprecated': True},
        'TLSv1.2': {'version': '1.2', 'oid': None, 'deprecated': False},
        'TLSv1.3': {'version': '1.3', 'oid': None, 'deprecated': False},
        'TLS 1.0': {'version': '1.0', 'oid': None, 'deprecated': True},
        'TLS 1.1': {'version': '1.1', 'oid': None, 'deprecated': True},
        'TLS 1.2': {'version': '1.2', 'oid': None, 'deprecated': False},
        'TLS 1.3': {'version': '1.3', 'oid': None, 'deprecated': False},
    }
    
    # =========================================================================
    # CORE EXPORT METHOD
    # =========================================================================
    
    @classmethod
    def export_scan_results(cls,
                           certificates: List[Dict[str, Any]],
                           keys: List[Dict[str, Any]] = None,
                           tls_results: List[Dict[str, Any]] = None,
                           metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Export scan results to CycloneDX CBOM format.
        
        Args:
            certificates: List of certificate dicts from CAIP scan
            keys: List of key dicts (Azure Key Vault + HSM keys combined)
            tls_results: Optional list of TLS scan results for protocol components
            metadata: Optional metadata dict with engagement_name, scan_id, etc.
            
        Returns:
            CycloneDX CBOM dictionary ready for JSON serialization
        """
        keys = keys or []
        tls_results = tls_results or []
        metadata = metadata or {}
        
        # Track algorithms for deduplication
        algorithm_tracker: Dict[str, Dict[str, Any]] = {}
        
        # Track TLS protocols for deduplication  
        protocol_tracker: Dict[str, Dict[str, Any]] = {}
        
        # Build components
        components = []
        dependencies = []
        
        # Process certificates
        for cert in certificates:
            cert_component, cert_algos, cert_protocols = cls._build_certificate_component(cert)
            components.append(cert_component)
            
            # Track algorithms from this certificate
            for algo_key, algo_data in cert_algos.items():
                if algo_key not in algorithm_tracker:
                    algorithm_tracker[algo_key] = algo_data
            
            # Track TLS protocols from this certificate
            for proto_key, proto_data in cert_protocols.items():
                if proto_key not in protocol_tracker:
                    protocol_tracker[proto_key] = proto_data
            
            # Build dependency: certificate depends on its algorithms
            if cert_algos:
                dependencies.append({
                    'ref': cert_component['bom-ref'],
                    'dependsOn': list(cert_algos.keys())
                })
        
        # Process keys
        for key in keys:
            key_component, key_algos = cls._build_key_component(key)
            components.append(key_component)
            
            # Track algorithms from this key
            for algo_key, algo_data in key_algos.items():
                if algo_key not in algorithm_tracker:
                    algorithm_tracker[algo_key] = algo_data
            
            # Build dependency: key depends on its algorithm
            if key_algos:
                dependencies.append({
                    'ref': key_component['bom-ref'],
                    'dependsOn': list(key_algos.keys())
                })
        
        # Process additional TLS results (if provided separately)
        for tls_result in tls_results:
            tls_protocols = cls._extract_tls_protocols(tls_result)
            for proto_key, proto_data in tls_protocols.items():
                if proto_key not in protocol_tracker:
                    protocol_tracker[proto_key] = proto_data
        
        # Add algorithm components
        for algo_ref, algo_data in algorithm_tracker.items():
            components.append(cls._build_algorithm_component(algo_ref, algo_data))
        
        # Add protocol components
        for proto_ref, proto_data in protocol_tracker.items():
            components.append(cls._build_protocol_component(proto_ref, proto_data))
        
        # Build final CBOM structure
        cbom = {
            'bomFormat': cls.BOM_FORMAT,
            'specVersion': cls.SPEC_VERSION,
            'serialNumber': f"urn:uuid:{uuid.uuid4()}",
            'version': 1,
            'metadata': cls._build_metadata(metadata, certificates, keys),
            'components': components,
            'dependencies': dependencies if dependencies else None
        }
        
        # Remove None values
        cbom = {k: v for k, v in cbom.items() if v is not None}
        
        logger.info(f"Generated CBOM with {len(components)} components "
                   f"({len(certificates)} certs, {len(keys)} keys, "
                   f"{len(algorithm_tracker)} algorithms, {len(protocol_tracker)} protocols)")
        
        return cbom
    
    # =========================================================================
    # COMPONENT BUILDERS
    # =========================================================================
    
    @classmethod
    def _build_certificate_component(cls, cert: Dict[str, Any]) -> Tuple[Dict, Dict, Dict]:
        """
        Build a CycloneDX certificate component.
        
        Args:
            cert: Certificate dictionary from CAIP scan
            
        Returns:
            Tuple of (component_dict, algorithms_dict, protocols_dict)
        """
        # Generate unique reference
        bom_ref = f"cert-{cert.get('fingerprint_sha256', uuid.uuid4().hex)[:16]}"
        
        # Extract subject info
        subject = cert.get('subject', {})
        if isinstance(subject, dict):
            subject_name = subject.get('commonName', subject.get('CN', 'Unknown'))
        else:
            subject_name = str(subject)
        
        # Extract issuer info
        issuer = cert.get('issuer', {})
        if isinstance(issuer, dict):
            issuer_name = issuer.get('commonName', issuer.get('CN', 'Unknown'))
        else:
            issuer_name = str(issuer)
        
        # Build crypto properties
        signature_algo = cert.get('signature_algorithm', 'Unknown')
        public_key_algo = cert.get('public_key_algorithm', 'Unknown')
        
        # Get OIDs
        sig_oid = cls._get_algorithm_oid(signature_algo, 'signature')
        key_oid = cls._get_algorithm_oid(public_key_algo, 'key')
        
        # Build algorithm refs for tracking
        algorithms = {}
        sig_algo_ref = f"algo-sig-{cls._normalize_algo_name(signature_algo)}"
        algorithms[sig_algo_ref] = {
            'name': signature_algo,
            'type': 'signature',
            'oid': sig_oid,
            'pqc_analysis': cert.get('pqc_analysis')
        }
        
        if public_key_algo and public_key_algo != signature_algo:
            key_algo_ref = f"algo-key-{cls._normalize_algo_name(public_key_algo)}"
            algorithms[key_algo_ref] = {
                'name': public_key_algo,
                'type': 'key',
                'oid': key_oid,
                'key_size': cert.get('public_key_size'),
                'pqc_analysis': cert.get('pqc_analysis')
            }
        
        # Track TLS protocols
        protocols = {}
        tls_version = cert.get('tls_version')
        if tls_version and tls_version != 'N/A':
            proto_ref = f"proto-tls-{tls_version.replace('.', '-').replace(' ', '')}"
            protocols[proto_ref] = {
                'name': tls_version,
                'type': 'tls',
                'info': cls.TLS_PROTOCOL_INFO.get(tls_version, {})
            }
        
        # Build certificate properties per CycloneDX spec
        certificate_properties = {
            'subjectName': cls._format_dn(cert.get('subject')),
            'issuerName': cls._format_dn(cert.get('issuer')),
            'notValidBefore': cert.get('not_before'),
            'notValidAfter': cert.get('not_after'),
            'signatureAlgorithmRef': sig_algo_ref,
            'subjectPublicKeyRef': list(algorithms.keys())[-1] if len(algorithms) > 1 else sig_algo_ref,
        }
        
        # Add optional certificate fields
        if cert.get('serial_number'):
            certificate_properties['serialNumber'] = cert.get('serial_number')
        
        if cert.get('fingerprint_sha256'):
            certificate_properties['certificateFingerprint'] = cert.get('fingerprint_sha256')
        
        if cert.get('san'):
            certificate_properties['subjectAlternativeNames'] = cert.get('san')
        
        if cert.get('key_usage'):
            certificate_properties['keyUsage'] = cert.get('key_usage')
        
        if cert.get('extended_key_usage'):
            certificate_properties['extendedKeyUsage'] = cert.get('extended_key_usage')
        
        # Build component
        component = {
            'type': 'cryptographic-asset',
            'bom-ref': bom_ref,
            'name': subject_name,
            'description': f"X.509 Certificate issued by {issuer_name}",
            'cryptoProperties': {
                'assetType': 'certificate',
                'certificateProperties': certificate_properties
            }
        }
        
        # Add evidence if we have source information
        evidence = cls._build_evidence(cert)
        if evidence:
            component['evidence'] = evidence
        
        # Add PQC analysis as properties if present
        if cert.get('pqc_analysis'):
            component['properties'] = cls._build_pqc_properties(cert.get('pqc_analysis'))
        
        return component, algorithms, protocols
    
    @classmethod
    def _build_key_component(cls, key: Dict[str, Any]) -> Tuple[Dict, Dict]:
        """
        Build a CycloneDX key component.
        
        Args:
            key: Key dictionary (Azure Key Vault or HSM key)
            
        Returns:
            Tuple of (component_dict, algorithms_dict)
        """
        # Generate unique reference
        key_id = key.get('key_id', key.get('object_id', uuid.uuid4().hex))
        bom_ref = f"key-{str(key_id).replace('/', '-')[-32:]}"
        
        key_name = key.get('name', key.get('label', 'Unknown'))
        key_type = key.get('key_type', 'Unknown')
        key_size = key.get('key_size')
        
        # Get algorithm OID
        key_oid = cls._get_algorithm_oid(key_type, 'key')
        
        # Build algorithm reference
        algorithms = {}
        algo_ref = f"algo-key-{cls._normalize_algo_name(key_type)}"
        if key_size:
            algo_ref = f"{algo_ref}-{key_size}"
        algorithms[algo_ref] = {
            'name': key_type,
            'type': 'key',
            'oid': key_oid,
            'key_size': key_size,
            'pqc_analysis': key.get('pqc_analysis')
        }
        
        # Determine key asset type
        is_private = key.get('private', False)
        asset_type = 'private-key' if is_private else 'public-key'
        
        # Build related crypto material properties
        related_material_props = {
            'type': asset_type,
            'algorithmRef': algo_ref,
        }
        
        # Add size if available
        if key_size:
            related_material_props['size'] = key_size
        
        # Determine state
        if key.get('enabled') is False:
            related_material_props['state'] = 'disabled'
        elif key.get('expires_on'):
            # Check if expired
            try:
                expires = datetime.fromisoformat(key['expires_on'].replace('Z', '+00:00'))
                if expires < datetime.now(timezone.utc):
                    related_material_props['state'] = 'expired'
                else:
                    related_material_props['state'] = 'active'
            except:
                related_material_props['state'] = 'active'
        else:
            related_material_props['state'] = 'active'
        
        # Add creation date if available
        if key.get('created_on'):
            related_material_props['creationDate'] = key.get('created_on')
        
        # Add activation/expiration dates
        if key.get('not_before'):
            related_material_props['activationDate'] = key.get('not_before')
        if key.get('expires_on'):
            related_material_props['expirationDate'] = key.get('expires_on')
        
        # Add secured by mechanism
        if key.get('hsm_backed'):
            related_material_props['securedBy'] = {
                'mechanism': 'Hardware Security Module',
                'description': 'Key protected by HSM'
            }
        elif key.get('source') == 'Luna HSM':
            related_material_props['securedBy'] = {
                'mechanism': 'Hardware Security Module',
                'description': 'Thales Luna HSM'
            }
        
        # Build component
        component = {
            'type': 'cryptographic-asset',
            'bom-ref': bom_ref,
            'name': key_name,
            'description': f"{key_type} key from {key.get('source', 'Unknown source')}",
            'cryptoProperties': {
                'assetType': 'related-crypto-material',
                'relatedCryptoMaterialProperties': related_material_props
            }
        }
        
        # Add evidence if we have source information
        evidence = cls._build_key_evidence(key)
        if evidence:
            component['evidence'] = evidence
        
        # Add PQC analysis as properties if present
        if key.get('pqc_analysis'):
            component['properties'] = cls._build_pqc_properties(key.get('pqc_analysis'))
        
        return component, algorithms
    
    @classmethod
    def _build_algorithm_component(cls, algo_ref: str, algo_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build a CycloneDX algorithm component.
        
        Args:
            algo_ref: Algorithm reference ID
            algo_data: Algorithm data dict with name, type, oid, etc.
            
        Returns:
            Algorithm component dictionary
        """
        algo_name = algo_data.get('name', 'Unknown')
        algo_type = algo_data.get('type', 'signature')
        algo_oid = algo_data.get('oid')
        pqc_analysis = algo_data.get('pqc_analysis')
        
        # Determine crypto functions based on algorithm type
        crypto_functions = cls._infer_crypto_functions(algo_name, algo_type)
        
        # Build algorithm properties
        algo_props = {
            'primitive': cls._get_algorithm_primitive(algo_name),
            'cryptoFunctions': crypto_functions,
        }
        
        # Add parameter set/length if known
        key_size = algo_data.get('key_size')
        if key_size:
            algo_props['parameterSetIdentifier'] = str(key_size)
        
        # Add NIST quantum security level if PQC
        if pqc_analysis and pqc_analysis.get('security_level'):
            algo_props['nistQuantumSecurityLevel'] = pqc_analysis.get('security_level')
        
        # Add classical security level estimate
        classical_level = cls._estimate_classical_security_level(algo_name, key_size)
        if classical_level:
            algo_props['classicalSecurityLevel'] = classical_level
        
        component = {
            'type': 'cryptographic-asset',
            'bom-ref': algo_ref,
            'name': algo_name,
            'description': f"{algo_type.title()} algorithm",
            'cryptoProperties': {
                'assetType': 'algorithm',
                'algorithmProperties': algo_props
            }
        }
        
        # Add OID if known
        if algo_oid:
            component['cryptoProperties']['oid'] = algo_oid
        
        # Add PQC-specific properties
        if pqc_analysis:
            props = cls._build_pqc_properties(pqc_analysis)
            if props:
                component['properties'] = props
        
        return component
    
    @classmethod
    def _build_protocol_component(cls, proto_ref: str, proto_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build a CycloneDX protocol component for TLS.
        
        Args:
            proto_ref: Protocol reference ID
            proto_data: Protocol data dict
            
        Returns:
            Protocol component dictionary
        """
        proto_name = proto_data.get('name', 'Unknown')
        proto_info = proto_data.get('info', {})
        
        # Build protocol properties
        protocol_props = {
            'type': 'tls',
            'version': proto_info.get('version', proto_name),
        }
        
        component = {
            'type': 'cryptographic-asset',
            'bom-ref': proto_ref,
            'name': f"TLS {proto_info.get('version', proto_name)}",
            'description': f"Transport Layer Security Protocol",
            'cryptoProperties': {
                'assetType': 'protocol',
                'protocolProperties': protocol_props
            }
        }
        
        # Add deprecation note as property
        if proto_info.get('deprecated'):
            component['properties'] = [{
                'name': 'deprecated',
                'value': 'true'
            }, {
                'name': 'security-note',
                'value': 'This TLS version is deprecated and should not be used'
            }]
        
        return component
    
    # =========================================================================
    # METADATA BUILDER
    # =========================================================================
    
    @classmethod
    def _build_metadata(cls, 
                       metadata: Dict[str, Any],
                       certificates: List[Dict],
                       keys: List[Dict]) -> Dict[str, Any]:
        """Build BOM metadata section."""
        
        bom_metadata = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'tools': {
                'components': [{
                    'type': 'application',
                    'name': 'CAIP',
                    'description': 'Cryptographic Asset Intelligence Platform',
                    'version': metadata.get('caip_version', '1.0.0')
                }]
            },
            'component': {
                'type': 'application',
                'name': metadata.get('engagement_name', 'PKI Assessment'),
                'description': 'Cryptographic asset inventory from CAIP scan'
            }
        }
        
        # Add supplier/manufacturer if provided
        if metadata.get('customer_name'):
            bom_metadata['component']['supplier'] = {
                'name': metadata.get('customer_name')
            }
        
        # Add properties for scan metadata
        properties = []
        if metadata.get('scan_id'):
            properties.append({'name': 'scan-id', 'value': str(metadata['scan_id'])})
        if metadata.get('engagement_id'):
            properties.append({'name': 'engagement-id', 'value': str(metadata['engagement_id'])})
        if metadata.get('policy_name'):
            properties.append({'name': 'policy-name', 'value': metadata['policy_name']})
        
        # Add summary statistics
        properties.append({'name': 'total-certificates', 'value': str(len(certificates))})
        properties.append({'name': 'total-keys', 'value': str(len(keys))})
        
        if properties:
            bom_metadata['properties'] = properties
        
        return bom_metadata
    
    # =========================================================================
    # EVIDENCE BUILDERS
    # =========================================================================
    
    @classmethod
    def _build_evidence(cls, cert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Build evidence section for certificate detection context."""
        occurrences = []
        
        # Add TLS endpoint occurrence
        destination = cert.get('found_at_destination')
        port = cert.get('found_on_port')
        if destination and destination != 'N/A':
            location = str(destination)
            if port and port != 'N/A':
                location = f"{location}:{port}"
            occurrences.append({
                'location': location,
                'additionalContext': f"Discovered via TLS scan"
            })
        
        # Add source information
        source = cert.get('source')
        if source:
            occurrences.append({
                'location': source,
                'additionalContext': f"Certificate source: {source}"
            })
        
        if not occurrences:
            return None
        
        return {
            'occurrences': occurrences
        }
    
    @classmethod
    def _build_key_evidence(cls, key: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Build evidence section for key detection context."""
        occurrences = []
        
        # Add vault/HSM location
        vault_url = key.get('vault_url')
        if vault_url:
            occurrences.append({
                'location': vault_url,
                'additionalContext': f"Azure Key Vault: {key.get('tenancy_name', 'Unknown tenant')}"
            })
        
        source = key.get('source')
        if source and source != 'Azure Key Vault':
            occurrences.append({
                'location': source,
                'additionalContext': f"Key source"
            })
        
        if not occurrences:
            return None
        
        return {
            'occurrences': occurrences
        }
    
    # =========================================================================
    # HELPER METHODS
    # =========================================================================
    
    @classmethod
    def _get_algorithm_oid(cls, algo_name: str, algo_type: str = 'signature') -> Optional[str]:
        """Look up OID for an algorithm name."""
        if not algo_name:
            return None
        
        # Normalize name for lookup
        normalized = algo_name.strip()
        
        # Try direct lookup
        if algo_type == 'signature':
            oid = cls.SIGNATURE_ALGORITHM_OIDS.get(normalized)
            if oid:
                return oid
        
        oid = cls.KEY_ALGORITHM_OIDS.get(normalized)
        if oid:
            return oid
        
        # Try case-insensitive lookup
        for name, oid in cls.SIGNATURE_ALGORITHM_OIDS.items():
            if name.lower() == normalized.lower():
                return oid
        
        for name, oid in cls.KEY_ALGORITHM_OIDS.items():
            if name.lower() == normalized.lower():
                return oid
        
        return None
    
    @classmethod
    def _normalize_algo_name(cls, algo_name: str) -> str:
        """Normalize algorithm name for use as reference ID."""
        if not algo_name:
            return 'unknown'
        return algo_name.lower().replace(' ', '-').replace('_', '-').replace('/', '-')
    
    @classmethod
    def _format_dn(cls, dn: Any) -> str:
        """Format a distinguished name as string."""
        if not dn:
            return ''
        if isinstance(dn, dict):
            parts = []
            # Standard order for DN components
            order = ['CN', 'commonName', 'O', 'organizationName', 'OU', 
                    'organizationalUnitName', 'L', 'localityName', 
                    'ST', 'stateOrProvinceName', 'C', 'countryName']
            for key in order:
                if key in dn:
                    parts.append(f"{key}={dn[key]}")
            # Add any remaining keys
            for key, value in dn.items():
                if key not in order:
                    parts.append(f"{key}={value}")
            return ', '.join(parts)
        return str(dn)
    
    @classmethod
    def _infer_crypto_functions(cls, algo_name: str, algo_type: str) -> List[str]:
        """Infer cryptographic functions from algorithm."""
        algo_upper = algo_name.upper() if algo_name else ''
        
        if algo_type == 'signature' or 'DSA' in algo_upper or 'ECDSA' in algo_upper:
            return ['sign', 'verify']
        
        if 'RSA' in algo_upper:
            return ['encrypt', 'decrypt', 'sign', 'verify']
        
        if 'KEM' in algo_upper or 'KYBER' in algo_upper:
            return ['encapsulate', 'decapsulate']
        
        if 'AES' in algo_upper:
            return ['encrypt', 'decrypt']
        
        if 'EC' in algo_upper or 'ECDH' in algo_upper:
            return ['keyagree']
        
        if 'ED25519' in algo_upper or 'ED448' in algo_upper:
            return ['sign', 'verify']
        
        return ['unknown']
    
    @classmethod
    def _get_algorithm_primitive(cls, algo_name: str) -> str:
        """Get algorithm primitive type."""
        algo_upper = algo_name.upper() if algo_name else ''
        
        if 'RSA' in algo_upper:
            return 'rsa'
        if 'ECDSA' in algo_upper or 'EC' in algo_upper:
            return 'ec'
        if 'DSA' in algo_upper and 'EC' not in algo_upper:
            return 'dsa'
        if 'ED25519' in algo_upper or 'ED448' in algo_upper:
            return 'ec'
        if 'ML-DSA' in algo_upper or 'DILITHIUM' in algo_upper:
            return 'lattice'
        if 'ML-KEM' in algo_upper or 'KYBER' in algo_upper:
            return 'lattice'
        if 'SLH-DSA' in algo_upper or 'SPHINCS' in algo_upper:
            return 'hash'
        if 'AES' in algo_upper:
            return 'ae'
        if 'SHA' in algo_upper:
            return 'hash'
        
        return 'unknown'
    
    @classmethod
    def _estimate_classical_security_level(cls, algo_name: str, key_size: Optional[int]) -> Optional[int]:
        """Estimate classical security level in bits."""
        algo_upper = algo_name.upper() if algo_name else ''
        
        if 'RSA' in algo_upper and key_size:
            # RSA security level approximations
            if key_size >= 15360:
                return 256
            if key_size >= 7680:
                return 192
            if key_size >= 3072:
                return 128
            if key_size >= 2048:
                return 112
            return 80
        
        if ('ECDSA' in algo_upper or 'EC' in algo_upper) and key_size:
            # EC security level is approximately half the key size
            return key_size // 2
        
        if 'ED25519' in algo_upper:
            return 128
        
        if 'ED448' in algo_upper:
            return 224
        
        return None
    
    @classmethod
    def _build_pqc_properties(cls, pqc_analysis: Dict[str, Any]) -> List[Dict[str, str]]:
        """Build properties list from PQC analysis."""
        if not pqc_analysis:
            return []
        
        properties = []
        
        if pqc_analysis.get('is_pqc'):
            properties.append({'name': 'pqc-enabled', 'value': 'true'})
        else:
            properties.append({'name': 'pqc-enabled', 'value': 'false'})
        
        if pqc_analysis.get('is_hybrid'):
            properties.append({'name': 'pqc-hybrid', 'value': 'true'})
        
        if pqc_analysis.get('pqc_algorithm'):
            properties.append({'name': 'pqc-algorithm', 'value': pqc_analysis['pqc_algorithm']})
        
        if pqc_analysis.get('pqc_category'):
            properties.append({'name': 'pqc-category', 'value': pqc_analysis['pqc_category']})
        
        if pqc_analysis.get('migration_status'):
            properties.append({'name': 'migration-status', 'value': pqc_analysis['migration_status']})
        
        if pqc_analysis.get('security_level'):
            properties.append({'name': 'nist-security-level', 'value': str(pqc_analysis['security_level'])})
        
        return properties
    
    @classmethod
    def _extract_tls_protocols(cls, tls_result: Dict[str, Any]) -> Dict[str, Dict]:
        """Extract TLS protocol information from TLS scan result."""
        protocols = {}
        
        supported = tls_result.get('supported_protocols', [])
        for proto in supported:
            proto_ref = f"proto-tls-{proto.replace('.', '-').replace(' ', '')}"
            protocols[proto_ref] = {
                'name': proto,
                'type': 'tls',
                'info': cls.TLS_PROTOCOL_INFO.get(proto, {})
            }
        
        return protocols
    
    # =========================================================================
    # FILE OUTPUT METHODS
    # =========================================================================
    
    @classmethod
    def save_to_json(cls, cbom: Dict[str, Any], output_path: str) -> Path:
        """
        Save CBOM to JSON file.
        
        Args:
            cbom: CycloneDX CBOM dictionary
            output_path: Output file path
            
        Returns:
            Path to saved file
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(cbom, f, indent=2, default=str)
        
        logger.info(f"CBOM saved to {output_file}")
        return output_file
    
    @classmethod
    def to_json_string(cls, cbom: Dict[str, Any], indent: int = 2) -> str:
        """
        Convert CBOM to JSON string.
        
        Args:
            cbom: CycloneDX CBOM dictionary
            indent: JSON indentation level
            
        Returns:
            JSON string
        """
        return json.dumps(cbom, indent=indent, default=str)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def export_to_cbom(certificates: List[Dict[str, Any]],
                   keys: List[Dict[str, Any]] = None,
                   metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Convenience function to export scan results to CycloneDX CBOM.
    
    Args:
        certificates: List of certificate dicts from CAIP scan
        keys: List of key dicts (combined from all sources)
        metadata: Optional metadata dict
        
    Returns:
        CycloneDX CBOM dictionary
    """
    return CBOMExportService.export_scan_results(
        certificates=certificates,
        keys=keys or [],
        metadata=metadata
    )
