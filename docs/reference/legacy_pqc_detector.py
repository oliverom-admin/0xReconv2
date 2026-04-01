# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: caip_pqc_functions/pqc_detector.py
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
PQC (Post-Quantum Cryptography) Detection Utility for CAIP

Provides detection of post-quantum and hybrid cryptographic algorithms
in certificates and keys based on NIST standardized OIDs.

This module:
- Detects ML-KEM, ML-DSA, SLH-DSA algorithms by OID
- Identifies hybrid classical+PQC combinations
- Categorizes algorithms by type (lattice, hash-based, etc.)
- Provides migration classification for certificates

OID mappings are externalized to support updates as standards evolve.

References:
- NIST FIPS 203 (ML-KEM)
- NIST FIPS 204 (ML-DSA) 
- NIST FIPS 205 (SLH-DSA)
- draft-ietf-lamps-dilithium-certificates
- draft-ietf-lamps-kyber-certificates
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger('caip.pqc')


class PQCCategory(Enum):
    """Categories of post-quantum algorithms"""
    CLASSICAL = "classical"
    LATTICE = "lattice"
    HASH_BASED = "hash_based"
    CODE_BASED = "code_based"
    ISOGENY = "isogeny"
    HYBRID = "hybrid"
    UNKNOWN = "unknown"


class MigrationStatus(Enum):
    """Migration status classification for assets"""
    PQC_READY = "pqc_ready"           # Already using PQC algorithms
    HYBRID_TRANSITION = "hybrid"      # Using hybrid classical+PQC
    NEEDS_MIGRATION = "needs_migration"  # Classical, needs migration
    UNKNOWN = "unknown"


@dataclass
class PQCAnalysis:
    """Result of PQC analysis for a certificate or key"""
    is_pqc: bool
    is_hybrid: bool
    pqc_algorithm: Optional[str]
    pqc_category: PQCCategory
    classical_algorithm: Optional[str]
    migration_status: MigrationStatus
    security_level: Optional[int]  # NIST security level 1-5
    notes: List[str]
    algorithm_class: Optional[str] = None      # 'asymmetric', 'symmetric', 'hash'
    vulnerability_level: Optional[str] = None  # 'critical', 'high', 'medium', 'low', 'none'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'is_pqc': self.is_pqc,
            'is_hybrid': self.is_hybrid,
            'pqc_algorithm': self.pqc_algorithm,
            'pqc_category': self.pqc_category.value,
            'classical_algorithm': self.classical_algorithm,
            'migration_status': self.migration_status.value,
            'security_level': self.security_level,
            'notes': self.notes,
            'algorithm_class': self.algorithm_class,
            'vulnerability_level': self.vulnerability_level,
        }


class PQCDetector:
    """
    Detects post-quantum cryptographic algorithms in certificates and keys.
    
    Uses OID-based detection for standardized PQC algorithms and
    signature algorithm name parsing for additional coverage.
    """
    
    # ==========================================================================
    # NIST PQC ALGORITHM OID MAPPINGS
    # These OIDs are from NIST FIPS 203/204/205 and IETF drafts
    # Update these as standards finalize
    # ==========================================================================
    
    # ML-DSA (Dilithium) - FIPS 204 - Lattice-based signatures
    # OID: 2.16.840.1.101.3.4.3.x (NIST algorithm OID arc)
    ML_DSA_OIDS = {
        '2.16.840.1.101.3.4.3.17': ('ML-DSA-44', 2),      # NIST Level 2
        '2.16.840.1.101.3.4.3.18': ('ML-DSA-65', 3),      # NIST Level 3
        '2.16.840.1.101.3.4.3.19': ('ML-DSA-87', 5),      # NIST Level 5
        # Pure versions
        '2.16.840.1.101.3.4.3.32': ('ML-DSA-44', 2),
        '2.16.840.1.101.3.4.3.33': ('ML-DSA-65', 3),
        '2.16.840.1.101.3.4.3.34': ('ML-DSA-87', 5),
    }
    
    # ML-KEM (Kyber) - FIPS 203 - Lattice-based key encapsulation
    ML_KEM_OIDS = {
        '2.16.840.1.101.3.4.4.1': ('ML-KEM-512', 1),      # NIST Level 1
        '2.16.840.1.101.3.4.4.2': ('ML-KEM-768', 3),      # NIST Level 3
        '2.16.840.1.101.3.4.4.3': ('ML-KEM-1024', 5),     # NIST Level 5
    }
    
    # SLH-DSA (SPHINCS+) - FIPS 205 - Hash-based signatures
    SLH_DSA_OIDS = {
        # SHA2 variants
        '2.16.840.1.101.3.4.3.20': ('SLH-DSA-SHA2-128s', 1),
        '2.16.840.1.101.3.4.3.21': ('SLH-DSA-SHA2-128f', 1),
        '2.16.840.1.101.3.4.3.22': ('SLH-DSA-SHA2-192s', 3),
        '2.16.840.1.101.3.4.3.23': ('SLH-DSA-SHA2-192f', 3),
        '2.16.840.1.101.3.4.3.24': ('SLH-DSA-SHA2-256s', 5),
        '2.16.840.1.101.3.4.3.25': ('SLH-DSA-SHA2-256f', 5),
        # SHAKE variants
        '2.16.840.1.101.3.4.3.26': ('SLH-DSA-SHAKE-128s', 1),
        '2.16.840.1.101.3.4.3.27': ('SLH-DSA-SHAKE-128f', 1),
        '2.16.840.1.101.3.4.3.28': ('SLH-DSA-SHAKE-192s', 3),
        '2.16.840.1.101.3.4.3.29': ('SLH-DSA-SHAKE-192f', 3),
        '2.16.840.1.101.3.4.3.30': ('SLH-DSA-SHAKE-256s', 5),
        '2.16.840.1.101.3.4.3.31': ('SLH-DSA-SHAKE-256f', 5),
    }
    
    # Hybrid algorithm OIDs (composite signatures)
    # These combine classical + PQC algorithms
    HYBRID_OIDS = {
        # ECDSA + ML-DSA composites (draft-ietf-lamps-pq-composite-sigs)
        '2.16.840.1.114027.80.8.1.1': ('ECDSA-P256-ML-DSA-44', 2),
        '2.16.840.1.114027.80.8.1.2': ('ECDSA-P384-ML-DSA-65', 3),
        '2.16.840.1.114027.80.8.1.3': ('ECDSA-P521-ML-DSA-87', 5),
        # RSA + ML-DSA composites
        '2.16.840.1.114027.80.8.1.4': ('RSA-PSS-ML-DSA-44', 2),
        '2.16.840.1.114027.80.8.1.5': ('RSA-PSS-ML-DSA-65', 3),
        '2.16.840.1.114027.80.8.1.6': ('RSA-PSS-ML-DSA-87', 5),
        # Ed25519 + ML-DSA
        '2.16.840.1.114027.80.8.1.7': ('Ed25519-ML-DSA-44', 2),
        '2.16.840.1.114027.80.8.1.8': ('Ed448-ML-DSA-65', 3),
    }
    
    # Classical algorithms for reference
    CLASSICAL_SIGNATURE_OIDS = {
        '1.2.840.113549.1.1.1': 'RSA',
        '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
        '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
        '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
        '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
        '1.2.840.113549.1.1.10': 'RSASSA-PSS',
        '1.2.840.10045.4.1': 'ecdsa-with-SHA1',
        '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
        '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
        '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
        '1.3.101.112': 'Ed25519',
        '1.3.101.113': 'Ed448',
        '1.2.840.10040.4.3': 'dsa-with-sha1',
        '2.16.840.1.101.3.4.3.1': 'dsa-with-sha224',
        '2.16.840.1.101.3.4.3.2': 'dsa-with-sha256',
    }
    
    # Algorithm name patterns for string-based detection
    PQC_NAME_PATTERNS = {
        'ML-DSA': (PQCCategory.LATTICE, 'ML-DSA'),
        'ML-KEM': (PQCCategory.LATTICE, 'ML-KEM'),
        'SLH-DSA': (PQCCategory.HASH_BASED, 'SLH-DSA'),
        'SPHINCS': (PQCCategory.HASH_BASED, 'SLH-DSA'),
        'Dilithium': (PQCCategory.LATTICE, 'ML-DSA'),
        'Kyber': (PQCCategory.LATTICE, 'ML-KEM'),
        'FALCON': (PQCCategory.LATTICE, 'FALCON'),
        'BIKE': (PQCCategory.CODE_BASED, 'BIKE'),
        'HQC': (PQCCategory.CODE_BASED, 'HQC'),
        'Classic McEliece': (PQCCategory.CODE_BASED, 'Classic McEliece'),
    }
    
    # ==========================================================================
    # KEY ALGORITHM QUANTUM VULNERABILITY CLASSIFICATION
    # Asymmetric algorithms are broken by Shor's algorithm
    # Symmetric algorithms are weakened by Grover's (halves effective key length)
    # ==========================================================================
    
    KEY_ALGORITHM_CLASSIFICATION = {
        # Asymmetric - Fully quantum vulnerable (Shor's algorithm)
        'RSA': ('asymmetric', 'critical'),
        'EC': ('asymmetric', 'critical'),
        'ECDSA': ('asymmetric', 'critical'),
        'ECDH': ('asymmetric', 'critical'),
        'DSA': ('asymmetric', 'critical'),
        'DH': ('asymmetric', 'critical'),
        'DIFFIEHELLMAN': ('asymmetric', 'critical'),
        'ED25519': ('asymmetric', 'critical'),
        'ED448': ('asymmetric', 'critical'),
        'X25519': ('asymmetric', 'critical'),
        'X448': ('asymmetric', 'critical'),
        'EDDSA': ('asymmetric', 'critical'),
        
        # Symmetric - Grover's algorithm halves effective key length
        'AES': ('symmetric', 'check_size'),      # Depends on key size
        'AES128': ('symmetric', 'medium'),       # 64-bit post-quantum - borderline
        'AES-128': ('symmetric', 'medium'),
        'AES192': ('symmetric', 'low'),          # 96-bit post-quantum - adequate
        'AES-192': ('symmetric', 'low'),
        'AES256': ('symmetric', 'none'),         # 128-bit post-quantum - secure
        'AES-256': ('symmetric', 'none'),
        '3DES': ('symmetric', 'medium'),         # Already weak, slightly weaker
        'TDES': ('symmetric', 'medium'),
        'DES': ('symmetric', 'high'),            # Already broken
        'DESEDE': ('symmetric', 'medium'),
        'CHACHA20': ('symmetric', 'check_size'),
        'CHACHA': ('symmetric', 'check_size'),
        
        # Hash-based / HMAC - Minimal quantum impact
        'HMAC': ('hash', 'none'),
        'HMAC-SHA1': ('hash', 'low'),            # SHA1 weakness, not quantum
        'HMAC-SHA256': ('hash', 'none'),
        'HMAC-SHA384': ('hash', 'none'),
        'HMAC-SHA512': ('hash', 'none'),
        'SHA': ('hash', 'none'),
        
        # Generic secret keys (often symmetric)
        'GENERIC_SECRET': ('symmetric', 'low'),
        'SECRET': ('symmetric', 'low'),
    }
    
    @classmethod
    def classify_key_algorithm(cls, key_type: str, key_size: int = None) -> Tuple[str, str]:
        """
        Classify a key algorithm's quantum vulnerability.
        
        Args:
            key_type: The key type/algorithm name
            key_size: Key size in bits (optional, used for size-dependent classification)
            
        Returns:
            Tuple of (algorithm_class, vulnerability_level)
            - algorithm_class: 'asymmetric', 'symmetric', 'hash', or 'unknown'
            - vulnerability_level: 'critical', 'high', 'medium', 'low', 'none', or 'unknown'
        """
        if not key_type:
            return ('unknown', 'unknown')
        
        key_type_upper = key_type.upper().replace(' ', '').replace('_', '')
        
        # Direct lookup first
        if key_type_upper in cls.KEY_ALGORITHM_CLASSIFICATION:
            algo_class, vuln = cls.KEY_ALGORITHM_CLASSIFICATION[key_type_upper]
            
            # Handle size-dependent classification
            if vuln == 'check_size' and key_size:
                if key_size >= 256:
                    return (algo_class, 'none')      # 128-bit post-quantum
                elif key_size >= 192:
                    return (algo_class, 'low')       # 96-bit post-quantum
                elif key_size >= 128:
                    return (algo_class, 'medium')    # 64-bit post-quantum
                else:
                    return (algo_class, 'high')      # <64-bit post-quantum
            elif vuln == 'check_size':
                return (algo_class, 'low')           # Unknown size, assume adequate
            
            return (algo_class, vuln)
        
        # Pattern matching for partial matches
        for pattern, (algo_class, vuln) in cls.KEY_ALGORITHM_CLASSIFICATION.items():
            if pattern in key_type_upper:
                if vuln == 'check_size' and key_size:
                    if key_size >= 256:
                        return (algo_class, 'none')
                    elif key_size >= 192:
                        return (algo_class, 'low')
                    elif key_size >= 128:
                        return (algo_class, 'medium')
                    else:
                        return (algo_class, 'high')
                elif vuln == 'check_size':
                    return (algo_class, 'low')
                return (algo_class, vuln)
        
        # Heuristic detection for unknown algorithms
        if any(x in key_type_upper for x in ['RSA', 'EC', 'DSA', 'DH', 'CURVE', 'ELLIPTIC']):
            return ('asymmetric', 'critical')
        if any(x in key_type_upper for x in ['AES', 'DES', 'CHACHA', 'CAMELLIA', 'ARIA', 'SEED', 'BLOCK']):
            return ('symmetric', 'low' if key_size and key_size >= 192 else 'medium')
        if any(x in key_type_upper for x in ['HMAC', 'SHA', 'HASH', 'MAC']):
            return ('hash', 'none')
        
        return ('unknown', 'unknown')
    
    HYBRID_NAME_PATTERNS = [
        'ECDSA-P256-ML-DSA',
        'ECDSA-P384-ML-DSA',
        'ECDSA-P521-ML-DSA',
        'RSA-ML-DSA',
        'RSA-PSS-ML-DSA',
        'Ed25519-ML-DSA',
        'Ed448-ML-DSA',
        'Composite',
    ]
    
    def __init__(self):
        """Initialize PQC detector with combined OID lookup table"""
        # Build combined OID lookup
        self._oid_lookup: Dict[str, Tuple[str, int, PQCCategory, bool]] = {}
        
        # Add ML-DSA OIDs
        for oid, (name, level) in self.ML_DSA_OIDS.items():
            self._oid_lookup[oid] = (name, level, PQCCategory.LATTICE, False)
        
        # Add ML-KEM OIDs
        for oid, (name, level) in self.ML_KEM_OIDS.items():
            self._oid_lookup[oid] = (name, level, PQCCategory.LATTICE, False)
        
        # Add SLH-DSA OIDs
        for oid, (name, level) in self.SLH_DSA_OIDS.items():
            self._oid_lookup[oid] = (name, level, PQCCategory.HASH_BASED, False)
        
        # Add Hybrid OIDs
        for oid, (name, level) in self.HYBRID_OIDS.items():
            self._oid_lookup[oid] = (name, level, PQCCategory.HYBRID, True)
        
        logger.debug(f"PQCDetector initialized with {len(self._oid_lookup)} OID mappings")
    
    def analyze_certificate(self, 
                           signature_algorithm_oid: Optional[str] = None,
                           signature_algorithm_name: Optional[str] = None,
                           public_key_algorithm: Optional[str] = None,
                           public_key_oid: Optional[str] = None) -> PQCAnalysis:
        """
        Analyze a certificate for PQC algorithm usage.
        
        Args:
            signature_algorithm_oid: OID of signature algorithm (e.g., '2.16.840.1.101.3.4.3.17')
            signature_algorithm_name: Name of signature algorithm (e.g., 'sha256WithRSAEncryption')
            public_key_algorithm: Public key algorithm name (e.g., 'RSA', 'ECDSA', 'ML-DSA')
            public_key_oid: OID of public key algorithm
            
        Returns:
            PQCAnalysis with detection results
        """
        notes = []
        is_pqc = False
        is_hybrid = False
        pqc_algorithm = None
        pqc_category = PQCCategory.CLASSICAL
        classical_algorithm = None
        security_level = None
        
        # Check signature algorithm OID first (most reliable)
        if signature_algorithm_oid:
            oid_clean = signature_algorithm_oid.strip()
            if oid_clean in self._oid_lookup:
                name, level, category, hybrid = self._oid_lookup[oid_clean]
                is_pqc = True
                is_hybrid = hybrid
                pqc_algorithm = name
                pqc_category = category
                security_level = level
                notes.append(f"Detected via signature OID: {oid_clean}")
                
                if hybrid:
                    # Extract classical component from hybrid name
                    classical_algorithm = self._extract_classical_from_hybrid(name)
            elif oid_clean in self.CLASSICAL_SIGNATURE_OIDS:
                classical_algorithm = self.CLASSICAL_SIGNATURE_OIDS[oid_clean]
                notes.append(f"Classical signature algorithm: {classical_algorithm}")
        
        # Check public key OID
        if public_key_oid and not is_pqc:
            oid_clean = public_key_oid.strip()
            if oid_clean in self._oid_lookup:
                name, level, category, hybrid = self._oid_lookup[oid_clean]
                is_pqc = True
                is_hybrid = hybrid
                pqc_algorithm = name
                pqc_category = category
                security_level = level
                notes.append(f"Detected via public key OID: {oid_clean}")
        
        # Fallback: Check algorithm names for PQC patterns
        if not is_pqc:
            for algo_name in [signature_algorithm_name, public_key_algorithm]:
                if algo_name:
                    result = self._check_name_patterns(algo_name)
                    if result:
                        is_pqc, is_hybrid, pqc_algorithm, pqc_category = result
                        notes.append(f"Detected via algorithm name pattern: {algo_name}")
                        break
        
        # If still no PQC detected, record the classical algorithm
        if not is_pqc:
            if signature_algorithm_name:
                classical_algorithm = signature_algorithm_name
            elif public_key_algorithm:
                classical_algorithm = public_key_algorithm
        
        # Determine migration status
        if is_pqc and not is_hybrid:
            migration_status = MigrationStatus.PQC_READY
        elif is_hybrid:
            migration_status = MigrationStatus.HYBRID_TRANSITION
        elif classical_algorithm:
            migration_status = MigrationStatus.NEEDS_MIGRATION
        else:
            migration_status = MigrationStatus.UNKNOWN
        
        return PQCAnalysis(
            is_pqc=is_pqc,
            is_hybrid=is_hybrid,
            pqc_algorithm=pqc_algorithm,
            pqc_category=pqc_category,
            classical_algorithm=classical_algorithm,
            migration_status=migration_status,
            security_level=security_level,
            notes=notes
        )
    
    def analyze_key(self,
                   key_type: Optional[str] = None,
                   key_algorithm_oid: Optional[str] = None,
                   key_size: Optional[int] = None,
                   key_operations: Optional[List[str]] = None) -> PQCAnalysis:
        """
        Analyze a key for PQC algorithm usage and quantum vulnerability.
        
        Args:
            key_type: Type of key (e.g., 'RSA', 'EC', 'AES', 'ML-KEM')
            key_algorithm_oid: OID of key algorithm
            key_size: Size of key in bits
            key_operations: List of permitted operations (e.g., ['encrypt', 'decrypt'])
            
        Returns:
            PQCAnalysis with detection results including vulnerability classification
        """
        notes = []
        is_pqc = False
        is_hybrid = False
        pqc_algorithm = None
        pqc_category = PQCCategory.CLASSICAL
        classical_algorithm = None
        security_level = None
        
        # Check key algorithm OID for PQC
        if key_algorithm_oid:
            oid_clean = key_algorithm_oid.strip()
            if oid_clean in self._oid_lookup:
                name, level, category, hybrid = self._oid_lookup[oid_clean]
                is_pqc = True
                is_hybrid = hybrid
                pqc_algorithm = name
                pqc_category = category
                security_level = level
                notes.append(f"Detected via key OID: {oid_clean}")
        
        # Check key type name patterns for PQC
        if not is_pqc and key_type:
            result = self._check_name_patterns(key_type)
            if result:
                is_pqc, is_hybrid, pqc_algorithm, pqc_category = result
                notes.append(f"Detected via key type: {key_type}")
        
        # Record classical algorithm if not PQC
        if not is_pqc:
            classical_algorithm = key_type
            if key_size:
                notes.append(f"Key size: {key_size} bits")
        
        # Classify key algorithm for quantum vulnerability
        algo_class, vulnerability = self.classify_key_algorithm(key_type, key_size)
        notes.append(f"Algorithm class: {algo_class}, Quantum vulnerability: {vulnerability}")
        
        # Determine migration status based on algorithm type and vulnerability
        if is_pqc and not is_hybrid:
            migration_status = MigrationStatus.PQC_READY
        elif is_hybrid:
            migration_status = MigrationStatus.HYBRID_TRANSITION
        elif algo_class == 'symmetric' and vulnerability in ('none', 'low'):
            # Strong symmetric keys (AES-256, AES-192) are post-quantum secure
            migration_status = MigrationStatus.PQC_READY
            notes.append("Symmetric algorithm with adequate strength - post-quantum secure")
        elif algo_class == 'hash' and vulnerability in ('none', 'low'):
            # Hash-based keys have minimal quantum impact
            migration_status = MigrationStatus.PQC_READY
            notes.append("Hash-based algorithm - minimal quantum impact")
        elif classical_algorithm:
            migration_status = MigrationStatus.NEEDS_MIGRATION
            if algo_class == 'asymmetric':
                notes.append("Asymmetric algorithm - vulnerable to Shor's algorithm")
            elif algo_class == 'symmetric' and vulnerability in ('medium', 'high'):
                notes.append("Symmetric algorithm with insufficient key size - consider increasing")
        else:
            migration_status = MigrationStatus.UNKNOWN
        
        return PQCAnalysis(
            is_pqc=is_pqc,
            is_hybrid=is_hybrid,
            pqc_algorithm=pqc_algorithm,
            pqc_category=pqc_category,
            classical_algorithm=classical_algorithm,
            migration_status=migration_status,
            security_level=security_level,
            notes=notes,
            algorithm_class=algo_class,
            vulnerability_level=vulnerability
        )
    
    def _check_name_patterns(self, name: str) -> Optional[Tuple[bool, bool, str, PQCCategory]]:
        """
        Check algorithm name against known PQC patterns.
        
        Returns:
            Tuple of (is_pqc, is_hybrid, algorithm_name, category) or None if no match
        """
        if not name:
            return None
        
        name_upper = name.upper()
        
        # Check for hybrid patterns first
        for hybrid_pattern in self.HYBRID_NAME_PATTERNS:
            if hybrid_pattern.upper() in name_upper:
                # Determine the PQC component
                for pqc_pattern, (category, algo_name) in self.PQC_NAME_PATTERNS.items():
                    if pqc_pattern.upper() in name_upper:
                        return (True, True, name, category)
                return (True, True, name, PQCCategory.HYBRID)
        
        # Check for pure PQC patterns
        for pqc_pattern, (category, algo_name) in self.PQC_NAME_PATTERNS.items():
            if pqc_pattern.upper() in name_upper:
                return (True, False, algo_name, category)
        
        return None
    
    def _extract_classical_from_hybrid(self, hybrid_name: str) -> Optional[str]:
        """Extract the classical algorithm component from a hybrid algorithm name."""
        classical_patterns = ['ECDSA', 'RSA', 'Ed25519', 'Ed448', 'DSA']
        for pattern in classical_patterns:
            if pattern in hybrid_name:
                return pattern
        return None
    
    def get_migration_priority(self, analysis: PQCAnalysis, 
                               days_until_expiration: int = None,
                               is_ca: bool = False) -> int:
        """
        DEPRECATED: Use PQCReportingService.calculate_priority_score() instead.
        
        This method uses simplified scoring logic that differs from the main
        MOSCA-informed scoring in pqc_reporting_service.py. It is retained
        for backward compatibility but should not be used for new code.
        
        For comprehensive priority scoring, use:
            from caip_service_layer.pqc_reporting_service import calculate_asset_priority
            result = calculate_asset_priority(asset, context)
        
        Args:
            analysis: PQCAnalysis result
            days_until_expiration: Days until certificate expires
            is_ca: Whether this is a CA certificate
            
        Returns:
            Priority score from 0-100 (simplified calculation)
        """
        import warnings
        warnings.warn(
            "get_migration_priority() is deprecated. Use PQCReportingService.calculate_priority_score() instead.",
            DeprecationWarning,
            stacklevel=2
        )
        
        if analysis.migration_status == MigrationStatus.PQC_READY:
            return 0  # No migration needed
        
        if analysis.migration_status == MigrationStatus.HYBRID_TRANSITION:
            return 10  # Already in transition
        
        # Base score for classical algorithms needing migration
        score = 50
        
        # Adjust for CA certificates (higher priority)
        if is_ca:
            score += 20
        
        # Adjust for expiration
        if days_until_expiration is not None:
            if days_until_expiration < 90:
                score += 15  # Expiring soon - good time to migrate
            elif days_until_expiration < 365:
                score += 10
            elif days_until_expiration > 1825:  # > 5 years
                score += 5   # Long-lived cert, needs attention
        
        # Adjust for algorithm strength
        classical_algo = analysis.classical_algorithm or ''
        if 'sha1' in classical_algo.lower():
            score += 10  # Weak hash
        if 'RSA' in classical_algo.upper() or 'rsa' in classical_algo.lower():
            score += 5   # RSA is quantum-vulnerable
        
        return min(score, 100)
    
    @classmethod
    def get_supported_algorithms(cls) -> Dict[str, List[str]]:
        """
        Get list of all supported PQC algorithms by category.
        
        Returns:
            Dictionary mapping category to list of algorithm names
        """
        result = {
            'lattice_signatures': [],
            'lattice_kem': [],
            'hash_based': [],
            'hybrid': []
        }
        
        for oid, (name, level) in cls.ML_DSA_OIDS.items():
            if name not in result['lattice_signatures']:
                result['lattice_signatures'].append(name)
        
        for oid, (name, level) in cls.ML_KEM_OIDS.items():
            if name not in result['lattice_kem']:
                result['lattice_kem'].append(name)
        
        for oid, (name, level) in cls.SLH_DSA_OIDS.items():
            if name not in result['hash_based']:
                result['hash_based'].append(name)
        
        for oid, (name, level) in cls.HYBRID_OIDS.items():
            if name not in result['hybrid']:
                result['hybrid'].append(name)
        
        return result


# Convenience function for quick analysis
def analyze_certificate_pqc(signature_algorithm: str = None,
                            signature_oid: str = None,
                            public_key_algorithm: str = None,
                            public_key_oid: str = None) -> Dict[str, Any]:
    """
    Convenience function for quick PQC analysis of a certificate.
    
    Returns dictionary suitable for direct inclusion in certificate data.
    """
    detector = PQCDetector()
    analysis = detector.analyze_certificate(
        signature_algorithm_oid=signature_oid,
        signature_algorithm_name=signature_algorithm,
        public_key_algorithm=public_key_algorithm,
        public_key_oid=public_key_oid
    )
    return analysis.to_dict()


def analyze_key_pqc(key_type: str = None,
                    key_oid: str = None,
                    key_size: int = None,
                    key_operations: list = None) -> Dict[str, Any]:
    """
    Convenience function for quick PQC analysis of a key.
    
    Returns dictionary suitable for direct inclusion in key data.
    """
    detector = PQCDetector()
    analysis = detector.analyze_key(
        key_type=key_type,
        key_algorithm_oid=key_oid,
        key_size=key_size,
        key_operations=key_operations
    )
    return analysis.to_dict()


# Module-level detector instance for reuse
_detector_instance: Optional[PQCDetector] = None

def get_detector() -> PQCDetector:
    """Get or create singleton PQC detector instance."""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = PQCDetector()
    return _detector_instance


print("PQCDetector module loaded")
