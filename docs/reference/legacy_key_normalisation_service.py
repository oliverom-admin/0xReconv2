# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: caip_service_layer/key_normalisation_service.py
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
Key Normalisation Service for CAIP

Provides a unified data format for cryptographic keys from different sources.
This service normalises both Luna HSM (KeyInfo) and Azure Key Vault 
(AzureKeyVaultKeyInfo) keys into a common structure for consistent 
assessment, scoring, and reporting.

The normalisation ensures:
- Consistent field naming across all key sources
- Proper derivation of security posture from source-specific attributes
- Unified expiration handling
- Consistent capability flags

Usage:
    from key_normalisation_service import KeyNormalisationService
    
    # Normalise a single key
    normalised = KeyNormalisationService.normalise_key(key_dict)
    
    # Normalise a list of keys
    normalised_keys = KeyNormalisationService.normalise_keys(keys_list)
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field

logger = logging.getLogger('caip.key_normalisation')


@dataclass
class NormalisedKey:
    """
    Unified key data structure for assessment and scoring.
    
    This dataclass represents the canonical format for all cryptographic keys
    regardless of their source (Luna HSM, Azure Key Vault, etc.).
    
    Field Categories:
    - Identity: Unique identification and naming
    - Algorithm: Cryptographic algorithm properties
    - Security Posture: Protection and access control attributes
    - Capabilities: Permitted operations
    - Lifecycle: Validity and expiration
    - Source: Origin and tracking information
    - Analysis: PQC and vulnerability assessment
    """
    
    # =========================================================================
    # IDENTITY
    # =========================================================================
    key_id: str                              # Unique identifier
    name: str                                # Human-readable name/label
    source_type: str                         # 'luna_hsm', 'azure_keyvault', 'generic'
    source: str                              # Full source description
    
    # =========================================================================
    # ALGORITHM PROPERTIES
    # =========================================================================
    key_type: str                            # Algorithm type (RSA, EC, AES, etc.)
    key_size: Optional[int] = None           # Key size in bits
    key_curve: Optional[str] = None          # EC curve name if applicable
    key_class: Optional[str] = None          # 'public', 'private', 'secret', 'unknown'
    
    # =========================================================================
    # SECURITY POSTURE (Normalised)
    # These fields are derived from source-specific attributes
    # =========================================================================
    is_sensitive: Optional[bool] = None      # Key material protected from disclosure
    is_extractable: Optional[bool] = None    # Key can be exported/extracted
    is_hardware_protected: Optional[bool] = None  # Key stored in HSM/hardware
    is_local: Optional[bool] = None               # Generated on the hardware (not imported)
    
    # Historical security posture (for PKCS#11 keys)
    is_always_sensitive: Optional[bool] = None    # Never been exposed in plaintext
    is_never_extractable: Optional[bool] = None   # Never been exportable
    is_modifiable: Optional[bool] = None          # Key attributes can be modified
    
    # =========================================================================
    # CAPABILITIES (Normalised)
    # =========================================================================
    can_encrypt: Optional[bool] = None
    can_decrypt: Optional[bool] = None
    can_sign: Optional[bool] = None
    can_verify: Optional[bool] = None
    can_wrap: Optional[bool] = None          # Can wrap other keys
    can_unwrap: Optional[bool] = None        # Can unwrap other keys
    can_derive: Optional[bool] = None        # Can derive other keys
    
    # =========================================================================
    # LIFECYCLE
    # =========================================================================
    created_on: Optional[str] = None         # ISO format creation date
    expires_on: Optional[str] = None         # ISO format expiration date
    not_before: Optional[str] = None         # ISO format activation date
    is_enabled: Optional[bool] = True        # Key is currently enabled/active
    days_until_expiration: Optional[int] = None  # Computed days until expiry
    
    # =========================================================================
    # ASSOCIATIONS
    # =========================================================================
    associated_certificate: Optional[Any] = None  # Linked certificate if any
    
    # =========================================================================
    # ANALYSIS
    # =========================================================================
    pqc_analysis: Optional[Dict[str, Any]] = None

    # =========================================================================
    # AZURE METADATA (extracted from Azure Key Vault keys)
    # =========================================================================
    azure_tags: Optional[Dict[str, str]] = None              # Azure resource tags
    azure_key_type: Optional[str] = None                     # EC, RSA, oct, RSA-HSM, EC-HSM
    azure_managed: Optional[bool] = None                     # Whether key is managed (cert-associated)
    azure_version: Optional[str] = None                      # Key version identifier
    azure_enabled: Optional[bool] = None                     # Azure enabled status
    azure_recovery_level: Optional[str] = None               # Recoverable, RecoverablePlusRecoverable, etc.
    azure_vault_name: Optional[str] = None                   # Azure Key Vault name
    azure_vault_id: Optional[str] = None                     # Full vault resource ID
    azure_vault_location: Optional[str] = None               # Azure region (e.g., eastus)
    azure_vault_resource_group: Optional[str] = None         # Azure resource group
    azure_vault_tier: Optional[str] = None                   # Standard or Premium
    azure_subscription_id: Optional[str] = None              # Azure subscription ID
    azure_created_on: Optional[str] = None                   # ISO format creation date
    azure_updated_on: Optional[str] = None                   # ISO format update date
    azure_expires_on: Optional[str] = None                   # ISO format expiration date
    azure_not_before: Optional[str] = None                   # ISO format not-before date

    # =========================================================================
    # ENVIRONMENT METADATA (auto-discovered via enrichment service)
    # =========================================================================
    inferred_environment_type: Optional[str] = None          # 'production', 'staging', 'development', 'testing', 'unknown'
    inferred_service_name: Optional[str] = None              # Inferred from hostname/port or tags
    inferred_application_name: Optional[str] = None          # Extracted from certificate CN or tags
    inferred_discovery_method: Optional[str] = None          # How environment was inferred
    inferred_discovery_confidence: Optional[float] = None    # Confidence score 0.0-1.0
    inferred_signal_breakdown: Optional[List[Dict]] = None   # Signal-by-signal breakdown for transparency

    # =========================================================================
    # SOURCE-SPECIFIC PRESERVED DATA
    # For fields that don't map cleanly but may be needed for reporting
    # =========================================================================
    source_specific: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialisation"""
        return asdict(self)


@dataclass
class NormalisedCertificate:
    """
    Unified certificate data structure for assessment and scoring.
    
    This dataclass represents the canonical format for all X.509 certificates
    regardless of their source (TLS scan, Azure Key Vault, Luna HSM, EJBCA, etc.).
    
    All computed fields are pre-calculated at normalisation time.
    """
    
    # =========================================================================
    # IDENTITY
    # =========================================================================
    cert_id: str                                 # Unique identifier (fingerprint or unique_id)
    serial_number: str                           # Certificate serial number
    fingerprint_sha256: str                      # SHA-256 fingerprint
    source: str                                  # Source description
    source_type: str                             # 'tls', 'azure_keyvault', 'luna_hsm', 'ejbca', 'file'
    
    # =========================================================================
    # SUBJECT & ISSUER
    # =========================================================================
    subject: Dict[str, str] = field(default_factory=dict)
    subject_cn: str = ''                         # Extracted common name
    issuer: Dict[str, str] = field(default_factory=dict)
    issuer_cn: str = ''                          # Extracted common name
    
    # =========================================================================
    # ALGORITHM PROPERTIES
    # =========================================================================
    signature_algorithm: str = ''
    public_key_algorithm: str = ''
    public_key_size: Optional[int] = None
    key_curve: Optional[str] = None
    
    # =========================================================================
    # VALIDITY & LIFECYCLE
    # =========================================================================
    not_before: Optional[str] = None             # ISO format
    not_after: Optional[str] = None              # ISO format
    certificate_validity_days: int = 0           # Total validity period
    days_until_expiration: int = 0               # Days remaining (negative if expired)
    is_expired: bool = False
    
    # =========================================================================
    # CERTIFICATE TYPE
    # =========================================================================
    is_ca: bool = False
    is_root_ca: bool = False
    is_intermediate_ca: bool = False
    is_self_signed: bool = False
    
    # =========================================================================
    # EXTENSIONS
    # =========================================================================
    san: List[str] = field(default_factory=list)
    san_count: int = 0
    key_usage: List[str] = field(default_factory=list)
    extended_key_usage: List[str] = field(default_factory=list)
    basic_constraints: Dict[str, Any] = field(default_factory=dict)
    
    # =========================================================================
    # REVOCATION
    # =========================================================================
    crl_distribution_points: List[str] = field(default_factory=list)
    ocsp_responders: List[str] = field(default_factory=list)
    ocsp_or_crl_implemented: bool = False                  # Computed: has revocation support

    # =========================================================================
    # TRUST
    # =========================================================================
    trusted_issuer_available: bool = False
    certificate_chain: List[Dict[str, Any]] = field(default_factory=list)
    
    # =========================================================================
    # TLS-SPECIFIC (populated for TLS scans)
    # =========================================================================
    found_at_destination: Optional[str] = None
    found_on_port: Optional[str] = None
    tls_version: Optional[str] = None
    tls_library: Optional[str] = None

    # Phase 1, 2, 3 TLS Enhanced Data Capture fields
    key_curve: Optional[str] = None                          # Phase 1: EC curve (secp256r1, etc.)
    symmetric_key_bits: Optional[int] = None                 # Phase 1: Cipher strength in bits
    has_forward_secrecy: Optional[bool] = None               # Phase 1: Forward secrecy support
    authority_key_identifier: Optional[str] = None           # Phase 1: AKI extension
    subject_key_identifier: Optional[str] = None             # Phase 1: SKI extension
    supported_tls_versions: List[str] = field(default_factory=list)  # Phase 2: TLS versions supported
    protocol_vulnerabilities: List[str] = field(default_factory=list) # Phase 2: Known vulnerabilities
    client_cert_required: Optional[bool] = None              # Phase 2: mTLS requirement
    ocsp_stapling_supported: Optional[bool] = None           # Phase 2: OCSP stapling capability
    session_ticket_supported: Optional[bool] = None          # Phase 2: Session resumption
    cipher_strength_rating: Optional[str] = None             # Phase 2: A/B/C/F grade
    lifespan_pattern: Optional[str] = None                   # Phase 2: Certificate lifetime pattern
    tls_handshake_time_ms: Optional[float] = None            # Phase 2: TLS handshake latency
    precert_poison_present: Optional[bool] = None            # Phase 3: Precert poison marker
    freshest_crl_urls: List[str] = field(default_factory=list) # Phase 3: Freshest CRL URLs
    
    # =========================================================================
    # PQC ANALYSIS
    # =========================================================================
    pqc_analysis: Optional[Dict[str, Any]] = None
    is_pqc: bool = False
    is_hybrid: bool = False
    pqc_algorithm: Optional[str] = None
    migration_status: str = 'needs_migration'
    
    # =========================================================================
    # CT & TRANSPARENCY
    # =========================================================================
    certificate_transparency_scts: List[Dict[str, Any]] = field(default_factory=list)
    
    # =========================================================================
    # SOURCE-SPECIFIC PRESERVED DATA
    # =========================================================================
    source_specific: Dict[str, Any] = field(default_factory=dict)

    # =========================================================================
    # AZURE METADATA (extracted from Azure Key Vault certificates)
    # =========================================================================
    azure_tags: Optional[Dict[str, str]] = None              # Azure resource tags
    azure_key_type: Optional[str] = None                     # EC, RSA, oct, RSA-HSM, EC-HSM
    azure_managed: Optional[bool] = None                     # Whether key/cert is managed
    azure_version: Optional[str] = None                      # Version identifier
    azure_enabled: Optional[bool] = None                     # Azure enabled status
    azure_recovery_level: Optional[str] = None               # Recoverable, RecoverablePlusRecoverable, etc.
    azure_vault_name: Optional[str] = None                   # Azure Key Vault name
    azure_vault_id: Optional[str] = None                     # Full vault resource ID
    azure_vault_location: Optional[str] = None               # Azure region (e.g., eastus)
    azure_vault_resource_group: Optional[str] = None         # Azure resource group
    azure_vault_tier: Optional[str] = None                   # Standard or Premium
    azure_subscription_id: Optional[str] = None              # Azure subscription ID
    azure_created_on: Optional[str] = None                   # ISO format creation date
    azure_updated_on: Optional[str] = None                   # ISO format update date
    azure_expires_on: Optional[str] = None                   # ISO format expiration date
    azure_not_before: Optional[str] = None                   # ISO format not-before date

    # =========================================================================
    # INFERRED ENVIRONMENT METADATA (auto-discovered from tags/hostname patterns)
    # =========================================================================
    inferred_discovery_method: Optional[str] = None          # How environment was inferred
    inferred_discovery_confidence: Optional[float] = None    # Confidence score 0.0-1.0

    # =========================================================================
    # ENVIRONMENT METADATA (auto-discovered via enrichment service)
    # =========================================================================
    environment_type: Optional[str] = None              # 'production', 'staging', 'development', 'testing', 'unknown'
    service_name: Optional[str] = None                  # Inferred from hostname/port (e.g., 'https-web', 'ldaps')
    application_name: Optional[str] = None              # Extracted from certificate CN or tags
    discovery_metadata: Optional[Dict[str, Any]] = None # {discovery_method, discovery_confidence}
    inferred_signal_breakdown: Optional[List[Dict]] = None   # Signal-by-signal breakdown for transparency

    # =========================================================================
    # SECURITY ANALYSIS (Phase 1.5 enrichments)
    # =========================================================================
    signature_algorithm_analysis: Optional[Dict[str, Any]] = None
    key_strength_analysis: Optional[Dict[str, Any]] = None
    pqc_readiness: Optional[Dict[str, Any]] = None
    revocation_status: Optional[Dict[str, Any]] = None

    # =========================================================================
    # PHASE 3: METADATA ANALYSIS (extracted and inferred metadata)
    # =========================================================================
    inferred_identity_metadata: Optional[Dict[str, Any]] = None      # Service name, tier, cloud, region
    inferred_purpose_metadata: Optional[Dict[str, Any]] = None       # Primary purpose, CA tier, criticality
    inferred_crypto_metadata: Optional[Dict[str, Any]] = None        # Key algorithm, size, strength, PQC status
    inferred_ha_metadata: Optional[Dict[str, Any]] = None            # HA enabled, replication count, clustering

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialisation"""
        return asdict(self)


class KeyNormalisationService:
    """
    Service for normalising keys from different sources into a unified format.
    
    Supports:
    - Luna HSM keys (KeyInfo dataclass)
    - Azure Key Vault keys (AzureKeyVaultKeyInfo dataclass)
    - Generic key dictionaries
    """
    
    # =========================================================================
    # DETECTION METHODS
    # =========================================================================
    
    @classmethod
    def detect_source_type(cls, key: Dict[str, Any]) -> str:
        """
        Detect the source type of a key based on its fields.
        
        Args:
            key: Key dictionary
            
        Returns:
            Source type string: 'luna_hsm', 'azure_keyvault', or 'generic'
        """
        source = (key.get('source') or '').lower()
        
        # Check for Luna HSM indicators
        if 'luna' in source:
            return 'luna_hsm'
        
        # Check for Azure Key Vault indicators
        if 'azure' in source or 'key vault' in source:
            return 'azure_keyvault'
        if key.get('vault_url') or key.get('tenancy_name'):
            return 'azure_keyvault'
        
        # Check for PKCS#11 indicators (Luna HSM)
        pkcs11_fields = ['is_sensitive', 'is_extractable', 'is_always_sensitive', 
                         'is_never_extractable', 'key_class']
        if any(key.get(f) is not None for f in pkcs11_fields):
            return 'luna_hsm'
        
        # Check for Azure-specific fields
        azure_fields = ['key_operations', 'hsm_backed', 'recovery_level', 
                        'service_principal_name']
        if any(key.get(f) is not None for f in azure_fields):
            return 'azure_keyvault'
        
        # Check source string for HSM indicators
        if 'hsm' in source:
            return 'luna_hsm'
        
        return 'generic'
    
    # =========================================================================
    # MAIN NORMALISATION METHODS
    # =========================================================================
    
    @classmethod
    def normalise_key(cls, key: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalise a single key to the unified format.
        
        Args:
            key: Key dictionary from any source
            
        Returns:
            Normalised key dictionary
        """
        source_type = cls.detect_source_type(key)
        
        if source_type == 'luna_hsm':
            normalised = cls._normalise_luna_key(key)
        elif source_type == 'azure_keyvault':
            normalised = cls._normalise_azure_key(key)
        else:
            normalised = cls._normalise_generic_key(key)
        
        # Compute days until expiration if not already set
        if normalised.days_until_expiration is None and normalised.expires_on:
            normalised.days_until_expiration = cls._compute_days_until_expiration(
                normalised.expires_on
            )
        
        # Apply PQC analysis if not present
        if normalised.pqc_analysis is None:
            normalised.pqc_analysis = cls._generate_pqc_analysis(normalised)
        
        result = normalised.to_dict()
        
        # Policy assessment aliases (backward compatibility with existing rules)
        result['id'] = result.get('key_id')
        result['public_key_algorithm'] = result.get('key_type')
        result['public_key_size'] = result.get('key_size')
        result['enabled'] = result.get('is_enabled')
        result['hsm_backed'] = result.get('is_hardware_protected')
        
        # Preserve original field names for HTML compatibility
        if source_type == 'luna_hsm':
            result['label'] = key.get('label') or result.get('name')
            result['object_id'] = key.get('object_id')
        elif source_type == 'azure_keyvault':
            result['label'] = key.get('label') or key.get('name') or result.get('name')
        
        return result
    
    @classmethod
    def normalise_keys(cls, keys: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Normalise a list of keys to the unified format.
        
        Args:
            keys: List of key dictionaries from any source
            
        Returns:
            List of normalised key dictionaries
        """
        normalised_keys = []
        for key in keys:
            try:
                normalised = cls.normalise_key(key)
                normalised_keys.append(normalised)
            except Exception as e:
                logger.warning(f"Failed to normalise key: {e}")
                # Include original key with minimal normalisation
                normalised_keys.append(cls._minimal_normalise(key))
        
        return normalised_keys
    
    # =========================================================================
    # SOURCE-SPECIFIC NORMALISATION
    # =========================================================================
    
    @classmethod
    def _normalise_luna_key(cls, key: Dict[str, Any]) -> NormalisedKey:
        """
        Normalise a Luna HSM (KeyInfo) key.
        
        Luna keys have PKCS#11 attributes that map directly to our normalised
        security posture fields.
        """
        # Identity
        key_id = key.get('label') or key.get('object_id') or 'unknown'
        name = key.get('label') or key.get('object_id') or 'Unnamed Key'
        
        # Key class determination
        key_class = key.get('key_class')
        if not key_class:
            # Infer from private flag
            if key.get('private') is True:
                key_class = 'private'
            elif key.get('private') is False:
                key_class = 'public'
            else:
                key_class = 'unknown'
        
        # Security posture - direct mapping from PKCS#11
        is_sensitive = key.get('is_sensitive')
        is_extractable = key.get('is_extractable')
        is_local = key.get('is_local')
        is_always_sensitive = key.get('is_always_sensitive')
        is_never_extractable = key.get('is_never_extractable')
        is_modifiable = key.get('is_modifiable')
        
        # Luna HSM keys are always hardware protected
        is_hardware_protected = True
        
        # Capabilities - direct mapping from PKCS#11
        can_encrypt = key.get('can_encrypt')
        can_decrypt = key.get('can_decrypt')
        can_sign = key.get('can_sign')
        can_verify = key.get('can_verify')
        can_wrap = key.get('can_wrap')
        can_unwrap = key.get('can_unwrap')
        can_derive = key.get('can_derive')
        
        # Lifecycle
        expires_on = key.get('end_date')  # Luna uses end_date
        not_before = key.get('start_date')  # Luna uses start_date
        
        # Associated certificate - may be a full CertificateInfo dict
        associated_cert = key.get('associated_certificate')
        
        # Preserve source-specific data
        source_specific = {
            'is_modifiable': key.get('is_modifiable'),
            'token': key.get('token'),
            'public_key_fingerprint': key.get('public_key_fingerprint'),
            'label': name,  # Preserve for HTML display compatibility
        }
        
        # Extract environment metadata if present (Luna keys may have environment inference)
        environment_metadata = key.get('environment_metadata', {})

        return NormalisedKey(
            key_id=key_id,
            name=name,
            source_type='luna_hsm',
            source=key.get('source', 'Luna HSM'),
            key_type=key.get('key_type', 'Unknown'),
            key_size=key.get('key_size'),
            key_curve=None,  # Luna doesn't expose curve name directly
            key_class=key_class,
            is_sensitive=is_sensitive,
            is_extractable=is_extractable,
            is_hardware_protected=is_hardware_protected,
            is_local=is_local,
            is_always_sensitive=is_always_sensitive,
            is_never_extractable=is_never_extractable,
            is_modifiable=is_modifiable,
            can_encrypt=can_encrypt,
            can_decrypt=can_decrypt,
            can_sign=can_sign,
            can_verify=can_verify,
            can_wrap=can_wrap,
            can_unwrap=can_unwrap,
            can_derive=can_derive,
            created_on=None,  # Luna doesn't expose creation date via PKCS#11
            expires_on=expires_on,
            not_before=not_before,
            is_enabled=True,  # Luna keys are enabled if accessible
            associated_certificate=associated_cert,
            pqc_analysis=key.get('pqc_analysis'),
            # NEW: Azure metadata fields (Luna keys don't have these - all None)
            azure_tags=None,
            azure_key_type=None,
            azure_managed=None,
            azure_version=None,
            azure_enabled=None,
            azure_recovery_level=None,
            azure_vault_name=None,
            azure_vault_id=None,
            azure_vault_location=None,
            azure_vault_resource_group=None,
            azure_vault_tier=None,
            azure_subscription_id=None,
            azure_created_on=None,
            azure_updated_on=None,
            azure_expires_on=None,
            azure_not_before=None,
            # NEW: Environment metadata fields (may be populated by enrichment service)
            inferred_environment_type=environment_metadata.get('environment_type'),
            inferred_service_name=environment_metadata.get('service_name'),
            inferred_application_name=environment_metadata.get('application_name'),
            inferred_discovery_method=environment_metadata.get('discovery_method'),
            inferred_discovery_confidence=environment_metadata.get('discovery_confidence'),
            inferred_signal_breakdown=environment_metadata.get('signal_breakdown'),  # Phase 1: Multi-signal fusion breakdown
            source_specific=source_specific
        )
    
    @classmethod
    def _normalise_azure_key(cls, key: Dict[str, Any]) -> NormalisedKey:
        """
        Normalise an Azure Key Vault (AzureKeyVaultKeyInfo) key.
        
        Azure keys have different attributes that we map to our normalised
        format, deriving security posture from available information.
        """
        # Identity
        key_id = key.get('key_id') or key.get('name') or 'unknown'
        name = key.get('name') or key.get('label') or 'Unnamed Key'
        
        # Key class - Azure keys are typically private (for signing/decryption)
        # or symmetric (for encryption). Public keys aren't stored separately.
        key_type_str = (key.get('key_type') or '').upper()
        if 'RSA' in key_type_str or 'EC' in key_type_str:
            key_class = 'private'  # Azure stores the private portion
        elif 'AES' in key_type_str or 'OCT' in key_type_str:
            key_class = 'secret'
        else:
            key_class = 'private'  # Default assumption for Azure
        
        # Security posture - derived from Azure-specific attributes
        hsm_backed = key.get('hsm_backed', False)
        recovery_level = (key.get('recovery_level') or '').lower()
        
        # Azure keys in "managed HSM" or with hsm_backed=True are hardware protected
        is_hardware_protected = hsm_backed or 'hsm' in key_type_str.lower()
        
        # Azure Key Vault keys are non-extractable by design
        # (you can't export the private key material)
        is_extractable = False
        
        # Azure keys are considered "sensitive" - the key material never leaves the vault
        is_sensitive = True
        
        # Azure keys generated in the vault are locally generated
        # Keys can be imported, but we default to True unless we know otherwise
        managed = key.get('managed', False)
        is_locally_generated = not managed  # Managed keys are cert-associated
        
        # Historical posture - Azure doesn't track this, assume good hygiene
        was_always_sensitive = True
        was_never_extractable = True
        
        # Capabilities - derived from key_operations list
        key_operations = key.get('key_operations') or []
        # Normalise operation names (Azure uses different casing/formats)
        ops_lower = [op.lower() for op in key_operations]
        
        can_encrypt = 'encrypt' in ops_lower
        can_decrypt = 'decrypt' in ops_lower
        can_sign = 'sign' in ops_lower
        can_verify = 'verify' in ops_lower
        can_wrap = 'wrapkey' in ops_lower or 'wrap' in ops_lower
        can_unwrap = 'unwrapkey' in ops_lower or 'unwrap' in ops_lower
        can_derive = 'derive' in ops_lower
        
        # Lifecycle
        expires_on = key.get('expires_on')
        not_before = key.get('not_before')
        created_on = key.get('created_on')
        is_enabled = key.get('enabled', True)
        
        # Compute days until expiration
        days_until_expiration = None
        if expires_on:
            days_until_expiration = cls._compute_days_until_expiration(expires_on)
        
        # Extract Azure metadata from key data (populated by Phase 1 collector)
        azure_metadata = key.get('azure_metadata', {})

        # Extract environment metadata from key data (populated by Phase 1 collector)
        environment_metadata = key.get('environment_metadata', {})

        # Preserve source-specific data
        source_specific = {
            'vault_url': key.get('vault_url'),
            'tenancy_name': key.get('tenancy_name'),
            'service_principal_name': key.get('service_principal_name'),
            'recovery_level': key.get('recovery_level'),
            'tags': key.get('tags'),
            'managed': key.get('managed'),
            'version': key.get('version'),
            'updated_on': key.get('updated_on'),
            'key_operations': key_operations,  # Preserve original operations list
        }

        return NormalisedKey(
            key_id=key_id,
            name=name,
            source_type='azure_keyvault',
            source=key.get('source', 'Azure Key Vault'),
            key_type=key.get('key_type', 'Unknown'),
            key_size=key.get('key_size'),
            key_curve=key.get('key_curve'),
            key_class=key_class,
            is_sensitive=is_sensitive,
            is_extractable=is_extractable,
            is_hardware_protected=is_hardware_protected,
            is_local=is_locally_generated,
            is_always_sensitive=was_always_sensitive,
            is_never_extractable=was_never_extractable,
            can_encrypt=can_encrypt,
            can_decrypt=can_decrypt,
            can_sign=can_sign,
            can_verify=can_verify,
            can_wrap=can_wrap,
            can_unwrap=can_unwrap,
            can_derive=can_derive,
            created_on=created_on,
            expires_on=expires_on,
            not_before=not_before,
            is_enabled=is_enabled,
            days_until_expiration=days_until_expiration,
            associated_certificate=key.get('associated_certificate'),
            pqc_analysis=key.get('pqc_analysis'),
            # NEW: Azure metadata fields (from Phase 1 collector)
            azure_tags=azure_metadata.get('tags'),
            azure_key_type=azure_metadata.get('key_type'),
            azure_managed=azure_metadata.get('managed'),
            azure_version=azure_metadata.get('version'),
            azure_enabled=azure_metadata.get('enabled'),
            azure_recovery_level=azure_metadata.get('recovery_level'),
            azure_vault_name=azure_metadata.get('vault_name'),
            azure_vault_id=azure_metadata.get('vault_id'),
            azure_vault_location=azure_metadata.get('vault_location'),
            azure_vault_resource_group=azure_metadata.get('vault_resource_group'),
            azure_vault_tier=azure_metadata.get('vault_tier'),
            azure_subscription_id=azure_metadata.get('subscription_id'),
            azure_created_on=azure_metadata.get('created_on'),
            azure_updated_on=azure_metadata.get('updated_on'),
            azure_expires_on=azure_metadata.get('expires_on'),
            azure_not_before=azure_metadata.get('not_before'),
            # NEW: Environment metadata fields (from Phase 1 collector)
            inferred_environment_type=environment_metadata.get('environment_type'),
            inferred_service_name=environment_metadata.get('service_name'),
            inferred_application_name=environment_metadata.get('application_name'),
            inferred_discovery_method=environment_metadata.get('discovery_method'),
            inferred_discovery_confidence=environment_metadata.get('discovery_confidence'),
            inferred_signal_breakdown=environment_metadata.get('signal_breakdown'),  # Phase 1: Multi-signal fusion breakdown
            source_specific=source_specific
        )
    
    @classmethod
    def _normalise_generic_key(cls, key: Dict[str, Any]) -> NormalisedKey:
        """
        Normalise a generic key dictionary.
        
        Used for keys that don't match Luna or Azure patterns.
        Attempts to extract as much information as possible.
        """
        # Identity
        key_id = (key.get('key_id') or key.get('object_id') or 
                  key.get('id') or key.get('name') or 'unknown')
        name = (key.get('name') or key.get('label') or 
                key.get('key_name') or 'Unnamed Key')
        
        # Key class
        key_class = key.get('key_class')
        if not key_class:
            if key.get('private') is True:
                key_class = 'private'
            elif key.get('private') is False:
                key_class = 'public'
            else:
                key_class = 'unknown'
        
        # Security posture - use what's available
        source = (key.get('source') or '').lower()
        is_hardware_protected = 'hsm' in source
        
        # Lifecycle - try various field names
        expires_on = (key.get('expires_on') or key.get('end_date') or 
                      key.get('expiry') or key.get('not_after'))
        not_before = (key.get('not_before') or key.get('start_date') or 
                      key.get('activation_date'))
        created_on = key.get('created_on') or key.get('created')
        
        # Extract environment metadata if present
        environment_metadata = key.get('environment_metadata', {})

        return NormalisedKey(
            key_id=key_id,
            name=name,
            source_type='generic',
            source=key.get('source', 'Unknown'),
            key_type=key.get('key_type') or key.get('kty') or 'Unknown',
            key_size=key.get('key_size'),
            key_curve=key.get('key_curve') or key.get('crv'),
            key_class=key_class,
            is_sensitive=key.get('is_sensitive'),
            is_extractable=key.get('is_extractable'),
            is_hardware_protected=is_hardware_protected,
            is_locally_generated=key.get('is_local'),
            was_always_sensitive=key.get('is_always_sensitive'),
            was_never_extractable=key.get('is_never_extractable'),
            can_encrypt=key.get('can_encrypt'),
            can_decrypt=key.get('can_decrypt'),
            can_sign=key.get('can_sign'),
            can_verify=key.get('can_verify'),
            can_wrap=key.get('can_wrap'),
            can_unwrap=key.get('can_unwrap'),
            can_derive=key.get('can_derive'),
            created_on=created_on,
            expires_on=expires_on,
            not_before=not_before,
            is_enabled=key.get('enabled', True),
            associated_certificate=key.get('associated_certificate'),
            pqc_analysis=key.get('pqc_analysis'),
            # NEW: Azure metadata fields (generic keys don't have these - all None)
            azure_tags=None,
            azure_key_type=None,
            azure_managed=None,
            azure_version=None,
            azure_enabled=None,
            azure_recovery_level=None,
            azure_vault_name=None,
            azure_vault_id=None,
            azure_vault_location=None,
            azure_vault_resource_group=None,
            azure_vault_tier=None,
            azure_subscription_id=None,
            azure_created_on=None,
            azure_updated_on=None,
            azure_expires_on=None,
            azure_not_before=None,
            # NEW: Environment metadata fields (may be populated by enrichment service)
            inferred_environment_type=environment_metadata.get('environment_type'),
            inferred_service_name=environment_metadata.get('service_name'),
            inferred_application_name=environment_metadata.get('application_name'),
            inferred_discovery_method=environment_metadata.get('discovery_method'),
            inferred_discovery_confidence=environment_metadata.get('discovery_confidence'),
            source_specific={}
        )
    
    @classmethod
    def _minimal_normalise(cls, key: Dict[str, Any]) -> Dict[str, Any]:
        """
        Minimal normalisation for keys that fail full normalisation.
        
        Preserves original data and adds required normalised fields.
        """
        result = dict(key)  # Copy original
        
        # Add required normalised fields if missing
        if 'source_type' not in result:
            result['source_type'] = cls.detect_source_type(key)
        if 'key_id' not in result:
            result['key_id'] = (key.get('object_id') or key.get('name') or 
                                key.get('label') or 'unknown')
        if 'name' not in result:
            result['name'] = key.get('label') or key.get('key_id') or 'Unnamed Key'
        
        return result
    
    # =========================================================================
    # UTILITY METHODS
    # =========================================================================
    
    @classmethod
    def _compute_days_until_expiration(cls, expires_on: str) -> Optional[int]:
        """
        Compute days until expiration from an ISO date string.
        
        Args:
            expires_on: ISO format date string
            
        Returns:
            Days until expiration, or None if parsing fails
        """
        if not expires_on:
            return None
        
        try:
            # Handle various ISO formats
            expires_str = expires_on.replace('Z', '+00:00')
            
            # Try parsing with timezone
            try:
                expiry = datetime.fromisoformat(expires_str)
            except ValueError:
                # Try without timezone
                expiry = datetime.fromisoformat(expires_on.split('+')[0].split('Z')[0])
                expiry = expiry.replace(tzinfo=timezone.utc)
            
            # Ensure timezone aware
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            
            now = datetime.now(timezone.utc)
            delta = expiry - now
            return max(0, delta.days)
            
        except Exception as e:
            logger.debug(f"Failed to parse expiration date '{expires_on}': {e}")
            return None
    
    @classmethod
    def _generate_pqc_analysis(cls, key: NormalisedKey) -> Dict[str, Any]:
        """
        Generate PQC analysis for a key if not already present.
        
        Args:
            key: NormalisedKey instance
            
        Returns:
            PQC analysis dictionary
        """
        try:
            from caip_pqc_functions.pqc_detector import get_detector
            
            detector = get_detector()
            result = detector.analyze_key(
                key_type=key.key_type,
                key_size=key.key_size
            )
            return result.to_dict()
            
        except ImportError:
            logger.debug("PQC detector not available")
            return None
        except Exception as e:
            logger.debug(f"PQC analysis failed: {e}")
            return None
        

    # =========================================================================
    # CERTIFICATE NORMALISATION
    # =========================================================================
    
    @classmethod
    def normalise_certificate(cls, cert: Dict[str, Any],
                             environment_metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Normalise a single certificate to the unified format.

        Args:
            cert: Certificate dictionary (from asdict(CertificateInfo) or raw dict)
            environment_metadata: Optional environment metadata from enrichment service
                                {
                                    'environment_type': str,
                                    'service_name': str,
                                    'application_name': str,
                                    'discovery_method': str,
                                    'discovery_confidence': float
                                }

        Returns:
            Normalised certificate dictionary with all computed fields + environment
        """
        import datetime as dt
        
        # Parse dates for calculations
        not_before_str = cert.get('not_before')
        not_after_str = cert.get('not_after')
        not_before_dt = None
        not_after_dt = None
        
        try:
            if not_before_str:
                if isinstance(not_before_str, str):
                    not_before_dt = dt.datetime.fromisoformat(not_before_str.replace('Z', '+00:00'))
                elif hasattr(not_before_str, 'isoformat'):
                    not_before_dt = not_before_str
            
            if not_after_str:
                if isinstance(not_after_str, str):
                    not_after_dt = dt.datetime.fromisoformat(not_after_str.replace('Z', '+00:00'))
                elif hasattr(not_after_str, 'isoformat'):
                    not_after_dt = not_after_str
        except Exception as e:
            logger.debug(f"Could not parse certificate dates: {e}")
        
        # Calculate validity period
        certificate_validity_days = 0
        if not_before_dt and not_after_dt:
            certificate_validity_days = (not_after_dt - not_before_dt).days
        
        # Calculate days until expiration
        days_until_expiration = 0
        is_expired = False
        if not_after_dt:
            now = dt.datetime.now(dt.timezone.utc) if not_after_dt.tzinfo else dt.datetime.now()
            days_until_expiration = (not_after_dt - now).days
            is_expired = days_until_expiration < 0
        
        # Extract subject/issuer CNs
        subject = cert.get('subject') or {}
        issuer = cert.get('issuer') or {}
        subject_cn = subject.get('commonName', '') if isinstance(subject, dict) else ''
        issuer_cn = issuer.get('commonName', '') if isinstance(issuer, dict) else ''
        
        # Detect source type from source string
        # NOTE: Order matters! Check specific sources before generic patterns
        source = cert.get('source', '')
        source_lower = source.lower()

        # Check specific sources FIRST (before generic patterns like ':')
        if 'azure' in source_lower or 'keyvault' in source_lower:
            source_type = 'azure_keyvault'
        elif 'luna' in source_lower or 'hsm' in source_lower:
            source_type = 'luna_hsm'
        elif 'ejbca' in source_lower:
            source_type = 'ejbca'
        elif 'file' in source_lower:
            source_type = 'file'
        # Check generic TLS patterns LAST
        elif 'tls' in source_lower or 'endpoint' in source_lower or ':' in source:
            source_type = 'tls'
        else:
            source_type = 'unknown'
        
        # Extract PQC analysis fields
        pqc_analysis = cert.get('pqc_analysis') or {}
        is_pqc = pqc_analysis.get('is_pqc', False) if pqc_analysis else False
        is_hybrid = pqc_analysis.get('is_hybrid', False) if pqc_analysis else False
        pqc_algorithm = pqc_analysis.get('pqc_algorithm') if pqc_analysis else None
        migration_status = pqc_analysis.get('migration_status', 'needs_migration') if pqc_analysis else 'needs_migration'
        
        # Determine trust indicators
        is_self_signed = cert.get('is_self_signed', False)
        is_ca = cert.get('is_ca', False)
        is_root_ca = cert.get('is_root_ca', False)
        is_intermediate_ca = cert.get('is_intermediate_ca', False)
        trusted_issuer_available = is_root_ca or (issuer_cn.lower() != 'unknown' if issuer_cn else False)
        
        # SAN handling
        san = cert.get('san') or []
        san_count = len(san)

        # Revocation support check (computed field for policy assessment)
        ocsp_responders = cert.get('ocsp_responders') or []
        crl_distribution_points = cert.get('crl_distribution_points') or []
        ocsp_or_crl_implemented = (len(ocsp_responders) > 0) or (len(crl_distribution_points) > 0)

        # Build normalised certificate
        normalised = NormalisedCertificate(
            cert_id=cert.get('unique_id') or cert.get('fingerprint_sha256') or cert.get('serial_number', 'unknown'),
            serial_number=cert.get('serial_number', ''),
            fingerprint_sha256=cert.get('fingerprint_sha256', ''),
            source=source,
            source_type=source_type,
            subject=subject,
            subject_cn=subject_cn,
            issuer=issuer,
            issuer_cn=issuer_cn,
            signature_algorithm=cert.get('signature_algorithm', ''),
            public_key_algorithm=cert.get('public_key_algorithm', ''),
            public_key_size=cert.get('public_key_size'),
            key_curve=cert.get('key_curve'),
            not_before=not_before_str if isinstance(not_before_str, str) else (not_before_str.isoformat() if not_before_str else None),
            not_after=not_after_str if isinstance(not_after_str, str) else (not_after_str.isoformat() if not_after_str else None),
            certificate_validity_days=certificate_validity_days,
            days_until_expiration=days_until_expiration,
            is_expired=is_expired,
            is_ca=is_ca,
            is_root_ca=is_root_ca,
            is_intermediate_ca=is_intermediate_ca,
            is_self_signed=is_self_signed,
            san=san,
            san_count=san_count,
            key_usage=cert.get('key_usage') or [],
            extended_key_usage=cert.get('extended_key_usage') or [],
            basic_constraints=cert.get('basic_constraints') or {},
            crl_distribution_points=cert.get('crl_distribution_points') or [],
            ocsp_responders=cert.get('ocsp_responders') or [],
            ocsp_or_crl_implemented=ocsp_or_crl_implemented,
            trusted_issuer_available=trusted_issuer_available,
            certificate_chain=cert.get('certificate_chain') or [],
            found_at_destination=cert.get('found_at_destination'),
            found_on_port=cert.get('found_on_port'),
            tls_version=cert.get('tls_version'),
            tls_library=cert.get('tls_library'),
            # Phase 1, 2, 3 TLS fields
            symmetric_key_bits=cert.get('symmetric_key_bits'),
            has_forward_secrecy=cert.get('has_forward_secrecy'),
            authority_key_identifier=cert.get('authority_key_identifier'),
            subject_key_identifier=cert.get('subject_key_identifier'),
            supported_tls_versions=cert.get('supported_tls_versions') or [],
            protocol_vulnerabilities=cert.get('protocol_vulnerabilities') or [],
            client_cert_required=cert.get('client_cert_required'),
            ocsp_stapling_supported=cert.get('ocsp_stapling_supported'),
            session_ticket_supported=cert.get('session_ticket_supported'),
            cipher_strength_rating=cert.get('cipher_strength_rating'),
            lifespan_pattern=cert.get('lifespan_pattern'),
            tls_handshake_time_ms=cert.get('tls_handshake_time_ms'),
            precert_poison_present=cert.get('precert_poison_present'),
            freshest_crl_urls=cert.get('freshest_crl_urls') or [],
            pqc_analysis=pqc_analysis if pqc_analysis else None,
            is_pqc=is_pqc,
            is_hybrid=is_hybrid,
            pqc_algorithm=pqc_algorithm,
            migration_status=migration_status,
            certificate_transparency_scts=cert.get('certificate_transparency_scts') or [],
            source_specific={},
            # Phase 3 metadata fields
            inferred_identity_metadata=None,
            inferred_purpose_metadata=None,
            inferred_crypto_metadata=None,
            inferred_ha_metadata=None
        )

        # NEW: Populate environment metadata if provided
        if environment_metadata:
            normalised.environment_type = environment_metadata.get('environment_type')
            normalised.service_name = environment_metadata.get('service_name')
            normalised.application_name = environment_metadata.get('application_name')
            normalised.discovery_metadata = {
                'discovery_method': environment_metadata.get('discovery_method'),
                'discovery_confidence': environment_metadata.get('discovery_confidence', 0.0)
            }
            # Phase 3: Extracted metadata from signals
            normalised.inferred_identity_metadata = environment_metadata.get('extracted_metadata', {}).get('identity')
            normalised.inferred_purpose_metadata = environment_metadata.get('extracted_metadata', {}).get('purpose')
            normalised.inferred_crypto_metadata = environment_metadata.get('extracted_metadata', {}).get('crypto')
            normalised.inferred_ha_metadata = environment_metadata.get('extracted_metadata', {}).get('ha')

        result = normalised.to_dict()

        # Policy assessment aliases (backward compatibility)
        result['id'] = result.get('cert_id')
        result['unique_id'] = result.get('cert_id')

        return result
    
    @classmethod
    def normalise_certificates(cls, certs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Normalise a list of certificates to the unified format.

        Args:
            certs: List of certificate dictionaries (may include enrichment fields)

        Returns:
            List of normalised certificate dictionaries
        """
        normalised_certs = []
        for cert in certs:
            try:
                # Extract Phase 1 environment metadata from cert dict if present
                environment_metadata = None
                has_environment_data = any(key in cert for key in ['environment_type', 'service_name', 'application_name', 'discovery_metadata'])
                if has_environment_data:
                    discovery_meta = cert.get('discovery_metadata', {})
                    environment_metadata = {
                        'environment_type': cert.get('environment_type'),
                        'service_name': cert.get('service_name'),
                        'application_name': cert.get('application_name'),
                        'discovery_method': discovery_meta.get('discovery_method') if isinstance(discovery_meta, dict) else None,
                        'discovery_confidence': discovery_meta.get('discovery_confidence') if isinstance(discovery_meta, dict) else None
                    }

                # Extract Phase 2-4 Azure metadata if present
                azure_metadata = cert.get('azure_metadata', {})
                if not isinstance(azure_metadata, dict):
                    azure_metadata = {}

                # Extract Phase 1.5 security metadata if present
                security_metadata = {}
                if 'signature_algorithm_analysis' in cert:
                    security_metadata['signature_algorithm_analysis'] = cert.get('signature_algorithm_analysis')
                if 'key_strength_analysis' in cert:
                    security_metadata['key_strength_analysis'] = cert.get('key_strength_analysis')
                if 'pqc_readiness' in cert:
                    security_metadata['pqc_readiness'] = cert.get('pqc_readiness')
                if 'revocation_status' in cert:
                    security_metadata['revocation_status'] = cert.get('revocation_status')

                normalised = cls.normalise_certificate(cert, environment_metadata=environment_metadata)

                # Merge Phase 2-4 Azure metadata into normalised cert
                if azure_metadata:
                    normalised['azure_tags'] = azure_metadata.get('tags')
                    normalised['azure_key_type'] = azure_metadata.get('key_type')
                    normalised['azure_managed'] = azure_metadata.get('managed')
                    normalised['azure_version'] = azure_metadata.get('version')
                    normalised['azure_enabled'] = azure_metadata.get('enabled')
                    normalised['azure_recovery_level'] = azure_metadata.get('recovery_level')
                    normalised['azure_vault_name'] = azure_metadata.get('vault_name')
                    normalised['azure_vault_id'] = azure_metadata.get('vault_id')
                    normalised['azure_vault_location'] = azure_metadata.get('vault_location')
                    normalised['azure_vault_resource_group'] = azure_metadata.get('vault_resource_group')
                    normalised['azure_vault_tier'] = azure_metadata.get('vault_tier')
                    normalised['azure_subscription_id'] = azure_metadata.get('subscription_id')
                    normalised['azure_created_on'] = azure_metadata.get('created_on')
                    normalised['azure_updated_on'] = azure_metadata.get('updated_on')
                    normalised['azure_expires_on'] = azure_metadata.get('expires_on')
                    normalised['azure_not_before'] = azure_metadata.get('not_before')

                # Extract inferred environment metadata fields
                if environment_metadata:
                    normalised['inferred_discovery_method'] = environment_metadata.get('discovery_method')
                    normalised['inferred_discovery_confidence'] = environment_metadata.get('discovery_confidence')

                # Merge Phase 1.5 security fields into normalised cert
                if security_metadata:
                    if 'signature_algorithm_analysis' in security_metadata:
                        normalised['signature_algorithm_analysis'] = security_metadata['signature_algorithm_analysis']
                    if 'key_strength_analysis' in security_metadata:
                        normalised['key_strength_analysis'] = security_metadata['key_strength_analysis']
                    if 'pqc_readiness' in security_metadata:
                        normalised['pqc_readiness'] = security_metadata['pqc_readiness']
                    if 'revocation_status' in security_metadata:
                        normalised['revocation_status'] = security_metadata['revocation_status']

                normalised_certs.append(normalised)
            except Exception as e:
                logger.warning(f"Failed to normalise certificate: {e}")
                # Include original cert with minimal additions
                cert['id'] = cert.get('unique_id') or cert.get('fingerprint_sha256', 'unknown')
                normalised_certs.append(cert)

        return normalised_certs

    # =========================================================================
    # STANDARDIZED NORMALIZATION AND ENRICHMENT ORCHESTRATION
    # =========================================================================

    @classmethod
    def normalise_and_enrich_certificates(
        cls,
        certs: List[Dict[str, Any]],
        enrichment_config: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Normalize certificates AND orchestrate enrichment in one unified step.

        This method combines three responsibilities:
        1. Normalize field names to canonical format
        2. Call enrichment services (via MetadataEnrichmentService)
        3. Standardize output structure (flatten all enrichment fields)

        The enrichment SERVICE does the analysis (TLSSecurityEnricher, AzureMetadataEnricher, etc.)
        This LAYER orchestrates the services and guarantees flat structure output.

        Args:
            certs: List of raw certificate dicts from any source
            enrichment_config: Configuration dict with keys:
                - enable_security_analysis: bool - Call TLSSecurityEnricher?
                - enable_environment_analysis: bool - Call source-specific enricher?
                - environment_enricher_type: str - Which enricher? ('Azure Key Vault', 'EJBCA', 'Luna HSM')
                - source_type: str - Source identifier for tracking (e.g., 'Azure Key Vault')
                - capture_security_analysis: bool - Flag for enricher (if supported)

        Returns:
            List of enriched dicts with ALL fields at top level (FLAT structure guaranteed)

        Guarantees:
            - All enrichment fields are at top level (not nested)
            - signature_algorithm_analysis is top level ✅
            - key_strength_analysis is top level ✅
            - pqc_readiness is top level ✅
            - environment_type is top level ✅
            - discovery_method is top level ✅
            - discovery_confidence is top level ✅
            - source_type is set ✅
            - No nested environment_metadata objects ✅
        """
        from caip_service_layer.metadata_enrichment_service import MetadataEnrichmentService

        logger.info(f"[normalise_and_enrich_certificates] Processing {len(certs)} certificates")

        # Default config
        if enrichment_config is None:
            enrichment_config = {}

        # =====================================================================
        # STEP 1: Normalize to standard field names
        # =====================================================================
        logger.info("[normalise_and_enrich_certificates] Step 1: Normalizing field names")
        normalised = cls.normalise_certificates(certs)
        logger.info(f"[normalise_and_enrich_certificates] ✅ Normalized {len(normalised)} certificates")

        # =====================================================================
        # STEP 2: Apply security enrichment (cryptographic analysis)
        # =====================================================================
        if enrichment_config.get('enable_security_analysis', False):
            logger.info("[normalise_and_enrich_certificates] Step 2: Applying security enrichment")

            try:
                # Call enrichment SERVICE to get TLSSecurityEnricher
                enricher = MetadataEnrichmentService.get_enricher('tls_security')
                logger.debug(f"[normalise_and_enrich_certificates] Got enricher: {enricher.__class__.__name__}")

                enriched = []
                for i, cert in enumerate(normalised):
                    try:
                        # Enricher does analysis, returns dict with enrichment fields added
                        enriched_cert = enricher.enrich(cert, enrichment_config)
                        enriched.append(enriched_cert)

                        if i == 0:  # Log first cert for debugging
                            logger.debug(f"[normalise_and_enrich_certificates] First enriched cert has fields: {list(enriched_cert.keys())}")
                    except Exception as e:
                        logger.warning(f"[normalise_and_enrich_certificates] Failed to enrich cert: {e}")
                        # Keep original cert if enrichment fails
                        enriched.append(cert)

                normalised = enriched
                logger.info(f"[normalise_and_enrich_certificates] ✅ Applied security enrichment to {len(enriched)} certificates")

            except Exception as e:
                logger.error(f"[normalise_and_enrich_certificates] Security enrichment failed: {e}")
                # Continue without security enrichment if service fails
                pass

        # =====================================================================
        # STEP 3: Apply environment enrichment (source-specific inference)
        # =====================================================================
        if enrichment_config.get('enable_environment_analysis', False):
            logger.info("[normalise_and_enrich_certificates] Step 3: Applying environment enrichment")

            enricher_type = enrichment_config.get('environment_enricher_type')
            if enricher_type:
                try:
                    # Normalize enricher_type name (handle 'EJBCA', 'Azure Key Vault', 'Luna HSM' from database)
                    enricher_type_lower = (enricher_type or '').lower()
                    if 'azure' in enricher_type_lower:
                        normalized_enricher_type = 'azure'
                    elif 'ejbca' in enricher_type_lower:
                        normalized_enricher_type = 'ejbca'
                    elif 'luna' in enricher_type_lower or 'hsm' in enricher_type_lower:
                        normalized_enricher_type = 'luna'
                    elif 'tls' in enricher_type_lower:
                        normalized_enricher_type = 'tls'
                    else:
                        normalized_enricher_type = enricher_type_lower

                    # Call enrichment SERVICE to get environment enricher
                    enricher = MetadataEnrichmentService.get_enricher(normalized_enricher_type)
                    logger.debug(f"[normalise_and_enrich_certificates] Got enricher: {enricher.__class__.__name__} (from {enricher_type})")

                    enriched = []
                    for i, cert in enumerate(normalised):
                        try:
                            # Determine enricher type based on certificate source or override
                            cert_enricher_type = enricher_type
                            cert_source = cert.get('source', '').lower()
                            enricher_type_lower = (enricher_type or '').lower()

                            # For scans: detect from cert source if using default TLS enricher
                            if enricher_type_lower in ['tls', 'tls_scan'] and cert_source:
                                if 'ejbca' in cert_source:
                                    cert_enricher_type = 'ejbca'
                                elif 'azure' in cert_source:
                                    cert_enricher_type = 'azure'
                                elif 'luna' in cert_source or 'hsm' in cert_source:
                                    cert_enricher_type = 'luna'

                            # For inventory sync: normalize names (e.g., 'Azure Key Vault' → 'azure')
                            elif 'azure' in enricher_type_lower:
                                cert_enricher_type = 'azure'
                            elif 'ejbca' in enricher_type_lower:
                                cert_enricher_type = 'ejbca'
                            elif 'luna' in enricher_type_lower or 'hsm' in enricher_type_lower:
                                cert_enricher_type = 'luna'

                            # Get source-specific enricher if different from default
                            if cert_enricher_type != enricher_type:
                                cert_enricher = MetadataEnrichmentService.get_enricher(cert_enricher_type)
                                logger.debug(f"[normalise_and_enrich_certificates] Using {cert_enricher_type} enricher (source={cert_source})")
                            else:
                                cert_enricher = enricher

                            # Enricher does analysis, returns dict with environment enrichment
                            enriched_cert = cert_enricher.enrich(cert, enrichment_config)

                            # ========== CRITICAL STEP: FLATTEN NESTED STRUCTURE ==========
                            # The enricher may have produced nested environment_metadata object.
                            # This layer is responsible for STANDARDIZING to flat structure.
                            if 'environment_metadata' in enriched_cert:
                                env_meta = enriched_cert.pop('environment_metadata')
                                logger.info(f"[normalise_and_enrich_certificates] Got environment_metadata from enricher: {list(env_meta.keys()) if env_meta else 'None'}")
                                if env_meta and 'signal_breakdown' in env_meta:
                                    logger.info(f"[normalise_and_enrich_certificates] signal_breakdown present with {len(env_meta['signal_breakdown'])} signals")

                                # Move nested fields to top level with inferred_ prefix
                                enriched_cert['inferred_environment_type'] = env_meta.get('environment_type')
                                enriched_cert['inferred_discovery_method'] = env_meta.get('discovery_method')
                                enriched_cert['inferred_discovery_confidence'] = env_meta.get('discovery_confidence')
                                enriched_cert['inferred_signal_breakdown'] = env_meta.get('signal_breakdown')  # Extract signal breakdown
                                enriched_cert['environment_metadata'] = env_meta  # Keep copy for backward compat
                            else:
                                logger.info(f"[normalise_and_enrich_certificates] No environment_metadata in enriched cert")

                            # NEW: Handle extracted_enrichment (service identity, purpose, crypto, ha fields)
                            if 'extracted_enrichment' in enriched_cert:
                                extracted_meta = enriched_cert.pop('extracted_enrichment')
                                logger.info(f"[normalise_and_enrich_certificates] Got extracted_enrichment from enricher with keys: {list(extracted_meta.keys()) if extracted_meta else 'None'}")

                                # Flatten extracted enrichment to top level
                                if extracted_meta:
                                    # Service identity fields
                                    identity = extracted_meta.get('identity', {})
                                    for key, val in identity.items():
                                        if val is not None:
                                            enriched_cert[f'extracted_{key}'] = val
                                    if identity:
                                        enriched_cert['inferred_identity_metadata'] = identity

                                    # Purpose fields
                                    purpose = extracted_meta.get('purpose', {})
                                    for key, val in purpose.items():
                                        if val is not None:
                                            enriched_cert[f'extracted_{key}'] = val
                                    if purpose:
                                        enriched_cert['inferred_purpose_metadata'] = purpose

                                    # Crypto fields
                                    crypto = extracted_meta.get('crypto', {})
                                    for key, val in crypto.items():
                                        if val is not None:
                                            enriched_cert[f'extracted_{key}'] = val
                                    if crypto:
                                        enriched_cert['inferred_crypto_metadata'] = crypto

                                    # HA fields
                                    ha = extracted_meta.get('ha', {})
                                    for key, val in ha.items():
                                        if val is not None:
                                            enriched_cert[f'extracted_{key}'] = val
                                    if ha:
                                        enriched_cert['inferred_ha_metadata'] = ha

                                    # Keep copy for backward compat
                                    enriched_cert['extracted_enrichment'] = extracted_meta
                            else:
                                logger.debug(f"[normalise_and_enrich_certificates] No extracted_enrichment in enriched cert")

                            enriched.append(enriched_cert)

                            if i == 0:  # Log first cert for debugging
                                logger.debug(f"[normalise_and_enrich_certificates] First enriched cert fields: {list(enriched_cert.keys())}")
                        except Exception as e:
                            logger.warning(f"[normalise_and_enrich_certificates] Failed to enrich cert: {e}")
                            # Keep original cert if enrichment fails
                            enriched.append(cert)

                    normalised = enriched
                    logger.info(f"[normalise_and_enrich_certificates] ✅ Applied environment enrichment to {len(enriched)} certificates")

                except Exception as e:
                    logger.error(f"[normalise_and_enrich_certificates] Environment enrichment failed: {e}")
                    # Continue without environment enrichment if service fails
                    pass

        # =====================================================================
        # STEP 4: Add source tracking (config source_type takes precedence)
        # =====================================================================
        logger.info("[normalise_and_enrich_certificates] Step 4: Adding source tracking")

        source_type = enrichment_config.get('source_type')
        if source_type:
            # Config source_type takes precedence over detected source_type
            for cert in normalised:
                cert['source_type'] = source_type

        # =====================================================================
        # STEP 5: Verify flat structure (safety check)
        # =====================================================================
        logger.info("[normalise_and_enrich_certificates] Step 5: Verifying flat structure")

        nested_count = 0
        for cert in normalised:
            # Ensure no nested enrichment objects remain
            if 'environment_metadata' in cert:
                env_meta = cert.pop('environment_metadata')
                # Ensure fields are at top level
                if 'environment_type' not in cert:
                    cert['environment_type'] = env_meta.get('environment_type')
                if 'discovery_method' not in cert:
                    cert['discovery_method'] = env_meta.get('discovery_method')
                if 'discovery_confidence' not in cert:
                    cert['discovery_confidence'] = env_meta.get('discovery_confidence')
                nested_count += 1

        if nested_count > 0:
            logger.warning(f"[normalise_and_enrich_certificates] Fixed {nested_count} nested structures to flat")

        logger.info(f"[normalise_and_enrich_certificates] ✅ Completed - {len(normalised)} certificates standardized to flat structure")
        return normalised

    @classmethod
    def normalise_and_enrich_keys(
        cls,
        keys: List[Dict[str, Any]],
        enrichment_config: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Normalize keys AND apply enrichment in one unified step.

        Currently keys don't have enrichment services like certificates (no TLSSecurityEnricher
        equivalent for keys), so this primarily normalizes the data to canonical format.

        This method provides consistency with normalise_and_enrich_certificates() pattern.

        Args:
            keys: List of raw key dicts from any source (Luna HSM, Azure Key Vault, etc.)
            enrichment_config: Configuration dict (optional, for future use when key enrichment available)

        Returns:
            List of normalised key dicts with all fields standardized
        """
        logger.info(f"[normalise_and_enrich_keys] Processing {len(keys)} keys")

        # Default config
        if enrichment_config is None:
            enrichment_config = {}

        # =====================================================================
        # STEP 1: Normalize to standard field names
        # =====================================================================
        logger.info("[normalise_and_enrich_keys] Step 1: Normalizing field names")
        normalised = cls.normalise_keys(keys)
        logger.info(f"[normalise_and_enrich_keys] ✅ Normalized {len(normalised)} keys")

        # =====================================================================
        # STEP 2: Add source tracking (if provided in config)
        # =====================================================================
        source_type = enrichment_config.get('source_type')
        if source_type:
            logger.info("[normalise_and_enrich_keys] Step 2: Adding source tracking")
            for key in normalised:
                key['source_type'] = source_type

        logger.info(f"[normalise_and_enrich_keys] ✅ Completed - {len(normalised)} keys standardized")
        return normalised

    # =========================================================================
    # FIELD MAPPING DOCUMENTATION
    # =========================================================================

    @classmethod
    def get_field_mapping(cls) -> Dict[str, Dict[str, str]]:
        """
        Get documentation of field mappings from source formats.
        
        Useful for understanding how fields are transformed.
        
        Returns:
            Dictionary mapping normalised field names to source field names
        """
        return {
            'key_id': {
                'luna_hsm': 'object_id or label',
                'azure_keyvault': 'key_id or name',
                'description': 'Unique identifier for the key'
            },
            'name': {
                'luna_hsm': 'label',
                'azure_keyvault': 'name',
                'description': 'Human-readable key name'
            },
            'key_class': {
                'luna_hsm': 'key_class (from PKCS#11)',
                'azure_keyvault': 'Derived from key_type (RSA/EC=private, AES=secret)',
                'description': 'Type of key: public, private, or secret'
            },
            'is_sensitive': {
                'luna_hsm': 'is_sensitive (CKA_SENSITIVE)',
                'azure_keyvault': 'Always True (keys never leave vault)',
                'description': 'Key material protected from disclosure'
            },
            'is_extractable': {
                'luna_hsm': 'is_extractable (CKA_EXTRACTABLE)',
                'azure_keyvault': 'Always False (Azure prevents export)',
                'description': 'Whether key can be exported'
            },
            'is_hardware_protected': {
                'luna_hsm': 'Always True (Luna is HSM)',
                'azure_keyvault': 'hsm_backed or HSM in key_type',
                'description': 'Key stored in hardware security module'
            },
            'is_locally_generated': {
                'luna_hsm': 'is_local (CKA_LOCAL)',
                'azure_keyvault': 'Inverse of managed flag',
                'description': 'Key generated on the hardware (not imported)'
            },
            'was_always_sensitive': {
                'luna_hsm': 'is_always_sensitive (CKA_ALWAYS_SENSITIVE)',
                'azure_keyvault': 'Assumed True (no history available)',
                'description': 'Key has never been exposed in plaintext'
            },
            'was_never_extractable': {
                'luna_hsm': 'is_never_extractable (CKA_NEVER_EXTRACTABLE)',
                'azure_keyvault': 'Assumed True (no history available)',
                'description': 'Key has never been exportable'
            },
            'can_decrypt': {
                'luna_hsm': 'can_decrypt (CKA_DECRYPT)',
                'azure_keyvault': '"decrypt" in key_operations',
                'description': 'Key can perform decryption'
            },
            'can_unwrap': {
                'luna_hsm': 'can_unwrap (CKA_UNWRAP)',
                'azure_keyvault': '"unwrapKey" in key_operations',
                'description': 'Key can unwrap other keys'
            },
            'expires_on': {
                'luna_hsm': 'end_date (CKA_END_DATE)',
                'azure_keyvault': 'expires_on',
                'description': 'Key expiration date (ISO format)'
            },
            'not_before': {
                'luna_hsm': 'start_date (CKA_START_DATE)',
                'azure_keyvault': 'not_before',
                'description': 'Key activation date (ISO format)'
            }
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def normalise_key(key: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function for single key normalisation."""
    return KeyNormalisationService.normalise_key(key)


def normalise_keys(keys: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convenience function for batch key normalisation."""
    return KeyNormalisationService.normalise_keys(keys)


def detect_key_source(key: Dict[str, Any]) -> str:
    """Convenience function for source detection."""
    return KeyNormalisationService.detect_source_type(key)


logger.info("Key Normalisation Service module loaded")
