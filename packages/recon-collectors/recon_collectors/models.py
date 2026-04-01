"""Data models for the recon-collectors package."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class CertificateInfo:
    """X.509 certificate metadata."""

    serial_number: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    unique_id: Optional[str] = None
    subject: Optional[dict] = field(default_factory=dict)
    issuer: Optional[dict] = field(default_factory=dict)
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    is_expired: Optional[bool] = False
    signature_algorithm: Optional[str] = None
    public_key_algorithm: Optional[str] = None
    public_key_size: Optional[int] = None
    key_curve: Optional[str] = None
    key_usage: Optional[list] = field(default_factory=list)
    extended_key_usage: Optional[list] = field(default_factory=list)
    san: Optional[list] = field(default_factory=list)
    basic_constraints: Optional[dict] = field(default_factory=dict)
    crl_distribution_points: Optional[list] = field(default_factory=list)
    ocsp_responders: Optional[list] = field(default_factory=list)
    certificate_transparency_scts: Optional[list[dict]] = field(
        default_factory=list
    )
    authority_key_identifier: Optional[str] = None
    subject_key_identifier: Optional[str] = None
    freshest_crl_urls: Optional[list] = field(default_factory=list)
    precert_poison_present: Optional[bool] = False
    is_ca: Optional[bool] = False
    is_self_signed: Optional[bool] = False
    source: Optional[str] = None
    found_at_destination: Optional[str] = None
    found_on_port: Optional[int] = None
    tls_version: Optional[str] = None
    tls_library: Optional[str] = None
    has_forward_secrecy: Optional[bool] = False
    symmetric_key_bits: Optional[int] = None
    cipher_strength_rating: Optional[str] = None
    tls_handshake_time_ms: Optional[float] = None
    supported_tls_versions: Optional[list] = field(default_factory=list)
    protocol_vulnerabilities: Optional[list] = field(default_factory=list)
    client_cert_required: Optional[bool] = False
    ocsp_stapling_supported: Optional[bool] = False
    session_ticket_supported: Optional[bool] = False
    lifespan_pattern: Optional[str] = None
    certificate_chain: Optional[list] = field(default_factory=list)
    pqc_analysis: Optional[dict] = field(default_factory=dict)
    is_pqc: Optional[bool] = False
    is_hybrid: Optional[bool] = False
    pqc_algorithm: Optional[str] = None
    migration_status: Optional[str] = "needs_migration"
    azure_metadata: Optional[dict] = field(default_factory=dict)
    environment_metadata: Optional[dict] = field(default_factory=dict)
    certificate_pem: Optional[str] = None


@dataclass
class KeyInfo:
    """Key metadata."""

    key_id: Optional[str] = None
    label: Optional[str] = None
    source_type: Optional[str] = None
    source: Optional[str] = None
    key_type: Optional[str] = None
    key_size: Optional[int] = None
    key_curve: Optional[str] = None
    key_class: Optional[str] = None
    is_sensitive: Optional[bool] = False
    is_extractable: Optional[bool] = False
    is_local: Optional[bool] = False
    is_always_sensitive: Optional[bool] = False
    is_never_extractable: Optional[bool] = False
    is_hardware_protected: Optional[bool] = False
    can_encrypt: Optional[bool] = False
    can_decrypt: Optional[bool] = False
    can_sign: Optional[bool] = False
    can_verify: Optional[bool] = False
    can_wrap: Optional[bool] = False
    can_unwrap: Optional[bool] = False
    can_derive: Optional[bool] = False
    created_on: Optional[datetime] = None
    expires_on: Optional[datetime] = None
    not_before: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    is_enabled: Optional[bool] = False
    associated_certificate: Optional[str] = None
    pqc_analysis: Optional[dict] = field(default_factory=dict)
    azure_metadata: Optional[dict] = field(default_factory=dict)
    environment_metadata: Optional[dict] = field(default_factory=dict)


@dataclass
class TLSScanResult:
    """TLS scan result for a single host/port."""

    host: Optional[str] = None
    port: Optional[int] = None
    timestamp: Optional[datetime] = None
    supported_protocols: Optional[list] = field(default_factory=list)
    cipher_suite: Optional[str] = None
    certificate: Optional[CertificateInfo] = None
    certificate_chain: Optional[list[CertificateInfo]] = field(
        default_factory=list
    )
    security_metadata: Optional[dict] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class CRLInfo:
    """Certificate Revocation List metadata."""

    source_url: Optional[str] = None
    issuer: Optional[str] = None
    this_update: Optional[datetime] = None
    next_update: Optional[datetime] = None
    total_revoked: Optional[int] = None
    revoked_serials: Optional[list] = field(default_factory=list)
    signature_algorithm: Optional[str] = None
    crl_number: Optional[int] = None
    is_stale: Optional[bool] = False
    error: Optional[str] = None


@dataclass
class Finding:
    """A finding produced by a policy rule evaluation."""

    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    severity: Optional[str] = None
    risk_score: Optional[float] = None
    title: Optional[str] = None
    description: Optional[str] = None
    remediation: Optional[str] = None
    evidence: Optional[dict] = field(default_factory=dict)
    compliance_impact: Optional[str] = None
    category: Optional[str] = None
    affected_asset_id: Optional[str] = None
    affected_asset_type: Optional[str] = None


@dataclass
class ScanResults:
    """Container for all results produced by a collector run."""

    certificates: Optional[list[CertificateInfo]] = field(
        default_factory=list
    )
    keys: Optional[list[KeyInfo]] = field(default_factory=list)
    tls_results: Optional[list[TLSScanResult]] = field(default_factory=list)
    crls: Optional[dict] = field(default_factory=dict)
    file_scan_results: Optional[list[dict]] = field(default_factory=list)
    findings: Optional[list[Finding]] = field(default_factory=list)
    normalised_certificates: Optional[list[dict]] = field(
        default_factory=list
    )
    normalised_keys: Optional[list[dict]] = field(default_factory=list)
    collector_stats: Optional[dict] = field(default_factory=dict)
    errors: Optional[list] = field(default_factory=list)
