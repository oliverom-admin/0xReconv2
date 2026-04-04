"""
Document Assessment Templates for CAIP

Provides built-in assessment templates for PKI governance documents.
Templates are based on:
- RFC 3647 (Certificate Policy and Certification Practices Framework)
- NCSC (UK National Cyber Security Centre) guidance
- NIST SP 800-57 (Key Management)
- NIST SP 800-130 (Cryptographic Key Management)
- ISO/IEC 27001 requirements
- WebTrust for CAs principles
"""

from typing import Dict, Any

# Import DocumentType for type hints
try:
    from .document_assessment_service import DocumentType
except ImportError:
    # Fallback for standalone execution
    from enum import Enum
    class DocumentType(Enum):
        CERTIFICATE_PRACTICE_STATEMENT = "certificate_practice_statement"
        CERTIFICATE_POLICY = "certificate_policy"
        PKI_DESIGN = "pki_design"
        KEY_MANAGEMENT_PLAN = "key_management_plan"
        PKI_OPERATIONAL_PROCESS = "pki_operational_process"
        BUSINESS_CONTINUITY = "business_continuity"
        UNKNOWN = "unknown"


def get_template(document_type: DocumentType) -> Dict[str, Any]:
    """
    Get the assessment template for a document type.
    
    Args:
        document_type: The type of document
        
    Returns:
        Template dictionary with sections and elements
    """
    templates = {
        DocumentType.CERTIFICATE_PRACTICE_STATEMENT: _get_cps_template(),
        DocumentType.CERTIFICATE_POLICY: _get_cp_template(),
        DocumentType.PKI_DESIGN: _get_pki_design_template(),
        DocumentType.KEY_MANAGEMENT_PLAN: _get_kmp_template(),
        DocumentType.PKI_OPERATIONAL_PROCESS: _get_ops_template(),
        DocumentType.BUSINESS_CONTINUITY: _get_bc_template(),
    }
    
    return templates.get(document_type, _get_cps_template())


def _get_cps_template() -> Dict[str, Any]:
    """
    Certificate Practice Statement template based on RFC 3647.
    """
    return {
        "name": "Certificate Practice Statement (CPS)",
        "version": "2.0",
        "frameworks": ["RFC3647", "NCSC", "NIST", "WebTrust", "ISO27001"],
        "description": "Assessment template for Certificate Practice Statements following RFC 3647 framework",
        "sections": [
            {
                "id": "introduction",
                "name": "Introduction",
                "aliases": ["Overview", "Purpose and Scope", "General Provisions", "About This Document", "Executive Summary", "Preface", "General Information"],
                "required": True,
                "weight": 5,
                "compliance_refs": ["RFC3647-1"],
                "keywords": ["introduction", "overview", "purpose", "scope", "background"],
                "description": "Document overview, scope, and applicability",
                "elements": [
                    {
                        "id": "document_overview",
                        "name": "Document Overview",
                        "description": "High-level description of the CPS purpose",
                        "keywords": ["overview", "purpose", "document", "cps"],
                        "aliases": ["About this Document", "Document Purpose", "General Overview", "CPS Overview", "Document Description"],
                        "required": True,
                        "weight": 3,
                        "compliance_refs": ["RFC3647-1.1"]
                    },
                    {
                        "id": "document_name_identification",
                        "name": "Document Name and Identification",
                        "description": "Formal identification including OID",
                        "keywords": ["oid", "object identifier", "document name", "identification"],
                        "aliases": ["Document Identification", "OID", "Policy Identifier", "Document ID", "Certificate Policy OID", "CP OID", "CPS OID"],
                        "required": True,
                        "weight": 4,
                        "compliance_refs": ["RFC3647-1.2"]
                    },
                    {
                        "id": "pki_participants",
                        "name": "PKI Participants",
                        "description": "Definition of CA, RA, subscribers, relying parties",
                        "keywords": ["ca", "ra", "subscriber", "relying party", "participants", "registration authority", "certificate authority"],
                        "aliases": ["Participants", "Roles", "PKI Entities", "Community and Applicability", "PKI Community", "Roles and Responsibilities", "Entities", "Stakeholders"],
                        "required": True,
                        "weight": 5,
                        "compliance_refs": ["RFC3647-1.3"]
                    },
                    {
                        "id": "certificate_usage",
                        "name": "Certificate Usage",
                        "description": "Appropriate and prohibited certificate uses",
                        "keywords": ["certificate usage", "appropriate use", "prohibited use", "intended use"],
                        "aliases": ["Appropriate Certificate Uses", "Certificate Applications", "Permitted Uses", "Prohibited Uses", "Usage Restrictions", "Certificate Use Cases", "Applicability"],
                        "required": True,
                        "weight": 4,
                        "compliance_refs": ["RFC3647-1.4"]
                    },
                    {
                        "id": "policy_administration",
                        "name": "Policy Administration",
                        "description": "Organization administering the document, contact details",
                        "keywords": ["policy administration", "contact", "responsible organization", "pma"],
                        "aliases": ["Administration", "Contact Information", "Policy Management", "Document Administration", "Governance", "Policy Authority", "Document Owner", "Contact Details"],
                        "required": True,
                        "weight": 4,
                        "compliance_refs": ["RFC3647-1.5"]
                    }
                ]
            },
            {
                "id": "publication_repository",
                "name": "Publication and Repository Responsibilities",
                "aliases": ["Repository", "Publication", "Repository Services", "Certificate Repository", "Public Information", "Directory Services", "Information Distribution"],
                "required": True,
                "weight": 5,
                "compliance_refs": ["RFC3647-2"],
                "keywords": ["repository", "publication", "availability", "access"],
                "description": "Repository location and publication requirements",
                "elements": [
                    {
                        "id": "repositories",
                        "name": "Repositories",
                        "description": "Location and availability of repositories",
                        "keywords": ["repository", "ldap", "http", "directory", "storage"],
                        "aliases": ["Repository Locations", "Directory", "LDAP", "Public Directory", "Certificate Directory", "Repository Access", "AIA", "CDP"],
                        "required": True,
                        "weight": 4,
                        "compliance_refs": ["RFC3647-2.1"]
                    },
                    {
                        "id": "publication_info",
                        "name": "Publication of Certification Information",
                        "description": "What information is published and where",
                        "keywords": ["publication", "certificates", "crl", "policies", "published"],
                        "aliases": ["Published Information", "Certificate Publication", "Public Information", "Information Published", "Publication of CA Information"],
                        "required": True,
                        "weight": 4,
                        "compliance_refs": ["RFC3647-2.2"]
                    },
                    {
                        "id": "publication_frequency",
                        "name": "Time or Frequency of Publication",
                        "description": "Publication schedules and frequencies",
                        "keywords": ["frequency", "schedule", "timing", "publication interval"],
                        "aliases": ["Publication Schedule", "Publication Frequency", "Update Frequency", "CRL Frequency", "Publication Timing"],
                        "required": True,
                        "weight": 3,
                        "compliance_refs": ["RFC3647-2.3"]
                    },
                    {
                        "id": "access_controls",
                        "name": "Access Controls on Repositories",
                        "description": "Security controls for repository access",
                        "keywords": ["access control", "security", "repository access", "authentication"],
                        "aliases": ["Repository Security", "Repository Access Controls", "Directory Access", "Public Access"],
                        "required": True,
                        "weight": 4,
                        "compliance_refs": ["RFC3647-2.4"]
                    }
                ]
            },
            {
                "id": "identification_authentication",
                "name": "Identification and Authentication",
                "aliases": ["I&A", "Identity Verification", "Identity Management", "Validation", "Vetting", "Identity Proofing", "Authentication Requirements", "Subscriber Authentication"],
                "required": True,
                "weight": 8,
                "compliance_refs": ["RFC3647-3", "NCSC-IA"],
                "keywords": ["identification", "authentication", "identity", "verification", "validation"],
                "description": "Identity proofing and authentication requirements",
                "elements": [
                    {
                        "id": "naming",
                        "name": "Naming",
                        "description": "Name forms and constraints",
                        "keywords": ["naming", "distinguished name", "dn", "subject name", "name constraints"],
                        "aliases": ["Name Requirements", "Distinguished Names", "Subject Names", "Name Forms", "Naming Conventions", "DN Structure"],
                        "required": True,
                        "weight": 5,
                        "compliance_refs": ["RFC3647-3.1"]
                    },
                    {
                        "id": "initial_identity_validation",
                        "name": "Initial Identity Validation",
                        "description": "Requirements for validating identity before certificate issuance",
                        "keywords": ["identity validation", "identity proofing", "vetting", "verification", "initial registration"],
                        "aliases": ["Identity Proofing", "Initial Validation", "Identity Verification", "Subscriber Validation", "Registration", "Enrollment Validation", "Applicant Verification"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["RFC3647-3.2", "NCSC-IA-1"]
                    },
                    {
                        "id": "authentication_rekey",
                        "name": "Identification and Authentication for Re-key Requests",
                        "description": "Re-key authentication requirements",
                        "keywords": ["rekey", "re-key", "renewal", "authentication"],
                        "aliases": ["Re-key Authentication", "Rekey", "Key Renewal", "Certificate Renewal Authentication", "Renewal Validation"],
                        "required": True,
                        "weight": 5,
                        "compliance_refs": ["RFC3647-3.3"]
                    },
                    {
                        "id": "authentication_revocation",
                        "name": "Identification and Authentication for Revocation Request",
                        "description": "Revocation request authentication",
                        "keywords": ["revocation", "authentication", "revocation request"],
                        "aliases": ["Revocation Authentication", "Revocation Request Validation", "Revocation Authorization"],
                        "required": True,
                        "weight": 6,
                        "compliance_refs": ["RFC3647-3.4"]
                    },
                    {
                        "id": "domain_validation",
                        "name": "Domain Validation Methods",
                        "description": "Methods for validating domain control",
                        "keywords": ["domain validation", "dcv", "domain control", "dns validation", "http validation", "email validation"],
                        "aliases": ["DCV", "Domain Control Validation", "DNS Validation", "HTTP Validation", "Email Validation", "Domain Verification", "WHOIS Validation"],
                        "required": False,
                        "weight": 6,
                        "compliance_refs": ["RFC3647-3.2.2", "CABF-BR"]
                    },
                    {
                        "id": "organization_validation",
                        "name": "Organization Validation",
                        "description": "Validation of organization identity",
                        "keywords": ["organization validation", "ov", "business validation", "legal existence", "organization identity"],
                        "aliases": ["OV", "Organization Identity", "Business Validation", "Legal Existence Verification", "Organization Verification", "Business Identity"],
                        "required": False,
                        "weight": 6,
                        "compliance_refs": ["RFC3647-3.2.2", "CABF-BR"]
                    },
                    {
                        "id": "extended_validation",
                        "name": "Extended Validation",
                        "description": "Enhanced validation for EV certificates",
                        "keywords": ["extended validation", "ev", "ev certificate", "enhanced validation", "high assurance"],
                        "aliases": ["EV", "EV Certificates", "Enhanced Validation", "High Assurance Validation", "EV Requirements"],
                        "required": False,
                        "weight": 5,
                        "compliance_refs": ["RFC3647-3.2", "CABF-EV"]
                    },
                    {
                        "id": "proof_possession",
                        "name": "Method to Prove Possession of Private Key",
                        "description": "How subscribers prove they possess the private key",
                        "keywords": ["proof of possession", "pop", "private key proof", "csr signature", "key possession"],
                        "aliases": ["POP", "Proof of Possession", "Key Possession Proof", "CSR Signature Verification", "Private Key Ownership"],
                        "required": True,
                        "weight": 5,
                        "compliance_refs": ["RFC3647-3.2.1"]
                    }
                ]
            },
            {
                "id": "certificate_lifecycle",
                "name": "Certificate Life-Cycle Operational Requirements",
                "aliases": ["Certificate Lifecycle", "Lifecycle Management", "Certificate Operations", "Certificate Management", "Operational Requirements", "Certificate Services"],
                "required": True,
                "weight": 9,
                "compliance_refs": ["RFC3647-4", "NCSC-CLM"],
                "keywords": ["lifecycle", "certificate lifecycle", "issuance", "renewal", "revocation"],
                "description": "Certificate lifecycle from application to expiration",
                "elements": [
                    {
                        "id": "certificate_application",
                        "name": "Certificate Application",
                        "description": "Application process and requirements",
                        "keywords": ["application", "enrollment", "request", "csr", "certificate signing request"],
                        "aliases": ["Enrollment", "Certificate Request", "Application Process", "Certificate Enrollment", "CSR", "Requesting Certificates", "Certificate Application Process"],
                        "required": True,
                        "weight": 6,
                        "compliance_refs": ["RFC3647-4.1"]
                    },
                    {
                        "id": "certificate_application_processing",
                        "name": "Certificate Application Processing",
                        "description": "How applications are processed and approved",
                        "keywords": ["processing", "approval", "validation", "verification"],
                        "aliases": ["Application Processing", "Request Processing", "Certificate Approval", "Processing Procedures", "Application Review"],
                        "required": True,
                        "weight": 6,
                        "compliance_refs": ["RFC3647-4.2"]
                    },
                    {
                        "id": "certificate_issuance",
                        "name": "Certificate Issuance",
                        "description": "Certificate issuance procedures",
                        "keywords": ["issuance", "issue", "generation", "creation", "signing"],
                        "aliases": ["Issuance Procedures", "Issuing Certificates", "Certificate Generation", "Certificate Signing", "Issue Procedures"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["RFC3647-4.3"]
                    },
                    {
                        "id": "certificate_acceptance",
                        "name": "Certificate Acceptance",
                        "description": "Acceptance procedures and requirements",
                        "keywords": ["acceptance", "accept", "subscriber acceptance"],
                        "aliases": ["Acceptance Procedures", "Certificate Delivery", "Subscriber Acceptance", "Acceptance Requirements"],
                        "required": True,
                        "weight": 4,
                        "compliance_refs": ["RFC3647-4.4"]
                    },
                    {
                        "id": "key_pair_usage",
                        "name": "Key Pair and Certificate Usage",
                        "description": "Constraints on key and certificate usage",
                        "keywords": ["key usage", "certificate usage", "constraints", "key pair"],
                        "aliases": ["Usage Constraints", "Key Usage", "Certificate Use", "Permitted Uses", "Usage Requirements"],
                        "required": True,
                        "weight": 5,
                        "compliance_refs": ["RFC3647-4.5"]
                    },
                    {
                        "id": "certificate_renewal",
                        "name": "Certificate Renewal",
                        "description": "Renewal procedures without re-key",
                        "keywords": ["renewal", "renew", "extend", "validity extension"],
                        "aliases": ["Renewal Procedures", "Renewing Certificates", "Certificate Extension", "Validity Extension", "Renewal Process"],
                        "required": True,
                        "weight": 5,
                        "compliance_refs": ["RFC3647-4.6"]
                    },
                    {
                        "id": "certificate_rekey",
                        "name": "Certificate Re-key",
                        "description": "Re-key procedures with new key pair",
                        "keywords": ["rekey", "re-key", "new key", "key replacement"],
                        "aliases": ["Re-key Procedures", "Rekey", "Key Replacement", "New Key Generation", "Key Update"],
                        "required": True,
                        "weight": 5,
                        "compliance_refs": ["RFC3647-4.7"]
                    },
                    {
                        "id": "certificate_modification",
                        "name": "Certificate Modification",
                        "description": "Modification of certificate attributes",
                        "keywords": ["modification", "modify", "change", "update attributes"],
                        "aliases": ["Modification Procedures", "Certificate Changes", "Attribute Modification"],
                        "required": False,
                        "weight": 3,
                        "compliance_refs": ["RFC3647-4.8"]
                    },
                    {
                        "id": "certificate_revocation",
                        "name": "Certificate Revocation and Suspension",
                        "description": "Revocation procedures and CRL/OCSP",
                        "keywords": ["revocation", "revoke", "crl", "ocsp", "suspension", "certificate revocation list"],
                        "aliases": ["Revocation Procedures", "CRL Management", "Certificate Revocation", "Revoking Certificates", "Revocation Process", "OCSP", "Certificate Status"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["RFC3647-4.9", "NCSC-REV"]
                    },
                    {
                        "id": "certificate_status_services",
                        "name": "Certificate Status Services",
                        "description": "OCSP and other status checking services",
                        "keywords": ["ocsp", "status", "certificate status", "online certificate status"],
                        "aliases": ["OCSP", "Status Services", "Online Status", "Validation Services", "Certificate Validation", "Status Checking"],
                        "required": True,
                        "weight": 6,
                        "compliance_refs": ["RFC3647-4.10"]
                    },
                    {
                        "id": "end_of_subscription",
                        "name": "End of Subscription",
                        "description": "Procedures when subscription ends",
                        "keywords": ["end of subscription", "termination", "subscriber termination"],
                        "aliases": ["Subscription Termination", "Subscription End", "End of Service"],
                        "required": False,
                        "weight": 3,
                        "compliance_refs": ["RFC3647-4.11"]
                    },
                    {
                        "id": "key_escrow_recovery",
                        "name": "Key Escrow and Recovery",
                        "description": "Key escrow and recovery procedures if applicable",
                        "keywords": ["escrow", "key escrow", "key recovery", "recovery", "backup"],
                        "aliases": ["Key Recovery", "Escrow", "Key Backup", "Key Archive", "Escrow Services", "Key Archival"],
                        "required": False,
                        "weight": 5,
                        "compliance_refs": ["RFC3647-4.12", "NIST-KR"]
                    }
                ]
            },
            {
                "id": "facility_management",
                "name": "Facility, Management, and Operational Controls",
                "aliases": ["Physical Security", "Operational Controls", "Management Controls", "Security Controls", "Physical and Operational Security", "Facility Controls", "Site Security"],
                "required": True,
                "weight": 8,
                "compliance_refs": ["RFC3647-5", "NCSC-PS", "ISO27001-A.11"],
                "keywords": ["facility", "physical security", "operational", "controls", "security"],
                "description": "Physical, procedural, and personnel security controls",
                "elements": [
                    {
                        "id": "physical_controls",
                        "name": "Physical Controls",
                        "description": "Physical security of CA facilities",
                        "keywords": ["physical security", "facility", "data center", "access control", "physical access"],
                        "aliases": ["Physical Security", "Facility Security", "Site Security", "Data Center Security", "Physical Access Controls", "Building Security", "Premises Security"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["RFC3647-5.1", "ISO27001-A.11"]
                    },
                    {
                        "id": "procedural_controls",
                        "name": "Procedural Controls",
                        "description": "Trusted roles and operational procedures",
                        "keywords": ["procedural", "trusted roles", "separation of duties", "dual control", "m of n"],
                        "aliases": ["Operational Procedures", "Trusted Roles", "Procedural Security", "Dual Control", "Separation of Duties", "Operational Controls", "Role Management"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["RFC3647-5.2", "NCSC-TR"]
                    },
                    {
                        "id": "personnel_controls",
                        "name": "Personnel Controls",
                        "description": "Personnel security requirements",
                        "keywords": ["personnel", "background check", "training", "staff", "employee"],
                        "aliases": ["Personnel Security", "Staff Security", "Employee Security", "Background Checks", "HR Security", "Staff Vetting", "Employee Vetting", "Training Requirements"],
                        "required": True,
                        "weight": 6,
                        "compliance_refs": ["RFC3647-5.3", "ISO27001-A.7"]
                    },
                    {
                        "id": "audit_logging",
                        "name": "Audit Logging Procedures",
                        "description": "Audit log requirements and retention",
                        "keywords": ["audit", "logging", "audit log", "audit trail", "records", "retention"],
                        "aliases": ["Audit Logs", "Logging", "Event Logging", "Security Logging", "Audit Records", "Audit Trail", "Log Management", "Logging Requirements"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["RFC3647-5.4", "NCSC-AL"]
                    },
                    {
                        "id": "records_archival",
                        "name": "Records Archival",
                        "description": "Record retention and archival procedures",
                        "keywords": ["archival", "archive", "retention", "records", "storage"],
                        "aliases": ["Record Retention", "Archiving", "Records Management", "Data Retention", "Archive Procedures", "Record Keeping"],
                        "required": True,
                        "weight": 5,
                        "compliance_refs": ["RFC3647-5.5"]
                    },
                    {
                        "id": "key_changeover",
                        "name": "Key Changeover",
                        "description": "CA key rollover procedures",
                        "keywords": ["key changeover", "key rollover", "ca key", "root key rotation"],
                        "aliases": ["CA Key Rollover", "Key Rotation", "Key Replacement", "CA Key Change", "Root Key Rollover", "Key Transition"],
                        "required": True,
                        "weight": 6,
                        "compliance_refs": ["RFC3647-5.6"]
                    },
                    {
                        "id": "compromise_disaster_recovery",
                        "name": "Compromise and Disaster Recovery",
                        "description": "Incident response and disaster recovery",
                        "keywords": ["compromise", "disaster recovery", "incident", "business continuity", "dr"],
                        "aliases": ["Disaster Recovery", "Incident Response", "Key Compromise", "Compromise Recovery", "DR", "Business Continuity", "Contingency", "Emergency Procedures"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["RFC3647-5.7", "ISO27001-A.17"]
                    },
                    {
                        "id": "ca_termination",
                        "name": "CA or RA Termination",
                        "description": "Procedures for CA/RA shutdown",
                        "keywords": ["termination", "shutdown", "ca termination", "end of operations"],
                        "aliases": ["CA Shutdown", "End of Operations", "CA Decommissioning", "Cessation", "CA Wind Down", "RA Termination"],
                        "required": True,
                        "weight": 5,
                        "compliance_refs": ["RFC3647-5.8"]
                    }
                ]
            },
            {
                "id": "technical_security",
                "name": "Technical Security Controls",
                "aliases": ["Technical Controls", "Cryptographic Controls", "Security Controls", "Technical Requirements", "Cryptographic Security", "System Security Controls"],
                "required": True,
                "weight": 9,
                "compliance_refs": ["RFC3647-6", "NCSC-TS", "NIST-800-57"],
                "keywords": ["technical", "cryptographic", "hsm", "key generation", "security controls"],
                "description": "Technical and cryptographic security controls",
                "elements": [
                    {
                        "id": "key_pair_generation",
                        "name": "Key Pair Generation and Installation",
                        "description": "CA and subscriber key generation",
                        "keywords": ["key generation", "key pair", "hsm", "hardware security module", "fips 140"],
                        "aliases": ["Key Generation", "Cryptographic Key Generation", "Key Creation", "HSM Key Generation", "CA Key Generation", "Subscriber Key Generation", "Key Pair Creation"],
                        "required": True,
                        "weight": 9,
                        "compliance_refs": ["RFC3647-6.1", "NIST-800-57"]
                    },
                    {
                        "id": "private_key_protection",
                        "name": "Private Key Protection and Cryptographic Module Engineering Controls",
                        "description": "HSM and key protection requirements",
                        "keywords": ["private key", "key protection", "hsm", "cryptographic module", "fips"],
                        "aliases": ["Key Protection", "HSM Requirements", "Private Key Security", "Cryptographic Module", "HSM Security", "Key Safeguarding", "FIPS 140"],
                        "required": True,
                        "weight": 9,
                        "compliance_refs": ["RFC3647-6.2", "NCSC-KP"]
                    },
                    {
                        "id": "other_key_management",
                        "name": "Other Aspects of Key Pair Management",
                        "description": "Key archival, backup, activation",
                        "keywords": ["key backup", "key archival", "key activation", "key destruction"],
                        "aliases": ["Key Management", "Key Backup", "Key Archival", "Key Destruction", "Key Lifecycle", "Key Storage"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["RFC3647-6.3"]
                    },
                    {
                        "id": "activation_data",
                        "name": "Activation Data",
                        "description": "PINs, passwords, and activation mechanisms",
                        "keywords": ["activation", "pin", "password", "passphrase", "operator card"],
                        "aliases": ["Activation Mechanisms", "PIN Management", "Activation Credentials", "Operator Cards", "Smart Cards", "Authentication Data"],
                        "required": True,
                        "weight": 6,
                        "compliance_refs": ["RFC3647-6.4"]
                    },
                    {
                        "id": "computer_security",
                        "name": "Computer Security Controls",
                        "description": "System security and network controls",
                        "keywords": ["computer security", "system security", "network security", "firewall", "access control"],
                        "aliases": ["System Security", "Network Security", "IT Security", "Computer Controls", "System Controls", "Server Security"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["RFC3647-6.5", "ISO27001-A.13"]
                    },
                    {
                        "id": "lifecycle_security",
                        "name": "Life Cycle Technical Controls",
                        "description": "System development and maintenance security",
                        "keywords": ["lifecycle", "development", "maintenance", "change management", "patching"],
                        "aliases": ["Development Security", "Maintenance", "Change Management", "System Development", "SDLC", "Patch Management", "Configuration Management"],
                        "required": True,
                        "weight": 5,
                        "compliance_refs": ["RFC3647-6.6"]
                    },
                    {
                        "id": "network_security",
                        "name": "Network Security Controls",
                        "description": "Network isolation and protection",
                        "keywords": ["network", "firewall", "segmentation", "isolation", "dmz"],
                        "aliases": ["Network Controls", "Firewall", "Network Segmentation", "Network Isolation", "DMZ", "Network Architecture", "Network Protection"],
                        "required": True,
                        "weight": 6,
                        "compliance_refs": ["RFC3647-6.7"]
                    },
                    {
                        "id": "time_stamping",
                        "name": "Time-stamping",
                        "description": "Time synchronization requirements",
                        "keywords": ["time", "timestamp", "ntp", "time synchronization", "time source"],
                        "aliases": ["Time Synchronization", "NTP", "Time Source", "Timestamping", "Time Services", "Clock Synchronization"],
                        "required": True,
                        "weight": 5,
                        "compliance_refs": ["RFC3647-6.8"]
                    },
                    {
                        "id": "algorithm_requirements",
                        "name": "Cryptographic Algorithm Requirements",
                        "description": "Approved algorithms and key sizes",
                        "keywords": ["algorithm", "rsa", "ecdsa", "sha", "key size", "key length", "cryptographic algorithm"],
                        "aliases": ["Approved Algorithms", "Algorithm Policy", "Key Sizes", "Cryptographic Standards", "Algorithm Suites", "Signature Algorithms", "Hash Algorithms"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["RFC3647-6.1.5", "NIST-800-57"]
                    },
                    {
                        "id": "hsm_requirements",
                        "name": "HSM and Cryptographic Module Requirements",
                        "description": "Hardware security module specifications and certification",
                        "keywords": ["hsm", "hardware security module", "fips 140-2", "fips 140-3", "common criteria", "cryptographic module"],
                        "aliases": ["Hardware Security Module", "FIPS 140-2", "FIPS 140-3", "Common Criteria", "Cryptographic Module Validation", "HSM Certification", "FIPS Validation"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["RFC3647-6.2.1", "NCSC-HSM"]
                    },
                    {
                        "id": "key_ceremony",
                        "name": "Key Ceremony Procedures",
                        "description": "CA key generation ceremony requirements",
                        "keywords": ["key ceremony", "root ceremony", "key generation ceremony", "ca key ceremony", "signing ceremony"],
                        "aliases": ["Root Key Ceremony", "CA Key Ceremony", "Key Generation Ceremony", "Ceremony Procedures", "Root Ceremony", "Signing Ceremony"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["RFC3647-6.1.1", "WebTrust-KG"]
                    },
                    {
                        "id": "pqc_readiness",
                        "name": "Post-Quantum Cryptography Readiness",
                        "description": "Preparation for quantum-resistant algorithms",
                        "keywords": ["post-quantum", "pqc", "quantum resistant", "quantum safe", "cnsa 2.0", "ml-kem", "ml-dsa"],
                        "aliases": ["Post-Quantum", "Quantum Resistant", "Quantum Safe", "CNSA 2.0", "PQC Migration", "Quantum Readiness", "Hybrid Certificates"],
                        "required": False,
                        "weight": 4,
                        "compliance_refs": ["NIST-PQC", "CNSA-2.0"]
                    }
                ]
            },
            {
                "id": "certificate_profiles",
                "name": "Certificate, CRL, and OCSP Profiles",
                "aliases": ["Certificate Profiles", "Profiles", "Certificate Format", "Certificate Structure", "X.509 Profiles", "CRL Profiles", "Certificate Extensions"],
                "required": True,
                "weight": 7,
                "compliance_refs": ["RFC3647-7", "RFC5280"],
                "keywords": ["profile", "certificate profile", "crl profile", "ocsp", "extensions"],
                "description": "Certificate and revocation information profiles",
                "elements": [
                    {
                        "id": "certificate_profile",
                        "name": "Certificate Profile",
                        "description": "Certificate format and extensions",
                        "keywords": ["certificate profile", "x.509", "extensions", "key usage", "basic constraints"],
                        "aliases": ["X.509 Profile", "Certificate Format", "Certificate Structure", "Certificate Contents", "Certificate Fields", "Certificate Extensions", "Certificate Template"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["RFC3647-7.1", "RFC5280"]
                    },
                    {
                        "id": "crl_profile",
                        "name": "CRL Profile",
                        "description": "CRL format and extensions",
                        "keywords": ["crl", "crl profile", "revocation list", "crl extensions"],
                        "aliases": ["CRL Format", "Certificate Revocation List", "CRL Structure", "CRL Extensions", "CRL Contents"],
                        "required": True,
                        "weight": 6,
                        "compliance_refs": ["RFC3647-7.2"]
                    },
                    {
                        "id": "ocsp_profile",
                        "name": "OCSP Profile",
                        "description": "OCSP response format",
                        "keywords": ["ocsp", "ocsp profile", "ocsp response", "online status"],
                        "aliases": ["OCSP Format", "OCSP Response", "Online Certificate Status", "OCSP Structure", "OCSP Contents"],
                        "required": True,
                        "weight": 6,
                        "compliance_refs": ["RFC3647-7.3"]
                    }
                ]
            },
            {
                "id": "compliance_audit",
                "name": "Compliance Audit and Other Assessments",
                "aliases": ["Audit", "Compliance", "Assessments", "Compliance Requirements", "Audit Requirements", "WebTrust", "ETSI", "Certification", "Attestation"],
                "required": True,
                "weight": 7,
                "compliance_refs": ["RFC3647-8", "WebTrust"],
                "keywords": ["compliance", "audit", "assessment", "webtrust", "etsi"],
                "description": "Audit and compliance requirements",
                "elements": [
                    {
                        "id": "audit_frequency",
                        "name": "Frequency or Circumstances of Assessment",
                        "description": "When audits are performed",
                        "keywords": ["audit frequency", "annual", "assessment schedule"],
                        "aliases": ["Audit Schedule", "Assessment Frequency", "Audit Frequency", "Audit Cycle", "Assessment Schedule"],
                        "required": True,
                        "weight": 5,
                        "compliance_refs": ["RFC3647-8.1"]
                    },
                    {
                        "id": "auditor_qualifications",
                        "name": "Identity/Qualifications of Assessor",
                        "description": "Auditor requirements",
                        "keywords": ["auditor", "assessor", "qualifications", "cpa", "webtrust"],
                        "aliases": ["Auditor Requirements", "Assessor Qualifications", "Auditor Qualifications", "Audit Firm", "External Auditor"],
                        "required": True,
                        "weight": 5,
                        "compliance_refs": ["RFC3647-8.2"]
                    },
                    {
                        "id": "audit_topics",
                        "name": "Topics Covered by Assessment",
                        "description": "Scope of audit coverage",
                        "keywords": ["audit scope", "topics", "coverage", "audit criteria"],
                        "aliases": ["Audit Scope", "Assessment Scope", "Audit Coverage", "Assessment Topics", "Audit Criteria"],
                        "required": True,
                        "weight": 5,
                        "compliance_refs": ["RFC3647-8.4"]
                    },
                    {
                        "id": "audit_deficiencies",
                        "name": "Actions Taken as a Result of Deficiency",
                        "description": "Remediation of audit findings",
                        "keywords": ["deficiency", "remediation", "corrective action", "finding"],
                        "aliases": ["Audit Remediation", "Audit Findings", "Corrective Actions", "Deficiency Remediation", "Non-conformities", "Remediation Actions"],
                        "required": True,
                        "weight": 5,
                        "compliance_refs": ["RFC3647-8.5"]
                    }
                ]
            },
            {
                "id": "legal_provisions",
                "name": "Other Business and Legal Matters",
                "aliases": ["Legal", "Business Matters", "Legal Matters", "Legal Provisions", "Terms and Conditions", "Legal Requirements", "Business and Legal"],
                "required": True,
                "weight": 6,
                "compliance_refs": ["RFC3647-9"],
                "keywords": ["legal", "liability", "warranty", "indemnification", "fees"],
                "description": "Legal, financial, and business provisions",
                "elements": [
                    {
                        "id": "fees",
                        "name": "Fees",
                        "description": "Certificate and service fees",
                        "keywords": ["fees", "pricing", "cost", "charges"],
                        "aliases": ["Pricing", "Costs", "Service Fees", "Certificate Fees", "Charges"],
                        "required": False,
                        "weight": 2,
                        "compliance_refs": ["RFC3647-9.1"]
                    },
                    {
                        "id": "liability",
                        "name": "Liability",
                        "description": "Liability limitations and warranties",
                        "keywords": ["liability", "warranty", "warranties", "limitation"],
                        "aliases": ["Warranties", "Liability Limitations", "Limited Liability", "Warranty Disclaimer", "Limitation of Liability"],
                        "required": True,
                        "weight": 5,
                        "compliance_refs": ["RFC3647-9.6"]
                    },
                    {
                        "id": "indemnification",
                        "name": "Indemnification",
                        "description": "Indemnification provisions",
                        "keywords": ["indemnification", "indemnify", "hold harmless"],
                        "aliases": ["Hold Harmless", "Indemnity", "Indemnification Provisions", "Subscriber Indemnification"],
                        "required": True,
                        "weight": 4,
                        "compliance_refs": ["RFC3647-9.7"]
                    },
                    {
                        "id": "governing_law",
                        "name": "Governing Law",
                        "description": "Applicable jurisdiction and law",
                        "keywords": ["governing law", "jurisdiction", "applicable law", "legal framework"],
                        "aliases": ["Jurisdiction", "Applicable Law", "Legal Jurisdiction", "Choice of Law", "Venue"],
                        "required": True,
                        "weight": 4,
                        "compliance_refs": ["RFC3647-9.13"]
                    },
                    {
                        "id": "dispute_resolution",
                        "name": "Dispute Resolution Procedures",
                        "description": "How disputes are resolved",
                        "keywords": ["dispute", "resolution", "arbitration", "mediation"],
                        "aliases": ["Dispute Resolution", "Arbitration", "Mediation", "Conflict Resolution", "Dispute Settlement"],
                        "required": True,
                        "weight": 3,
                        "compliance_refs": ["RFC3647-9.14"]
                    },
                    {
                        "id": "financial_responsibility",
                        "name": "Financial Responsibility",
                        "description": "Insurance and financial capability requirements",
                        "keywords": ["insurance", "financial", "assets", "bonding", "coverage"],
                        "aliases": ["Insurance Requirements", "Financial Capability", "Assets", "Bonding", "Financial Assurance", "Insurance Coverage"],
                        "required": False,
                        "weight": 3,
                        "compliance_refs": ["RFC3647-9.2"]
                    },
                    {
                        "id": "confidentiality_business",
                        "name": "Confidentiality of Business Information",
                        "description": "Protection of business confidential information",
                        "keywords": ["confidentiality", "business information", "confidential", "proprietary", "trade secret"],
                        "aliases": ["Business Confidentiality", "Confidential Information", "Proprietary Information", "Trade Secrets", "Non-disclosure"],
                        "required": True,
                        "weight": 4,
                        "compliance_refs": ["RFC3647-9.3"]
                    },
                    {
                        "id": "privacy_personal_information",
                        "name": "Privacy of Personal Information",
                        "description": "Privacy protection and data handling",
                        "keywords": ["privacy", "personal information", "pii", "data protection", "gdpr"],
                        "aliases": ["Privacy Policy", "Personal Data", "Data Privacy", "PII Protection", "GDPR Compliance", "Data Protection", "Privacy Notice"],
                        "required": True,
                        "weight": 5,
                        "compliance_refs": ["RFC3647-9.4"]
                    },
                    {
                        "id": "intellectual_property",
                        "name": "Intellectual Property Rights",
                        "description": "IP rights and ownership",
                        "keywords": ["intellectual property", "ip rights", "copyright", "trademark", "ownership"],
                        "aliases": ["IP Rights", "Copyright", "Trademark", "Ownership Rights", "Property Rights"],
                        "required": False,
                        "weight": 2,
                        "compliance_refs": ["RFC3647-9.5"]
                    },
                    {
                        "id": "representations_warranties",
                        "name": "Representations and Warranties",
                        "description": "CA, RA, subscriber and relying party warranties",
                        "keywords": ["representations", "warranties", "ca warranty", "subscriber warranty", "relying party"],
                        "aliases": ["CA Warranties", "Subscriber Warranties", "Relying Party Warranties", "RA Warranties", "Certificate Warranties", "Warranty Statements"],
                        "required": True,
                        "weight": 5,
                        "compliance_refs": ["RFC3647-9.6"]
                    },
                    {
                        "id": "term_termination",
                        "name": "Term and Termination",
                        "description": "Agreement duration and termination provisions",
                        "keywords": ["term", "termination", "duration", "effective date", "expiration"],
                        "aliases": ["Agreement Term", "Termination Provisions", "Contract Duration", "Effective Period"],
                        "required": False,
                        "weight": 2,
                        "compliance_refs": ["RFC3647-9.10"]
                    },
                    {
                        "id": "amendments",
                        "name": "Amendments",
                        "description": "Document amendment procedures",
                        "keywords": ["amendments", "modifications", "changes", "revisions", "updates"],
                        "aliases": ["Document Amendments", "Policy Changes", "CPS Amendments", "Modification Procedures", "Revision Process"],
                        "required": True,
                        "weight": 3,
                        "compliance_refs": ["RFC3647-9.12"]
                    },
                    {
                        "id": "compliance_applicable_law",
                        "name": "Compliance with Applicable Law",
                        "description": "Legal and regulatory compliance requirements",
                        "keywords": ["compliance", "applicable law", "regulatory", "legal requirements", "statutory"],
                        "aliases": ["Legal Compliance", "Regulatory Compliance", "Statutory Requirements", "Legal Obligations"],
                        "required": True,
                        "weight": 4,
                        "compliance_refs": ["RFC3647-9.15"]
                    }
                ]
            }
        ]
    }


def _get_cp_template() -> Dict[str, Any]:
    """
    Certificate Policy template - focuses on policy requirements vs practices.
    """
    # CP template is similar to CPS but with different emphasis
    cps_template = _get_cps_template()
    cps_template["name"] = "Certificate Policy (CP)"
    cps_template["description"] = "Assessment template for Certificate Policies following RFC 3647 framework"
    
    # Add CP-specific elements
    for section in cps_template["sections"]:
        if section["id"] == "introduction":
            section["elements"].append({
                "id": "policy_qualifiers",
                "name": "Policy Qualifiers",
                "description": "Certificate policy qualifiers and user notices",
                "keywords": ["policy qualifier", "user notice", "cps pointer", "qualifier"],
                "aliases": ["Qualifiers"],
                "required": True,
                "weight": 5,
                "compliance_refs": ["RFC3647-1.2", "RFC5280"]
            })
    
    return cps_template


def _get_pki_design_template() -> Dict[str, Any]:
    """
    PKI Design Document template.
    """
    return {
        "name": "PKI Design Document",
        "version": "2.0",
        "frameworks": ["NCSC", "NIST", "ISO27001"],
        "description": "Assessment template for PKI technical design documents",
        "sections": [
            {
                "id": "executive_summary",
                "name": "Executive Summary",
                "aliases": ["Overview", "Summary"],
                "required": True,
                "weight": 4,
                "compliance_refs": ["NCSC-PKI-1"],
                "keywords": ["executive summary", "overview", "summary", "introduction"],
                "description": "High-level summary of the PKI design",
                "elements": [
                    {
                        "id": "design_objectives",
                        "name": "Design Objectives",
                        "description": "Goals and objectives of the PKI",
                        "keywords": ["objectives", "goals", "requirements", "purpose"],
                        "aliases": ["Goals", "Requirements"],
                        "required": True,
                        "weight": 5,
                        "compliance_refs": ["NCSC-PKI-1.1"]
                    },
                    {
                        "id": "scope_boundaries",
                        "name": "Scope and Boundaries",
                        "description": "What is in and out of scope",
                        "keywords": ["scope", "boundaries", "in scope", "out of scope"],
                        "aliases": ["Scope"],
                        "required": True,
                        "weight": 4,
                        "compliance_refs": ["NCSC-PKI-1.2"]
                    }
                ]
            },
            {
                "id": "trust_model",
                "name": "Trust Model",
                "aliases": ["Trust Architecture", "CA Hierarchy"],
                "required": True,
                "weight": 9,
                "compliance_refs": ["NCSC-TM", "NIST-TM"],
                "keywords": ["trust model", "trust", "hierarchy", "root ca", "subordinate"],
                "description": "PKI trust model and CA hierarchy design",
                "elements": [
                    {
                        "id": "ca_hierarchy",
                        "name": "CA Hierarchy",
                        "description": "Structure of the CA hierarchy",
                        "keywords": ["hierarchy", "root ca", "issuing ca", "subordinate ca", "intermediate"],
                        "aliases": ["CA Structure", "Hierarchy Design"],
                        "required": True,
                        "weight": 9,
                        "compliance_refs": ["NCSC-TM-1"]
                    },
                    {
                        "id": "trust_anchor",
                        "name": "Trust Anchor Management",
                        "description": "Root CA trust anchor handling",
                        "keywords": ["trust anchor", "root", "trust store", "root certificate"],
                        "aliases": ["Root CA", "Trust Anchors"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["NCSC-TM-2"]
                    },
                    {
                        "id": "cross_certification",
                        "name": "Cross-Certification",
                        "description": "Cross-certification with external PKIs",
                        "keywords": ["cross certification", "bridge", "external trust", "federation"],
                        "aliases": ["Bridge CA", "Federation"],
                        "required": False,
                        "weight": 5,
                        "compliance_refs": ["NCSC-TM-3"]
                    }
                ]
            },
            {
                "id": "architecture",
                "name": "Technical Architecture",
                "aliases": ["System Architecture", "Infrastructure"],
                "required": True,
                "weight": 9,
                "compliance_refs": ["NCSC-ARCH", "ISO27001-A.13"],
                "keywords": ["architecture", "infrastructure", "system", "network", "topology"],
                "description": "Technical infrastructure and architecture",
                "elements": [
                    {
                        "id": "network_architecture",
                        "name": "Network Architecture",
                        "description": "Network design and segmentation",
                        "keywords": ["network", "segmentation", "dmz", "firewall", "zone"],
                        "aliases": ["Network Design", "Network Topology"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["NCSC-ARCH-1", "ISO27001-A.13"]
                    },
                    {
                        "id": "hsm_design",
                        "name": "HSM Architecture",
                        "description": "Hardware Security Module design",
                        "keywords": ["hsm", "hardware security module", "cryptographic module", "luna", "ncipher"],
                        "aliases": ["HSM Design", "Cryptographic Hardware"],
                        "required": True,
                        "weight": 9,
                        "compliance_refs": ["NCSC-HSM", "NIST-800-57"]
                    },
                    {
                        "id": "ca_servers",
                        "name": "CA Server Design",
                        "description": "CA server specifications",
                        "keywords": ["server", "ca server", "specifications", "hardware", "operating system"],
                        "aliases": ["Server Specifications"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["NCSC-ARCH-2"]
                    },
                    {
                        "id": "database_design",
                        "name": "Database Design",
                        "description": "Certificate database architecture",
                        "keywords": ["database", "storage", "repository", "certificate store"],
                        "aliases": ["Data Storage"],
                        "required": True,
                        "weight": 6,
                        "compliance_refs": ["NCSC-ARCH-3"]
                    },
                    {
                        "id": "high_availability",
                        "name": "High Availability Design",
                        "description": "HA and redundancy design",
                        "keywords": ["high availability", "ha", "redundancy", "failover", "clustering"],
                        "aliases": ["HA Design", "Redundancy"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["NCSC-HA"]
                    }
                ]
            },
            {
                "id": "cryptographic_design",
                "name": "Cryptographic Design",
                "aliases": ["Crypto Design", "Algorithm Selection"],
                "required": True,
                "weight": 9,
                "compliance_refs": ["NCSC-CRYPTO", "NIST-800-57"],
                "keywords": ["cryptographic", "algorithm", "key size", "rsa", "ecc", "sha"],
                "description": "Cryptographic algorithm and key specifications",
                "elements": [
                    {
                        "id": "algorithm_selection",
                        "name": "Algorithm Selection",
                        "description": "Choice of cryptographic algorithms",
                        "keywords": ["algorithm", "rsa", "ecdsa", "sha-256", "sha-384", "signature"],
                        "aliases": ["Algorithms", "Crypto Algorithms"],
                        "required": True,
                        "weight": 9,
                        "compliance_refs": ["NCSC-CRYPTO-1", "NIST-800-57"]
                    },
                    {
                        "id": "key_sizes",
                        "name": "Key Sizes",
                        "description": "Key length specifications",
                        "keywords": ["key size", "key length", "2048", "4096", "256-bit", "384-bit"],
                        "aliases": ["Key Lengths"],
                        "required": True,
                        "weight": 9,
                        "compliance_refs": ["NCSC-CRYPTO-2", "NIST-800-57"]
                    },
                    {
                        "id": "validity_periods",
                        "name": "Validity Periods",
                        "description": "Certificate and key validity periods",
                        "keywords": ["validity", "lifetime", "expiration", "period", "years"],
                        "aliases": ["Certificate Lifetime"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["NCSC-CRYPTO-3"]
                    },
                    {
                        "id": "pqc_readiness",
                        "name": "Post-Quantum Cryptography Readiness",
                        "description": "PQC migration planning",
                        "keywords": ["post-quantum", "pqc", "quantum", "quantum-safe", "hybrid", "ml-kem", "ml-dsa"],
                        "aliases": ["Quantum Readiness", "PQC"],
                        "required": False,
                        "weight": 6,
                        "compliance_refs": ["NCSC-PQC", "NIST-PQC"]
                    }
                ]
            },
            {
                "id": "certificate_profiles",
                "name": "Certificate Profile Design",
                "aliases": ["Certificate Templates", "Profiles"],
                "required": True,
                "weight": 8,
                "compliance_refs": ["RFC5280", "NCSC-PROF"],
                "keywords": ["certificate profile", "template", "extensions", "key usage"],
                "description": "Certificate profile specifications",
                "elements": [
                    {
                        "id": "root_ca_profile",
                        "name": "Root CA Certificate Profile",
                        "description": "Root CA certificate specification",
                        "keywords": ["root ca", "root certificate", "self-signed", "ca:true"],
                        "aliases": ["Root Certificate"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["RFC5280", "NCSC-PROF-1"]
                    },
                    {
                        "id": "issuing_ca_profile",
                        "name": "Issuing CA Certificate Profile",
                        "description": "Subordinate CA certificate specification",
                        "keywords": ["issuing ca", "subordinate ca", "intermediate", "path length"],
                        "aliases": ["Subordinate CA Certificate"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["RFC5280", "NCSC-PROF-2"]
                    },
                    {
                        "id": "end_entity_profiles",
                        "name": "End Entity Certificate Profiles",
                        "description": "End entity certificate specifications",
                        "keywords": ["end entity", "user certificate", "server certificate", "client certificate"],
                        "aliases": ["User Certificates", "Server Certificates"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["RFC5280", "NCSC-PROF-3"]
                    }
                ]
            },
            {
                "id": "integration",
                "name": "Integration Design",
                "aliases": ["Interfaces", "API Design"],
                "required": True,
                "weight": 6,
                "compliance_refs": ["NCSC-INT"],
                "keywords": ["integration", "api", "interface", "protocol", "scep", "est", "cmp"],
                "description": "Integration with external systems",
                "elements": [
                    {
                        "id": "enrollment_protocols",
                        "name": "Enrollment Protocols",
                        "description": "Certificate enrollment protocols",
                        "keywords": ["enrollment", "scep", "est", "cmp", "acme", "protocol"],
                        "aliases": ["Enrollment Methods"],
                        "required": True,
                        "weight": 6,
                        "compliance_refs": ["NCSC-INT-1"]
                    },
                    {
                        "id": "directory_integration",
                        "name": "Directory Integration",
                        "description": "LDAP/AD integration",
                        "keywords": ["ldap", "active directory", "directory", "ad"],
                        "aliases": ["LDAP Integration"],
                        "required": False,
                        "weight": 5,
                        "compliance_refs": ["NCSC-INT-2"]
                    },
                    {
                        "id": "revocation_services",
                        "name": "Revocation Services",
                        "description": "CRL and OCSP service design",
                        "keywords": ["crl", "ocsp", "revocation", "cdp", "aia"],
                        "aliases": ["CRL/OCSP Design"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["NCSC-INT-3"]
                    }
                ]
            }
        ]
    }


def _get_kmp_template() -> Dict[str, Any]:
    """
    Key Management Plan template based on NIST SP 800-57 and NCSC guidance.
    """
    return {
        "name": "Key Management Plan",
        "version": "2.0",
        "frameworks": ["NIST-800-57", "NIST-800-130", "NCSC", "ISO27001", "PCI-DSS"],
        "description": "Assessment template for Key Management Plans",
        "sections": [
            {
                "id": "introduction",
                "name": "Introduction and Scope",
                "aliases": ["Overview", "Purpose"],
                "required": True,
                "weight": 4,
                "compliance_refs": ["NIST-800-57"],
                "keywords": ["introduction", "scope", "purpose", "objectives"],
                "description": "Document scope and objectives",
                "elements": [
                    {
                        "id": "kmp_scope",
                        "name": "Scope of Key Management",
                        "description": "What keys are covered by this plan",
                        "keywords": ["scope", "covered keys", "key types", "cryptographic keys"],
                        "aliases": ["Key Scope"],
                        "required": True,
                        "weight": 5,
                        "compliance_refs": ["NIST-800-57-5"]
                    },
                    {
                        "id": "roles_responsibilities",
                        "name": "Roles and Responsibilities",
                        "description": "Key management roles",
                        "keywords": ["roles", "responsibilities", "key custodian", "crypto officer", "security officer"],
                        "aliases": ["Key Management Roles"],
                        "required": True,
                        "weight": 6,
                        "compliance_refs": ["NIST-800-57-5.1", "PCI-DSS-3.5"]
                    }
                ]
            },
            {
                "id": "key_generation",
                "name": "Key Generation",
                "aliases": ["Key Creation", "Key Production"],
                "required": True,
                "weight": 9,
                "compliance_refs": ["NIST-800-57-8.1", "NCSC-KG"],
                "keywords": ["key generation", "generation", "creation", "random", "entropy"],
                "description": "Key generation procedures and requirements",
                "elements": [
                    {
                        "id": "generation_methods",
                        "name": "Generation Methods",
                        "description": "How keys are generated",
                        "keywords": ["generation method", "random number", "rng", "drbg", "entropy source"],
                        "aliases": ["Key Creation Methods"],
                        "required": True,
                        "weight": 9,
                        "compliance_refs": ["NIST-800-57-8.1.1"]
                    },
                    {
                        "id": "key_ceremony",
                        "name": "Key Ceremony Procedures",
                        "description": "Formal key generation ceremonies",
                        "keywords": ["key ceremony", "ceremony", "root key", "ca key generation", "witnessed"],
                        "aliases": ["Ceremony Procedures"],
                        "required": True,
                        "weight": 9,
                        "compliance_refs": ["NCSC-KC", "WebTrust-KC"]
                    },
                    {
                        "id": "hsm_requirements",
                        "name": "HSM Requirements",
                        "description": "Hardware security module requirements",
                        "keywords": ["hsm", "hardware security module", "fips 140", "common criteria", "cryptographic module"],
                        "aliases": ["Cryptographic Module Requirements"],
                        "required": True,
                        "weight": 9,
                        "compliance_refs": ["NIST-800-57-8.1.2", "FIPS-140-3"]
                    }
                ]
            },
            {
                "id": "key_distribution",
                "name": "Key Distribution",
                "aliases": ["Key Transport", "Key Exchange"],
                "required": True,
                "weight": 8,
                "compliance_refs": ["NIST-800-57-8.2"],
                "keywords": ["distribution", "transport", "exchange", "transmission"],
                "description": "Secure key distribution methods",
                "elements": [
                    {
                        "id": "distribution_methods",
                        "name": "Distribution Methods",
                        "description": "How keys are distributed",
                        "keywords": ["distribution", "key transport", "key wrapping", "key agreement"],
                        "aliases": ["Transport Methods"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["NIST-800-57-8.2.1"]
                    },
                    {
                        "id": "key_injection",
                        "name": "Key Injection Procedures",
                        "description": "Loading keys into systems",
                        "keywords": ["injection", "key loading", "key import", "pkcs#11"],
                        "aliases": ["Key Loading"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["NIST-800-57-8.2.2"]
                    }
                ]
            },
            {
                "id": "key_storage",
                "name": "Key Storage",
                "aliases": ["Key Protection", "Key Safeguarding"],
                "required": True,
                "weight": 9,
                "compliance_refs": ["NIST-800-57-8.3", "PCI-DSS-3.5"],
                "keywords": ["storage", "protection", "safeguarding", "secure storage"],
                "description": "Secure key storage requirements",
                "elements": [
                    {
                        "id": "storage_mechanisms",
                        "name": "Storage Mechanisms",
                        "description": "Where and how keys are stored",
                        "keywords": ["storage", "hsm", "secure storage", "encrypted storage"],
                        "aliases": ["Storage Methods"],
                        "required": True,
                        "weight": 9,
                        "compliance_refs": ["NIST-800-57-8.3.1", "PCI-DSS-3.5.2"]
                    },
                    {
                        "id": "access_controls",
                        "name": "Key Access Controls",
                        "description": "Who can access keys and how",
                        "keywords": ["access control", "authorization", "authentication", "m of n", "dual control"],
                        "aliases": ["Access Management"],
                        "required": True,
                        "weight": 9,
                        "compliance_refs": ["NIST-800-57-8.3.2", "PCI-DSS-3.5.3"]
                    },
                    {
                        "id": "key_encryption",
                        "name": "Key Encryption Keys",
                        "description": "KEK hierarchy and management",
                        "keywords": ["kek", "key encryption key", "master key", "key wrapping"],
                        "aliases": ["KEK Management"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["NIST-800-57-8.3.3", "PCI-DSS-3.5.3"]
                    }
                ]
            },
            {
                "id": "key_usage",
                "name": "Key Usage",
                "aliases": ["Key Utilization", "Cryptoperiod"],
                "required": True,
                "weight": 8,
                "compliance_refs": ["NIST-800-57-5.3"],
                "keywords": ["usage", "cryptoperiod", "key usage", "operational"],
                "description": "Key usage constraints and cryptoperiods",
                "elements": [
                    {
                        "id": "cryptoperiods",
                        "name": "Cryptoperiods",
                        "description": "Key validity periods",
                        "keywords": ["cryptoperiod", "validity", "lifetime", "expiration"],
                        "aliases": ["Key Lifetimes"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["NIST-800-57-5.3"]
                    },
                    {
                        "id": "usage_constraints",
                        "name": "Usage Constraints",
                        "description": "Restrictions on key usage",
                        "keywords": ["constraints", "restrictions", "permitted use", "key purpose"],
                        "aliases": ["Key Restrictions"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["NIST-800-57-5.2"]
                    }
                ]
            },
            {
                "id": "key_backup_recovery",
                "name": "Key Backup and Recovery",
                "aliases": ["Key Escrow", "Key Recovery"],
                "required": True,
                "weight": 9,
                "compliance_refs": ["NIST-800-57-8.4", "PCI-DSS-3.6"],
                "keywords": ["backup", "recovery", "escrow", "restoration"],
                "description": "Key backup and recovery procedures",
                "elements": [
                    {
                        "id": "backup_procedures",
                        "name": "Backup Procedures",
                        "description": "How keys are backed up",
                        "keywords": ["backup", "key backup", "secure backup", "offline backup"],
                        "aliases": ["Key Backup"],
                        "required": True,
                        "weight": 9,
                        "compliance_refs": ["NIST-800-57-8.4.1", "PCI-DSS-3.6.1"]
                    },
                    {
                        "id": "recovery_procedures",
                        "name": "Recovery Procedures",
                        "description": "How keys are recovered",
                        "keywords": ["recovery", "restoration", "key recovery", "emergency access"],
                        "aliases": ["Key Recovery"],
                        "required": True,
                        "weight": 9,
                        "compliance_refs": ["NIST-800-57-8.4.2"]
                    },
                    {
                        "id": "split_knowledge",
                        "name": "Split Knowledge and Dual Control",
                        "description": "M of N and split knowledge requirements",
                        "keywords": ["split knowledge", "m of n", "dual control", "secret sharing", "custodian"],
                        "aliases": ["M of N Control"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["NIST-800-57-8.4.3", "PCI-DSS-3.6.6"]
                    }
                ]
            },
            {
                "id": "key_rotation",
                "name": "Key Rotation and Rollover",
                "aliases": ["Key Changeover", "Key Update"],
                "required": True,
                "weight": 8,
                "compliance_refs": ["NIST-800-57-8.5", "PCI-DSS-3.6.4"],
                "keywords": ["rotation", "rollover", "changeover", "renewal"],
                "description": "Key rotation procedures",
                "elements": [
                    {
                        "id": "rotation_schedule",
                        "name": "Rotation Schedule",
                        "description": "When keys are rotated",
                        "keywords": ["schedule", "rotation frequency", "renewal schedule"],
                        "aliases": ["Rotation Frequency"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["NIST-800-57-8.5.1", "PCI-DSS-3.6.4"]
                    },
                    {
                        "id": "rotation_procedures",
                        "name": "Rotation Procedures",
                        "description": "How keys are rotated",
                        "keywords": ["rotation procedure", "key rollover", "transition"],
                        "aliases": ["Rollover Procedures"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["NIST-800-57-8.5.2"]
                    }
                ]
            },
            {
                "id": "key_destruction",
                "name": "Key Destruction",
                "aliases": ["Key Revocation", "Key Termination"],
                "required": True,
                "weight": 8,
                "compliance_refs": ["NIST-800-57-8.6", "PCI-DSS-3.6.5"],
                "keywords": ["destruction", "revocation", "termination", "zeroization"],
                "description": "Secure key destruction procedures",
                "elements": [
                    {
                        "id": "destruction_methods",
                        "name": "Destruction Methods",
                        "description": "How keys are securely destroyed",
                        "keywords": ["destruction", "zeroization", "secure delete", "overwrite"],
                        "aliases": ["Zeroization"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["NIST-800-57-8.6.1", "PCI-DSS-3.6.5"]
                    },
                    {
                        "id": "destruction_verification",
                        "name": "Destruction Verification",
                        "description": "Verifying key destruction",
                        "keywords": ["verification", "confirmation", "audit", "witnessed"],
                        "aliases": ["Verification"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["NIST-800-57-8.6.2"]
                    }
                ]
            },
            {
                "id": "compromise_handling",
                "name": "Key Compromise Handling",
                "aliases": ["Compromise Response", "Incident Response"],
                "required": True,
                "weight": 8,
                "compliance_refs": ["NIST-800-57-8.7"],
                "keywords": ["compromise", "incident", "breach", "response"],
                "description": "Procedures for handling key compromise",
                "elements": [
                    {
                        "id": "compromise_detection",
                        "name": "Compromise Detection",
                        "description": "How compromise is detected",
                        "keywords": ["detection", "monitoring", "indicators", "alerting"],
                        "aliases": ["Detection Methods"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["NIST-800-57-8.7.1"]
                    },
                    {
                        "id": "compromise_response",
                        "name": "Compromise Response Procedures",
                        "description": "Steps when compromise occurs",
                        "keywords": ["response", "revocation", "replacement", "notification"],
                        "aliases": ["Response Procedures"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["NIST-800-57-8.7.2"]
                    }
                ]
            }
        ]
    }


def _get_ops_template() -> Dict[str, Any]:
    """
    PKI Operational Process Document template.
    """
    return {
        "name": "PKI Operational Process Document",
        "version": "2.0",
        "frameworks": ["NCSC", "ISO27001", "ITIL"],
        "description": "Assessment template for PKI operational procedures",
        "sections": [
            {
                "id": "operational_overview",
                "name": "Operational Overview",
                "aliases": ["Introduction", "Scope"],
                "required": True,
                "weight": 4,
                "compliance_refs": ["NCSC-OPS"],
                "keywords": ["operations", "overview", "scope", "responsibilities"],
                "description": "Overview of PKI operations",
                "elements": [
                    {
                        "id": "operational_scope",
                        "name": "Operational Scope",
                        "description": "Scope of operations covered",
                        "keywords": ["scope", "covered operations", "systems"],
                        "aliases": ["Scope"],
                        "required": True,
                        "weight": 4,
                        "compliance_refs": ["NCSC-OPS-1"]
                    }
                ]
            },
            {
                "id": "daily_operations",
                "name": "Daily Operations",
                "aliases": ["Day-to-Day Operations", "Routine Operations"],
                "required": True,
                "weight": 7,
                "compliance_refs": ["NCSC-OPS-DO"],
                "keywords": ["daily", "routine", "monitoring", "health check"],
                "description": "Day-to-day operational procedures",
                "elements": [
                    {
                        "id": "health_monitoring",
                        "name": "System Health Monitoring",
                        "description": "Monitoring CA system health",
                        "keywords": ["monitoring", "health check", "status", "availability"],
                        "aliases": ["System Monitoring"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["NCSC-OPS-DO-1"]
                    },
                    {
                        "id": "log_review",
                        "name": "Log Review Procedures",
                        "description": "Daily log review requirements",
                        "keywords": ["log review", "audit log", "daily review", "anomaly detection"],
                        "aliases": ["Audit Log Review"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["NCSC-OPS-DO-2", "ISO27001-A.12.4"]
                    },
                    {
                        "id": "certificate_operations",
                        "name": "Certificate Operations",
                        "description": "Daily certificate issuance/revocation",
                        "keywords": ["certificate issuance", "revocation", "daily operations"],
                        "aliases": ["Cert Operations"],
                        "required": True,
                        "weight": 6,
                        "compliance_refs": ["NCSC-OPS-DO-3"]
                    }
                ]
            },
            {
                "id": "change_management",
                "name": "Change Management",
                "aliases": ["Change Control", "Configuration Management"],
                "required": True,
                "weight": 8,
                "compliance_refs": ["ISO27001-A.12.1", "ITIL-CM"],
                "keywords": ["change management", "change control", "configuration", "approval"],
                "description": "Change management procedures",
                "elements": [
                    {
                        "id": "change_request",
                        "name": "Change Request Process",
                        "description": "How changes are requested",
                        "keywords": ["change request", "rfc", "change ticket"],
                        "aliases": ["RFC Process"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["ISO27001-A.12.1.2", "ITIL-CM-1"]
                    },
                    {
                        "id": "change_approval",
                        "name": "Change Approval Process",
                        "description": "Change approval requirements",
                        "keywords": ["approval", "cab", "authorization", "sign-off"],
                        "aliases": ["CAB Process"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["ISO27001-A.12.1.2", "ITIL-CM-2"]
                    },
                    {
                        "id": "change_implementation",
                        "name": "Change Implementation",
                        "description": "How changes are implemented",
                        "keywords": ["implementation", "deployment", "rollback"],
                        "aliases": ["Implementation Procedures"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["ISO27001-A.12.1.2"]
                    }
                ]
            },
            {
                "id": "incident_management",
                "name": "Incident Management",
                "aliases": ["Incident Response", "Security Incidents"],
                "required": True,
                "weight": 9,
                "compliance_refs": ["ISO27001-A.16", "NCSC-IR"],
                "keywords": ["incident", "response", "security incident", "breach"],
                "description": "Incident handling procedures",
                "elements": [
                    {
                        "id": "incident_detection",
                        "name": "Incident Detection",
                        "description": "How incidents are detected",
                        "keywords": ["detection", "alerting", "monitoring", "siem"],
                        "aliases": ["Detection"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["ISO27001-A.16.1.2"]
                    },
                    {
                        "id": "incident_classification",
                        "name": "Incident Classification",
                        "description": "How incidents are classified",
                        "keywords": ["classification", "severity", "priority", "triage"],
                        "aliases": ["Classification"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["ISO27001-A.16.1.4"]
                    },
                    {
                        "id": "incident_response",
                        "name": "Incident Response Procedures",
                        "description": "Response procedures for incidents",
                        "keywords": ["response", "containment", "eradication", "recovery"],
                        "aliases": ["Response Procedures"],
                        "required": True,
                        "weight": 9,
                        "compliance_refs": ["ISO27001-A.16.1.5", "NCSC-IR-1"]
                    },
                    {
                        "id": "incident_reporting",
                        "name": "Incident Reporting",
                        "description": "Internal and external reporting",
                        "keywords": ["reporting", "notification", "escalation", "communication"],
                        "aliases": ["Reporting"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["ISO27001-A.16.1.3"]
                    }
                ]
            },
            {
                "id": "maintenance",
                "name": "System Maintenance",
                "aliases": ["Preventive Maintenance", "Patching"],
                "required": True,
                "weight": 7,
                "compliance_refs": ["ISO27001-A.12.6", "NCSC-PM"],
                "keywords": ["maintenance", "patching", "updates", "preventive"],
                "description": "System maintenance procedures",
                "elements": [
                    {
                        "id": "patching",
                        "name": "Patching Procedures",
                        "description": "Security patching process",
                        "keywords": ["patching", "security updates", "vulnerability management"],
                        "aliases": ["Security Updates"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["ISO27001-A.12.6.1", "NCSC-PM-1"]
                    },
                    {
                        "id": "scheduled_maintenance",
                        "name": "Scheduled Maintenance",
                        "description": "Planned maintenance windows",
                        "keywords": ["scheduled", "maintenance window", "planned outage"],
                        "aliases": ["Planned Maintenance"],
                        "required": True,
                        "weight": 6,
                        "compliance_refs": ["NCSC-PM-2"]
                    },
                    {
                        "id": "backup_procedures",
                        "name": "Backup Procedures",
                        "description": "System and data backup",
                        "keywords": ["backup", "data backup", "system backup", "restoration"],
                        "aliases": ["Backup"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["ISO27001-A.12.3"]
                    }
                ]
            },
            {
                "id": "access_management",
                "name": "Access Management",
                "aliases": ["Access Control", "User Management"],
                "required": True,
                "weight": 8,
                "compliance_refs": ["ISO27001-A.9"],
                "keywords": ["access", "user management", "authentication", "authorization"],
                "description": "Access control procedures",
                "elements": [
                    {
                        "id": "user_provisioning",
                        "name": "User Provisioning",
                        "description": "Creating and managing user accounts",
                        "keywords": ["provisioning", "user creation", "onboarding"],
                        "aliases": ["User Creation"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["ISO27001-A.9.2.1"]
                    },
                    {
                        "id": "access_review",
                        "name": "Access Review",
                        "description": "Periodic access reviews",
                        "keywords": ["access review", "recertification", "periodic review"],
                        "aliases": ["Recertification"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["ISO27001-A.9.2.5"]
                    },
                    {
                        "id": "privileged_access",
                        "name": "Privileged Access Management",
                        "description": "Managing privileged accounts",
                        "keywords": ["privileged", "admin", "elevated access", "pam"],
                        "aliases": ["PAM"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["ISO27001-A.9.2.3"]
                    }
                ]
            }
        ]
    }


def _get_bc_template() -> Dict[str, Any]:
    """
    Business Continuity Document template.
    """
    return {
        "name": "Business Continuity Document",
        "version": "2.0",
        "frameworks": ["ISO22301", "ISO27001", "NCSC"],
        "description": "Assessment template for PKI Business Continuity Plans",
        "sections": [
            {
                "id": "bc_overview",
                "name": "Business Continuity Overview",
                "aliases": ["Introduction", "BCP Overview"],
                "required": True,
                "weight": 5,
                "compliance_refs": ["ISO22301-4", "ISO27001-A.17"],
                "keywords": ["business continuity", "overview", "scope", "objectives"],
                "description": "BCP scope and objectives",
                "elements": [
                    {
                        "id": "bc_scope",
                        "name": "BCP Scope",
                        "description": "What is covered by the BCP",
                        "keywords": ["scope", "coverage", "systems", "processes"],
                        "aliases": ["Scope"],
                        "required": True,
                        "weight": 5,
                        "compliance_refs": ["ISO22301-4.3"]
                    },
                    {
                        "id": "bc_objectives",
                        "name": "Business Continuity Objectives",
                        "description": "RTO, RPO, and other objectives",
                        "keywords": ["objectives", "rto", "rpo", "recovery time", "recovery point"],
                        "aliases": ["Recovery Objectives"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["ISO22301-6.2"]
                    }
                ]
            },
            {
                "id": "risk_assessment",
                "name": "Risk Assessment",
                "aliases": ["BIA", "Impact Analysis"],
                "required": True,
                "weight": 8,
                "compliance_refs": ["ISO22301-8.2", "ISO27001-A.17.1"],
                "keywords": ["risk", "impact", "assessment", "bia", "threat"],
                "description": "Business impact and risk assessment",
                "elements": [
                    {
                        "id": "business_impact_analysis",
                        "name": "Business Impact Analysis",
                        "description": "Analysis of business impact",
                        "keywords": ["bia", "business impact", "impact analysis", "critical functions"],
                        "aliases": ["BIA"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["ISO22301-8.2.2"]
                    },
                    {
                        "id": "threat_assessment",
                        "name": "Threat Assessment",
                        "description": "Assessment of threats and risks",
                        "keywords": ["threat", "risk assessment", "vulnerabilities", "scenarios"],
                        "aliases": ["Risk Assessment"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["ISO22301-8.2.3"]
                    }
                ]
            },
            {
                "id": "recovery_strategies",
                "name": "Recovery Strategies",
                "aliases": ["Recovery Options", "Continuity Strategies"],
                "required": True,
                "weight": 9,
                "compliance_refs": ["ISO22301-8.3"],
                "keywords": ["recovery", "strategy", "failover", "redundancy"],
                "description": "Business continuity strategies",
                "elements": [
                    {
                        "id": "primary_site_recovery",
                        "name": "Primary Site Recovery",
                        "description": "Recovery of primary site",
                        "keywords": ["primary site", "main site", "recovery"],
                        "aliases": ["Primary Recovery"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["ISO22301-8.3.1"]
                    },
                    {
                        "id": "alternate_site",
                        "name": "Alternate Site Procedures",
                        "description": "Failover to alternate site",
                        "keywords": ["alternate site", "dr site", "secondary site", "failover"],
                        "aliases": ["DR Site"],
                        "required": True,
                        "weight": 9,
                        "compliance_refs": ["ISO22301-8.3.2", "ISO27001-A.17.2"]
                    },
                    {
                        "id": "data_recovery",
                        "name": "Data Recovery Procedures",
                        "description": "Recovering PKI data",
                        "keywords": ["data recovery", "backup restoration", "database recovery"],
                        "aliases": ["Data Restoration"],
                        "required": True,
                        "weight": 9,
                        "compliance_refs": ["ISO22301-8.3.3"]
                    },
                    {
                        "id": "key_recovery",
                        "name": "CA Key Recovery",
                        "description": "Recovering CA keys",
                        "keywords": ["key recovery", "ca key", "hsm recovery", "key restoration"],
                        "aliases": ["CA Recovery"],
                        "required": True,
                        "weight": 10,
                        "compliance_refs": ["NCSC-KR"]
                    }
                ]
            },
            {
                "id": "bc_procedures",
                "name": "Business Continuity Procedures",
                "aliases": ["BC Procedures", "Response Procedures"],
                "required": True,
                "weight": 9,
                "compliance_refs": ["ISO22301-8.4"],
                "keywords": ["procedures", "response", "activation", "steps"],
                "description": "Detailed continuity procedures",
                "elements": [
                    {
                        "id": "activation_criteria",
                        "name": "Activation Criteria",
                        "description": "When to activate BCP",
                        "keywords": ["activation", "criteria", "trigger", "declaration"],
                        "aliases": ["Trigger Criteria"],
                        "required": True,
                        "weight": 8,
                        "compliance_refs": ["ISO22301-8.4.1"]
                    },
                    {
                        "id": "notification_procedures",
                        "name": "Notification Procedures",
                        "description": "Who to notify and how",
                        "keywords": ["notification", "communication", "escalation", "contacts"],
                        "aliases": ["Communication Plan"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["ISO22301-8.4.3"]
                    },
                    {
                        "id": "recovery_procedures",
                        "name": "Recovery Procedures",
                        "description": "Step-by-step recovery",
                        "keywords": ["recovery procedures", "steps", "runbook", "playbook"],
                        "aliases": ["Recovery Runbook"],
                        "required": True,
                        "weight": 9,
                        "compliance_refs": ["ISO22301-8.4.4"]
                    },
                    {
                        "id": "return_to_normal",
                        "name": "Return to Normal Operations",
                        "description": "Returning from DR mode",
                        "keywords": ["return to normal", "failback", "restoration", "normalization"],
                        "aliases": ["Failback"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["ISO22301-8.4.5"]
                    }
                ]
            },
            {
                "id": "testing_maintenance",
                "name": "Testing and Maintenance",
                "aliases": ["BC Testing", "DR Testing"],
                "required": True,
                "weight": 8,
                "compliance_refs": ["ISO22301-9.1", "ISO27001-A.17.1.3"],
                "keywords": ["testing", "exercise", "drill", "maintenance"],
                "description": "BCP testing and maintenance",
                "elements": [
                    {
                        "id": "test_schedule",
                        "name": "Test Schedule",
                        "description": "Testing frequency and types",
                        "keywords": ["test schedule", "frequency", "annual", "quarterly"],
                        "aliases": ["Testing Frequency"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["ISO22301-9.1.2"]
                    },
                    {
                        "id": "test_types",
                        "name": "Types of Tests",
                        "description": "Tabletop, functional, full tests",
                        "keywords": ["tabletop", "functional test", "full test", "simulation"],
                        "aliases": ["Test Types"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["ISO22301-9.1.3"]
                    },
                    {
                        "id": "test_documentation",
                        "name": "Test Documentation",
                        "description": "Recording test results",
                        "keywords": ["documentation", "results", "lessons learned", "improvements"],
                        "aliases": ["Test Results"],
                        "required": True,
                        "weight": 6,
                        "compliance_refs": ["ISO22301-9.1.4"]
                    },
                    {
                        "id": "plan_maintenance",
                        "name": "Plan Maintenance",
                        "description": "Keeping the BCP current",
                        "keywords": ["maintenance", "review", "update", "version control"],
                        "aliases": ["BCP Maintenance"],
                        "required": True,
                        "weight": 6,
                        "compliance_refs": ["ISO22301-10.2"]
                    }
                ]
            },
            {
                "id": "roles_responsibilities",
                "name": "Roles and Responsibilities",
                "aliases": ["BC Team", "Response Team"],
                "required": True,
                "weight": 7,
                "compliance_refs": ["ISO22301-5.3"],
                "keywords": ["roles", "responsibilities", "team", "contacts"],
                "description": "BC roles and responsibilities",
                "elements": [
                    {
                        "id": "bc_team",
                        "name": "BC Team Structure",
                        "description": "BC team organization",
                        "keywords": ["team", "structure", "organization", "members"],
                        "aliases": ["Team Structure"],
                        "required": True,
                        "weight": 6,
                        "compliance_refs": ["ISO22301-5.3"]
                    },
                    {
                        "id": "contact_list",
                        "name": "Emergency Contact List",
                        "description": "Contact information",
                        "keywords": ["contacts", "emergency", "phone", "email"],
                        "aliases": ["Contact Information"],
                        "required": True,
                        "weight": 7,
                        "compliance_refs": ["ISO22301-8.4.3"]
                    }
                ]
            }
        ]
    }
