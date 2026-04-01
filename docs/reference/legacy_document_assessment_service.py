# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: caip_document_assessment_functions/document_assessment_service.py
# Copied: 2026-04-01
# Used in: Phase 15 — Document Assessment
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
Document Assessment Service Layer for CAIP

Provides document parsing and compliance assessment for PKI governance documents.
Supports assessment of:
- Certificate Practice Statements (CPS)
- Certificate Policies (CP)
- PKI Design Documents
- Key Management Plans
- PKI Operational Process Documents
- Business Continuity Documents

Assessment is performed against industry standards:
- NCSC (UK National Cyber Security Centre)
- NIST (SP 800-57, SP 800-130)
- ISO/IEC 27001
- RFC 3647 (CP/CPS Framework)
- WebTrust for CAs
- PCI-DSS (where applicable)
"""

import os
import re
import json
import logging
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from pathlib import Path
from enum import Enum

# Import PKI terminology dictionary
try:
    from caip_service_layer.pki_terminology import get_legacy_synonyms, match_terms, get_canonical_term
    PKI_TERMINOLOGY_AVAILABLE = True
    print(f"[TERMINOLOGY] Loaded PKI terminology: {len(get_legacy_synonyms())} terms")
except ImportError as e:
    PKI_TERMINOLOGY_AVAILABLE = False
    get_legacy_synonyms = None
    match_terms = None
    get_canonical_term = None
    print(f"[TERMINOLOGY] ✗ Failed to load: {e}")

logger = logging.getLogger('caip.operational')


# =============================================================================
# ENUMS AND CONSTANTS
# =============================================================================

class DocumentType(Enum):
    """Supported document types for assessment"""
    CERTIFICATE_PRACTICE_STATEMENT = "certificate_practice_statement"
    CERTIFICATE_POLICY = "certificate_policy"
    PKI_DESIGN = "pki_design"
    KEY_MANAGEMENT_PLAN = "key_management_plan"
    PKI_OPERATIONAL_PROCESS = "pki_operational_process"
    BUSINESS_CONTINUITY = "business_continuity"
    UNKNOWN = "unknown"


class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    NCSC = "NCSC"
    NIST = "NIST"
    ISO27001 = "ISO27001"
    RFC3647 = "RFC3647"
    WEBTRUST = "WebTrust"
    PCI_DSS = "PCI-DSS"


class AssessmentSeverity(Enum):
    """Severity levels for assessment findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class DocumentSection:
    """Represents a parsed section from a document"""
    heading: str
    level: int  # Heading level (1, 2, 3, etc.)
    content: str
    start_position: int
    end_position: int
    subsections: List['DocumentSection'] = field(default_factory=list)
    mapped_element_id: Optional[str] = None
    mapping_confidence: float = 0.0


@dataclass
class DocumentMetadata:
    """Metadata extracted from a document"""
    filename: str
    file_type: str  # pdf, docx
    file_size: int
    page_count: Optional[int]
    word_count: int
    detected_document_type: DocumentType
    document_type_confidence: float
    version_detected: Optional[str]
    date_detected: Optional[str]
    organization_detected: Optional[str]
    hash_sha256: str


@dataclass
class AssessmentElement:
    """An element that should be present in a document"""
    element_id: str
    name: str
    description: str
    keywords: List[str]
    aliases: List[str]
    required: bool
    weight: float  # Importance weight (1-10)
    compliance_refs: List[str]  # e.g., ["RFC3647-1.2", "NCSC-KM-1"]
    parent_section_id: Optional[str]


@dataclass
class AssessmentFinding:
    """A finding from document assessment"""
    finding_id: str
    element_id: str
    element_name: str
    status: str  # "found", "partial", "missing"
    severity: AssessmentSeverity
    confidence: float
    matched_section: Optional[str]
    matched_content_snippet: Optional[str]
    compliance_refs: List[str]
    recommendation: str
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'finding_id': self.finding_id,
            'element_id': self.element_id,
            'element_name': self.element_name,
            'status': self.status,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'matched_section': self.matched_section,
            'matched_content_snippet': self.matched_content_snippet,
            'compliance_refs': self.compliance_refs,
            'recommendation': self.recommendation,
            'details': self.details
        }


@dataclass
class DocumentAssessmentResult:
    """Complete result of document assessment"""
    assessment_id: str
    document_metadata: DocumentMetadata
    document_type: DocumentType
    template_used: str
    assessed_at: str
    sections_found: List[DocumentSection]
    findings: List[AssessmentFinding]
    coverage_score: float  # 0-100
    compliance_scores: Dict[str, float]  # Score per framework
    summary: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'assessment_id': self.assessment_id,
            'document_metadata': {
                'filename': self.document_metadata.filename,
                'file_type': self.document_metadata.file_type,
                'file_size': self.document_metadata.file_size,
                'page_count': self.document_metadata.page_count,
                'word_count': self.document_metadata.word_count,
                'detected_document_type': self.document_metadata.detected_document_type.value,
                'document_type_confidence': self.document_metadata.document_type_confidence,
                'version_detected': self.document_metadata.version_detected,
                'date_detected': self.document_metadata.date_detected,
                'organization_detected': self.document_metadata.organization_detected,
                'hash_sha256': self.document_metadata.hash_sha256
            },
            'document_type': self.document_type.value,
            'template_used': self.template_used,
            'assessed_at': self.assessed_at,
            'sections_found': [
                {
                    'heading': s.heading,
                    'level': s.level,
                    'mapped_element_id': s.mapped_element_id,
                    'mapping_confidence': s.mapping_confidence
                } for s in self.sections_found
            ],
            'findings': [f.to_dict() for f in self.findings],
            'coverage_score': self.coverage_score,
            'compliance_scores': self.compliance_scores,
            'summary': self.summary
        }


# =============================================================================
# DOCUMENT PARSER
# =============================================================================

class DocumentParser:
    """
    Parses PDF and DOCX documents to extract structure and content.
    """
    
    # Common heading patterns for PKI documents
    HEADING_PATTERNS = [
        # Numbered headings: 1. Introduction, 1.1 Overview, etc.
        r'^(\d+(?:\.\d+)*)\s+(.+)$',
        # All caps headings
        r'^([A-Z][A-Z\s]{3,})$',
        # Title case with colon
        r'^([A-Z][a-zA-Z\s]+):\s*$',
    ]
    
    @staticmethod
    def parse_document(file_path: str) -> Tuple[str, DocumentMetadata, List[DocumentSection]]:
        """
        Parse a document and extract its content and structure.
        
        Args:
            file_path: Path to the document file
            
        Returns:
            Tuple of (full_text, metadata, sections)
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Document not found: {file_path}")
        
        file_type = path.suffix.lower().lstrip('.')
        
        if file_type == 'pdf':
            return DocumentParser._parse_pdf(path)
        elif file_type in ['docx', 'doc']:
            return DocumentParser._parse_docx(path)
        else:
            raise ValueError(f"Unsupported file type: {file_type}")
    
    @staticmethod
    def _parse_pdf(path: Path) -> Tuple[str, DocumentMetadata, List[DocumentSection]]:
        """Parse PDF document"""
        try:
            import fitz  # PyMuPDF
        except ImportError:
            try:
                import pdfplumber
                return DocumentParser._parse_pdf_pdfplumber(path)
            except ImportError:
                raise ImportError("Either PyMuPDF (fitz) or pdfplumber is required for PDF parsing")
        
        doc = fitz.open(str(path))
        full_text = ""
        page_count = len(doc)
        
        for page in doc:
            full_text += page.get_text() + "\n"
        
        doc.close()
        
        # Calculate hash
        with open(path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        # Extract sections from text
        sections = DocumentParser._extract_sections(full_text)
        
        # Detect document type
        doc_type, confidence = DocumentParser._detect_document_type(full_text, sections)
        
        # Extract additional metadata
        version = DocumentParser._extract_version(full_text)
        date = DocumentParser._extract_date(full_text)
        org = DocumentParser._extract_organization(full_text)
        
        metadata = DocumentMetadata(
            filename=path.name,
            file_type='pdf',
            file_size=path.stat().st_size,
            page_count=page_count,
            word_count=len(full_text.split()),
            detected_document_type=doc_type,
            document_type_confidence=confidence,
            version_detected=version,
            date_detected=date,
            organization_detected=org,
            hash_sha256=file_hash
        )
        
        return full_text, metadata, sections
    
    @staticmethod
    def _parse_pdf_pdfplumber(path: Path) -> Tuple[str, DocumentMetadata, List[DocumentSection]]:
        """Parse PDF using pdfplumber as fallback"""
        import pdfplumber
        
        full_text = ""
        page_count = 0
        
        with pdfplumber.open(str(path)) as pdf:
            page_count = len(pdf.pages)
            for page in pdf.pages:
                text = page.extract_text()
                if text:
                    full_text += text + "\n"
        
        # Calculate hash
        with open(path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        sections = DocumentParser._extract_sections(full_text)
        doc_type, confidence = DocumentParser._detect_document_type(full_text, sections)
        version = DocumentParser._extract_version(full_text)
        date = DocumentParser._extract_date(full_text)
        org = DocumentParser._extract_organization(full_text)
        
        metadata = DocumentMetadata(
            filename=path.name,
            file_type='pdf',
            file_size=path.stat().st_size,
            page_count=page_count,
            word_count=len(full_text.split()),
            detected_document_type=doc_type,
            document_type_confidence=confidence,
            version_detected=version,
            date_detected=date,
            organization_detected=org,
            hash_sha256=file_hash
        )
        
        return full_text, metadata, sections
    
    @staticmethod
    def _parse_docx(path: Path) -> Tuple[str, DocumentMetadata, List[DocumentSection]]:
        """Parse DOCX document"""
        try:
            from docx import Document
        except ImportError:
            raise ImportError("python-docx is required for DOCX parsing")
        
        doc = Document(str(path))
        
        full_text = ""
        sections = []
        current_position = 0
        
        for para in doc.paragraphs:
            text = para.text.strip()
            if not text:
                continue
            
            # Check if this is a heading
            if para.style.name.startswith('Heading'):
                try:
                    level = int(para.style.name.replace('Heading ', ''))
                except ValueError:
                    level = 1
                
                section = DocumentSection(
                    heading=text,
                    level=level,
                    content="",
                    start_position=current_position,
                    end_position=current_position + len(text)
                )
                sections.append(section)
            else:
                # Add to last section's content if exists
                if sections:
                    sections[-1].content += text + "\n"
                    sections[-1].end_position = current_position + len(text)
            
            full_text += text + "\n"
            current_position += len(text) + 1
        
        # If no heading styles found, try pattern-based extraction
        if not sections:
            sections = DocumentParser._extract_sections(full_text)
        
        # Calculate hash
        with open(path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        doc_type, confidence = DocumentParser._detect_document_type(full_text, sections)
        version = DocumentParser._extract_version(full_text)
        date = DocumentParser._extract_date(full_text)
        org = DocumentParser._extract_organization(full_text)
        
        metadata = DocumentMetadata(
            filename=path.name,
            file_type='docx',
            file_size=path.stat().st_size,
            page_count=None,  # DOCX doesn't have fixed pages
            word_count=len(full_text.split()),
            detected_document_type=doc_type,
            document_type_confidence=confidence,
            version_detected=version,
            date_detected=date,
            organization_detected=org,
            hash_sha256=file_hash
        )
        
        return full_text, metadata, sections
    
    @staticmethod
    def _extract_sections(text: str) -> List[DocumentSection]:
        """Extract sections from text using pattern matching"""
        sections = []
        lines = text.split('\n')
        current_section = None
        current_content = []
        current_position = 0
        
        for line in lines:
            stripped = line.strip()
            if not stripped:
                current_position += len(line) + 1
                continue
            
            # Check for numbered heading pattern (most reliable for PKI docs)
            numbered_match = re.match(r'^(\d+(?:\.\d+)*)\s+(.+)$', stripped)
            if numbered_match:
                # Save previous section
                if current_section:
                    current_section.content = '\n'.join(current_content)
                    current_section.end_position = current_position
                    sections.append(current_section)
                
                # Determine level from numbering
                number_parts = numbered_match.group(1).split('.')
                level = len(number_parts)
                
                current_section = DocumentSection(
                    heading=stripped,
                    level=level,
                    content="",
                    start_position=current_position,
                    end_position=current_position
                )
                current_content = []
            else:
                current_content.append(stripped)
            
            current_position += len(line) + 1
        
        # Save final section
        if current_section:
            current_section.content = '\n'.join(current_content)
            current_section.end_position = current_position
            sections.append(current_section)
        
        return sections
    
    @staticmethod
    def _detect_document_type(text: str, sections: List[DocumentSection]) -> Tuple[DocumentType, float]:
        """
        Detect the document type based on content analysis.
        
        Returns:
            Tuple of (DocumentType, confidence_score)
        """
        text_lower = text.lower()
        section_headings = ' '.join([s.heading.lower() for s in sections])
        
        # Score each document type based on keyword presence
        scores = {
            DocumentType.CERTIFICATE_PRACTICE_STATEMENT: 0.0,
            DocumentType.CERTIFICATE_POLICY: 0.0,
            DocumentType.PKI_DESIGN: 0.0,
            DocumentType.KEY_MANAGEMENT_PLAN: 0.0,
            DocumentType.PKI_OPERATIONAL_PROCESS: 0.0,
            DocumentType.BUSINESS_CONTINUITY: 0.0,
        }
        
        # CPS indicators
        cps_keywords = [
            'certificate practice statement', 'cps', 'practice statement',
            'relying party', 'subscriber agreement', 'certificate lifecycle',
            'repository and publication', 'identification and authentication'
        ]
        for kw in cps_keywords:
            if kw in text_lower:
                scores[DocumentType.CERTIFICATE_PRACTICE_STATEMENT] += 10
        
        # CP indicators
        cp_keywords = [
            'certificate policy', 'cp ', 'oid', 'object identifier',
            'policy qualifier', 'certificate profile', 'name constraints'
        ]
        for kw in cp_keywords:
            if kw in text_lower:
                scores[DocumentType.CERTIFICATE_POLICY] += 10
        
        # PKI Design indicators
        design_keywords = [
            'pki design', 'architecture', 'topology', 'trust model',
            'ca hierarchy', 'root ca', 'issuing ca', 'technical design',
            'high level design', 'low level design', 'system architecture'
        ]
        for kw in design_keywords:
            if kw in text_lower:
                scores[DocumentType.PKI_DESIGN] += 10
        
        # Key Management Plan indicators
        kmp_keywords = [
            'key management', 'key lifecycle', 'key ceremony', 'key generation',
            'key escrow', 'key recovery', 'cryptographic key', 'hsm',
            'hardware security module', 'key custodian', 'm of n'
        ]
        for kw in kmp_keywords:
            if kw in text_lower:
                scores[DocumentType.KEY_MANAGEMENT_PLAN] += 10
        
        # Operational Process indicators
        ops_keywords = [
            'operational process', 'operations manual', 'standard operating',
            'sop', 'runbook', 'procedure', 'incident response', 'change management',
            'operational security', 'physical security', 'personnel security'
        ]
        for kw in ops_keywords:
            if kw in text_lower:
                scores[DocumentType.PKI_OPERATIONAL_PROCESS] += 10
        
        # Business Continuity indicators
        bc_keywords = [
            'business continuity', 'disaster recovery', 'bcp', 'drp',
            'recovery point', 'recovery time', 'rpo', 'rto', 'failover',
            'backup', 'resilience', 'continuity plan'
        ]
        for kw in bc_keywords:
            if kw in text_lower:
                scores[DocumentType.BUSINESS_CONTINUITY] += 10
        
        # Find highest scoring type
        max_score = max(scores.values())
        if max_score == 0:
            return DocumentType.UNKNOWN, 0.0
        
        best_type = max(scores, key=scores.get)
        
        # Calculate confidence (normalize to 0-1)
        # Max possible score varies by type, but ~100 is reasonable max
        confidence = min(max_score / 100.0, 1.0)
        
        return best_type, confidence
    
    @staticmethod
    def _extract_version(text: str) -> Optional[str]:
        """Extract version number from document"""
        patterns = [
            r'[Vv]ersion[:\s]+(\d+(?:\.\d+)*)',
            r'[Vv](\d+(?:\.\d+)+)',
            r'[Rr]evision[:\s]+(\d+(?:\.\d+)*)',
        ]
        for pattern in patterns:
            match = re.search(pattern, text[:2000])  # Check first 2000 chars
            if match:
                return match.group(1)
        return None
    
    @staticmethod
    def _extract_date(text: str) -> Optional[str]:
        """Extract document date"""
        patterns = [
            r'(?:Date|Effective|Published)[:\s]+(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})',
            r'(?:Date|Effective|Published)[:\s]+(\d{4}[/-]\d{1,2}[/-]\d{1,2})',
            r'(\d{1,2}\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4})',
            r'((?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4})',
        ]
        for pattern in patterns:
            match = re.search(pattern, text[:3000], re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    @staticmethod
    def _extract_organization(text: str) -> Optional[str]:
        """Extract organization name from document"""
        patterns = [
            r'(?:Organization|Organisation|Company|Issued by)[:\s]+([A-Z][A-Za-z\s&,]+(?:Ltd|LLC|Inc|Corp|PLC)?)',
            r'^([A-Z][A-Za-z\s&]+(?:Ltd|LLC|Inc|Corp|PLC))',
        ]
        for pattern in patterns:
            match = re.search(pattern, text[:2000], re.MULTILINE)
            if match:
                return match.group(1).strip()
        return None


# =============================================================================
# SECTION MAPPER
# =============================================================================

class SectionMapper:
    """
    Maps extracted document sections to expected template elements
    using fuzzy matching and keyword analysis.
    
    Uses comprehensive PKI terminology dictionary when available,
    with fallback to embedded synonyms for resilience.
    """
    
    # Fallback synonym mappings (used if pki_terminology.py not available)
    _FALLBACK_SYNONYMS = {
        #'introduction': ['overview', 'purpose', 'scope', 'background', 'about', 'general', 'preface', 'executive summary'],
        #'key_generation': ['key creation', 'key production', 'cryptographic key generation', 'generate keys', 'key pair generation', 'creating keys'],
        #'key_escrow': ['key recovery', 'key backup', 'emergency key access', 'key archival', 'key storage', 'backup keys'],
        #'key_ceremony': ['key generation ceremony', 'root key ceremony', 'ceremony', 'signing ceremony', 'key signing event'],
        #'certificate_lifecycle': ['cert lifecycle', 'certificate management', 'lifecycle management', 'certificate operations', 'cert management', 'managing certificates'],
        #'revocation': ['certificate revocation', 'revocation process', 'crl', 'ocsp', 'revoking', 'revoke', 'certificate status', 'validity', 'suspended'],
        #'physical_security': ['physical controls', 'data center security', 'facility security', 'physical access', 'building security', 'site security', 'premises security', 'environmental controls'],
        #'personnel_security': ['staff security', 'employee security', 'trusted roles', 'background checks', 'personnel controls', 'human resources', 'staff vetting', 'employee vetting'],
        #'audit': ['audit logging', 'audit trail', 'logging', 'audit records', 'event logging', 'audit events', 'security logging', 'log management', 'monitoring'],
        #'disaster_recovery': ['dr', 'recovery', 'backup and recovery', 'business continuity', 'continuity', 'failover', 'recovery procedures', 'contingency'],
        #'incident_response': ['incident management', 'security incident', 'breach response', 'incident handling', 'security events', 'compromise', 'security breach'],
        #'identification': ['identity verification', 'identity proofing', 'authentication', 'verification', 'validation', 'vetting', 'identity management'],
        #'repository': ['publication', 'directory', 'ldap', 'storage', 'distribution', 'public access', 'availability'],
        #'profiles': ['certificate profiles', 'certificate format', 'extensions', 'x.509', 'certificate structure', 'certificate contents'],
        #'compliance': ['audit', 'assessment', 'webtrust', 'etsi', 'iso', 'attestation', 'certification', 'accreditation'],
        #'legal': ['liability', 'warranty', 'indemnification', 'legal matters', 'terms and conditions', 'agreements', 'obligations', 'responsibilities'],
        #'technical_security': ['technical controls', 'cryptographic controls', 'security controls', 'system security', 'technical requirements'],
        #'#network_security': ['network controls', 'firewall', 'segmentation', 'network protection', 'network architecture'],
        #'certificate_issuance': ['issuing certificates', 'certificate generation', 'certificate creation', 'enrollment', 'certificate request'],
        #'certificate_renewal': ['renewing certificates', 'certificate extension', 'validity extension', 'renewal process'],
        #'naming': ['distinguished name', 'subject name', 'name forms', 'naming conventions', 'dn', 'subject'],
        #'private_key': ['key protection', 'key security', 'hsm', 'hardware security module', 'cryptographic module', 'key safeguarding'],
        #'operational': ['operations', 'procedures', 'processes', 'operational controls', 'day to day', 'routine'],
        #'termination': ['shutdown', 'end of operations', 'cessation', 'decommissioning', 'wind down'],
    }
    
    # Property to get synonyms (uses terminology dictionary if available)
    @staticmethod
    def _get_synonyms() -> dict:
        """Get synonyms dictionary, preferring pki_terminology if available."""
        if PKI_TERMINOLOGY_AVAILABLE and get_legacy_synonyms is not None:
            return get_legacy_synonyms()
        return SectionMapper._FALLBACK_SYNONYMS
    
    # Class property for backward compatibility
    SYNONYMS = property(lambda self: SectionMapper._get_synonyms())
    
    @staticmethod
    def map_sections_to_template(
        sections: List[DocumentSection],
        template_elements: List[AssessmentElement],
        full_text: str
    ) -> List[Tuple[AssessmentElement, Optional[DocumentSection], float]]:
        """
        Map document sections to template elements.
        
        Args:
            sections: Parsed document sections
            template_elements: Expected elements from template
            full_text: Full document text for content search
            
        Returns:
            List of (element, matched_section, confidence) tuples
        """
        mappings = []
        
        for element in template_elements:
            best_match = None
            best_confidence = 0.0
            
            # Try to match against sections
            for section in sections:
                confidence = SectionMapper._calculate_match_confidence(
                    element, section, full_text
                )
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_match = section
            
            # If no section match, search full text for keywords
            if best_confidence < 0.3:
                text_confidence = SectionMapper._search_keywords_in_text(
                    element, full_text
                )
                if text_confidence > best_confidence:
                    best_confidence = text_confidence
                    best_match = None  # Found in text but not in a specific section
            
            mappings.append((element, best_match, best_confidence))
            
            # Update section with mapping info
            if best_match and best_confidence > 0.3:
                best_match.mapped_element_id = element.element_id
                best_match.mapping_confidence = best_confidence
        
        return mappings
    
    @staticmethod
    def _calculate_match_confidence(
        element: AssessmentElement,
        section: DocumentSection,
        full_text: str
    ) -> float:
        """
        Calculate confidence that a section matches an element.
        """
        confidence = 0.0
        section_text = (section.heading + ' ' + section.content).lower()
        
        # Check element name match
        if element.name.lower() in section.heading.lower():
            confidence += 0.4
        
        # Check aliases
        for alias in element.aliases:
            if alias.lower() in section.heading.lower():
                confidence += 0.3
                break
        
        # Check synonyms (use terminology dictionary if available)
        element_key = element.element_id.lower().replace('_', ' ')
        synonyms_dict = SectionMapper._get_synonyms()
        for key, synonyms in synonyms_dict.items():
            if key in element_key:
                for syn in synonyms:
                    if syn in section.heading.lower():
                        confidence += 0.2
                        break
        
        # Enhanced matching with terminology dictionary
        if PKI_TERMINOLOGY_AVAILABLE and match_terms is not None:
            # Get term matches from comprehensive dictionary
            heading_matches = match_terms(section.heading)
            content_matches = match_terms(section_text[:500])  # First 500 chars
            
            # Check if any matched terms relate to element
            element_terms = element_key.split()
            for canonical, match_confidence, matched_text in heading_matches:
                if any(term in canonical for term in element_terms):
                    confidence += match_confidence * 0.15
                    break
        
        # Check keywords in section content
        keyword_matches = 0
        for keyword in element.keywords:
            if keyword.lower() in section_text:
                keyword_matches += 1
        
        if element.keywords:
            keyword_ratio = keyword_matches / len(element.keywords)
            confidence += keyword_ratio * 0.4
        
        return min(confidence, 1.0)
    
    @staticmethod
    def _search_keywords_in_text(element: AssessmentElement, full_text: str) -> float:
        """
        Search for element keywords in full document text.
        """
        text_lower = full_text.lower()
        keyword_matches = 0
        
        for keyword in element.keywords:
            if keyword.lower() in text_lower:
                keyword_matches += 1
        
        if not element.keywords:
            return 0.0
        
        return (keyword_matches / len(element.keywords)) * 0.8

    @staticmethod
    def _search_with_terminology(element: AssessmentElement, full_text: str) -> float:
        """
        Enhanced search using terminology dictionary for better coverage.
        
        This method uses the comprehensive PKI terminology to find
        related terms even when exact keywords aren't present.
        """
        if not PKI_TERMINOLOGY_AVAILABLE or match_terms is None:
            return 0.0
        
        # Get terminology matches from text
        text_sample = full_text[:5000].lower()  # Sample first 5000 chars
        term_matches = match_terms(text_sample)
        
        if not term_matches:
            return 0.0
        
        # Map element to expected canonical terms
        element_key = element.element_id.lower().replace('_', ' ')
        element_words = set(element_key.split())
        
        # Check for matching canonical terms
        match_count = 0
        for canonical, confidence, _ in term_matches:
            canonical_words = set(canonical.split('_'))
            if element_words & canonical_words:  # Intersection
                match_count += 1
        
        if match_count > 0:
            return min(0.6, match_count * 0.15)
        
        return 0.0
    
# =============================================================================
# CONTENT ASSESSOR
# =============================================================================

class ContentAssessor:
    """
    Assesses document content against template requirements.
    Generates findings based on presence, partial presence, or absence of elements.
    """
    
    @staticmethod
    def assess_content(
        mappings: List[Tuple[AssessmentElement, Optional[DocumentSection], float]],
        full_text: str,
        document_type: DocumentType
    ) -> List[AssessmentFinding]:
        """
        Assess document content and generate findings.
        
        Args:
            mappings: Element to section mappings
            full_text: Full document text
            document_type: Type of document being assessed
            
        Returns:
            List of assessment findings
        """
        findings = []
        finding_counter = 1
        
        for element, section, confidence in mappings:
            finding = ContentAssessor._assess_element(
                element, section, confidence, full_text, finding_counter
            )
            findings.append(finding)
            finding_counter += 1
        
        return findings
    
    @staticmethod
    def _assess_element(
        element: AssessmentElement,
        section: Optional[DocumentSection],
        confidence: float,
        full_text: str,
        finding_number: int
    ) -> AssessmentFinding:
        """
        Assess a single element and generate a finding.
        """
        finding_id = f"DOC-{finding_number:04d}"
        
        # Determine status based on confidence
        if confidence >= 0.525:
            status = "found"
            severity = AssessmentSeverity.INFO
            recommendation = f"Content for '{element.name}' appears to be adequately covered."
        elif confidence >= 0.25:
            status = "partial"
            severity = AssessmentSeverity.MEDIUM if element.required else AssessmentSeverity.LOW
            recommendation = (
                f"'{element.name}' appears to be partially covered. "
                f"Consider expanding this section to include: {', '.join(element.keywords[:3])}."
            )
        else:
            status = "missing"
            severity = AssessmentSeverity.HIGH if element.required else AssessmentSeverity.MEDIUM
            recommendation = (
                f"'{element.name}' was not found in the document. "
                f"This section should address: {element.description}"
            )
        
        # Extract content snippet if section found
        snippet = None
        matched_section_name = None
        if section:
            matched_section_name = section.heading
            content_preview = section.content[:200] if section.content else ""
            snippet = content_preview + "..." if len(section.content) > 200 else content_preview
        
        return AssessmentFinding(
            finding_id=finding_id,
            element_id=element.element_id,
            element_name=element.name,
            status=status,
            severity=severity,
            confidence=confidence,
            matched_section=matched_section_name,
            matched_content_snippet=snippet,
            compliance_refs=element.compliance_refs,
            recommendation=recommendation,
            details={
                'required': element.required,
                'weight': element.weight,
                'keywords_searched': element.keywords
            }
        )


# =============================================================================
# DOCUMENT ASSESSMENT SERVICE
# =============================================================================

class DocumentAssessmentService:
    """
    Main service class for document assessment.
    Orchestrates parsing, mapping, and assessment operations.
    """
    
    # Template storage path
    TEMPLATES_PATH = Path(__file__).parent / 'document_templates'
    
    @classmethod
    def assess_document(
        cls,
        file_path: str,
        document_type: Optional[DocumentType] = None,
        frameworks: Optional[List[ComplianceFramework]] = None
    ) -> DocumentAssessmentResult:
        """
        Perform full assessment of a document.
        
        Args:
            file_path: Path to the document file
            document_type: Optional override for document type (auto-detected if not provided)
            frameworks: Optional list of frameworks to assess against
            
        Returns:
            DocumentAssessmentResult with findings and scores
        """
        # Parse document
        logger.info(f"Parsing document: {file_path}")
        full_text, metadata, sections = DocumentParser.parse_document(file_path)
        
        # Determine document type
        if document_type:
            doc_type = document_type
        else:
            doc_type = metadata.detected_document_type
        
        if doc_type == DocumentType.UNKNOWN:
            logger.warning("Could not determine document type, using CPS template as default")
            doc_type = DocumentType.CERTIFICATE_PRACTICE_STATEMENT
        
        # Load appropriate template
        template = cls._load_template(doc_type)
        template_name = template.get('name', doc_type.value)
        
        # Get elements from template
        template_elements = cls._parse_template_elements(template)
        
        # Map sections to elements
        logger.info(f"Mapping {len(sections)} sections to {len(template_elements)} template elements")
        mappings = SectionMapper.map_sections_to_template(
            sections, template_elements, full_text
        )
        
        # Assess content
        logger.info("Assessing document content")
        findings = ContentAssessor.assess_content(mappings, full_text, doc_type)
        
        # Calculate scores
        coverage_score = cls._calculate_coverage_score(findings, template_elements)
        compliance_scores = cls._calculate_compliance_scores(findings, template)
        
        # Generate summary
        summary = cls._generate_summary(findings, coverage_score, compliance_scores)
        
        # Create result
        assessment_id = hashlib.sha256(
            f"{file_path}_{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        result = DocumentAssessmentResult(
            assessment_id=assessment_id,
            document_metadata=metadata,
            document_type=doc_type,
            template_used=template_name,
            assessed_at=datetime.now().isoformat(),
            sections_found=sections,
            findings=findings,
            coverage_score=coverage_score,
            compliance_scores=compliance_scores,
            summary=summary
        )
        
        logger.info(f"Assessment complete. Coverage score: {coverage_score:.1f}%")
        return result
    
    @classmethod
    def _load_template(cls, document_type: DocumentType) -> Dict[str, Any]:
        """Load assessment template for document type"""
        # First try to load from file
        template_file = cls.TEMPLATES_PATH / f"{document_type.value}.json"
        
        if template_file.exists():
            with open(template_file, 'r') as f:
                return json.load(f)
        
        # Fall back to built-in templates
        return cls._get_builtin_template(document_type)
    
    @classmethod
    def _get_builtin_template(cls, document_type: DocumentType) -> Dict[str, Any]:
        """Get built-in template for document type"""
        # Import templates from the templates module
        from .document_templates import get_template
        return get_template(document_type)
    
    @classmethod
    def _parse_template_elements(cls, template: Dict[str, Any]) -> List[AssessmentElement]:
        """Parse template into assessment elements"""
        elements = []
        
        for section in template.get('sections', []):
            # Create element for section itself
            section_element = AssessmentElement(
                element_id=section['id'],
                name=section['name'],
                description=section.get('description', ''),
                keywords=section.get('keywords', []),
                aliases=section.get('aliases', []),
                required=section.get('required', False),
                weight=section.get('weight', 5),
                compliance_refs=section.get('compliance_refs', []),
                parent_section_id=None
            )
            elements.append(section_element)
            
            # Create elements for sub-elements
            for sub_element in section.get('elements', []):
                element = AssessmentElement(
                    element_id=sub_element['id'],
                    name=sub_element.get('name', sub_element['id']),
                    description=sub_element.get('description', ''),
                    keywords=sub_element.get('keywords', []),
                    aliases=sub_element.get('aliases', []),
                    required=sub_element.get('required', False),
                    weight=sub_element.get('weight', 5),
                    compliance_refs=sub_element.get('compliance_refs', []),
                    parent_section_id=section['id']
                )
                elements.append(element)
        
        return elements
    
    @classmethod
    def _calculate_coverage_score(
        cls,
        findings: List[AssessmentFinding],
        elements: List[AssessmentElement]
    ) -> float:
        """Calculate overall coverage score (0-100)"""
        if not elements:
            return 0.0
        
        total_weight = sum(e.weight for e in elements)
        achieved_weight = 0.0
        
        element_map = {e.element_id: e for e in elements}
        
        for finding in findings:
            element = element_map.get(finding.element_id)
            if not element:
                continue
            
            if finding.status == "found":
                achieved_weight += element.weight * finding.confidence
            elif finding.status == "partial":
                achieved_weight += element.weight * finding.confidence * 0.65
        
        if total_weight == 0:
            return 0.0
        
        return (achieved_weight / total_weight) * 100
    
    @classmethod
    def _calculate_compliance_scores(
        cls,
        findings: List[AssessmentFinding],
        template: Dict[str, Any]
    ) -> Dict[str, float]:
        """Calculate per-framework compliance scores"""
        frameworks = template.get('frameworks', ['RFC3647', 'NCSC', 'NIST'])
        scores = {}
        
        for framework in frameworks:
            framework_findings = [
                f for f in findings
                if any(framework in ref for ref in f.compliance_refs)
            ]
            
            if not framework_findings:
                scores[framework] = 0.0
                continue
            
            found = sum(1 for f in framework_findings if f.status == "found")
            partial = sum(1 for f in framework_findings if f.status == "partial")
            total = len(framework_findings)
            
            scores[framework] = ((found + partial * 0.65) / total) * 100 if total > 0 else 0.0
        
        return scores
    
    @classmethod
    def _generate_summary(
        cls,
        findings: List[AssessmentFinding],
        coverage_score: float,
        compliance_scores: Dict[str, float]
    ) -> Dict[str, Any]:
        """Generate assessment summary"""
        found_count = sum(1 for f in findings if f.status == "found")
        partial_count = sum(1 for f in findings if f.status == "partial")
        missing_count = sum(1 for f in findings if f.status == "missing")
        
        critical_missing = [
            f for f in findings
            if f.status == "missing" and f.severity in [AssessmentSeverity.CRITICAL, AssessmentSeverity.HIGH]
        ]
        
        return {
            'total_elements_assessed': len(findings),
            'elements_found': found_count,
            'elements_partial': partial_count,
            'elements_missing': missing_count,
            'coverage_score': round(coverage_score, 1),
            'compliance_scores': {k: round(v, 1) for k, v in compliance_scores.items()},
            'critical_gaps': [
                {
                    'element': f.element_name,
                    'recommendation': f.recommendation
                }
                for f in critical_missing[:5]  # Top 5 critical gaps
            ],
            'assessment_grade': cls._calculate_grade(compliance_scores)
        }
    
    @staticmethod
    def _calculate_grade(compliance_scores: Dict[str, float]) -> str:
        """Calculate letter grade from average compliance score"""
        if not compliance_scores:
            return 'F'
        
        # Calculate average of all compliance framework scores
        avg_score = sum(compliance_scores.values()) / len(compliance_scores)
        
        if avg_score >= 90:
            return 'A'
        elif avg_score >= 80:
            return 'B'
        elif avg_score >= 70:
            return 'C'
        elif avg_score >= 60:
            return 'D'
        else:
            return 'F'
    
    @classmethod
    def get_supported_document_types(cls) -> List[Dict[str, str]]:
        """Get list of supported document types"""
        return [
            {
                'id': DocumentType.CERTIFICATE_PRACTICE_STATEMENT.value,
                'name': 'Certificate Practice Statement (CPS)',
                'description': 'Details how a CA operates and issues certificates'
            },
            {
                'id': DocumentType.CERTIFICATE_POLICY.value,
                'name': 'Certificate Policy (CP)',
                'description': 'Defines certificate usage rules and requirements'
            },
            {
                'id': DocumentType.PKI_DESIGN.value,
                'name': 'PKI Design Document',
                'description': 'Technical architecture and design specifications'
            },
            {
                'id': DocumentType.KEY_MANAGEMENT_PLAN.value,
                'name': 'Key Management Plan',
                'description': 'Cryptographic key lifecycle procedures'
            },
            {
                'id': DocumentType.PKI_OPERATIONAL_PROCESS.value,
                'name': 'PKI Operational Process Document',
                'description': 'Day-to-day operational procedures'
            },
            {
                'id': DocumentType.BUSINESS_CONTINUITY.value,
                'name': 'Business Continuity Document',
                'description': 'Disaster recovery and continuity planning'
            }
        ]
    
    @classmethod
    def list_available_templates(cls) -> List[Dict[str, Any]]:
        """List all available assessment templates"""
        templates = []
        
        for doc_type in DocumentType:
            if doc_type == DocumentType.UNKNOWN:
                continue
            
            try:
                template = cls._load_template(doc_type)
                templates.append({
                    'document_type': doc_type.value,
                    'name': template.get('name', doc_type.value),
                    'version': template.get('version', '1.0'),
                    'frameworks': template.get('frameworks', []),
                    'section_count': len(template.get('sections', []))
                })
            except Exception as e:
                logger.warning(f"Could not load template for {doc_type}: {e}")
        
        return templates
