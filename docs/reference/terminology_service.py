from typing import Dict, List, Set, Tuple, Optional
import re

# Optional dependencies for enhanced matching
try:
    from nltk.stem import PorterStemmer
    from nltk.tokenize import word_tokenize
    import nltk
    # Ensure punkt tokenizer is available
    try:
        nltk.data.find('tokenizers/punkt')
    except LookupError:
        nltk.download('punkt', quiet=True)
    try:
        nltk.data.find('tokenizers/punkt_tab')
    except LookupError:
        nltk.download('punkt_tab', quiet=True)
    STEMMING_AVAILABLE = True
except ImportError:
    STEMMING_AVAILABLE = False
    PorterStemmer = None

try:
    from rapidfuzz import fuzz
    FUZZY_AVAILABLE = True
except ImportError:
    FUZZY_AVAILABLE = False
    fuzz = None


# =============================================================================
# TERMINOLOGY SERVICE CLASS
# =============================================================================

class TerminologyDictionary:
    """
    Comprehensive PKI terminology service providing synonym matching,
    abbreviation expansion, and term categorization.
    """
    
    def __init__(
        self,
        synonyms: dict[str, list[str]],
        abbreviations: dict[str, list[str]] = None,
        compound_terms: list[str] = None,
        regulatory_terms: dict[str, dict[str, list[str]]] = None
    ):
        self.synonyms = synonyms
        self.abbreviations = abbreviations or {}
        self.regulatory_terms = regulatory_terms or {}
        self.compound_terms = set(compound_terms or [])
        
        # Build reverse lookup for synonyms
        self._synonym_reverse: dict[str, str] = {}
        for canonical, variants in self.synonyms.items():
            for variant in variants:
                self._synonym_reverse[variant.lower()] = canonical
        
        # Build reverse lookup for abbreviations
        self._abbrev_reverse: dict[str, str] = {}
        for abbrev, expansions in self.abbreviations.items():
            for expansion in expansions:
                self._abbrev_reverse[expansion.lower()] = abbrev
        
        # Initialize stemmer if available
        self._stemmer = PorterStemmer() if STEMMING_AVAILABLE else None
        
        # Build stemmed variants cache for faster matching
        self._stemmed_variants: dict[str, set[str]] = {}
        if self._stemmer:
            for canonical, variants in self.synonyms.items():
                stemmed_set = set()
                # Stem the canonical term
                for word in canonical.replace('_', ' ').split():
                    stemmed_set.add(self._stemmer.stem(word.lower()))
                # Stem all variants
                for variant in variants:
                    for word in variant.split():
                        stemmed_set.add(self._stemmer.stem(word.lower()))
                self._stemmed_variants[canonical] = stemmed_set
    
    def get_canonical_term(self, term: str) -> Optional[str]:
        """Get the canonical term for a given variant."""
        term_lower = term.lower().strip()
        
        # Check if it's already a canonical term
        if term_lower in self.synonyms:
            return term_lower
        
        # Check reverse lookup
        return self._synonym_reverse.get(term_lower)
    
    def get_synonyms(self, term: str) -> list[str]:
        """Get all synonyms for a term (including the term itself)."""
        canonical = self.get_canonical_term(term)
        if canonical:
            return [canonical] + self.synonyms.get(canonical, [])
        return [term]
    
    def expand_abbreviation(self, abbrev: str) -> list[str]:
        """Expand an abbreviation to its full forms."""
        return self.abbreviations.get(abbrev.upper(), [])
    
    def get_abbreviation(self, term: str) -> Optional[str]:
        """Get the abbreviation for a full term."""
        return self._abbrev_reverse.get(term.lower())
    
    def is_compound_term(self, term: str) -> bool:
        """Check if a term is a recognized compound term."""
        return term.lower() in self.compound_terms
    
    def get_regulatory_terms(self, framework: str) -> dict[str, list[str]]:
        """Get terms specific to a regulatory framework."""
        return self.regulatory_terms.get(framework.lower(), {})
    
    def match_term(self, text: str, threshold: float = 0.3, 
                   use_stemming: bool = True, use_fuzzy: bool = True,
                   fuzzy_threshold: int = 85) -> list[Tuple[str, float, str]]:
        """
        Match text against terminology dictionary.
        
        Args:
            text: Text to search for terminology matches
            threshold: Minimum confidence score (0.0-1.0)
            use_stemming: Enable stemmed matching (requires nltk)
            use_fuzzy: Enable fuzzy matching (requires rapidfuzz)
            fuzzy_threshold: Minimum fuzzy match score (0-100)
        
        Returns list of (canonical_term, confidence, matched_text) tuples.
        """
        matches = []
        text_lower = text.lower()
        
        # Check compound terms first (most specific, highest confidence)
        for compound in self.compound_terms:
            if compound in text_lower:
                canonical = self.get_canonical_term(compound)
                if canonical:
                    matches.append((canonical, 0.95, compound))
        
        # Check exact synonym matches
        for canonical, variants in self.synonyms.items():
            for variant in variants:
                if variant in text_lower:
                    matches.append((canonical, 0.85, variant))
        
        # Check abbreviations (word boundary aware)
        for abbrev, expansions in self.abbreviations.items():
            if re.search(rf'\b{re.escape(abbrev)}\b', text, re.IGNORECASE):
                for expansion in expansions:
                    canonical = self.get_canonical_term(expansion)
                    if canonical:
                        matches.append((canonical, 0.9, abbrev))
                        break
        
        # Stemmed matching - catches "revoked" -> "revocation", "certificates" -> "certificate"
        if use_stemming and self._stemmer and self._stemmed_variants:
            text_words = text_lower.split()
            text_stems = set(self._stemmer.stem(word) for word in text_words)
            
            for canonical, variant_stems in self._stemmed_variants.items():
                # Skip if already matched exactly
                if any(m[0] == canonical and m[1] >= 0.8 for m in matches):
                    continue
                
                # Check for stem overlap
                overlap = text_stems & variant_stems
                if overlap:
                    # Calculate confidence based on overlap ratio
                    overlap_ratio = len(overlap) / len(variant_stems)
                    if overlap_ratio >= 0.3:  # At least 30% stem overlap
                        confidence = 0.6 + (overlap_ratio * 0.2)  # 0.6-0.8 range
                        matched_stems = ', '.join(sorted(overlap))
                        matches.append((canonical, confidence, f"stem:{matched_stems}"))
        
        # Fuzzy matching - catches typos and OCR errors
        if use_fuzzy and FUZZY_AVAILABLE and fuzz:
            # Extract potential terms from text (2-4 word phrases)
            words = text_lower.split()
            phrases_to_check = []
            for i in range(len(words)):
                for length in range(1, min(5, len(words) - i + 1)):
                    phrase = ' '.join(words[i:i+length])
                    if len(phrase) >= 4:  # Skip very short phrases
                        phrases_to_check.append(phrase)
            
            for canonical, variants in self.synonyms.items():
                # Skip if already matched with high confidence
                if any(m[0] == canonical and m[1] >= 0.7 for m in matches):
                    continue
                
                best_fuzzy_score = 0
                best_fuzzy_match = None
                
                for variant in variants:
                    if len(variant) < 4:  # Skip very short variants
                        continue
                    for phrase in phrases_to_check:
                        score = fuzz.ratio(phrase, variant)
                        if score > best_fuzzy_score and score >= fuzzy_threshold:
                            best_fuzzy_score = score
                            best_fuzzy_match = (phrase, variant)
                
                if best_fuzzy_match:
                    confidence = 0.4 + (best_fuzzy_score / 100) * 0.35  # 0.4-0.75 range
                    matches.append((canonical, confidence, f"fuzzy:{best_fuzzy_match[0]}~{best_fuzzy_match[1]}"))
        
        # Deduplicate and sort by confidence
        seen = set()
        unique_matches = []
        for match in sorted(matches, key=lambda x: -x[1]):
            if match[0] not in seen:
                seen.add(match[0])
                unique_matches.append(match)
        
        return [m for m in unique_matches if m[1] >= threshold]
    
    def get_all_variants(self, canonical: str) -> Set[str]:
        """Get all variants of a canonical term including abbreviations."""
        variants = set()
        
        # Add canonical term
        variants.add(canonical)
        
        # Add synonyms
        variants.update(self.synonyms.get(canonical, []))
        
        # Add abbreviations
        for abbrev, expansions in self.abbreviations.items():
            for expansion in expansions:
                if self.get_canonical_term(expansion) == canonical:
                    variants.add(abbrev.lower())
        
        return variants
    
    def get_legacy_synonyms_dict(self) -> dict[str, list[str]]:
        """
        Get synonyms in the legacy SectionMapper format.
        This provides backward compatibility with existing code.
        """
        return self.synonyms.copy()
    
    def stem_text(self, text: str) -> list[str]:
        """
        Stem all words in text. Returns list of stems.
        Returns original words if stemming not available.
        """
        words = text.lower().split()
        if self._stemmer:
            return [self._stemmer.stem(word) for word in words]
        return words
    
    def fuzzy_match(self, term: str, text: str, threshold: int = 85) -> Optional[Tuple[str, int]]:
        """
        Find fuzzy match for term in text.
        
        Args:
            term: Term to search for
            text: Text to search in
            threshold: Minimum match score (0-100)
            
        Returns:
            Tuple of (matched_substring, score) or None if no match above threshold
        """
        if not FUZZY_AVAILABLE or not fuzz:
            return None
        
        text_lower = text.lower()
        term_lower = term.lower()
        
        # Check partial ratio for substring matching
        score = fuzz.partial_ratio(term_lower, text_lower)
        if score >= threshold:
            return (term, score)
        
        return None
    
    def stems_match(self, term1: str, term2: str) -> bool:
        """
        Check if two terms match when stemmed.
        E.g., "revoked" and "revocation" both stem to "revok".
        """
        if not self._stemmer:
            return term1.lower() == term2.lower()
        
        stems1 = set(self._stemmer.stem(w) for w in term1.lower().split())
        stems2 = set(self._stemmer.stem(w) for w in term2.lower().split())
        
        return bool(stems1 & stems2)
    
    @staticmethod
    def is_stemming_available() -> bool:
        """Check if stemming functionality is available."""
        return STEMMING_AVAILABLE
    
    @staticmethod
    def is_fuzzy_available() -> bool:
        """Check if fuzzy matching functionality is available."""
        return FUZZY_AVAILABLE

class TerminologyService:
    """Factory for domain-specific terminology dictionaries."""
    _instances: Dict[str, TerminologyDictionary] = {}
    
    @classmethod
    def register(cls, domain: str, dictionary: TerminologyDictionary):
        """Register a terminology dictionary for a domain."""
        cls._instances[domain] = dictionary
    
    @classmethod
    def get(cls, domain: str) -> TerminologyDictionary:
        """Get terminology dictionary for a domain."""
        if domain not in cls._instances:
            raise ValueError(f"Unknown domain: {domain}")
        return cls._instances[domain]
    
    @classmethod
    def get_or_none(cls, domain: str) -> Optional[TerminologyDictionary]:
        """Get terminology dictionary or None if not registered."""
        return cls._instances.get(domain)

# =============================================================================
# MODULE-LEVEL CONVENIENCE FUNCTIONS
# =============================================================================

_default_dictionary: Optional[TerminologyDictionary] = None


def get_dictionary() -> TerminologyDictionary:
    """Get the default PKI terminology dictionary instance."""
    global _default_dictionary
    if _default_dictionary is None:
        _default_dictionary = TerminologyDictionary()
    return _default_dictionary


def get_synonyms(term: str) -> list[str]:
    """Get all synonyms for a term."""
    return get_dictionary().get_synonyms(term)


def get_canonical_term(term: str) -> Optional[str]:
    """Get the canonical term for a variant."""
    return get_dictionary().get_canonical_term(term)


def expand_abbreviation(abbrev: str) -> list[str]:
    """Expand an abbreviation."""
    return get_dictionary().expand_abbreviation(abbrev)


def match_terms(text: str) -> list[Tuple[str, float, str]]:
    """Match text against the terminology dictionary."""
    return get_dictionary().match_term(text)


def get_legacy_synonyms() -> dict[str, list[str]]:
    """Get synonyms in legacy SectionMapper format."""
    return get_dictionary().get_legacy_synonyms_dict()
