# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: caip_scanning_functions/collectors/file_share.py
# Copied: 2026-04-01
# Used in: Phase 6 — Remaining Collectors
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
File share certificate scanner
Scans certificate files from network shares and local directories
"""

import os
import re
import hashlib
import datetime
import logging
from datetime import timezone
from pathlib import Path
from typing import Dict, List, Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID

from ..models import CertificateInfo, Finding

# Set up logging
logger = logging.getLogger(__name__)


class FileShareError(Exception):
    """Base exception for file share scanning errors"""
    pass


class FileAccessError(FileShareError):
    """Error accessing file or directory"""
    pass


class FileParseError(FileShareError):
    """Error parsing file contents"""
    pass


class FileShareScanner:
    """
    Scans file shares and local drives for cryptographic assets
    Supports searching for specific file types and regex patterns
    With recursion depth limiting to 20 levels
    """
    
    # Default cryptographic file extensions
    DEFAULT_CRYPTO_EXTENSIONS = {
        '.pem': 'PEM Certificate/Key',
        '.crt': 'X.509 Certificate',
        '.cer': 'X.509 Certificate',
        '.p12': 'PKCS#12 Archive',
        '.pfx': 'PKCS#12 Archive',
        '.key': 'Private Key',
        '.pub': 'Public Key',
        '.der': 'DER Certificate',
        '.p7b': 'PKCS#7 Archive',
        '.jks': 'Java KeyStore',
        '.keystore': 'Java KeyStore',
        '.pkcs8': 'PKCS#8 Key',
        '.pks': 'PKCS#12 Archive',
        '.pvk': 'Private Key',
        '.pssc': 'PowerShell Certificate',
    }
    
    # Default regex patterns for detecting cryptographic content
    DEFAULT_REGEX_PATTERNS = [
        r'-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----',
        r'-----BEGIN ENCRYPTED PRIVATE KEY-----',
        r'-----BEGIN CERTIFICATE-----',
        r'-----BEGIN CERTIFICATE REQUEST-----',
        r'-----BEGIN PUBLIC KEY-----',
        r'MIIBIjANBgkqhkiG9w0BA',  # Base64 start of DER certificate
        r'-----BEGIN PKCS7-----',
        r'-----BEGIN CMS SIGNED DATA-----',
        r'Proc-Type: 4,ENCRYPTED',  # OpenSSL encrypted key indicator
    ]
    
    MAX_RECURSION_DEPTH = 20  # Limit directory recursion to prevent runaway scans
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, progress_callback: Optional[callable] = None):
        """Initialize FileShareScanner with optional configuration and progress callback"""
        self.config = config or {}
        self.crypto_extensions = set(self.config.get('crypto_extensions', self.DEFAULT_CRYPTO_EXTENSIONS.keys()))
        #self.regex_patterns = [re.compile(p) for p in self.config.get('regex_patterns', self.DEFAULT_REGEX_PATTERNS)]
        self.regex_patterns = [re.compile(p, re.MULTILINE) for p in self.config.get('regex_patterns', self.DEFAULT_REGEX_PATTERNS)]
        self.max_file_size = self.config.get('max_file_size_mb', 100) * 1024 * 1024
        self.timeout_seconds = self.config.get('timeout_seconds', 30)
        self.results = []
        self.files_scanned = 0
        self.progress_callback = progress_callback
        self._depth_map = {}  # Track directory depth
        
    def _log_progress(self, message: str):
        """Log progress through callback if provided"""
        if self.progress_callback:
            self.progress_callback(message)
        else:
            print(message)
    
    def _get_directory_depth(self, path: Path) -> int:
        """Calculate directory depth relative to base path"""
        try:
            return len(path.parts)
        except (AttributeError, TypeError) as e:
            logger.debug(f"Error calculating directory depth for {path}: {e}")
            return 0
    
    def scan_path(self, path: str, base_path: Optional[Path] = None) -> List[Dict[str, Any]]:
        """
        Scan a file share or local path for cryptographic assets
        
        Args:
            path: UNC path (\\server\share) or local path (C:\path)
            base_path: Base path for depth calculation (set on first call)
            
        Returns:
            List of findings with file info and match details
        """
        results = []
        path_obj = Path(path)
        
        # Set base path for depth tracking on first call
        if base_path is None:
            base_path = path_obj
            self._log_progress(f"[File Scan] Starting scan of {path}")
        
        try:
            if not path_obj.exists():
                self._log_progress(f"    WARNING: Path does not exist: {path}")
                return results
            
            # Calculate current depth
            current_depth = len(path_obj.relative_to(base_path).parts)
            
            # Check recursion depth limit
            if current_depth > self.MAX_RECURSION_DEPTH:
                self._log_progress(f"    WARNING: Max recursion depth ({self.MAX_RECURSION_DEPTH}) reached at {path}")
                return results
            
            # Scan files in current directory only
            try:
                for item in path_obj.iterdir():
                    try:
                        if item.is_file():
                            file_result = self._scan_file(item)
                            if file_result:
                                results.append(file_result)
                                self.files_scanned += 1
                                # Log progress every 10 files
                                if self.files_scanned % 10 == 0:
                                    self._log_progress(f"[File Scan] Scanned {self.files_scanned} files, found {len(self.results)} cryptographic assets")
                        elif item.is_dir() and current_depth < self.MAX_RECURSION_DEPTH:
                            # Recursively scan subdirectory
                            subdir_results = self.scan_path(str(item), base_path)
                            results.extend(subdir_results)
                    except PermissionError as e:
                        logger.debug(f"Permission denied accessing {item}: {e}")
                        continue
                    except OSError as e:
                        logger.warning(f"OS error accessing {item}: {e}")
                        continue

            except PermissionError as e:
                self._log_progress(f"    WARNING: Permission denied accessing {path}")
                logger.warning(f"Permission denied listing directory {path}: {e}")
                
        except Exception as e:
            self._log_progress(f"    ERROR scanning path {path}: {str(e)}")
            logger.exception(f"Unexpected error scanning path {path}: {type(e).__name__}: {e}")
            
        self.results.extend(results)
        return results
    
    def _scan_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Scan individual file for cryptographic content
        Only flag by extension - no content parsing required
        
        Returns:
            Dict with file info and matches, or None if not cryptographic
        """
        try:
            # Check file extension - this is the primary detection method
            extension_match = file_path.suffix.lower() in self.crypto_extensions
            
            # If extension doesn't match, check content for text files only
            if not extension_match:
                # Skip binary files and large files if no extension match
                try:
                    file_size = file_path.stat().st_size
                    if file_size > self.max_file_size:
                        return None
                    
                    # Only attempt content reading for small text files
                    if file_size < 100000:  # Only check content for files < 100KB
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                content = f.read(10000)  # Read first 10KB
                                
                                # Check for regex matches
                                regex_matches = []
                                for pattern in self.regex_patterns:
                                    if pattern.search(content):
                                        regex_matches.append(pattern.pattern)
                                
                                if regex_matches:
                                    extension_match = False
                                else:
                                    return None
                        except (UnicodeDecodeError, PermissionError):
                            return None
                    else:
                        return None
                except (OSError, IOError) as e:
                    logger.debug(f"Error reading file {file_path}: {e}")
                    return None

            # File matched on extension or content
            if extension_match or (not extension_match and 'regex_matches' in locals() and regex_matches):
                try:
                    file_size = file_path.stat().st_size
                    modified_time = datetime.datetime.fromtimestamp(
                        file_path.stat().st_mtime,
                        tz=timezone.utc
                    ).isoformat()
                except (OSError, IOError, ValueError) as e:
                    logger.debug(f"Error getting file stats for {file_path}: {e}")
                    file_size = 0
                    modified_time = None
                
                # Determine confidence based on detection method
                if extension_match and file_path.suffix.lower() in self.DEFAULT_CRYPTO_EXTENSIONS:
                    confidence = 'high'
                else:
                    confidence = 'medium'
                
                # Collect matched patterns if available
                matched_patterns = []
                if 'regex_matches' in locals() and regex_matches:
                    matched_patterns = regex_matches
                
                # Read file content for rule evaluation
                # Important: Always attempt to read content for files with crypto extensions
                # This is needed for content_matches_any() function in rule assessment
                file_content = None
                if file_path.suffix.lower() in ['.key', '.pem', '.pkcs8', '.pvk', '.cer', '.crt', '.p12', '.pfx']:
                    try:
                        file_size_check = file_path.stat().st_size
                        if file_size_check < 100000:  # Only read small files
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                file_content = f.read(10000)  # Read first 10KB
                    except (IOError, OSError, PermissionError) as e:
                        logger.debug(f"Error reading file content for {file_path}: {e}")
                        file_content = None
                
                return {
                    'file_path': str(file_path),
                    'file_name': file_path.name,
                    'file_size': file_size,
                    'extension': file_path.suffix.lower(),
                    'extension_type': self.DEFAULT_CRYPTO_EXTENSIONS.get(file_path.suffix.lower(), 'Unknown'),
                    'extension_match': extension_match,
                    'modified_time': modified_time,
                    'confidence': confidence,
                    'file_content': file_content,
                    'matched_patterns': matched_patterns,
                    'matched_pattern': matched_patterns[0] if matched_patterns else None
                }
        except Exception as e:
            # Silently skip files that can't be read
            pass
            
        return None
    
    def get_results_summary(self) -> Dict[str, Any]:
        """Get summary of all scan results"""
        return {
            'total_files_found': len(self.results),
            'high_confidence': sum(1 for r in self.results if r['confidence'] == 'high'),
            'medium_confidence': sum(1 for r in self.results if r['confidence'] == 'medium'),
            'total_size_bytes': sum(r['file_size'] for r in self.results),
            'files_scanned': self.files_scanned,
            'files': self.results
        }
    
    def convert_results_to_findings(self) -> List['Finding']:
        """
        Convert file scan results to Finding objects for integration into report
        
        Returns:
            List of Finding objects for discovered cryptographic files
        """
        findings = []
        
        for idx, file_result in enumerate(self.results, 1):
            # Determine severity based on file type and confidence
            extension = file_result.get('extension', '').lower()
            confidence = file_result.get('confidence', 'medium')
            
            # Private key files and keystores get higher severity
            if extension in ['.key', '.pfx', '.p12', '.pkcs8', '.pvk', '.jks', '.keystore']:
                severity = 'high'
                risk_score = 8.5
            elif extension in ['.pem', '.cer', '.crt', '.der']:
                severity = 'medium'
                risk_score = 5.0
            else:
                severity = 'low'
                risk_score = 2.0
            
            file_path = file_result.get('file_path', 'unknown')
            file_name = file_result.get('file_name', 'unknown')
            extension_type = file_result.get('extension_type', 'Cryptographic Asset')
            
            finding = Finding(
                id=f"FILE_SCAN_{idx:04d}",
                severity=severity,
                title=f"Cryptographic Asset Discovered: {file_name}",
                description=f"Discovered {extension_type} at {file_path}. File size: {file_result.get('file_size', 0)} bytes. Last modified: {file_result.get('modified_time', 'unknown')}. Confidence: {confidence}.",
                affected_entities=[file_path],
                remediation=f"Review the location and access controls for this cryptographic asset. Ensure it is properly secured and only accessible to authorized systems. Consider centralizing key management using a dedicated key management system.",
                risk_score=risk_score,
                category="file_scan"
            )
            findings.append(finding)
        
        return findings


print("FileShareScanner class defined")


# Policy Assessor
