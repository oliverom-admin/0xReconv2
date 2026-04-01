# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: caip_scanning_functions/collectors/crl_collector.py
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
CRL (Certificate Revocation List) collector and validator
"""

import datetime
import logging
from datetime import timezone
from typing import Optional, Dict, List

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
from cryptography.exceptions import InvalidSignature

from ..models import CertificateInfo, CRLInfo, DEPENDENCIES_AVAILABLE

# Set up logging
logger = logging.getLogger(__name__)


class CRLCollectionError(Exception):
    """Base exception for CRL collection errors"""
    pass


class CRLDownloadError(CRLCollectionError):
    """Error downloading CRL from URL"""
    pass


class CRLParseError(CRLCollectionError):
    """Error parsing CRL data"""
    pass


class CRLCollector:
    """Download and parse Certificate Revocation Lists (CRLs)"""
    
    def __init__(self, timeout: int = 30):
        """
        Initialize CRL Collector.
        
        Args:
            timeout: Timeout in seconds for HTTP requests
        """
        self.timeout = timeout
        self.cache = {}  # Cache CRLs by URL to avoid duplicate downloads
        print(f"CRLCollector initialized with timeout={timeout}")
    
    def collect_crl(self, url: str) -> Optional[CRLInfo]:
        """
        Download and parse CRL from URL.
        
        Args:
            url: URL to download CRL from
            
        Returns:
            CRLInfo if successful, None otherwise
        """
        
        # Check cache first
        if url in self.cache:
            print(f"  Using cached CRL for {url}")
            return self.cache[url]
        
        if not DEPENDENCIES_AVAILABLE['requests']:
            print(f"  ❌ Cannot fetch CRL (requests library not available)")
            return None
        
        import requests
        
        print(f"  Fetching CRL from {url}...")
        
        try:
            # Download CRL
            response = requests.get(url, timeout=self.timeout, verify=False)
            
            if response.status_code != 200:
                print(f"  ❌ HTTP {response.status_code}")
                return None
            
            # Parse CRL (try both DER and PEM)
            crl = None
            crl_data = response.content

            if not crl_data or len(crl_data) == 0:
                print(f"  ❌ Empty CRL response from {url}")
                logger.error(f"Empty CRL response from {url}")
                return None

            try:
                crl = x509.load_der_x509_crl(crl_data, default_backend())
                logger.debug(f"Successfully parsed CRL as DER format from {url}")
            except (ValueError, TypeError) as der_error:
                logger.debug(f"DER parsing failed for {url}: {der_error}, trying PEM format")
                try:
                    crl = x509.load_pem_x509_crl(crl_data, default_backend())
                    logger.debug(f"Successfully parsed CRL as PEM format from {url}")
                except (ValueError, TypeError) as pem_error:
                    error_msg = f"Failed to parse CRL from {url}: DER error: {der_error}, PEM error: {pem_error}"
                    print(f"  ❌ Failed to parse CRL (invalid format)")
                    logger.error(error_msg)
                    return None
            
            # Extract issuer
            issuer = {}
            for attr in crl.issuer:
                issuer[attr.oid._name] = attr.value
            
            # Get CRL number
            crl_number = None
            try:
                crl_num_ext = crl.extensions.get_extension_for_oid(ExtensionOID.CRL_NUMBER)
                crl_number = crl_num_ext.value.crl_number
            except x509.ExtensionNotFound:
                logger.debug(f"CRL number extension not found in CRL from {url}")
            except (AttributeError, ValueError) as e:
                logger.warning(f"Failed to extract CRL number from {url}: {e}")
            
            # Get revoked certificates
            revoked = []
            for revoked_cert in crl:
                # Handle both old and new cryptography library versions
                try:
                    revocation_date = revoked_cert.revocation_date_utc
                except AttributeError:
                    revocation_date = revoked_cert.revocation_date
                
                revocation_info = {
                    "serial_number": f"{revoked_cert.serial_number:X}",
                    "revocation_date": revocation_date.isoformat()
                }

                # Try to get revocation reason (CRL reason code extension on revoked cert entry)
                try:
                    if hasattr(revoked_cert, 'extensions') and revoked_cert.extensions:
                        try:
                            # Reason code is stored with OID 2.5.29.21 (cRLReason)
                            reason_ext = revoked_cert.extensions.get_extension_for_oid(
                                x509.ObjectIdentifier("2.5.29.21")
                            )
                            revocation_info["reason"] = str(reason_ext.value.reason)
                        except x509.ExtensionNotFound:
                            pass  # No reason extension is normal
                except (AttributeError, ValueError, TypeError) as e:
                    logger.debug(f"Could not extract revocation reason for serial {revocation_info.get('serial_number', 'unknown')}: {e}")
                
                revoked.append(revocation_info)
            
            # Check if CRL is stale
            try:
                next_update = crl.next_update_utc
            except AttributeError:
                next_update = crl.next_update
            
            try:
                last_update = crl.last_update_utc
            except AttributeError:
                last_update = crl.last_update
            
            # Ensure next_update is timezone-aware
            if next_update.tzinfo is None:
                next_update = next_update.replace(tzinfo=timezone.utc)
            
            # Ensure last_update is timezone-aware
            if last_update.tzinfo is None:
                last_update = last_update.replace(tzinfo=timezone.utc)
            
            is_stale = datetime.datetime.now(timezone.utc) > next_update
            
            # Calculate how stale
            if is_stale:
                days_stale = (datetime.datetime.now(timezone.utc) - next_update).days
                print(f"  ⚠️  CRL is STALE by {days_stale} days!")
            
            crl_info = CRLInfo(
                issuer=issuer,
                this_update=last_update.isoformat(),
                next_update=next_update.isoformat(),
                revoked_certificates=revoked,
                signature_algorithm=crl.signature_algorithm_oid._name,
                crl_number=crl_number,
                source_url=url,
                is_stale=is_stale,
                total_revoked=len(revoked),
                fetch_timestamp=datetime.datetime.now(timezone.utc).isoformat()
            )
            
            # Cache the result
            self.cache[url] = crl_info
            
            print(f"  ✅ CRL downloaded: {len(revoked)} revoked certificates")
            if crl_number:
                print(f"    CRL Number: {crl_number}")
            print(f"    Valid until: {next_update.isoformat()[:19]}")
            
            return crl_info
        
        except requests.exceptions.Timeout:
            error_msg = f"Timeout after {self.timeout}s fetching CRL from {url}"
            print(f"  ❌ Timeout fetching CRL")
            logger.error(error_msg)
            return None
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Connection error fetching CRL from {url}: {e}"
            print(f"  ❌ Connection failed: {e}")
            logger.error(error_msg)
            return None
        except requests.exceptions.SSLError as e:
            error_msg = f"SSL/TLS error fetching CRL from {url}: {e}"
            print(f"  ❌ SSL error: {e}")
            logger.error(error_msg)
            return None
        except requests.exceptions.RequestException as e:
            error_msg = f"Request error fetching CRL from {url}: {e}"
            print(f"  ❌ Request failed: {e}")
            logger.error(error_msg)
            return None
        except (ValueError, TypeError) as e:
            error_msg = f"Data processing error for CRL from {url}: {e}"
            print(f"  ❌ Data error: {e}")
            logger.error(error_msg)
            return None
        except Exception as e:
            error_msg = f"Unexpected error processing CRL from {url}: {type(e).__name__}: {e}"
            print(f"  ❌ Error processing CRL: {e}")
            logger.exception(error_msg)
            return None
    
    def check_certificate_revocation(self, cert: CertificateInfo, crl_info: CRLInfo) -> bool:
        """
        Check if certificate is revoked in CRL.
        
        Args:
            cert: Certificate to check
            crl_info: CRL to check against
            
        Returns:
            True if revoked, False otherwise
        """
        for revoked in crl_info.revoked_certificates:
            if revoked['serial_number'] == cert.serial_number:
                return True
        return False
    
    def collect_crls_for_certificates(self, certificates: List[CertificateInfo]) -> Dict[str, CRLInfo]:
        """
        Collect all CRLs referenced by certificates.
        
        Args:
            certificates: List of certificates to extract CRL URLs from
            
        Returns:
            Dictionary mapping CRL URLs to CRLInfo objects
        """
        print("\n[CRL Collection] Gathering CRLs from certificates...")
        
        # Get unique CRL URLs
        crl_urls = set()
        for cert in certificates:
            if cert.crl_distribution_points:
                crl_urls.update(cert.crl_distribution_points)
        
        print(f"  Found {len(crl_urls)} unique CRL URLs")
        
        if not crl_urls:
            print("  No CRL URLs found in certificates")
            return {}
        
        # Download CRLs
        crl_results = {}
        for url in crl_urls:
            crl_info = self.collect_crl(url)
            if crl_info:
                crl_results[url] = crl_info
        
        print(f"  Successfully downloaded {len(crl_results)}/{len(crl_urls)} CRLs")
        
        return crl_results
