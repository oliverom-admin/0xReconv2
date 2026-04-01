# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: caip_scanning_functions/collectors/ejbca_collector.py
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
EJBCA (Enterprise Java PKI) certificate collector
Collects certificates from EJBCA servers via REST API with P12 authentication
"""

import os
import hashlib
import base64
import logging
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID

from ..models import CertificateInfo, DEPENDENCIES_AVAILABLE
from caip_pqc_functions.pqc_detector import get_detector

# Set up logging
logger = logging.getLogger(__name__)


class EJBCAError(Exception):
    """Base exception for EJBCA collector errors"""
    pass


class EJBCAConnectionError(EJBCAError):
    """Error connecting to EJBCA server"""
    pass


class EJBCAAuthenticationError(EJBCAError):
    """Error authenticating with EJBCA server"""
    pass


class EJBCAP12Error(EJBCAError):
    """Error loading or parsing P12 certificate"""
    pass


class EJBCACollector:
    def __init__(self, base_url: str, p12_path: str, p12_password: str, timeout: int = 30):
        """
        Initialize EJBCA collector
        
        Args:
            base_url: EJBCA server URL (e.g., https://ejbca.example.com:8443)
            p12_path: Path to P12 certificate file for authentication
            p12_password: Password for P12 file
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.p12_path = p12_path
        self.p12_password = p12_password
        self.timeout = timeout
        self.session = None
        self.temp_dir = None
        self._ca_cert_cache = {}  # Cache: ca_name -> list of x509 certificates (chain)
        print(f"EJBCACollector initialized for {self.base_url}")
    
    def __del__(self):
        """Cleanup temporary files on deletion"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                import shutil
                shutil.rmtree(self.temp_dir)
            except OSError as e:
                logger.warning(f"Failed to cleanup temporary directory {self.temp_dir}: {e}")
            except Exception as e:
                logger.debug(f"Unexpected error during cleanup of {self.temp_dir}: {e}")
    
    def _create_session(self) -> bool:
        """Create requests session with P12 client certificate"""
        if not DEPENDENCIES_AVAILABLE['requests']:
            print("   requests library not available")
            return False

        try:
            import os
            import tempfile
            import requests
            import urllib3
            from requests.auth import HTTPDigestAuth
            from cryptography.hazmat.primitives.serialization import pkcs12
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Validate P12 file exists
            if not os.path.exists(self.p12_path):
                error_msg = f"P12 certificate file not found: {self.p12_path}"
                print(f"   {error_msg}")
                logger.error(error_msg)
                return False

            try:
                with open(self.p12_path, 'rb') as f:
                    p12_data = f.read()
            except IOError as e:
                error_msg = f"Failed to read P12 file {self.p12_path}: {e}"
                print(f"   {error_msg}")
                logger.error(error_msg)
                return False
            except PermissionError as e:
                error_msg = f"Permission denied reading P12 file {self.p12_path}: {e}"
                print(f"   {error_msg}")
                logger.error(error_msg)
                return False

            # Parse PKCS12
            try:
                private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
                    p12_data,
                    self.p12_password.encode() if isinstance(self.p12_password, str) else self.p12_password,
                    backend=default_backend()
                )
            except ValueError as e:
                error_msg = f"Invalid P12 password or corrupted P12 file {self.p12_path}: {e}"
                print(f"   {error_msg}")
                logger.error(error_msg)
                return False
            except TypeError as e:
                error_msg = f"Invalid P12 data format in {self.p12_path}: {e}"
                print(f"   {error_msg}")
                logger.error(error_msg)
                return False

            if certificate is None:
                error_msg = f"No certificate found in P12 file {self.p12_path}"
                print(f"   {error_msg}")
                logger.error(error_msg)
                return False

            if private_key is None:
                error_msg = f"No private key found in P12 file {self.p12_path}"
                print(f"   {error_msg}")
                logger.error(error_msg)
                return False

            # Export to PEM format in memory
            try:
                # Create temporary directory for PEM files
                self.temp_dir = tempfile.mkdtemp()

                # Write certificate PEM
                cert_path = os.path.join(self.temp_dir, 'cert.pem')
                with open(cert_path, 'wb') as f:
                    f.write(certificate.public_bytes(serialization.Encoding.PEM))

                # Write private key PEM
                key_path = os.path.join(self.temp_dir, 'key.pem')
                with open(key_path, 'wb') as f:
                    f.write(private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
            except (IOError, OSError) as e:
                error_msg = f"Failed to write temporary PEM files: {e}"
                print(f"   {error_msg}")
                logger.error(error_msg)
                return False

            self.session = requests.Session()
            self.session.cert = (cert_path, key_path)
            self.session.verify = False

            print(f"  Session created with P12 authentication")
            logger.info(f"Successfully created EJBCA session for {self.base_url}")
            return True
            
        except Exception as e:
            print(f"   Failed to create session: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def get_cas(self) -> List[str]:
        """Retrieve list of Certificate Authorities from EJBCA"""
        if not self.session:
            if not self._create_session():
                return []
        
        try:
            # EJBCA REST API endpoint for CAs
            url = f"{self.base_url}/ejbca/ejbca-rest-api/v1/ca"
            print(f"  Fetching CAs from {url}")
            
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                try:
                    response_data = response.json()
                except ValueError as e:
                    error_msg = f"Invalid JSON in CA list response from {self.base_url}: {e}"
                    print(f"   Invalid JSON response: {e}")
                    logger.error(error_msg)
                    return []

                # Handle different response formats
                # Format 1: Direct list of CA names
                if isinstance(response_data, list):
                    cas = response_data
                # Format 2: Dict with 'certificate_authorities' key
                elif isinstance(response_data, dict) and 'certificate_authorities' in response_data:
                    cas = response_data['certificate_authorities']
                    # Extract CA names if they're objects
                    if isinstance(cas, list) and len(cas) > 0:
                        if isinstance(cas[0], dict):
                            # Extract name from each CA object
                            ca_names = []
                            for ca in cas:
                                if 'name' in ca:
                                    ca_names.append(ca['name'])
                                elif 'caName' in ca:
                                    ca_names.append(ca['caName'])
                            if ca_names:
                                cas = ca_names
                # Format 3: Dict with CA names as keys
                elif isinstance(response_data, dict):
                    cas = list(response_data.keys())
                else:
                    cas = []

                print(f"  Retrieved {len(cas)} Certificate Authority(ies)")
                if cas:
                    print(f"  CA Names: {cas}")
                return cas
            elif response.status_code == 401:
                error_msg = f"Authentication failed for EJBCA server {self.base_url} - check P12 certificate"
                print(f"   HTTP 401 Unauthorized")
                logger.error(error_msg)
                return []
            elif response.status_code == 403:
                error_msg = f"Access forbidden to EJBCA server {self.base_url} - insufficient permissions"
                print(f"   HTTP 403 Forbidden")
                logger.error(error_msg)
                return []
            elif response.status_code == 404:
                error_msg = f"EJBCA CA endpoint not found at {url} - check API version"
                print(f"   HTTP 404 Not Found")
                logger.error(error_msg)
                return []
            else:
                error_msg = f"EJBCA server returned HTTP {response.status_code}: {response.text[:200]}"
                print(f"   HTTP {response.status_code}: {response.text[:200]}")
                logger.error(error_msg)
                return []
        except requests.exceptions.Timeout:
            error_msg = f"Timeout connecting to EJBCA server {self.base_url}"
            print(f"   Connection timeout")
            logger.error(error_msg)
            return []
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Connection error to EJBCA server {self.base_url}: {e}"
            print(f"   Connection error: {e}")
            logger.error(error_msg)
            return []
        except requests.exceptions.RequestException as e:
            error_msg = f"Request error to EJBCA server {self.base_url}: {e}"
            print(f"   Request failed: {e}")
            logger.error(error_msg)
            return []
        except Exception as e:
            error_msg = f"Unexpected error getting CAs from {self.base_url}: {type(e).__name__}: {e}"
            print(f"   Failed to get CAs: {e}")
            logger.exception(error_msg)
            return []
    
    def _fetch_ca_certificate_chain(self, ca_name: str) -> List:
        """
        Fetch the CA certificate chain from EJBCA and cache it.
        Returns list of x509 certificate objects (issuer chain, not including leaf).
        """
        if ca_name in self._ca_cert_cache:
            return self._ca_cert_cache[ca_name]
        
        if not self.session:
            if not self._create_session():
                return []
        
        ca_certs = []
        
        try:
            # EJBCA uses issuer_dn for the certificate download endpoint, not CA name
            # First, we need to get certificates to find the issuer DN
            # Or we can try common DN patterns based on CA name
            
            # Try the certificate/download endpoint with URL-encoded issuer DN
            # Common patterns: CN={ca_name} or just the ca_name if it's already a DN
            import urllib.parse
            
            # Try different DN patterns
            dn_patterns = [
                f"CN={ca_name}",  # Common: CN=Volvo Group EJBCA Mgmt
                ca_name,          # Maybe it's already a full DN
            ]
            
            for issuer_dn in dn_patterns:
                encoded_dn = urllib.parse.quote(issuer_dn, safe='')
                url = f"{self.base_url}/ejbca/ejbca-rest-api/v1/ca/{encoded_dn}/certificate/download"
                print(f"    Trying CA cert download: {url}")
                
                response = self.session.get(url, timeout=self.timeout)
                print(f"      Response: HTTP {response.status_code}")
                
                if response.status_code == 200:
                    # Response should be PEM certificate(s)
                    pem_data = response.content
                    print(f"      Got {len(pem_data)} bytes, content starts with: {pem_data[:60]}")
                    
                    # Parse PEM certificates (may contain chain)
                    try:
                        # Split on certificate boundaries to handle multiple certs
                        pem_text = pem_data.decode('utf-8', errors='ignore')
                        cert_blocks = []
                        
                        # Find all certificate blocks
                        import re
                        cert_pattern = re.compile(
                            r'-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----',
                            re.DOTALL
                        )
                        matches = cert_pattern.findall(pem_text)
                        
                        if matches:
                            for match in matches:
                                try:
                                    # Reconstruct PEM
                                    pem_cert = f"-----BEGIN CERTIFICATE-----\n{match}\n-----END CERTIFICATE-----"
                                    cert = x509.load_pem_x509_certificate(pem_cert.encode(), default_backend())
                                    ca_certs.append(cert)
                                    cn = self._extract_subject_dict(cert).get('commonName', 'Unknown')
                                    print(f"      Parsed CA cert: {cn}")
                                except Exception as e:
                                    print(f"      Failed to parse cert block: {e}")
                        else:
                            # Try loading as single cert (might be DER)
                            try:
                                cert = x509.load_pem_x509_certificate(pem_data, default_backend())
                                ca_certs.append(cert)
                            except (ValueError, TypeError) as pem_err:
                                try:
                                    cert = x509.load_der_x509_certificate(pem_data, default_backend())
                                    ca_certs.append(cert)
                                except (ValueError, TypeError) as der_err:
                                    logger.warning(f"Failed to parse CA cert as PEM ({pem_err}) or DER ({der_err})")
                        
                        if ca_certs:
                            print(f"      Successfully retrieved {len(ca_certs)} CA certificate(s)")
                            break  # Success, stop trying patterns
                            
                    except Exception as e:
                        print(f"      Error parsing CA certificates: {e}")
                else:
                    print(f"      Response: {response.text[:200] if response.text else 'empty'}")
            
            # If download endpoint failed, try the CA list endpoint to get more info
            if not ca_certs:
                url = f"{self.base_url}/ejbca/ejbca-rest-api/v1/ca"
                print(f"    Trying CA list endpoint for issuer info: {url}")
                
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    try:
                        ca_list = response.json()
                    except ValueError as e:
                        logger.warning(f"Failed to parse CA list JSON response: {e}")
                        ca_list = {}
                    print(f"      CA list response keys/type: {type(ca_list)}")
                    
                    # Look for our CA in the list to find its DN
                    if isinstance(ca_list, dict) and 'certificate_authorities' in ca_list:
                        for ca_info in ca_list.get('certificate_authorities', []):
                            if isinstance(ca_info, dict):
                                # Check if this is our CA
                                ca_info_name = ca_info.get('name') or ca_info.get('caName') or ''
                                if ca_info_name == ca_name or ca_name in ca_info_name:
                                    print(f"      Found CA info: {ca_info.keys()}")
                                    # Try to get DN from the CA info
                                    dn = ca_info.get('dn') or ca_info.get('subjectDn') or ca_info.get('issuer_dn')
                                    if dn:
                                        print(f"      Found CA DN: {dn}")
                                        # Try downloading with the correct DN
                                        encoded_dn = urllib.parse.quote(dn, safe='')
                                        url = f"{self.base_url}/ejbca/ejbca-rest-api/v1/ca/{encoded_dn}/certificate/download"
                                        response = self.session.get(url, timeout=self.timeout)
                                        if response.status_code == 200:
                                            try:
                                                cert = x509.load_pem_x509_certificate(response.content, default_backend())
                                                ca_certs.append(cert)
                                                print(f"      Retrieved CA cert via DN lookup")
                                            except (ValueError, TypeError) as e:
                                                logger.debug(f"Failed to parse CA cert from DN lookup: {e}")
                                    break
            
        except Exception as e:
            print(f"      Failed to fetch CA certificate: {e}")
            import traceback
            traceback.print_exc()
        
        # Cache results even if empty (avoid repeated failed calls)
        self._ca_cert_cache[ca_name] = ca_certs
        return ca_certs

    def get_certificates(self, ca_name: str) -> List[CertificateInfo]:
        """
        Retrieve all certificates for a given CA using EJBCA v2 REST API
        
        Args:
            ca_name: Name of the Certificate Authority
            
        Returns:
            List of CertificateInfo objects
        """
        if not self.session:
            if not self._create_session():
                return []
        
        certificates = []
        
        try:
            print(f"  Fetching certificates for CA '{ca_name}'...")
            
            # EJBCA v2 REST API search endpoint
            url = f"{self.base_url}/ejbca/ejbca-rest-api/v2/certificate/search"
            print(f"    URL: {url}")
            
            # Build search request body for v2 API
            # CA name needs to be prefixed with CN=
            ca_search_value = f"{ca_name}"
            
            search_body = {
                "pagination": {
                    "page_size": 10,
                    "current_page": 1
                },
                "sort": {
                    "property": "USERNAME",
                    "operation": "ASC"
                },
                "criteria": [
                    {
                        "property": "CA",
                        "value": ca_search_value,
                        "operation": "EQUAL"
                    }
                ]
            }
            
            print(f"    Search criteria: CA='{ca_search_value}'")
            
            # Make POST request with search body
            response = self.session.post(
                url,
                json=search_body,
                timeout=self.timeout,
                headers={'Content-Type': 'application/json'}
            )
            
            print(f"    Response: HTTP {response.status_code}")
            
            if response.status_code == 200:
                response_data = response.json()
                
                # Extract certificates from response
                # EJBCA v2 API returns results in 'certificates' array
                cert_list = []
                
                if isinstance(response_data, dict):
                    if 'certificates' in response_data:
                        cert_list = response_data.get('certificates', [])
                        print(f"     Found 'certificates' key with {len(cert_list)} items")
                    elif 'results' in response_data:
                        cert_list = response_data.get('results', [])
                        print(f"     Found 'results' key with {len(cert_list)} items")
                    elif 'entities' in response_data:
                        cert_list = response_data.get('entities', [])
                        print(f"     Found 'entities' key with {len(cert_list)} items")
                    else:
                        print(f"     No recognized key found. Available keys: {list(response_data.keys())[:10]}")
                        cert_list = []
                elif isinstance(response_data, list):
                    cert_list = response_data
                    print(f"     Response is list with {len(cert_list)} items")
                
                print(f"    Processing {len(cert_list)} certificate(s)...")
                
                # Process each certificate
                for idx, cert_data in enumerate(cert_list):
                    try:
                        cert_obj = self._parse_certificate_response(cert_data, ca_name)
                        if cert_obj:
                            certificates.append(cert_obj)
                            print(f"      [{idx+1}]  Successfully parsed")
                        else:
                            print(f"      [{idx+1}]  Parser returned None")
                    except Exception as e:
                        print(f"      [{idx+1}]  Parse error - {str(e)[:100]}")
                        continue
            else:
                print(f"     HTTP {response.status_code}")
                if response.status_code == 400:
                    print(f"    Note: Bad request - check search criteria")
                elif response.status_code == 401:
                    print(f"    Note: Authentication failed - check P12 certificate")
                elif response.status_code == 404:
                    print(f"    Note: Endpoint not found - verify API path")
                
                # Print response body for debugging
                try:
                    print(f"    Response: {response.text[:200]}")
                except:
                    pass
                    
        except Exception as e:
            print(f"     Failed to get certificates for {ca_name}: {e}")
            import traceback
            traceback.print_exc()
        
        return certificates
    
    def _parse_certificate_response(self, cert_data: Dict, ca_name: str) -> Optional[CertificateInfo]:
        """Parse certificate data from EJBCA API response"""
        try:
            # Extract certificate data
            cert_b64 = cert_data.get('base64Cert')
            if not cert_b64:
                cert_b64 = cert_data.get('certificate')
                if not cert_b64:
                    cert_b64 = cert_data.get('cert')
                if not cert_b64:
                    return None
            
            # Convert to string and clean
            cert_b64_str = str(cert_b64).strip()
            
            # Remove b'...' wrapper if present
            if cert_b64_str.startswith("b'") and cert_b64_str.endswith("'"):
                cert_b64_str = cert_b64_str[2:-1]
            elif cert_b64_str.startswith('b"') and cert_b64_str.endswith('"'):
                cert_b64_str = cert_b64_str[2:-1]
            
            # Handle escape sequences
            cert_b64_str = cert_b64_str.replace('\\n', '\n').replace('\\r', '\r').replace('\n', '').replace('\r', '')
            
            # First base64 decode
            import base64
            try:
                decoded_once = base64.b64decode(cert_b64_str)
            except Exception as e:
                print(f"        Failed to decode base64: {e}")
                return None
            
            # Check if result is still base64 text (ASCII characters)
            # The first 20 bytes should start with 0x30 (DER SEQUENCE) for valid certificate
            # But if it's base64 text, it will be ASCII like "MII..." which is 0x4D 0x49 0x49...
            if len(decoded_once) > 0 and decoded_once[0] == 0x4D:  # 'M' in ASCII
                # Looks like base64 text, try to decode again
                try:
                    cert_data_bytes = base64.b64decode(decoded_once)
                except:
                    cert_data_bytes = decoded_once
            else:
                cert_data_bytes = decoded_once
            
            # Verify we have bytes
            if not isinstance(cert_data_bytes, bytes):
                print(f"        Certificate data is not bytes: {type(cert_data_bytes)}")
                return None
            
            # Try to load as PEM first
            cert = None
            try:
                cert = x509.load_pem_x509_certificate(cert_data_bytes, default_backend())
            except Exception as pem_error:
                # Try DER
                try:
                    cert = x509.load_der_x509_certificate(cert_data_bytes, default_backend())
                except Exception as der_error:
                    print(f"        Failed to load certificate (tried both PEM and DER): {str(pem_error)[:80]}")
                    return None
            
            if not cert:
                return None
            subject = {}
            for attr in cert.subject:
                subject[attr.oid._name] = attr.value
            
            # Extract issuer
            issuer = {}
            for attr in cert.issuer:
                issuer[attr.oid._name] = attr.value
            
            # Get signature algorithm
            sig_algo = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid)
            
            # Get public key info
            pub_key = cert.public_key()
            #key_curve = None  # For ECDSA certificates
            if hasattr(pub_key, 'curve'):
                key_size = pub_key.curve.key_size
                #key_curve = pub_key.curve.name
                key_algo = 'ECDSA'
            elif hasattr(pub_key, 'key_size'):
                key_size = pub_key.key_size
                key_algo = 'RSA'
            else:
                key_size = 0
                key_algo = 'Unknown'
            
            # Extract extensions
            key_usage = []
            try:
                ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
                ku = ku_ext.value
                if ku.digital_signature:
                    key_usage.append('Digital Signature')
                if ku.key_encipherment:
                    key_usage.append('Key Encipherment')
                if ku.content_commitment:
                    key_usage.append('Content Commitment')
            except x509.ExtensionNotFound:
                pass  # Extension not present is normal
            except (AttributeError, ValueError) as e:
                logger.debug(f"Error extracting key usage: {e}")

            extended_key_usage = []
            try:
                eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
                for oid in eku_ext.value:
                    extended_key_usage.append(oid._name)
            except x509.ExtensionNotFound:
                pass  # Extension not present is normal
            except (AttributeError, ValueError) as e:
                logger.debug(f"Error extracting extended key usage: {e}")

            # Extract CRL Distribution Points
            crl_dps = []
            try:
                crl_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
                for dp in crl_ext.value:
                    if dp.full_name:
                        for name in dp.full_name:
                            crl_dps.append(str(name.value))
            except x509.ExtensionNotFound:
                pass
            
            # Extract OCSP responders
            ocsp_responders = []
            try:
                aia_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
                for desc in aia_ext.value:
                    if desc.access_method.dotted_string == "1.3.6.1.5.5.7.48.1":  # OCSP
                        ocsp_responders.append(str(desc.access_location.value))
            except x509.ExtensionNotFound:
                pass

            # Check for Certificate Transparency SCTs
            scts = []
            try:
                sct_ext = cert.extensions.get_extension_for_oid(
                x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")  # CT precertificate SCTs
                )
                scts.append({"status": "present", "count": "unknown"})
            except x509.ExtensionNotFound:
                pass
            
            # Basic constraints
            basic_constraints = {'ca': False, 'path_length': None}
            try:
                bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                basic_constraints['ca'] = bc_ext.value.ca
                basic_constraints['path_length'] = bc_ext.value.path_length
            except x509.ExtensionNotFound:
                pass  # Extension not present is normal
            except (AttributeError, ValueError) as e:
                logger.debug(f"Error extracting basic constraints: {e}")
            
            # Handle datetime attributes properly
            try:
                not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
                not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
            except AttributeError:
                not_before = cert.not_valid_before
                not_after = cert.not_valid_after
            
            # Ensure timezone awareness
            if not_before.tzinfo is None:
                not_before = not_before.replace(tzinfo=timezone.utc)
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=timezone.utc)
            
            # Get SAN
            san = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    san.append(name.value)
            except x509.ExtensionNotFound:
                pass  # SAN is optional
            except (AttributeError, ValueError) as e:
                logger.debug(f"Error extracting SAN: {e}")

            ca_name = ca_name

            # Check if self-signed
            is_self_signed = cert.issuer == cert.subject

            fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
            serial_number_hex = f"{cert.serial_number:X}"
            
            # Build certificate chain - first try from EJBCA CA certs, then fall back to AIA
            print(f"    Building certificate chain...")
            cert_chain = self._build_chain_from_ejbca(cert, ca_name)
            
            # PQC Analysis
            pqc_analysis = None
            try:
                pqc_detector = get_detector()
                sig_oid = cert.signature_algorithm_oid.dotted_string if hasattr(cert.signature_algorithm_oid, 'dotted_string') else None
                pqc_result = pqc_detector.analyze_certificate(
                    signature_algorithm_oid=sig_oid,
                    signature_algorithm_name=sig_algo,
                    public_key_algorithm=key_algo
                )
                pqc_analysis = pqc_result.to_dict()
                if pqc_result.is_pqc:
                    print(f"    🔐 PQC Algorithm detected: {pqc_result.pqc_algorithm}")
            except Exception as e:
                print(f"    PQC analysis skipped: {e}")
            
            # Create CertificateInfo object
            return CertificateInfo(
                serial_number=serial_number_hex,
                subject=subject,
                issuer=issuer,
                not_before=not_before.isoformat(),
                not_after=not_after.isoformat(),
                signature_algorithm=sig_algo,
                public_key_algorithm=key_algo,
                public_key_size=key_size,
                key_usage=key_usage,
                extended_key_usage=extended_key_usage,
                basic_constraints=basic_constraints,
                san=san,
                source=f"EJBCA: [Server: {self.base_url}, CA: {ca_name}]",
                unique_id=f"ejbca_{serial_number_hex}_{fingerprint[:16]}",
                ca_name=ca_name,
                fingerprint_sha256=fingerprint,
                is_ca=False,
                is_self_signed=is_self_signed,
                crl_distribution_points=crl_dps,
                ocsp_responders=ocsp_responders,
                certificate_transparency_scts=scts,
                found_at_destination=f"'ca_name': {ca_name}, 'server': {self.base_url}",
                found_on_port="N/A",
                tls_library=None,
                tls_version=None,
                certificate_chain=cert_chain,
                pqc_analysis=pqc_analysis,
                #key_curve=key_curve
                #source_metadata={'ca_name': ca_name, 'server': self.base_url}
            )
        except Exception as e:
            print(f"    Error parsing certificate: {e}")
            return None
    
    def _build_chain_from_ejbca(self, cert, ca_name: str) -> List[Dict[str, Any]]:
        """
        Build certificate chain using EJBCA CA certificates first, then fall back to AIA.
        This is more reliable than AIA since we're already authenticated to EJBCA.
        """
        chain = []
        
        try:
            # Start with the leaf certificate
            chain.append(self._cert_to_chain_dict(cert))
            
            # If self-signed, we're done
            if cert.issuer == cert.subject:
                print(f"      Leaf is self-signed, chain complete")
                return chain
            
            # Fetch CA certificate chain from EJBCA
            ca_certs = self._fetch_ca_certificate_chain(ca_name)
            
            if ca_certs:
                print(f"      Building chain from {len(ca_certs)} cached CA certificate(s)")
                
                # Build chain by matching issuer to subject
                current_cert = cert
                visited_fps = {hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()}
                max_depth = 10  # Prevent infinite loops
                
                for _ in range(max_depth):
                    # Find the issuer certificate
                    issuer_found = False
                    for ca_cert in ca_certs:
                        # Check if this CA issued the current cert
                        if ca_cert.subject == current_cert.issuer:
                            ca_fp = hashlib.sha256(ca_cert.public_bytes(serialization.Encoding.DER)).hexdigest()
                            if ca_fp not in visited_fps:
                                chain.append(self._cert_to_chain_dict(ca_cert))
                                visited_fps.add(ca_fp)
                                print(f"      Added issuer: {self._extract_subject_dict(ca_cert).get('commonName', 'Unknown')}")
                                
                                # Check if this is a root (self-signed)
                                if ca_cert.issuer == ca_cert.subject:
                                    print(f"      Root certificate reached, chain complete ({len(chain)} certs)")
                                    return chain
                                
                                current_cert = ca_cert
                                issuer_found = True
                                break
                    
                    if not issuer_found:
                        print(f"      Issuer not found in EJBCA CA certs, trying AIA...")
                        break
                
                # If we built a complete chain, return it
                if len(chain) > 1:
                    last_cert_in_chain = chain[-1]
                    if last_cert_in_chain.get('is_self_signed', False):
                        return chain
            else:
                print(f"      No CA certificates available from EJBCA")
            
            # Fall back to AIA if chain incomplete
            if len(chain) <= 1 or not chain[-1].get('is_self_signed', False):
                print(f"      Falling back to AIA for chain completion...")
                aia_chain = self._build_chain_from_aia(cert)
                if len(aia_chain) > len(chain):
                    return aia_chain
            
        except Exception as e:
            print(f"      Error building chain from EJBCA: {e}")
            # Fall back to AIA
            return self._build_chain_from_aia(cert)
        
        return chain
        
    def _build_chain_from_aia(self, cert) -> List[Dict[str, Any]]:
        """
        Build certificate chain by following AIA (Authority Information Access) URLs.
        Downloads intermediate and root certificates from URLs in the certificate.
        """
        chain = []
        
        try:
            # Start with the leaf certificate
            chain.append(self._cert_to_chain_dict(cert))
            
            # Try to get AIA extension for issuer URL
            try:
                aia_ext = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
                )
                
                for desc in aia_ext.value:
                    # Look for CA Issuers access method (1.3.6.1.5.5.7.48.2)
                    if desc.access_method.dotted_string == "1.3.6.1.5.5.7.48.2":
                        issuer_url = str(desc.access_location.value)
                        print(f"      Found issuer URL in AIA: {issuer_url}")
                        
                        # Download the issuer certificate
                        try:
                            import urllib.request
                            import ssl
                            
                            # Create SSL context that doesn't verify
                            ctx = ssl.create_default_context()
                            ctx.check_hostname = False
                            ctx.verify_mode = ssl.CERT_NONE
                            
                            print(f"      Downloading issuer from: {issuer_url}")
                            with urllib.request.urlopen(issuer_url, timeout=10, context=ctx) as response:
                                issuer_der = response.read()
                            
                            # Load the issuer certificate
                            issuer_cert = x509.load_der_x509_certificate(issuer_der, default_backend())
                            chain.append(self._cert_to_chain_dict(issuer_cert))
                            print(f"      Added issuer certificate: {self._extract_subject_dict(issuer_cert).get('commonName', 'Unknown')}")
                            
                            # If issuer is self-signed (root), we're done
                            if issuer_cert.issuer == issuer_cert.subject:
                                print(f"      Root certificate detected (self-signed), chain complete")
                                return chain
                            
                            # Try to get the next level (recursively)
                            try:
                                next_chain = self._build_chain_from_aia(issuer_cert)
                                # Skip the first cert (duplicate) and add the rest
                                if next_chain and len(next_chain) > 1:
                                    chain.extend(next_chain[1:])
                            except Exception as e:
                                print(f"      Could not get next level: {e}")
                                
                        except Exception as e:
                            print(f"      Error downloading from {issuer_url}: {e}")
                            
            except x509.ExtensionNotFound:
                print(f"      No AIA extension found in certificate")
                
        except Exception as e:
            print(f"    Error building chain from AIA: {e}")
        
        return chain
    
    def _cert_to_chain_dict(self, cert) -> Dict[str, Any]:
        """Convert a cryptography certificate to chain dict format"""
        return {
            'subject': self._extract_subject_dict(cert),
            'issuer': self._extract_issuer_dict(cert),
            'serial_number': f"{cert.serial_number:X}",
            'fingerprint_sha256': hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
            'not_before': cert.not_valid_before.isoformat(),
            'not_after': cert.not_valid_after.isoformat(),
            'is_self_signed': cert.issuer == cert.subject
        }
    
    def _extract_subject_dict(self, cert) -> Dict[str, str]:
        """Extract subject as dictionary"""
        subject = {}
        try:
            for attr in cert.subject:
                subject[attr.oid._name] = attr.value
        except Exception:
            pass
        return subject
    
    def _extract_issuer_dict(self, cert) -> Dict[str, str]:
        """Extract issuer as dictionary"""
        issuer = {}
        try:
            for attr in cert.issuer:
                issuer[attr.oid._name] = attr.value
        except Exception:
            pass
        return issuer
    
    def collect_all(self) -> List[CertificateInfo]:
        """Collect certificates from all CAs on EJBCA server"""
        all_certificates = []
        
        print(f"\n[*] Collecting certificates from EJBCA ({self.base_url})...")
        
        # Get list of CAs
        cas = self.get_cas()
        if not cas:
            print("   No CAs found or failed to retrieve CA list")
            return []
        
        # Collect certificates from each CA
        for ca_name in cas:
            try:
                certs = self.get_certificates(ca_name)
                all_certificates.extend(certs)
            except Exception as e:
                print(f"   Error collecting from CA '{ca_name}': {e}")
                continue
        
        print(f"[+] Total certificates collected from EJBCA: {len(all_certificates)}")
        return all_certificates

    def download_ca_certificate(self, ca_name: str) -> Optional[str]:
        """
        Download CA certificate in PEM format to extract key information.

        Args:
            ca_name: Name of the Certificate Authority

        Returns:
            PEM-encoded certificate string, or None on error
        """
        if not self.session:
            if not self._create_session():
                return None

        try:
            import urllib.parse

            # Try downloading with CA name (URL-encoded)
            encoded_name = urllib.parse.quote(ca_name, safe='')
            url = f"{self.base_url}/ejbca/ejbca-rest-api/v1/ca/{encoded_name}/certificate/download"

            response = self.session.get(url, timeout=self.timeout)

            if response.status_code == 200:
                return response.text
            else:
                logger.debug(f"Could not download CA cert for '{ca_name}': HTTP {response.status_code}")
                return None

        except Exception as e:
            logger.debug(f"Error downloading CA certificate: {e}")
            return None

    def get_ca_extended_info(self, ca_name: str) -> Dict[str, Any]:
        """
        Retrieve extended CA configuration information.

        Args:
            ca_name: Name of the Certificate Authority

        Returns:
            Dictionary with CA configuration:
            - name: CA name
            - keyAlgorithm: RSA, ECDSA, etc
            - keySpec: Key size/curve
            - signatureAlgorithm: Signature algorithm
            - validity: CA cert validity in days
            - crlPeriod: CRL issuance period in hours
            - caStatus: Active, Offline, etc

        Returns empty dict on error (graceful fallback)
        """
        if not self.session:
            if not self._create_session():
                return {}

        try:
            import urllib.parse

            # Try to get CA info from CA list endpoint
            url = f"{self.base_url}/ejbca/ejbca-rest-api/v1/ca"
            print(f"  Fetching extended CA info for '{ca_name}'...")

            response = self.session.get(url, timeout=self.timeout)

            if response.status_code == 200:
                response_data = response.json()

                # Parse CA list
                cas = []
                if isinstance(response_data, list):
                    cas = response_data
                elif isinstance(response_data, dict) and 'certificate_authorities' in response_data:
                    cas = response_data['certificate_authorities']
                elif isinstance(response_data, dict):
                    cas = list(response_data.values()) if response_data else []

                # Find matching CA and extract extended info
                for ca_info in cas:
                    if isinstance(ca_info, dict):
                        ca_info_name = ca_info.get('name') or ca_info.get('caName') or ''
                        if ca_info_name == ca_name or ca_name in ca_info_name:
                            print(f"    Found CA: {ca_info_name}")
                            # Extract key info from CA certificate
                            key_algo = 'Unknown'
                            key_spec = 'Unknown'
                            try:
                                cert_pem = self.download_ca_certificate(ca_name)
                                if cert_pem:
                                    from cryptography import x509
                                    from cryptography.hazmat.backends import default_backend
                                    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448

                                    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                                    public_key = cert.public_key()

                                    if isinstance(public_key, rsa.RSAPublicKey):
                                        key_algo = 'RSA'
                                        key_spec = str(public_key.key_size)
                                    elif isinstance(public_key, ec.EllipticCurvePublicKey):
                                        key_algo = 'ECDSA'
                                        key_spec = public_key.curve.name
                                    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                                        key_algo = 'EdDSA'
                                        key_spec = type(public_key).__name__.replace('PublicKey', '')
                                    else:
                                        key_algo = type(public_key).__name__.replace('PublicKey', '')
                                        key_spec = 'Unknown'

                                    logger.debug(f"Extracted key info for {ca_name}: {key_algo} {key_spec}")
                            except Exception as e:
                                logger.debug(f"Could not extract key from CA cert '{ca_name}': {e}")

                            # Map EJBCA API fields to expected field names
                            extended_info = {
                                'name': ca_info.get('name', ca_name),
                                'caStatus': ca_info.get('status', 'Active'),
                                # Use extracted key info, fallback to API fields
                                'keyAlgorithm': ca_info.get('keyAlgorithm') or ca_info.get('key_algorithm') or key_algo,
                                'keySpec': ca_info.get('keySpec') or ca_info.get('key_spec') or key_spec,
                                'signatureAlgorithm': ca_info.get('signatureAlgorithm') or ca_info.get('signature_algorithm') or 'Unknown',
                                'validity': ca_info.get('validity') or ca_info.get('valid_days'),
                                'crlPeriod': ca_info.get('crlPeriod') or ca_info.get('crl_period') or ca_info.get('crlPeriodInHours'),
                                # Include original fields for reference
                                'subject_dn': ca_info.get('subject_dn'),
                                'issuer_dn': ca_info.get('issuer_dn'),
                                'expiration_date': ca_info.get('expiration_date'),
                            }
                            return extended_info

                logger.debug(f"CA '{ca_name}' not found in CA list")
                return {}

            else:
                logger.debug(f"Failed to get extended CA info - HTTP {response.status_code}")
                return {}

        except Exception as e:
            logger.debug(f"Error retrieving extended CA info: {e}")
            return {}

    def is_healthy(self) -> bool:
        """Check if EJBCA server is healthy"""
        cas = self.get_cas()
        return len(cas) > 0

print("EJBCACollector class defined")


# File Share Scanner for Cryptographic Assets
