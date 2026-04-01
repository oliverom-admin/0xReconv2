# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: caip_scanning_functions/collectors/tls_scanner.py
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
TLS/SSL certificate scanner for network endpoints
"""

import ssl
import socket
import hashlib
import ipaddress
import datetime
import logging
import time
from typing import Optional
from datetime import timezone

try:
    from OpenSSL import SSL, crypto
    PYOPENSSL_AVAILABLE = True
except ImportError:
    PYOPENSSL_AVAILABLE = False

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
import platform

from ..models import CertificateInfo, TLSScanResult
from caip_pqc_functions.pqc_detector import get_detector
from caip_service_layer.environment_inference_service import EnvironmentInferenceService

# Set up logging
logger = logging.getLogger(__name__)


class TLSScanError(Exception):
    """Base exception for TLS scanning errors"""
    pass


class TLSConnectionError(TLSScanError):
    """Error establishing TLS connection"""
    pass


class TLSTimeoutError(TLSScanError):
    """Timeout during TLS connection"""
    pass


class TLSCertificateError(TLSScanError):
    """Error parsing TLS certificate"""
    pass


class TLSScanner:
    """Scan TLS/SSL certificates from network endpoints"""
    
    def __init__(self, timeout: int = 1):
        """
        Initialize TLS Scanner.
        
        Args:
            timeout: Timeout in seconds for socket connections
        """
        self.timeout = timeout
        print(f"TLSScanner initialized with timeout={timeout}")
    
    def _detect_tls_library(self, context: ssl.SSLContext) -> str:
        """
        Detect the TLS/SSL library being used.
        
        Returns the SSL library name (OpenSSL, LibreSSL, BoringSSL, etc.)
        """
        try:
            # Get SSL version info
            ssl_version = ssl.OPENSSL_VERSION
            
            # Parse the version string to identify the library
            if 'LibreSSL' in ssl_version:
                return 'LibreSSL'
            elif 'BoringSSL' in ssl_version:
                return 'BoringSSL'
            elif 'OpenSSL' in ssl_version:
                # Extract OpenSSL version
                return ssl_version.split(' ')[0] + ' ' + ssl_version.split(' ')[1]
            else:
                return ssl_version
        except Exception as e:
            return f"Unknown ({str(e)})"
        
    def _extract_chain_pyopenssl(self, host: str, port: int) -> list[dict[str, any]]:
        """
        Extract certificate chain using pyOpenSSL.
        Works directly with OpenSSL SSL certificate verification.
        """
        chain = []
        try:
            if not PYOPENSSL_AVAILABLE:
                print(f"    pyOpenSSL not available")
                return chain
            
            from OpenSSL import SSL, crypto
            import socket as socket_module
            
            # Create SSL context
            context = SSL.Context(SSL.TLS_METHOD)
            context.set_verify(SSL.VERIFY_NONE, lambda *args: True)
            
            # Create connection
            sock = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
            sock.settimeout(self.timeout)
            ssl_sock = SSL.Connection(context, sock)
            ssl_sock.set_tlsext_host_name(host.encode())
            
            try:
                ssl_sock.connect((host, port))
                
                # Get peer certificate chain
                peer_cert_chain = ssl_sock.get_peer_cert_chain()
                
                if peer_cert_chain:
                    print(f"    pyOpenSSL extracted {len(peer_cert_chain)} certificates")
                    
                    for i, cert in enumerate(peer_cert_chain):
                        try:
                            # Get certificate in DER format
                            cert_der = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
                            cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
                            
                            chain.append({
                                'subject': self._extract_subject_dict(cert_obj),
                                'issuer': self._extract_issuer_dict(cert_obj),
                                'serial_number': f"{cert_obj.serial_number:X}",
                                'fingerprint_sha256': hashlib.sha256(cert_der).hexdigest(),
                                'not_before': cert_obj.not_valid_before.isoformat(),
                                'not_after': cert_obj.not_valid_after.isoformat(),
                                'is_self_signed': cert_obj.issuer == cert_obj.subject
                            })
                            print(f"      Added cert {i + 1}")
                        except Exception as e:
                            print(f"      Error processing cert {i}: {e}")
                else:
                    print(f"    No peer cert chain from pyOpenSSL")
                    
            except socket.timeout as e:
                error_msg = f"Timeout connecting to {host}:{port} with pyOpenSSL after {self.timeout}s"
                print(f"    Connection timeout with pyOpenSSL")
                logger.warning(error_msg)
            except socket.error as e:
                error_msg = f"Socket error connecting to {host}:{port}: {e}"
                print(f"    Socket error with pyOpenSSL: {e}")
                logger.warning(error_msg)
            except SSL.Error as e:
                error_msg = f"SSL error connecting to {host}:{port}: {e}"
                print(f"    SSL error with pyOpenSSL: {e}")
                logger.warning(error_msg)
            except Exception as e:
                error_msg = f"Error connecting to {host}:{port} with pyOpenSSL: {type(e).__name__}: {e}"
                print(f"    Error connecting with pyOpenSSL: {e}")
                logger.warning(error_msg)
            finally:
                try:
                    ssl_sock.close()
                except (OSError, AttributeError) as e:
                    logger.debug(f"Error closing SSL socket: {e}")
                    
        except Exception as e:
            print(f"  pyOpenSSL chain extraction error: {e}")
        
        return chain
    
    def _extract_certificate_chain(self, sock) -> list[dict[str, any]]:
        """
        Extract full certificate chain from the socket connection.
        
        Returns a list of certificate information dictionaries representing
        the full chain from leaf to root.
        """
        chain = []
        try:
            # Get the peer certificate in DER format (leaf)
            cert_der = sock.getpeercert(binary_form=True)
            if cert_der:
                try:
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    chain.append({
                        'subject': self._extract_subject_dict(cert),
                        'issuer': self._extract_issuer_dict(cert),
                        'serial_number': f"{cert.serial_number:X}",
                        'fingerprint_sha256': hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
                        'not_before': cert.not_valid_before.isoformat(),
                        'not_after': cert.not_valid_after.isoformat(),
                        'is_self_signed': cert.issuer == cert.subject
                    })
                except Exception as e:
                    print(f"    Error processing leaf certificate: {e}")
            
            # Try to get the full chain using different methods
            peer_cert_chain = None
            
            # Method 1: Try getpeercert_chain() (Python 3.6+, optional)
            try:
                if hasattr(sock, 'getpeercert_chain'):
                    peer_cert_chain = sock.getpeercert_chain()
                    print(f"    Chain extraction: getpeercert_chain returned {len(peer_cert_chain) if peer_cert_chain else 0} certs")
            except Exception as e:
                print(f"    getpeercert_chain() not available or failed: {e}")
            
            # Method 2: Try SSL context method
            if not peer_cert_chain:
                try:
                    # Get verified chain from SSL context
                    import ssl
                    ssl_context = ssl.create_default_context()
                    # This is a fallback - real chain should come from handshake
                    print(f"    Note: Using leaf-only extraction (full chain not available)")
                except Exception as e:
                    print(f"    SSL context chain method failed: {e}")
            
            # If we got a chain with more than just the leaf, process it
            if peer_cert_chain and len(peer_cert_chain) > 1:
                print(f"    Processing {len(peer_cert_chain) - 1} additional chain certificates")
                for i, chain_cert_der in enumerate(peer_cert_chain[1:], start=1):
                    try:
                        chain_cert = x509.load_der_x509_certificate(chain_cert_der, default_backend())
                        chain.append({
                            'subject': self._extract_subject_dict(chain_cert),
                            'issuer': self._extract_issuer_dict(chain_cert),
                            'serial_number': f"{chain_cert.serial_number:X}",
                            'fingerprint_sha256': hashlib.sha256(chain_cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
                            'not_before': chain_cert.not_valid_before.isoformat(),
                            'not_after': chain_cert.not_valid_after.isoformat(),
                            'is_self_signed': chain_cert.issuer == chain_cert.subject
                        })
                        print(f"      Added intermediate/root cert {i}")
                    except Exception as e:
                        print(f"      Error processing chain cert {i}: {e}")
            else:
                print(f"    Chain empty or contains only leaf - using leaf-only mode")
                
        except Exception as e:
            print(f"  Error extracting certificate chain: {e}")
        
        return chain
    
    def _extract_subject_dict(self, cert) -> dict[str, str]:
        """Extract subject as dictionary"""
        subject = {}
        try:
            for attr in cert.subject:
                subject[attr.oid._name] = attr.value
        except Exception:
            pass
        return subject
    
    def _extract_issuer_dict(self, cert) -> dict[str, str]:
        """Extract issuer as dictionary"""
        issuer = {}
        try:
            for attr in cert.issuer:
                issuer[attr.oid._name] = attr.value
        except Exception:
            pass
        return issuer
    
    def scan_host(self, host: str, port: int) -> Optional[TLSScanResult]:
        """
        Scan a host:port for TLS/SSL certificate information.
        
        Args:
            host: Hostname or IP address
            port: Port number
            
        Returns:
            TLSScanResult if successful, None otherwise
        """
        print(f"  Attempting to scan {host}:{port}...")
        handshake_start = time.time()
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    protocol = ssock.version()
                    cipher = ssock.cipher()
                    symmetric_key_bits = cipher[2] if cipher and len(cipher) > 2 else None

                    # Detect TLS library
                    tls_lib = self._detect_tls_library(context)
                    
                    # Capture TLS version/protocol
                    tls_ver = protocol if protocol else "Unknown"
                    
                    # Extract certificate chain
                    cert_chain = self._extract_certificate_chain(ssock)
                    
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    
                    # Extract subject
                    subject = {}
                    for attr in cert.subject:
                        subject[attr.oid._name] = attr.value
                    
                    # Extract issuer
                    issuer = {}
                    for attr in cert.issuer:
                        issuer[attr.oid._name] = attr.value
                    
                    # Extract key usage
                    key_usage = []
                    try:
                        ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
                        ku = ku_ext.value
                        if ku.digital_signature: key_usage.append("digitalSignature")
                        if ku.key_encipherment: key_usage.append("keyEncipherment")
                        if ku.key_cert_sign: key_usage.append("keyCertSign")
                        if ku.crl_sign: key_usage.append("cRLSign")
                    except x509.ExtensionNotFound:
                        pass
                    
                    # Extract extended key usage
                    eku = []
                    try:
                        eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
                        eku = [str(usage) for usage in eku_ext.value]
                    except x509.ExtensionNotFound:
                        pass

                    # Extract SAN
                    san = []
                    try:
                        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        san = [str(name) for name in san_ext.value]
                    except x509.ExtensionNotFound:
                        pass  # SAN is optional
                    except (AttributeError, ValueError) as e:
                        logger.debug(f"Error extracting SAN from {host}:{port}: {e}")

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
                            x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
                        )
                        scts.append({"status": "present", "count": "unknown"})
                    except x509.ExtensionNotFound:
                        pass

                    # Extract Basic Constraints
                    basic_constraints = {}
                    try:
                        bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                        basic_constraints = {
                            "ca": bc_ext.value.ca,
                            "path_length": bc_ext.value.path_length
                        }
                    except x509.ExtensionNotFound:
                        pass

                    # Check if self-signed
                    is_self_signed = cert.issuer == cert.subject
                    
                    # Get public key info
                    public_key = cert.public_key()
                    pub_key_algo = type(public_key).__name__
                    pub_key_size = public_key.key_size if hasattr(public_key, 'key_size') else 0
                    
                    # Extract EC curve name if ECDSA
                    key_curve = None
                    if hasattr(public_key, 'curve'):
                        key_curve = public_key.curve.name

                    # Detect forward secrecy capability
                    has_forward_secrecy = False
                    if cipher and cipher[0]:
                        cipher_name = cipher[0].upper()
                        has_forward_secrecy = 'ECDHE' in cipher_name or 'DHE' in cipher_name or 'PSK' in cipher_name

                    # Extract Authority Key Identifier
                    authority_key_identifier = None
                    try:
                        aki_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
                        aki_value = aki_ext.value.key_identifier
                        authority_key_identifier = aki_value.hex() if aki_value else None
                    except x509.ExtensionNotFound:
                        pass

                    # Extract Subject Key Identifier
                    subject_key_identifier = None
                    try:
                        ski_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
                        ski_value = ski_ext.value.digest
                        subject_key_identifier = ski_value.hex() if ski_value else None
                    except x509.ExtensionNotFound:
                        pass

                    # Phase 3: Check for Precertificate Poison
                    precert_poison_present = False
                    try:
                        poison_ext = cert.extensions.get_extension_for_oid(
                            x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.3")  # Precert Poison OID
                        )
                        precert_poison_present = True
                    except x509.ExtensionNotFound:
                        pass

                    # Phase 3: Extract Freshest CRL (Delta CRL)
                    freshest_crl_urls = []
                    try:
                        fcrl_ext = cert.extensions.get_extension_for_oid(
                            x509.ObjectIdentifier("2.5.29.46")  # Freshest CRL OID
                        )
                        for dp in fcrl_ext.value:
                            if dp.full_name:
                                for name in dp.full_name:
                                    freshest_crl_urls.append(str(name.value))
                    except x509.ExtensionNotFound:
                        pass

                    # Generate fingerprint
                    fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

                    # Create unique ID
                    unique_id = hashlib.sha256(f"{cert.serial_number}{subject.get('commonName', '')}".encode()).hexdigest()[:16]
                    
                    # PQC Analysis
                    pqc_analysis = None
                    try:
                        pqc_detector = get_detector()
                        sig_oid = cert.signature_algorithm_oid.dotted_string if hasattr(cert.signature_algorithm_oid, 'dotted_string') else None
                        sig_name = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else None
                        pqc_result = pqc_detector.analyze_certificate(
                            signature_algorithm_oid=sig_oid,
                            signature_algorithm_name=sig_name,
                            public_key_algorithm=pub_key_algo
                        )
                        pqc_analysis = pqc_result.to_dict()
                        if pqc_result.is_pqc:
                            print(f"    🔐 PQC detected on {host}:{port}: {pqc_result.pqc_algorithm}")
                    except Exception as e:
                        pass  # PQC detection is optional

                    # Phase 2: Protocol Intelligence calculations
                    handshake_time_ms = (time.time() - handshake_start) * 1000

                    # Calculate validity period for lifespan pattern
                    validity_period_days = (cert.not_valid_after - cert.not_valid_before).days

                    # Enumerate TLS versions
                    version_enum = self._enumerate_tls_versions(host, port)

                    # Rate cipher strength
                    cipher_strength = self._rate_cipher_strength(
                        cipher[0] if cipher else None,
                        symmetric_key_bits
                    )

                    # Get lifespan pattern
                    lifespan_pattern = self._get_lifespan_pattern(validity_period_days)

                    cert_info = CertificateInfo(
                        serial_number=f"{cert.serial_number:X}",
                        subject=subject,
                        issuer=issuer,
                        not_before=cert.not_valid_before.isoformat(),
                        not_after=cert.not_valid_after.isoformat(),
                        signature_algorithm=cert.signature_algorithm_oid._name,
                        public_key_algorithm=pub_key_algo,
                        public_key_size=pub_key_size,
                        key_usage=key_usage,
                        extended_key_usage=eku,
                        san=san,
                        basic_constraints=basic_constraints,
                        fingerprint_sha256=fingerprint,
                        crl_distribution_points=crl_dps,
                        ocsp_responders=ocsp_responders,
                        certificate_transparency_scts=scts,
                        source="TLS",
                        unique_id=unique_id,
                        is_ca=False,
                        is_self_signed=is_self_signed,
                        found_at_destination=host,
                        found_on_port=port,
                        tls_library=tls_lib,
                        tls_version=tls_ver,
                        certificate_chain=cert_chain,
                        pqc_analysis=pqc_analysis,
                        key_curve=key_curve,
                        symmetric_key_bits=symmetric_key_bits,
                        has_forward_secrecy=has_forward_secrecy,
                        authority_key_identifier=authority_key_identifier,
                        subject_key_identifier=subject_key_identifier,
                        supported_tls_versions=version_enum['supported_versions'],
                        protocol_vulnerabilities=version_enum['vulnerabilities'],
                        client_cert_required=version_enum['client_cert_required'],
                        ocsp_stapling_supported=version_enum['ocsp_stapling'],
                        session_ticket_supported=version_enum['session_ticket'],
                        cipher_strength_rating=cipher_strength,
                        lifespan_pattern=lifespan_pattern,
                        tls_handshake_time_ms=handshake_time_ms,
                        precert_poison_present=precert_poison_present,
                        freshest_crl_urls=freshest_crl_urls
                    )

                    # Extract environment metadata using inference service
                    env_metadata = EnvironmentInferenceService.infer_from_tls_scan(
                        host=host,
                        port=port,
                        cert_subject=subject
                    )

                    return TLSScanResult(
                        host=host,
                        port=port,
                        timestamp=datetime.datetime.now(timezone.utc).isoformat(),
                        supported_protocols=[protocol],
                        cipher_suites=[cipher[0]] if cipher else [],
                        certificate_chain=[cert_info],
                        environment_metadata=env_metadata
                    )

        except socket.timeout:
            error_msg = f"Connection timeout to {host}:{port} after {self.timeout}s"
            print(f"  [TIMEOUT] {host}:{port} - Connection timeout")
            logger.error(error_msg)
            return None
        except socket.gaierror as e:
            error_msg = f"DNS resolution failed for {host}: {e}"
            print(f"  [ERROR] {host}:{port} - DNS resolution failed: {e}")
            logger.error(error_msg)
            return None
        except ConnectionRefusedError:
            error_msg = f"Connection refused by {host}:{port}"
            print(f"  [ERROR] {host}:{port} - Connection refused")
            logger.error(error_msg)
            return None
        except ConnectionResetError:
            error_msg = f"Connection reset by {host}:{port}"
            print(f"  [ERROR] {host}:{port} - Connection reset")
            logger.error(error_msg)
            return None
        except ssl.SSLError as e:
            error_msg = f"SSL/TLS error connecting to {host}:{port}: {e}"
            print(f"  [SSL ERROR] {host}:{port} - SSL error: {e}")
            logger.error(error_msg)
            return None
        except OSError as e:
            error_msg = f"OS error connecting to {host}:{port}: {e}"
            print(f"  [ERROR] {host}:{port} - OS error: {e}")
            logger.error(error_msg)
            return None
        except (ValueError, TypeError) as e:
            error_msg = f"Certificate parsing error for {host}:{port}: {e}"
            print(f"  [ERROR] {host}:{port} - Certificate error: {e}")
            logger.error(error_msg)
            return None
        except Exception as e:
            error_msg = f"Unexpected error scanning {host}:{port}: {type(e).__name__}: {e}"
            print(f"  [ERROR] {host}:{port} - Unexpected error: {e}")
            logger.exception(error_msg)
            return None

    def _enumerate_tls_versions(self, host: str, port: int) -> dict:
        """
        Enumerate supported TLS versions and detect vulnerabilities.

        Tests connection with different TLS versions to determine support.
        Detects known vulnerabilities like POODLE, DROWN, etc.

        Returns:
            {
                'supported_versions': List[str],
                'vulnerabilities': List[str],
                'client_cert_required': bool,
                'ocsp_stapling': bool,
                'session_ticket': bool
            }
        """
        supported = []
        vulnerabilities = []
        client_cert_required = False
        ocsp_stapling = False
        session_ticket = False

        # Build list of TLS versions to test - only add if available
        tls_versions = []

        # Try to add each TLS version if available
        if hasattr(ssl, 'PROTOCOL_TLSv1'):
            tls_versions.append((ssl.PROTOCOL_TLSv1, "TLSv1.0"))

        if hasattr(ssl, 'PROTOCOL_TLSv1_1'):
            tls_versions.append((ssl.PROTOCOL_TLSv1_1, "TLSv1.1"))

        if hasattr(ssl, 'PROTOCOL_TLSv1_2'):
            tls_versions.append((ssl.PROTOCOL_TLSv1_2, "TLSv1.2"))

        if hasattr(ssl, 'PROTOCOL_TLSv1_3'):
            tls_versions.append((ssl.PROTOCOL_TLSv1_3, "TLSv1.3"))

        # If no TLS versions available, skip enumeration gracefully
        if not tls_versions:
            return {
                'supported_versions': [],
                'vulnerabilities': [],
                'client_cert_required': False,
                'ocsp_stapling': False,
                'session_ticket': False
            }

        for protocol_version, version_name in tls_versions:
            try:
                context = ssl.SSLContext(protocol_version)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        supported.append(version_name)

                        # Check for session ticket support
                        if hasattr(ssock, 'session'):
                            session_ticket = True

                        # Check for OCSP stapling (crude check)
                        try:
                            ocsp_stapling = True  # TODO: Proper OCSP detection
                        except:
                            pass

            except ssl.SSLError as e:
                # Check for client certificate requirement
                if 'CERTIFICATE_REQUIRED' in str(e) or 'certificate required' in str(e).lower():
                    client_cert_required = True

            except socket.timeout:
                pass  # Version not available
            except Exception:
                pass  # Version not available

        # Detect known vulnerabilities based on supported versions
        if "TLSv1.0" in supported or "TLSv1.1" in supported:
            vulnerabilities.append("Legacy TLS versions")

        if "SSLv3" in supported:
            vulnerabilities.append("POODLE (SSLv3 fallback)")

        return {
            'supported_versions': supported,
            'vulnerabilities': vulnerabilities,
            'client_cert_required': client_cert_required,
            'ocsp_stapling': ocsp_stapling,
            'session_ticket': session_ticket
        }

    def _rate_cipher_strength(self, cipher_name: str, key_bits: int) -> str:
        """
        Rate cipher suite strength based on NIST/OWASP guidelines.

        Returns: 'A' (Strong) | 'B' (Acceptable) | 'C' (Weak) | 'F' (Broken)
        """
        if not cipher_name:
            return 'Unknown'

        cipher_upper = cipher_name.upper()

        # Broken ciphers (Grade F)
        broken_patterns = ['DES', 'RC4', 'MD5', 'NULL', 'EXPORT', 'ADH', 'ANON']
        if any(pattern in cipher_upper for pattern in broken_patterns):
            return 'F'

        # Weak ciphers (Grade C)
        weak_patterns = ['3DES', 'SHA1', 'PSK', 'CBC']
        if any(pattern in cipher_upper for pattern in weak_patterns):
            if 'TLSv1.3' not in cipher_upper:
                return 'C'

        # Strong ciphers (Grade A)
        if 'TLSv1.3' in cipher_upper or 'CHACHA20' in cipher_upper:
            return 'A'

        if 'AES' in cipher_upper and 'GCM' in cipher_upper:
            if key_bits >= 256:
                return 'A'
            else:
                return 'B'

        # Default acceptable
        return 'B'

    def _get_lifespan_pattern(self, validity_days: int) -> str:
        """Classify certificate lifespan pattern."""
        if validity_days < 365:
            return "short-lived (auto-renewal infrastructure)"
        elif validity_days > 1095:  # 3 years
            return "long-lived (manual renewal, legacy)"
        else:
            return "standard (1-2 years)"
