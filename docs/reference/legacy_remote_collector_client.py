# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: remote_collector/client.py
# Copied: 2026-04-01
# Used in: Phase 17 — Remote Collector Agent
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
Collector Client - Communication with Central CAIP Server

Handles all HTTP communication with the central server:
- Registration using bootstrap token
- Heartbeat reporting
- Scan report submission
- Policy retrieval
"""

import logging
import hashlib
import ssl
from datetime import datetime
from typing import Optional, Dict, Any, Tuple, List
from pathlib import Path

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:
    raise ImportError("requests library required. Install with: pip install requests")

try:
    from urllib3.util.ssl_ import create_urllib3_context
except ImportError:
    raise ImportError("urllib3 library required. Install with: pip install urllib3")

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

from .config import CollectorConfig

logger = logging.getLogger('collector.client')


class CustomSSLAdapter(HTTPAdapter):
    """
    HTTPS adapter that validates certificate chain but skips hostname verification.

    This allows collectors to connect to the dashboard using any address (IP or FQDN)
    while maintaining full mTLS security:
    - Server certificate is validated against CA chain
    - Client certificate is presented for mutual authentication
    - Hostname verification is skipped (acceptable in closed infrastructure)

    Threat model: Protects against MITM attacks by unauthorized parties without
    the CA private keys. Does NOT protect against DNS hijacking (accepted tradeoff
    for deployment flexibility in internal networks).
    """

    def __init__(self, cert_file=None, key_file=None, ca_file=None):
        """Initialize adapter with optional mTLS certificates."""
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_file = ca_file
        super().__init__()

    def init_poolmanager(self, *args, **kwargs):
        """Initialize connection pool with custom SSL context."""
        from pathlib import Path
        import ssl

        # Create a standard SSL context
        ctx = create_urllib3_context()

        # Enforce minimum TLSv1.2, allow TLSv1.3 for better compatibility
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Load CA certificate if provided and file exists
        if self.ca_file:
            ca_path = Path(self.ca_file)
            if ca_path.exists():
                try:
                    ctx.load_verify_locations(self.ca_file)
                except Exception as e:
                    logger.warning(f"Error loading CA file {self.ca_file}: {e}")
            else:
                logger.debug(f"CA file not yet available: {self.ca_file}")

        # Load client certificate and key for mTLS if provided and files exist
        if self.cert_file and self.key_file:
            cert_path = Path(self.cert_file)
            key_path = Path(self.key_file)

            if cert_path.exists() and key_path.exists():
                try:
                    ctx.load_cert_chain(self.cert_file, self.key_file)
                except Exception as e:
                    logger.error(f"Error loading client cert chain - cert: {self.cert_file}, key: {self.key_file}")
                    logger.error(f"This usually means the certificate and key don't match (from different CSRs)")
                    raise
            else:
                logger.debug(f"Client cert/key not yet available: cert={cert_path.exists()}, key={key_path.exists()}")

        # Require certificate validation (check cert chain is valid)
        ctx.verify_mode = ssl.CERT_REQUIRED

        # Skip hostname verification (allows IP addresses and any FQDN)
        ctx.check_hostname = False

        # Pass the custom context to the pool manager
        kwargs['ssl_context'] = ctx

        # Also set assert_hostname to False to suppress urllib3 hostname checking
        kwargs['assert_hostname'] = False

        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        """Create proxy manager with custom SSL context."""
        from pathlib import Path
        import ssl

        ctx = create_urllib3_context()

        # Enforce minimum TLSv1.2, allow TLSv1.3 for better compatibility
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Load CA certificate if provided and file exists
        if self.ca_file:
            ca_path = Path(self.ca_file)
            if ca_path.exists():
                try:
                    ctx.load_verify_locations(self.ca_file)
                except Exception as e:
                    logger.warning(f"Error loading CA file {self.ca_file}: {e}")
            else:
                logger.debug(f"CA file not yet available: {self.ca_file}")

        # Load client certificate and key for mTLS if provided and files exist
        if self.cert_file and self.key_file:
            cert_path = Path(self.cert_file)
            key_path = Path(self.key_file)

            if cert_path.exists() and key_path.exists():
                try:
                    ctx.load_cert_chain(self.cert_file, self.key_file)
                except Exception as e:
                    logger.error(f"Error loading client cert chain - cert: {self.cert_file}, key: {self.key_file}")
                    logger.error(f"This usually means the certificate and key don't match (from different CSRs)")
                    raise
            else:
                logger.debug(f"Client cert/key not yet available: cert={cert_path.exists()}, key={key_path.exists()}")

        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = False
        proxy_kwargs['ssl_context'] = ctx
        proxy_kwargs['assert_hostname'] = False
        return super().proxy_manager_for(proxy, **proxy_kwargs)


class CollectorClientError(Exception):
    """Base exception for collector client errors."""
    pass


class RegistrationError(CollectorClientError):
    """Error during collector registration."""
    pass


class AuthenticationError(CollectorClientError):
    """API key authentication failed."""
    pass


class CommunicationError(CollectorClientError):
    """Network or server communication error."""
    pass


class CollectorClient:
    """
    HTTP client for communicating with CAIP central server.

    Handles authentication, retries, and error handling for all
    collector-to-server communication.
    """

    def __init__(self, config: CollectorConfig):
        """
        Initialize collector client.

        Args:
            config: CollectorConfig instance
        """
        self.config = config
        self._session = requests.Session()

        # Register custom SSL adapter that skips hostname verification but validates cert chain
        # This allows collectors to connect via IP address or any FQDN while maintaining mTLS
        # Pass cert paths to adapter (may be None if not registered yet)
        adapter = CustomSSLAdapter(
            cert_file=config.cert_path,
            key_file=config.key_path,
            ca_file=config.ca_cert_path
        )
        self._session.mount('https://', adapter)
        self._adapter = adapter  # Keep reference for later updates

        # Set default headers
        self._session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': f'CAIP-Collector/1.0 ({config.collector_id or "unregistered"})'
        })

        # Configure SSL verification - will be set by _load_tls_config() when CA cert is available
        # Load mTLS client certificates if available (required for port 5444)
        self._load_tls_config()

    def _get_api_headers(self) -> Dict[str, str]:
        """Get headers with API key for authenticated requests."""
        if not self.config.api_key:
            raise AuthenticationError("No API key configured. Register first.")

        return {
            'X-API-Key': self.config.api_key
        }

    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        authenticated: bool = True,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """
        Make HTTP request to server.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            data: Request body data
            authenticated: Whether to include API key
            timeout: Request timeout in seconds

        Returns:
            Response data as dictionary

        Raises:
            AuthenticationError: If authentication fails
            CommunicationError: If request fails
        """
        url = f"{self.config.server_url.rstrip('/')}{endpoint}"

        headers = {}
        if authenticated:
            headers.update(self._get_api_headers())

        try:
            response = self._session.request(
                method=method,
                url=url,
                json=data,
                headers=headers,
                timeout=timeout
            )

            # Handle authentication errors
            if response.status_code == 401:
                raise AuthenticationError("API key invalid or expired")

            if response.status_code == 403:
                raise AuthenticationError("Access denied")

            # Parse response
            try:
                result = response.json()
            except ValueError:
                raise CommunicationError(f"Invalid JSON response from server: {response.text[:200]}")

            # Check for error status
            if response.status_code >= 400:
                error_msg = result.get('message', f"HTTP {response.status_code}")
                raise CommunicationError(error_msg)

            return result

        except requests.exceptions.ConnectionError as e:
            raise CommunicationError(f"Cannot connect to server at {self.config.server_url}: {e}")

        except requests.exceptions.Timeout:
            raise CommunicationError(f"Request timed out after {timeout}s")

        except requests.exceptions.SSLError as e:
            # Log detailed SSL error information
            logger.error(f"SSL verification failed for {url}")
            logger.error(f"SSL Error: {e}")
            logger.error(f"CA cert path configured: {self.config.ca_cert_path}")
            if self.config.ca_cert_path and Path(self.config.ca_cert_path).exists():
                logger.error(f"CA cert file exists and is readable")
                # Try to read and display CA cert details
                try:
                    with open(self.config.ca_cert_path, 'r') as f:
                        ca_content = f.read()
                    if ca_content:
                        logger.error(f"CA cert first 200 chars: {ca_content[:200]}")
                except Exception as cert_read_error:
                    logger.error(f"Could not read CA cert: {cert_read_error}")
            else:
                logger.error(f"CA cert path not configured or file does not exist")
            logger.error(f"Session verify setting: {self._session.verify}")
            raise CommunicationError(f"SSL certificate verification failed: {e}")

        except requests.exceptions.RequestException as e:
            raise CommunicationError(f"Request failed: {e}")

    # =========================================================================
    # REGISTRATION
    # =========================================================================

    def register(self, bootstrap_token: str, collector_id: str) -> Dict[str, Any]:
        """
        Register collector with central server using bootstrap token.

        Args:
            bootstrap_token: One-time registration token from dashboard
            collector_id: Unique identifier for this collector

        Returns:
            Registration response containing API key and config

        Raises:
            RegistrationError: If registration fails
        """
        logger.info(f"Registering collector {collector_id} with server {self.config.server_url}")

        try:
            result = self._make_request(
                method='POST',
                endpoint='/api/remote/register',
                data={
                    'token': bootstrap_token,
                    'collector_id': collector_id
                },
                authenticated=False,
                timeout=30
            )

            if result.get('status') != 'success':
                raise RegistrationError(result.get('message', 'Registration failed'))

            # Update config with registration data
            self.config.collector_id = result.get('collector_id')
            self.config.api_key = result.get('api_key')
            self.config.registered_at = datetime.now().isoformat()

            # Apply server-provided config
            server_config = result.get('config', {})
            if server_config.get('transmission_mode'):
                self.config.transmission_mode = server_config['transmission_mode']
            if server_config.get('collector_name'):
                self.config.collector_name = server_config['collector_name']
            if server_config.get('organization'):
                self.config.organization = server_config['organization']
            if server_config.get('location'):
                self.config.location = server_config['location']
            if server_config.get('environment'):
                self.config.environment = server_config['environment']

            # Update session headers with new ID
            self._session.headers['User-Agent'] = f'CAIP-Collector/1.0 ({collector_id})'

            logger.info(f"Registration successful. Collector ID: {collector_id}")
            return result

        except CommunicationError as e:
            raise RegistrationError(f"Registration failed: {e}")

    # =========================================================================
    # HEARTBEAT WITH CONFIG SYNC
    # =========================================================================

    def send_heartbeat(
        self,
        status: str = 'healthy',
        version: str = '1.0.0',
        uptime_seconds: Optional[int] = None,
        resource_usage: Optional[Dict] = None,
        config_version: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Send heartbeat to server with config synchronization.

        The server returns config updates and pending jobs in the response.

        Args:
            status: Collector health status
            version: Collector version
            uptime_seconds: Time since collector started
            resource_usage: CPU/memory/disk usage stats
            config_version: Current local config version

        Returns:
            Server response with config and job information:
            {
                "status": "ok",
                "config_changed": true/false,
                "config_version": 5,
                "config": {...},  # if config_changed
                "pending_jobs_count": 2,
                "pending_jobs": [...]  # if jobs pending
            }
        """
        data = {
            'status': status,
            'version': version,
            'config_version': config_version or getattr(self.config, 'config_version', 0),
            'timestamp': datetime.now().isoformat()
        }

        if uptime_seconds is not None:
            data['uptime_seconds'] = uptime_seconds

        if resource_usage:
            data['resource_usage'] = resource_usage

        result = self._make_request(
            method='POST',
            endpoint='/api/remote/heartbeat',
            data=data,
            authenticated=True,
            timeout=15
        )

        # Update last heartbeat time
        self.config.last_heartbeat = datetime.now().isoformat()

        # Apply config updates if present
        if result.get('config_changed') and result.get('config'):
            self._apply_config_update(result['config'])

        return result

    def _apply_config_update(self, new_config: Dict[str, Any]) -> None:
        """
        Apply configuration update from server.

        Args:
            new_config: New configuration from server
        """
        logger.info(f"Applying config update from server (v{new_config.get('version', '?')})")

        # Update config fields
        if 'version' in new_config:
            self.config.config_version = new_config['version']

        if 'transmission_mode' in new_config:
            self.config.transmission_mode = new_config['transmission_mode']

        if 'scan_targets' in new_config:
            self.config.scan_targets = new_config['scan_targets']

        if 'schedule' in new_config:
            self.config.schedule = new_config['schedule']

        if 'heartbeat_interval' in new_config:
            self.config.heartbeat_interval_seconds = new_config['heartbeat_interval']

        # Save updated config to disk
        try:
            self.config.save()
            logger.info("Config saved successfully")
        except Exception as e:
            logger.error(f"Failed to save config: {e}")

    # =========================================================================
    # JOB HANDLING
    # =========================================================================

    def get_pending_jobs(self) -> List[Dict[str, Any]]:
        """
        Get pending jobs from server.

        Returns:
            List of pending jobs
        """
        result = self._make_request(
            method='GET',
            endpoint='/api/remote/jobs',
            authenticated=True
        )
        return result.get('jobs', [])

    def acknowledge_job(self, job_id: int) -> bool:
        """
        Acknowledge receipt of a job.

        Args:
            job_id: Job identifier

        Returns:
            True if successfully acknowledged
        """
        try:
            self._make_request(
                method='POST',
                endpoint=f'/api/remote/jobs/{job_id}/ack',
                authenticated=True
            )
            return True
        except CommunicationError:
            return False

    def start_job(self, job_id: int) -> bool:
        """
        Mark a job as started.

        Args:
            job_id: Job identifier

        Returns:
            True if successful
        """
        try:
            self._make_request(
                method='POST',
                endpoint=f'/api/remote/jobs/{job_id}/start',
                authenticated=True
            )
            return True
        except CommunicationError:
            return False

    def complete_job(
        self,
        job_id: int,
        success: bool,
        result: Optional[Dict] = None,
        error_message: Optional[str] = None
    ) -> bool:
        """
        Mark a job as completed.

        Args:
            job_id: Job identifier
            success: Whether job succeeded
            result: Job result data
            error_message: Error message if failed

        Returns:
            True if successful
        """
        try:
            self._make_request(
                method='POST',
                endpoint=f'/api/remote/jobs/{job_id}/complete',
                data={
                    'success': success,
                    'result': result,
                    'error_message': error_message
                },
                authenticated=True
            )
            return True
        except CommunicationError:
            return False

    # =========================================================================
    # REPORTS
    # =========================================================================

    def submit_report(
        self,
        scan_id: str,
        certificates: list,
        findings: list,
        risk_score: float,
        metadata: Optional[Dict] = None,
        report_json: Optional[Dict] = None,
        run_number: int = 1
    ) -> Dict[str, Any]:
        """
        Submit scan report to server.

        Args:
            scan_id: Unique scan identifier
            certificates: List of discovered certificates
            findings: List of risk findings
            risk_score: Calculated risk score (0-100)
            metadata: Additional scan metadata
            report_json: Full dashboard-formatted report (for upload)
            run_number: Run number for report filename

        Returns:
            Server response with report ID
        """
        # Build report based on transmission mode
        report_data = self._build_report(
            scan_id=scan_id,
            certificates=certificates,
            findings=findings,
            risk_score=risk_score,
            metadata=metadata,
            report_json=report_json,
            run_number=run_number
        )

        result = self._make_request(
            method='POST',
            endpoint='/api/remote/report',
            data=report_data,
            authenticated=True,
            timeout=60  # Longer timeout for large reports
        )

        # Update last scan time
        self.config.last_scan = datetime.now().isoformat()

        logger.info(f"Report submitted: {scan_id}, Report ID: {result.get('report_id')}")
        return result

    def _build_report(
        self,
        scan_id: str,
        certificates: list,
        findings: list,
        risk_score: float,
        metadata: Optional[Dict] = None,
        report_json: Optional[Dict] = None,
        run_number: int = 1
    ) -> Dict[str, Any]:
        """
        Build report payload based on transmission mode.

        Full mode: Include complete certificate data
        Selective mode: Include metadata and findings, minimal cert data
        Anonymized mode: Tokenize all identifying information

        Args:
            report_json: Full dashboard-formatted report (already filtered by transmission_mode)
            run_number: Run number for report filename
        """
        mode = self.config.transmission_mode

        report = {
            'scan_id': scan_id,
            'transmission_mode': mode,
            'timestamp': datetime.now().isoformat(),
            'certificate_count': len(certificates),
            'findings': findings,
            'risk_score': risk_score,
            'run_number': run_number
        }

        if mode == 'full':
            # Include complete certificate data
            report['certificates'] = certificates
            if metadata:
                report['metadata'] = metadata

        elif mode == 'selective':
            # Include summary data, not full certificates
            report['summary'] = self._build_certificate_summary(certificates)
            if metadata:
                report['metadata'] = metadata
            # Full cert data cached locally (handled by scanner)

        elif mode == 'anonymized':
            # Tokenize all identifying information
            report['summary'] = self._build_anonymized_summary(certificates)
            report['findings'] = self._anonymize_findings(findings)
            # Token mappings stored locally (Phase 4)

        # Include filtered report JSON if provided (for dashboard upload)
        if report_json:
            report['report_json'] = report_json

        return report

    def _build_certificate_summary(self, certificates: list) -> Dict[str, Any]:
        """Build summary statistics from certificates."""
        if not certificates:
            return {'total': 0}

        # Count by various attributes
        by_issuer = {}
        by_key_type = {}
        by_expiry_bucket = {}
        expiring_soon = 0

        for cert in certificates:
            # Count by issuer - issuer might be dict or string
            issuer_obj = cert.get('issuer', 'Unknown')
            if isinstance(issuer_obj, dict):
                issuer = issuer_obj.get('commonName', 'Unknown')
            else:
                issuer = str(issuer_obj) if issuer_obj else 'Unknown'
            by_issuer[issuer] = by_issuer.get(issuer, 0) + 1

            # Count by key type
            key_type = cert.get('key_type', 'Unknown')
            by_key_type[key_type] = by_key_type.get(key_type, 0) + 1

            # Check expiry
            if cert.get('days_until_expiry', 999) < 30:
                expiring_soon += 1

        return {
            'total': len(certificates),
            'by_issuer': by_issuer,
            'by_key_type': by_key_type,
            'expiring_within_30_days': expiring_soon
        }

    def _build_anonymized_summary(self, certificates: list) -> Dict[str, Any]:
        """Build anonymized summary with tokenized identifiers."""
        summary = self._build_certificate_summary(certificates)

        # Tokenize issuer names
        if 'by_issuer' in summary:
            tokenized_issuers = {}
            for issuer, count in summary['by_issuer'].items():
                token = self._tokenize(issuer, 'ISSUER')
                tokenized_issuers[token] = count
            summary['by_issuer'] = tokenized_issuers

        return summary

    def _anonymize_findings(self, findings: list) -> list:
        """Anonymize identifying information in findings."""
        anonymized = []

        for finding in findings:
            anon_finding = finding.copy()

            # Tokenize certificate CN if present
            if 'certificate_cn' in anon_finding:
                anon_finding['certificate_token'] = self._tokenize(
                    anon_finding.pop('certificate_cn'),
                    'CERT'
                )

            # Tokenize hostname if present
            if 'hostname' in anon_finding:
                anon_finding['host_token'] = self._tokenize(
                    anon_finding.pop('hostname'),
                    'HOST'
                )

            anonymized.append(anon_finding)

        return anonymized

    def _tokenize(self, value: str, prefix: str) -> str:
        """
        Create deterministic token for a value.

        In Phase 4, this will use HMAC with a local key and store mappings.
        For now, uses simple hash prefix.
        """
        # Simple tokenization - Phase 4 will add proper HMAC + local storage
        hash_value = hashlib.sha256(value.encode()).hexdigest()[:12]
        return f"{prefix}-{hash_value}"

    # =========================================================================
    # POLICY
    # =========================================================================

    def get_policy(self) -> Dict[str, Any]:
        """
        Get assigned policy from server.

        Returns:
            Policy configuration
        """
        result = self._make_request(
            method='GET',
            endpoint='/api/remote/policy',
            authenticated=True
        )

        return result.get('policy', {})

    # =========================================================================
    # STATUS
    # =========================================================================

    def check_connection(self) -> Tuple[bool, str]:
        """
        Check connection to server.

        Returns:
            Tuple of (success, message)
        """
        try:
            self.send_heartbeat()
            return True, "Connected successfully"
        except AuthenticationError as e:
            return False, f"Authentication failed: {e}"
        except CommunicationError as e:
            return False, f"Connection failed: {e}"
        except Exception as e:
            return False, f"Error: {e}"

    # =========================================================================
    # CERTIFICATE MANAGEMENT (mTLS)
    # =========================================================================

    def _load_tls_config(self):
        """Load mTLS certificates from disk if available."""
        try:
            # Only attempt to load if paths are configured
            if not self.config.cert_path or not self.config.key_path:
                logger.debug("Certificate paths not configured - skipping mTLS cert load")
                return

            cert_path = Path(self.config.cert_path)
            key_path = Path(self.config.key_path)
            ca_cert_path = Path(self.config.ca_cert_path) if self.config.ca_cert_path else None

            if cert_path.exists() and key_path.exists():
                self._session.cert = (str(cert_path), str(key_path))

                # Re-mount the adapter with new cert paths to ensure poolmanager is recreated
                # This is necessary because init_poolmanager is only called once per adapter
                if hasattr(self, '_adapter'):
                    new_adapter = CustomSSLAdapter(
                        cert_file=str(cert_path),
                        key_file=str(key_path),
                        ca_file=str(ca_cert_path) if ca_cert_path and ca_cert_path.exists() else None
                    )
                    self._session.mount('https://', new_adapter)
                    self._adapter = new_adapter
                    logger.info(f"Re-mounted SSL adapter with client cert paths")

                logger.info("mTLS certificates loaded")
            else:
                logger.debug(f"Certificate files not yet available at configured paths")

            if ca_cert_path and ca_cert_path.exists():
                self._session.verify = str(ca_cert_path)

                # If we haven't already mounted with CA cert, do it now
                if hasattr(self, '_adapter'):
                    # Only re-mount if ca_file is not already set in the adapter
                    if not self._adapter.ca_file or self._adapter.ca_file != str(ca_cert_path):
                        new_adapter = CustomSSLAdapter(
                            cert_file=self._adapter.cert_file,
                            key_file=self._adapter.key_file,
                            ca_file=str(ca_cert_path)
                        )
                        self._session.mount('https://', new_adapter)
                        self._adapter = new_adapter
                        logger.info(f"Re-mounted SSL adapter with CA cert path")

                logger.info("CA certificate loaded for verification")
                logger.debug("SSL context: certificate chain validation enabled, hostname verification disabled")
        except Exception as e:
            logger.warning(f"Could not load TLS config: {e}")

    def register_with_certificate(
        self,
        bootstrap_token: str,
        collector_id: str,
        engagement_id: str
    ) -> Dict[str, Any]:
        """
        Register collector with certificate-based authentication.

        Generates a CSR locally, submits it with bootstrap token,
        receives signed certificate and CA chain, stores locally.

        Args:
            bootstrap_token: One-time registration token
            collector_id: Unique collector identifier
            engagement_id: Engagement identifier (determines CA)

        Returns:
            Registration response with certificate paths

        Raises:
            RegistrationError: If registration fails
        """
        if not CRYPTO_AVAILABLE:
            raise RegistrationError("cryptography library required for certificate registration")

        logger.info(f"Registering collector {collector_id} with certificate authentication")

        try:
            # Generate CSR
            csr_pem = self._generate_csr(collector_id)

            # For initial registration on port 5443, disable SSL verification because:
            # 1. We don't have a certificate yet (no mTLS)
            # 2. We're using bootstrap token authentication
            # 3. After registration, we'll get a certificate and CA chain
            # Create a temporary session with SSL verification disabled
            import requests
            import warnings
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            temp_session = requests.Session()
            temp_session.verify = False

            # Submit for certificate registration
            url = f"{self.config.server_url.rstrip('/')}/api/v1/remote/certificate/register"
            try:
                response = temp_session.request(
                    method='POST',
                    url=url,
                    json={
                        'collector_id': collector_id,
                        'engagement_id': engagement_id,
                        'csr': csr_pem,
                        'collector_name': self.config.collector_name,
                        'location': self.config.location
                    },
                    headers={'X-Bootstrap-Token': bootstrap_token},
                    timeout=30
                )
            except requests.exceptions.SSLError as e:
                # If SSL verification fails even with verify=False, there might be a connection issue
                logger.error(f"SSL connection error during registration: {e}")
                raise CommunicationError(f"Cannot connect to server at {url}: {e}")

            # Parse response
            try:
                result = response.json()
            except ValueError:
                raise RegistrationError(f"Invalid JSON response: {response.text[:200]}")

            if response.status_code >= 400:
                error_msg = result.get('error', f"HTTP {response.status_code}")
                raise RegistrationError(error_msg)

            # Debug: log what we got from server
            logger.info(f"Registration response keys: {list(result.keys())}")
            if 'api_key' in result:
                logger.info(f"API key present in response: {result['api_key'][:20]}...")
            else:
                logger.warning(f"API key NOT in response")

            # Save certificates
            cert_pem = result.get('certificate')
            ca_chain_pem = result.get('ca_chain')

            if not cert_pem or not ca_chain_pem:
                raise RegistrationError("Server did not return certificate or CA chain")

            # Store certificate and CA chain
            cert_dir = Path('/opt/caip/trust')
            cert_dir.mkdir(parents=True, exist_ok=True)

            cert_path = cert_dir / 'collector.crt'
            ca_cert_path = cert_dir / 'ca.crt'

            with open(cert_path, 'w') as f:
                f.write(cert_pem)
            cert_path.chmod(0o600)

            with open(ca_cert_path, 'w') as f:
                f.write(ca_chain_pem)
            ca_cert_path.chmod(0o644)

            # Update config
            self.config.collector_id = collector_id
            self.config.engagement_id = engagement_id
            self.config.cert_path = str(cert_path)
            self.config.ca_cert_path = str(ca_cert_path)
            self.config.registered_at = datetime.now().isoformat()

            # Use collector_name from server response as the authoritative collector_id
            # The server derives this from the bootstrap token's collector_name field
            server_collector_id = result.get('collector_name') or result.get('collector_id') or collector_id
            self.config.collector_id = server_collector_id
            logger.info(f"Using collector_id from server: {server_collector_id}")

            # Save API key if provided by server
            if 'api_key' in result:
                self.config.api_key = result['api_key']
                logger.info(f"Received API key from server: {result['api_key'][:20]}...")
            else:
                logger.warning("No API key in registration response")

            # Switch to mTLS endpoint (port 5444) for post-registration communication
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(self.config.server_url)

            # Build new netloc with port 5444
            if parsed.hostname:
                netloc = f"{parsed.hostname}:5444"
            else:
                netloc = "localhost:5444"

            # Reconstruct URL with new port
            new_parsed = (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
            new_server_url = urlunparse(new_parsed)
            self.config.server_url = new_server_url

            # SECURITY FIX 4: Save config ONCE after all updates are complete
            # Prevents data loss from multiple consecutive saves that can overwrite fields
            self.config.save()
            logger.info(f"Configuration saved with api_key={'present' if self.config.api_key else 'MISSING'}")
            logger.info(f"Switched to mTLS endpoint: {self.config.server_url}")

            # Load TLS config for future requests (with client certificate for mTLS)
            self._load_tls_config()

            # Log connection details for debugging certificate selection
            logger.info(f"[Collector] Switched to mTLS endpoint: {self.config.server_url}")
            logger.info(f"[Collector] SNI will send: {parsed.hostname}")
            logger.info(f"[Collector] Engagement ID in config: {self.config.engagement_id}")
            logger.info(f"[Collector] Client cert path: {self.config.cert_path}")
            logger.info(f"[Collector] CA cert path: {self.config.ca_cert_path}")
            logger.info(f"[Collector] Server cert verification: {self._session.verify if hasattr(self, '_session') else 'session not initialized'}")

            logger.info(f"Certificate registration successful. Expires: {result.get('expires_at')}")
            return result

        except CommunicationError as e:
            raise RegistrationError(f"Certificate registration failed: {e}")

    def _generate_csr(self, collector_id: str) -> str:
        """
        Generate Certificate Signing Request locally.

        Creates a new private key and CSR with subject CN=collector-{id}.
        Private key is stored locally (in self.config.key_path).

        Args:
            collector_id: Collector identifier (used in CN)

        Returns:
            CSR in PEM format
        """
        logger.info(f"Generating CSR for collector {collector_id}")

        try:
            # Generate private key (RSA 4096 to match server certificates)
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )

            # Save private key
            key_dir = Path('/opt/caip/trust')
            key_dir.mkdir(parents=True, exist_ok=True)
            key_path = key_dir / 'collector.key'

            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

            with open(key_path, 'wb') as f:
                f.write(key_pem)
            key_path.chmod(0o600)

            self.config.key_path = str(key_path)

            # Build CSR
            csr_builder = x509.CertificateSigningRequestBuilder()
            csr_builder = csr_builder.subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, f"collector-{collector_id}"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.config.organization or "CAIP"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            ]))

            csr = csr_builder.sign(
                private_key,
                hashes.SHA256(),
                default_backend()
            )

            csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
            logger.info("CSR generated successfully")
            return csr_pem

        except Exception as e:
            logger.error(f"CSR generation failed: {e}")
            raise RegistrationError(f"Failed to generate CSR: {e}")

    def renew_certificate(self) -> Dict[str, Any]:
        """
        Renew collector certificate with new CSR.

        Generates a new CSR, submits it to the renewal endpoint,
        receives new certificate, stores locally, and reloads TLS config.

        Returns:
            Renewal response with new certificate info

        Raises:
            CommunicationError: If renewal fails
        """
        if not self.config.collector_id:
            raise AuthenticationError("Collector not registered")

        if not CRYPTO_AVAILABLE:
            raise CommunicationError("cryptography library required for certificate renewal")

        logger.info(f"Renewing certificate for collector {self.config.collector_id}")

        try:
            # Generate new CSR
            csr_pem = self._generate_csr(self.config.collector_id)

            # Submit renewal request (authenticated with current mTLS cert)
            result = self._make_request(
                method='POST',
                endpoint='/api/v1/remote/certificate/renew',
                data={
                    'collector_id': self.config.collector_id,
                    'csr': csr_pem
                },
                authenticated=True,
                timeout=30
            )

            # Save new certificate
            cert_pem = result.get('certificate')
            ca_chain_pem = result.get('ca_chain')

            if not cert_pem:
                raise CommunicationError("Server did not return new certificate")

            cert_path = Path(self.config.cert_path)
            with open(cert_path, 'w') as f:
                f.write(cert_pem)
            cert_path.chmod(0o600)

            if ca_chain_pem:
                ca_cert_path = Path(self.config.ca_cert_path)
                with open(ca_cert_path, 'w') as f:
                    f.write(ca_chain_pem)

            # Reload TLS config for future requests
            self._load_tls_config()

            logger.info(f"Certificate renewal successful. Expires: {result.get('expires_at')}")
            return result

        except CommunicationError as e:
            logger.error(f"Certificate renewal failed: {e}")
            raise

    def get_certificate_status(self) -> Optional[Dict[str, Any]]:
        """
        Get current certificate status from server.

        Returns:
            Certificate status information, or None if no certificate exists

        Raises:
            CommunicationError: If status check fails
        """
        if not self.config.collector_id:
            return None

        try:
            result = self._make_request(
                method='GET',
                endpoint=f'/api/v1/remote/certificate/status?collector_id={self.config.collector_id}',
                authenticated=False,  # No auth required for status check
                timeout=10
            )
            return result
        except CommunicationError as e:
            logger.warning(f"Could not get certificate status: {e}")
            return None

    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        authenticated: bool = True,
        headers: Optional[Dict] = None,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """
        Make HTTP request to server (extended version with custom headers).

        Args:
            method: HTTP method
            endpoint: API endpoint
            data: Request body
            authenticated: Whether to use API key/cert auth
            headers: Additional headers to add
            timeout: Request timeout in seconds

        Returns:
            Response data as dictionary

        Raises:
            CommunicationError: If request fails
        """
        url = f"{self.config.server_url.rstrip('/')}{endpoint}"

        req_headers = {}
        if authenticated:
            req_headers.update(self._get_api_headers())
        if headers:
            req_headers.update(headers)

        try:
            response = self._session.request(
                method=method,
                url=url,
                json=data,
                headers=req_headers,
                timeout=timeout
            )

            # Handle authentication errors
            if response.status_code == 401:
                raise AuthenticationError("API key invalid or expired")

            if response.status_code == 403:
                raise AuthenticationError("Access denied")

            # Parse response
            try:
                result = response.json()
            except ValueError:
                raise CommunicationError(f"Invalid JSON response from server: {response.text[:200]}")

            # Check for error status
            if response.status_code >= 400:
                error_msg = result.get('error', f"HTTP {response.status_code}")
                raise CommunicationError(error_msg)

            return result

        except requests.exceptions.ConnectionError as e:
            raise CommunicationError(f"Cannot connect to server at {self.config.server_url}: {e}")

        except requests.exceptions.Timeout:
            raise CommunicationError(f"Request timed out after {timeout}s")

        except requests.exceptions.RequestException as e:
            raise CommunicationError(f"Request failed: {e}")
