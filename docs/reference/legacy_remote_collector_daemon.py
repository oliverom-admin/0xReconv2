# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: remote_collector/daemon.py
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
Collector Daemon - Background Service Mode

Runs the collector as a persistent service that:
- Sends periodic heartbeats
- Executes scheduled scans
- Submits reports to central server
- Handles graceful shutdown
"""

import os
import sys
import time
import signal
import logging
import threading
import json
from datetime import datetime
from typing import Optional, Callable, Dict, Any

try:
    from flask import Flask, jsonify
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Support both relative imports (when run as package) and absolute imports (when run as script)
try:
    from .config import CollectorConfig
    from .client import CollectorClient, CommunicationError, AuthenticationError
    from .scanner import CollectorScanner, CombinedScanResult
except (ImportError, ValueError):
    from config import CollectorConfig
    from client import CollectorClient, CommunicationError, AuthenticationError
    from scanner import CollectorScanner, CombinedScanResult

logger = logging.getLogger('collector.daemon')


class CollectorDaemon:
    """
    Background daemon for the remote collector.

    Manages:
    - Heartbeat thread (periodic status updates)
    - Scan scheduler (periodic certificate scans)
    - Report submission (after each scan)
    - Graceful shutdown handling
    """

    def __init__(self, config: CollectorConfig):
        """
        Initialize daemon.

        Args:
            config: Collector configuration
        """
        # Initialize Luna HSM client if available
        self._initialize_luna()

        self.config = config
        self.client = CollectorClient(config)
        self.scanner = CollectorScanner()

        # State
        self._running = False
        self._start_time: Optional[datetime] = None
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._scan_thread: Optional[threading.Thread] = None
        self._flask_thread: Optional[threading.Thread] = None
        self._cert_renewal_thread: Optional[threading.Thread] = None
        self._shutdown_event = threading.Event()

        # Statistics
        self._heartbeat_count = 0
        self._scan_count = 0
        self._last_scan_result: Optional[CombinedScanResult] = None

        # Token mappings for anonymized mode decryption (Option A)
        # Stored locally, never transmitted to dashboard
        self.token_mappings = {}

        # Flask app for local decryption endpoint (if available)
        self.flask_app = None
        if FLASK_AVAILABLE:
            self._init_flask_app()

        # Register signal handlers
        self._setup_signal_handlers()

    def _initialize_luna(self):
        """Initialize Luna HSM client environment."""
        try:
            luna_home = "/opt/caip/luna/setup-ISR_KaaS_Full"

            # Create socket directory if needed
            socket_dir = os.path.expanduser("~/.Chrystoki")
            try:
                os.makedirs(socket_dir, mode=0o700, exist_ok=True)
                logger.debug(f"Ensured Luna socket directory: {socket_dir}")
            except OSError:
                pass  # May fail due to permissions, but socket dir should exist

            # Ensure Luna environment variables are set
            if not os.environ.get('LD_LIBRARY_PATH') or luna_home not in os.environ.get('LD_LIBRARY_PATH', ''):
                lib_dir = f"{luna_home}/libs/64"
                existing_path = os.environ.get('LD_LIBRARY_PATH', '')
                os.environ['LD_LIBRARY_PATH'] = f"{lib_dir}:{lib_dir}/fips:{lib_dir}/hw:{luna_home}/libs"
                if existing_path:
                    os.environ['LD_LIBRARY_PATH'] += f":{existing_path}"
                logger.info("Set LD_LIBRARY_PATH for Luna HSM")

            if not os.environ.get('CTCONF'):
                os.environ['CTCONF'] = f"{luna_home}/Chrystoki.conf"
                logger.info("Set CTCONF for Luna HSM")

            if not os.environ.get('ChrystokiConfigurationPath'):
                os.environ['ChrystokiConfigurationPath'] = luna_home
                logger.info("Set ChrystokiConfigurationPath for Luna HSM")

            logger.info("Luna HSM initialization complete")
        except Exception as e:
            logger.warning(f"Luna HSM initialization failed (non-fatal): {e}")

    def _setup_signal_handlers(self):
        """Set up graceful shutdown handlers."""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, initiating shutdown...")
        self.stop()

    @property
    def uptime_seconds(self) -> int:
        """Get daemon uptime in seconds."""
        if self._start_time:
            return int((datetime.now() - self._start_time).total_seconds())
        return 0

    def _init_flask_app(self):
        """
        Initialize Flask app for local decryption endpoint (Option A).

        The decryption endpoint allows users to decrypt anonymized tokens
        on the local network only. Token mappings are stored locally and
        never transmitted to the dashboard.
        """
        try:
            self.flask_app = Flask('collector-decrypt')
            self.flask_app.config['JSON_SORT_KEYS'] = False

            @self.flask_app.route('/api/local/health', methods=['GET'])
            def health():
                """Health check endpoint."""
                return jsonify({'status': 'ok', 'service': 'collector-decrypt'})

            @self.flask_app.route('/api/local/decrypt/<token>', methods=['GET'])
            def decrypt_token(token):
                """
                Decrypt an anonymized token to its original value.

                This endpoint is only accessible on the local network.
                Token mappings are stored locally on the collector and
                never transmitted to the dashboard.

                Args:
                    token: Anonymized token (e.g., CERT-a3f8d7c9b4e2)

                Returns:
                    JSON with token and original_value, or 404 if not found
                """
                if token not in self.token_mappings:
                    return jsonify({'error': f'Token not found: {token}'}), 404

                original_value = self.token_mappings[token]
                token_type = token.split('-')[0] if '-' in token else 'UNKNOWN'

                return jsonify({
                    'token': token,
                    'type': token_type,
                    'original_value': original_value
                }), 200

            logger.info("Flask decryption endpoint initialized at /api/local/decrypt/<token>")

        except Exception as e:
            logger.error(f"Failed to initialize Flask app: {e}")
            self.flask_app = None

    def _run_flask_app(self):
        """Run Flask app in background thread."""
        try:
            if not self.flask_app:
                return

            logger.info("Flask app starting on 127.0.0.1:8000")
            self.flask_app.run(
                host='127.0.0.1',  # Localhost only - not accessible from internet
                port=8000,
                debug=False,
                use_reloader=False,  # Disable reloader in daemon mode
                threaded=True
            )
        except Exception as e:
            logger.error(f"Flask app error: {e}", exc_info=True)

    def start(self):
        """
        Start the daemon.

        Begins heartbeat and scan threads.
        """
        if self._running:
            logger.warning("Daemon already running")
            return

        if not self.config.is_registered():
            raise RuntimeError("Collector not registered. Run registration first.")

        logger.info("Starting collector daemon...")
        self._running = True
        self._start_time = datetime.now()
        self._shutdown_event.clear()

        # Start Flask decryption endpoint (if available)
        if self.flask_app:
            self._flask_thread = threading.Thread(
                target=self._run_flask_app,
                name="FlaskThread",
                daemon=True
            )
            self._flask_thread.start()
            logger.info("Flask decryption endpoint started (localhost:8000)")

        # Start heartbeat thread
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            name="HeartbeatThread",
            daemon=True
        )
        self._heartbeat_thread.start()
        logger.info(f"Heartbeat thread started (interval: {self.config.heartbeat_interval_seconds}s)")

        # Start certificate renewal thread
        self._cert_renewal_thread = threading.Thread(
            target=self._certificate_renewal_loop,
            name="CertRenewalThread",
            daemon=True
        )
        self._cert_renewal_thread.start()
        logger.info("Certificate renewal thread started (checks hourly)")

        # Start scan scheduler if enabled
        if self.config.schedule.get('enabled', False):
            self._scan_thread = threading.Thread(
                target=self._scan_loop,
                name="ScanThread",
                daemon=True
            )
            self._scan_thread.start()
            logger.info(f"Scan scheduler started (interval: {self.config.schedule.get('interval_minutes', 60)}m)")

            # Run initial scan if configured
            if self.config.schedule.get('run_on_startup', True):
                logger.info("Running startup scan...")
                self._run_scan()

        logger.info("Collector daemon started successfully")

    def stop(self):
        """Stop the daemon gracefully."""
        if not self._running:
            return

        logger.info("Stopping collector daemon...")
        self._running = False
        self._shutdown_event.set()

        # Wait for threads to finish
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            self._heartbeat_thread.join(timeout=5)

        if self._scan_thread and self._scan_thread.is_alive():
            self._scan_thread.join(timeout=30)

        logger.info("Collector daemon stopped")

    def run(self):
        """
        Run daemon in foreground (blocking).

        Use this for systemd/service deployment.
        """
        self.start()

        logger.info("Daemon running. Press Ctrl+C to stop.")

        try:
            while self._running:
                self._shutdown_event.wait(timeout=1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def _heartbeat_loop(self):
        """Background thread for sending heartbeats."""
        while self._running and not self._shutdown_event.is_set():
            try:
                self._send_heartbeat()
                self._heartbeat_count += 1
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")

            # Wait for next heartbeat interval
            self._shutdown_event.wait(timeout=self.config.heartbeat_interval_seconds)

    def _send_heartbeat(self):
        """Send a single heartbeat to server and process any pending jobs."""
        try:
            resource_usage = self._get_resource_usage()

            response = self.client.send_heartbeat(
                status='healthy',
                version='1.0.0',
                uptime_seconds=self.uptime_seconds,
                resource_usage=resource_usage,
                config_version=getattr(self.config, 'config_version', 0)
            )

            # Check for config changes (already handled by client._apply_config_update)
            if response.get('config_changed'):
                logger.info(f"Configuration updated from server (v{response.get('config_version', '?')})")
                # Update local config_version
                self.config.config_version = response.get('config_version', 0)

                # Reload scan targets from updated config
                if response.get('config', {}).get('scan_targets'):
                    self.config.scan_targets = response['config']['scan_targets']
                    logger.info(f"Updated scan targets: {len(self.config.scan_targets)} target(s)")

            # Process any pending jobs from the server
            pending_jobs = response.get('pending_jobs', [])
            if pending_jobs:
                logger.info(f"Received {len(pending_jobs)} pending job(s) from server")
                self._process_jobs(pending_jobs)

            logger.debug(f"Heartbeat sent successfully (#{self._heartbeat_count + 1})")

        except AuthenticationError as e:
            logger.error(f"Authentication failed: {e}")
            # Don't stop daemon, might be transient
        except CommunicationError as e:
            logger.warning(f"Heartbeat failed (will retry): {e}")

    def _process_jobs(self, jobs: list):
        """
        Process pending jobs from the server.

        Args:
            jobs: List of job dictionaries from server
        """
        for job in jobs:
            job_id = job.get('id')
            job_type = job.get('job_type')

            if not job_id or not job_type:
                logger.warning(f"Invalid job received: {job}")
                continue

            logger.info(f"Processing job #{job_id}: {job_type}")

            try:
                # Acknowledge the job
                if not self.client.acknowledge_job(job_id):
                    logger.warning(f"Failed to acknowledge job #{job_id}")
                    continue

                # Mark job as started
                if not self.client.start_job(job_id):
                    logger.warning(f"Failed to start job #{job_id}")
                    continue

                # Execute the job based on type
                if job_type == 'scan':
                    result = self._execute_scan_job(job)
                elif job_type == 'config_reload':
                    result = self._execute_config_reload_job(job)
                else:
                    logger.warning(f"Unknown job type: {job_type}")
                    self.client.complete_job(job_id, success=False, error_message=f"Unknown job type: {job_type}")
                    continue

                # Log detailed result
                if not result.get('success'):
                    logger.error(f"Job #{job_id} execution failed: {result.get('error')}")

                # Mark job as completed
                self.client.complete_job(
                    job_id,
                    success=result.get('success', False),
                    result=result.get('data'),
                    error_message=result.get('error')
                )

                logger.info(f"Job #{job_id} completed: {'success' if result.get('success') else 'failed'}")

            except Exception as e:
                logger.error(f"Job #{job_id} failed with exception: {e}", exc_info=True)
                try:
                    self.client.complete_job(job_id, success=False, error_message=str(e))
                except Exception:
                    pass

    def _execute_scan_job(self, job: dict) -> dict:
        """
        Execute a scan job using self-contained configuration from payload.

        The job payload contains COMPLETE scan configuration:
        - config: Full collector configuration with credentials resolved
        - policy: Complete policy rules for assessment
        - scan_id: Unique scan identifier
        - scan_name: Human-readable scan name

        This is Phase 2 of the job-based architecture refactoring:
        The job payload is the ONLY source of truth for scan execution.
        No reliance on local scan_targets or config files.

        Args:
            job: Job dictionary with self-contained payload

        Returns:
            Result dictionary with success, data, error
        """
        try:
            import json

            # Extract payload
            payload = job.get('payload', {})
            if isinstance(payload, str):
                payload = json.loads(payload) if payload else {}

            logger.debug(f"Scan job payload: {payload}")

            # Log what's in the payload (INFO level for visibility)
            payload_keys = list(payload.keys())
            logger.info(f"Job payload contains keys: {payload_keys}")
            logger.info(f"  - config present: {'config' in payload}")
            logger.info(f"  - policy present: {'policy' in payload}")

            # Phase 2 Change: Extract full config and policy from job payload
            # (NOT from local configuration files)
            config = payload.get('config')
            policy = payload.get('policy')
            scan_id = payload.get('scan_id', f"SCAN-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
            scan_name = payload.get('scan_name', 'Remote Collector Scan')
            run_number = payload.get('run_number', 1)

            if not config:
                return {
                    'success': False,
                    'error': 'Job payload missing required config'
                }

            # IMPORTANT: Override job's transmission_mode with COLLECTOR's transmission_mode
            # The collector config (from heartbeat) takes precedence over what dashboard sends
            config['transmission_mode'] = self.config.transmission_mode

            # Add dashboard URL and token for remote log pushing
            config['dashboard_url'] = self.config.dashboard_url
            config['dashboard_token'] = self.config.dashboard_token

            logger.info(f"Executing scan job {scan_id} ({scan_name}) with transmission_mode={self.config.transmission_mode}")

            # Execute scan using CollectorScanner with full config from job payload
            # The config contains collector-based structure (ejbca, tls_scan, etc.)
            # not targets-based, so we use run_scan_with_config()
            try:
                scanner = CollectorScanner(config, policy)
                result = scanner.run_scan_with_config(
                    config=config,
                    policy=policy,
                    scan_id=scan_id,
                    run_number=run_number
                )
            except Exception as e:
                logger.error(f"Scan execution failed: {e}")
                return {
                    'success': False,
                    'error': f"Scan execution failed: {str(e)}"
                }

            # Handle both dict (from ExecutionContext) and object (from old scanner) formats
            if isinstance(result, dict):
                # ExecutionContext returns dict format
                scan_result_id = result.get('scan_id', scan_id)
                certs = result.get('certificates', [])
                findings = result.get('findings', [])
                errors = result.get('errors', [])

                logger.info(
                    f"Job scan completed: {scan_result_id}, "
                    f"certs={len(certs)}, "
                    f"findings={len(findings)}, "
                    f"errors={len(errors)}"
                )

                # Store last result
                self._last_scan_result = result
                self._scan_count += 1

                # Submit report to server if results exist
                if certs or findings:
                    try:
                        self.client.submit_scan_results(result)
                        logger.debug(f"Submitted scan results for {scan_result_id}")
                    except Exception as e:
                        logger.error(f"Failed to submit results: {e}")

                return {
                    'success': True,
                    'data': {
                        'scan_id': scan_result_id,
                        'scan_name': scan_name,
                        'certificates_found': len(certs),
                        'findings_count': len(findings),
                        'errors_count': len(errors)
                    }
                }
            else:
                # Old format (object with attributes)
                self._last_scan_result = result
                self._scan_count += 1

                logger.info(
                    f"Job scan completed: {result.scan_id}, "
                    f"certs={len(result.certificates)}, "
                    f"keys={len(result.keys)}, "
                    f"findings={len(result.findings)}"
                )

                # Store token mappings if anonymized mode (for decryption endpoint)
                if config.get('transmission_mode') == 'anonymized':
                    # Token mappings are returned by orchestrator in anonymized mode
                    # They're stored in the daemon for local decryption via Flask endpoint
                    if hasattr(result, 'token_mappings') and result.token_mappings:
                        self.token_mappings.update(result.token_mappings)
                        logger.info(f"Stored {len(result.token_mappings)} token mappings for decryption")

                # Submit report to server
                if result.certificates or result.findings or result.keys:
                    self._submit_report(result, run_number)

                return {
                    'success': True,
                    'data': {
                        'scan_id': result.scan_id,
                        'scan_name': scan_name,
                        'certificates_found': len(result.certificates),
                        'keys_found': len(result.keys),
                        'findings_count': len(result.findings),
                        'risk_score': result.risk_score
                    }
                }

        except Exception as e:
            logger.error(f"Scan job failed: {e}", exc_info=True)
            return {'success': False, 'error': str(e)}

    def _execute_config_reload_job(self, job: dict) -> dict:
        """
        Execute a config reload job.

        Args:
            job: Job dictionary

        Returns:
            Result dictionary
        """
        try:
            # Fetch fresh config from server via heartbeat
            response = self.client.send_heartbeat(
                status='healthy',
                version='1.0.0',
                config_version=0  # Force config refresh by sending version 0
            )

            if response.get('config'):
                logger.info("Configuration reloaded from server")
                return {'success': True, 'data': {'config_version': response.get('config_version')}}
            else:
                return {'success': False, 'error': 'No config returned from server'}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _scan_loop(self):
        """Background thread for scheduled scans."""
        interval_seconds = self.config.schedule.get('interval_minutes', 60) * 60

        while self._running and not self._shutdown_event.is_set():
            # Wait for scan interval
            self._shutdown_event.wait(timeout=interval_seconds)

            if not self._running:
                break

            try:
                self._run_scan()
            except Exception as e:
                logger.error(f"Scheduled scan error: {e}")

    def _run_scan(self):
        """Execute a scan and submit results."""
        logger.info("Starting scheduled scan...")

        try:
            # Get scan targets from config
            targets = self.config.scan_targets

            if not targets:
                logger.warning("No scan targets configured")
                return

            # Run the scan
            result = self.scanner.run_scan(targets)
            self._last_scan_result = result
            self._scan_count += 1

            logger.info(
                f"Scan completed: {result.scan_id}, "
                f"certs={len(result.certificates)}, "
                f"findings={len(result.findings)}, "
                f"risk_score={result.risk_score}"
            )

            # Submit report to server
            if result.certificates or result.findings:
                self._submit_report(result)
            else:
                logger.info("No certificates or findings to report")

        except Exception as e:
            logger.error(f"Scan failed: {e}", exc_info=True)

    def _submit_report(self, result: CombinedScanResult, run_number: int = 1):
        """Submit scan result to server."""
        try:
            response = self.client.submit_report(
                scan_id=result.scan_id,
                certificates=result.certificates,
                findings=result.findings,
                risk_score=result.risk_score,
                metadata={
                    'total_targets': result.total_targets,
                    'successful_targets': result.successful_targets,
                    'failed_targets': result.failed_targets,
                    'started_at': result.started_at,
                    'completed_at': result.completed_at,
                    'errors': result.errors
                },
                run_number=run_number,  # Include run number for correct report filename
                report_json=result.report_json  # Pass filtered report for dashboard upload
            )

            logger.info(f"Report submitted: {response.get('report_id')}")

        except AuthenticationError as e:
            logger.error(f"Report submission auth failed: {e}")
        except CommunicationError as e:
            logger.error(f"Report submission failed: {e}")
            # TODO: Queue for retry

    def _get_resource_usage(self) -> dict:
        """Get current resource usage stats."""
        if not PSUTIL_AVAILABLE:
            return {}

        try:
            return {
                'cpu_percent': psutil.cpu_percent(interval=0.1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:\\').percent
            }
        except Exception as e:
            logger.debug(f"Error getting resource usage: {e}")
            return {}

    def get_status(self) -> dict:
        """Get current daemon status."""
        return {
            'running': self._running,
            'uptime_seconds': self.uptime_seconds,
            'heartbeat_count': self._heartbeat_count,
            'scan_count': self._scan_count,
            'last_scan': self._last_scan_result.scan_id if self._last_scan_result else None,
            'collector_id': self.config.collector_id,
            'server': self.config.server_url,
            'transmission_mode': self.config.transmission_mode
        }

    # =========================================================================
    # CERTIFICATE RENEWAL (AUTO)
    # =========================================================================

    def _certificate_renewal_loop(self):
        """
        Background thread: Check certificate expiry and auto-renew.

        Runs every hour to:
        1. Check if certificate exists and when it expires
        2. Trigger renewal if < 7 days until expiry
        3. Handle renewal errors with logging
        """
        while self._running:
            try:
                cert_status = self._check_certificate_expiry()

                if cert_status['exists'] and cert_status['days_until_expiry'] < 7:
                    days_left = cert_status['days_until_expiry']
                    logger.info(f"Certificate expiring in {days_left} days, initiating renewal...")
                    self._perform_certificate_renewal()

            except Exception as e:
                logger.error(f"Certificate renewal check failed: {e}")

            # Sleep for 1 hour before next check
            for _ in range(60):  # Check in 60 x 1-minute intervals to allow quick shutdown
                if not self._running:
                    break
                time.sleep(60)

    def _check_certificate_expiry(self) -> Dict[str, Any]:
        """
        Check if collector certificate exists and when it expires.

        Returns:
            Dictionary with:
            {
                'exists': bool,
                'expires_at': str (ISO format) or None,
                'days_until_expiry': int or None,
                'serial': str or None
            }
        """
        try:
            from pathlib import Path
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from datetime import datetime, timezone

            cert_path = Path(self.config.cert_path) if self.config.cert_path else None

            if not cert_path or not cert_path.exists():
                logger.debug("No certificate file found")
                return {'exists': False}

            # Load certificate
            with open(cert_path, 'rb') as f:
                cert_data = f.read()

            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            expires_at = cert.not_valid_after  # Property, not a method in cryptography 41+
            # cert.not_valid_after is timezone-naive, so use naive datetime for comparison
            days_until_expiry = (expires_at - datetime.now()).days

            return {
                'exists': True,
                'expires_at': expires_at.isoformat(),
                'days_until_expiry': days_until_expiry,
                'serial': str(cert.serial_number)
            }

        except ImportError:
            logger.debug("Cryptography library not available, skipping cert check")
            return {'exists': False}
        except Exception as e:
            logger.error(f"Error checking certificate expiry: {e}")
            return {'exists': False}

    def _perform_certificate_renewal(self):
        """
        Perform certificate renewal with the dashboard.

        Generates new CSR, submits renewal request, stores new certificate.
        On success, reloads TLS configuration for future connections.
        On failure, logs error and retries on next interval.
        """
        try:
            logger.info(f"Renewing certificate for collector {self.config.collector_id}")
            result = self.client.renew_certificate()

            logger.info(f"Certificate renewal successful. New expiry: {result.get('expires_at')}")
            logger.info(f"Grace period for old cert: {result.get('grace_period_until')}")

        except Exception as e:
            logger.error(f"Certificate renewal failed (will retry later): {e}")
            # Don't crash daemon, will retry on next interval


def run_daemon(config_path: Optional[str] = None):
    """
    Entry point for running daemon from command line.

    Args:
        config_path: Path to configuration file
    """
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )

    # Load config
    config = CollectorConfig.load(config_path)

    if not config.is_registered():
        print("Error: Collector not registered. Run 'register' command first.")
        sys.exit(1)

    # Create and run daemon
    daemon = CollectorDaemon(config)

    print(f"Starting CAIP Collector Daemon")
    print(f"  Collector ID: {config.collector_id}")
    print(f"  Server: {config.server_url}")
    print(f"  Mode: {config.transmission_mode}")
    print(f"  Heartbeat interval: {config.heartbeat_interval_seconds}s")

    if config.schedule.get('enabled'):
        print(f"  Scan interval: {config.schedule.get('interval_minutes')}m")
    else:
        print(f"  Scheduled scanning: disabled")

    print()

    daemon.run()
