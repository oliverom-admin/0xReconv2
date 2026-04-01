# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: caip_scanning_functions/_scan_orchestrator.py
# Copied: 2026-04-01
# Used in: Phase 7 — Scan Orchestration
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
Scan Orchestrator Service Layer for CAIP

Encapsulates all scan execution logic, extracted from the monolithic run_scan() function.
This provides:
- Clean separation between HTTP routing and scan execution
- Testable scan phases without Flask context
- Reusable orchestration for scheduled scans, CLI, etc.

Migration from app.py run_scan_background() function (lines ~1208-1780)
"""

import json
import datetime
import logging
import traceback
import ipaddress
from typing import Dict, List, Any, Optional, Callable

# Import models
from caip_scanning_functions.models import ScanResults, CertificateInfo

# Import service layers
from connector_service import ConnectorService
from caip_policy_functions.policy_assessment_service import PolicyAssessmentService

# Import reporting service
from caip_reporting_functions.reporting_service import ReportingService

# Import metadata enrichment service
from caip_service_layer.metadata_enrichment_service import MetadataEnrichmentService

# Import environment inference service for signal fusion
try:
    from caip_service_layer.environment_inference_service import EnvironmentInferenceService
    ENVIRONMENT_INFERENCE_AVAILABLE = True
except ImportError:
    ENVIRONMENT_INFERENCE_AVAILABLE = False
    logger.warning("EnvironmentInferenceService not available - signal fusion disabled")

# Import scoring service (optional - for PKI health check scoring)
try:
    from caip_servcie_layer.scoring_service import ScoringEngine, AggregationEngine
    SCORING_AVAILABLE = True
except ImportError:
    SCORING_AVAILABLE = False

logger = logging.getLogger('caip.operational')


class ScanOrchestrator:
    """
    Orchestrates the execution of PKI scans across multiple phases.
    
    Phases:
        1. TLS Scanning
        2. Azure Key Vault Collection
        3. Luna HSM Collection
        4. EJBCA Collection
        5. CRL Checking
        6. File Scanning
        7. Policy Assessment
        8. Report Generation
    
    Usage:
        orchestrator = ScanOrchestrator(
            config=config_dict,
            policy=policy_dict,
            log_callback=my_log_function
        )
        result = orchestrator.execute()
    """
    
    def __init__(
        self,
        config: Dict[str, Any],
        policy: Dict[str, Any],
        scan_id: int,
        run_number: int,
        scan_name: str,
        reports_folder: str,
        log_callback: Optional[Callable[[int, str, int], None]] = None,
        assessment_type: str = 'pki_health_check'
    ):
        """
        Initialize the scan orchestrator.
        
        Args:
            config: Parsed configuration JSON from the scan's configuration
            policy: Parsed policy JSON from the scan's policy
            scan_id: Database ID of the scan being executed
            run_number: Current run number for this scan
            scan_name: Name of the scan (for report naming)
            reports_folder: Path to save generated reports
            log_callback: Function to call for logging (signature: scan_id, message, run_number)
            assessment_type: Type of assessment ('pki_health_check' or 'pqc_assessment')
        """
        self.config = config
        self.policy = policy
        self.scan_id = scan_id
        self.run_number = run_number
        self.scan_name = scan_name
        self.reports_folder = reports_folder
        self.log_callback = log_callback or self._default_log
        self.assessment_type = assessment_type
        
        # Initialize results container
        self.scan_results = ScanResults()

        # Assessment scoring results (populated in phase 7 if scoring enabled)
        self.assessment_score = None
        
        # Collector statistics (populated during collection phases)
        self.collector_stats = {
            'tls': {
                'enabled': False,
                'endpoints_configured': 0,
                'endpoints_scanned': 0,
                'endpoints_successful': 0,
                'certificates_discovered': 0,
                'subnets': [],
                'hostnames': []
            },
            'azure_keyvault': {
                'enabled': False,
                'tenancies': [],
                'total_tenancies': 0,
                'total_service_principals': 0,
                'total_vaults_configured': 0,
                'total_vaults_successful': 0,
                'total_certificates': 0,
                'total_keys': 0
            },
            'luna_hsm': {
                'enabled': False,
                'hsms': [],
                'total_hsms': 0,
                'total_partitions': 0,
                'total_keys': 0,
                'total_certificates': 0
            },
            'ejbca': {
                'enabled': False,
                'servers': [],
                'total_servers_configured': 0,
                'total_servers_successful': 0,
                'total_cas': 0,
                'total_certificates': 0
            },
            'crl': {
                'enabled': False,
                'total_urls_discovered': 0,
                'total_crls_fetched': 0,
                'total_crls_failed': 0
            },
            'file_scan': {
                'enabled': False,
                'paths': [],
                'total_paths_configured': 0,
                'total_paths_scanned': 0,
                'total_files_found': 0,
                'high_confidence': 0,
                'medium_confidence': 0
            }
        }
        
        # Report path (set after report generation)
        self.report_path = None
        
        # Assessment score (populated during Phase 7 for PKI health checks)
        self.assessment_score = None
    
    def _default_log(self, scan_id: int, message: str, run_number: int):
        """Default logging if no callback provided"""
        logger.info(f"[Scan {scan_id} Run {run_number}] {message}")
    
    def _log(self, message: str):
        """Convenience method for logging"""
        self.log_callback(self.scan_id, message, self.run_number)

    def _check_cancelled(self) -> bool:
        """
        Check if the scan has been cancelled by checking database status.
        Uses time-based caching to avoid excessive database queries.
        """
        import time
        
        # Only check database every 2 seconds
        current_time = time.time()
        if not hasattr(self, '_last_cancel_check'):
            self._last_cancel_check = 0
            self._is_cancelled = False
        
        if current_time - self._last_cancel_check < 2:
            return self._is_cancelled
        
        self._last_cancel_check = current_time
        
        try:
            from database_service import DatabaseService
            conn = DatabaseService.get_connection()
            c = conn.cursor()
            c.execute('SELECT status FROM scans WHERE id = ?', (self.scan_id,))
            row = c.fetchone()
            conn.close()
            if row and row['status'] == 'Cancelled':
                self._is_cancelled = True
                return True
        except Exception:
            pass
        return False
    
    # =========================================================================
    # MAIN EXECUTION
    # =========================================================================

    def _get_collector_results(self) -> Dict[str, Dict[str, Any]]:
        """
        Convert collector_stats to collector_results format for API/DB storage.

        Returns dict with {collector_name: {enabled: bool, success: bool}}
        Success is determined by whether the collector found any assets.
        """
        collector_results = {}

        # TLS collector
        tls_stats = self.collector_stats.get('tls', {})
        if tls_stats.get('enabled'):
            configured = tls_stats.get('endpoints_configured', 0)
            successful = tls_stats.get('endpoints_successful', 0)
            collector_results['tls'] = {
                'enabled': True,
                'success': successful > 0 if configured > 0 else True
            }

        # Azure Key Vault collector
        azure_stats = self.collector_stats.get('azure_keyvault', {})
        if azure_stats.get('enabled'):
            configured = azure_stats.get('total_vaults_configured', 0)
            successful = azure_stats.get('total_vaults_successful', 0)
            collector_results['azure_keyvault'] = {
                'enabled': True,
                'success': successful > 0 if configured > 0 else True
            }

        # Luna HSM collector
        hsm_stats = self.collector_stats.get('luna_hsm', {})
        if hsm_stats.get('enabled'):
            collector_results['luna_hsm'] = {
                'enabled': True,
                'success': hsm_stats.get('total_keys', 0) > 0 or hsm_stats.get('total_certificates', 0) > 0
            }

        # EJBCA collector
        ejbca_stats = self.collector_stats.get('ejbca', {})
        if ejbca_stats.get('enabled'):
            configured = ejbca_stats.get('total_servers_configured', 0)
            successful = ejbca_stats.get('total_servers_successful', 0)
            collector_results['ejbca'] = {
                'enabled': True,
                'success': successful > 0 if configured > 0 else True
            }

        # CRL collector
        crl_stats = self.collector_stats.get('crl', {})
        if crl_stats.get('enabled'):
            fetched = crl_stats.get('total_crls_fetched', 0)
            collector_results['crl'] = {
                'enabled': True,
                'success': fetched > 0
            }

        # File scan collector
        file_stats = self.collector_stats.get('file_scan', {})
        if file_stats.get('enabled'):
            found = file_stats.get('total_files_found', 0)
            high_conf = file_stats.get('high_confidence', 0)
            collector_results['file_scan'] = {
                'enabled': True,
                'success': found > 0 or high_conf > 0
            }

        return collector_results

    def execute(self) -> Dict[str, Any]:
        """
        Execute the complete scan orchestration.
        
        Returns:
            Dict containing:
                - success: bool
                - report_path: str (if successful)
                - error: str (if failed)
                - scan_results: ScanResults object
        """
        try:
            self._log(f"Starting scan run #{self.run_number}...")
            self._log("Configuration and policy loaded successfully")
            
            # Execute all phases with cancellation checks
            phases = [
                (self._phase_1_tls_scanning, "TLS Scanning"),
                (self._phase_2_azure_keyvault, "Azure Key Vault"),
                (self._phase_3_luna_hsm, "Luna HSM"),
                (self._phase_4_ejbca, "EJBCA"),
                (self._phase_5_crl_checking, "CRL Checking"),
                (self._phase_6_file_scanning, "File Scanning"),
                (self._phase_6_5_normalisation, "Normalisation"),
                (self._phase_7_policy_assessment, "Policy Assessment"),
                (self._phase_8_report_generation, "Report Generation"),
            ]
            
            for phase_func, phase_name in phases:
                if self._check_cancelled():
                    self._log(f"Scan cancelled by user before {phase_name}")
                    return {
                        'success': False,
                        'error': 'Scan cancelled by user',
                        'scan_results': self.scan_results,
                        'collector_results': self._get_collector_results()
                    }
                phase_func()
            
            self._log(f"Scan completed successfully. Report saved to: {self.report_path}")

            return {
                'success': True,
                'report_path': self.report_path,
                'scan_results': self.scan_results,
                'collector_results': self._get_collector_results()
            }
            
        except Exception as e:
            error_details = traceback.format_exc()
            self._log(f"ERROR: {str(e)}\n\nTraceback:\n{error_details}")
            logger.error(f"Error running scan {self.scan_id}: {e}")

            return {
                'success': False,
                'error': str(e),
                'error_details': error_details,
                'scan_results': self.scan_results,
                'collector_results': self._get_collector_results()
            }
    
    # =========================================================================
    # PHASE 1: TLS SCANNING
    # =========================================================================
    
    def _phase_1_tls_scanning(self):
        """Execute TLS scanning phase"""
        tls_config = self.config.get('tls_scan', {})
        if not tls_config.get('enabled', False):
            return
        
        self._log("[Phase 1] Performing TLS scanning...")
        
        # Initialize collector stats
        self.collector_stats['tls']['enabled'] = True
        self.collector_stats['tls']['subnets'] = tls_config.get('subnets', [])
        self.collector_stats['tls']['hostnames'] = tls_config.get('hostnames', [])
        
        try:
            timeout = tls_config.get('timeout', 10)
            
            # Generate endpoints from hostnames and subnets
            tls_endpoints = self._generate_tls_endpoints(tls_config)
            self.collector_stats['tls']['endpoints_configured'] = len(tls_endpoints)
            
            self._log(f"  Generated {len(tls_endpoints)} endpoints to scan")
            
            endpoints_scanned = 0
            endpoints_successful = 0
            certs_discovered = 0
            
            for endpoint in tls_endpoints:
                # Check for cancellation
                if self._check_cancelled():
                    self._log("  Scan cancelled by user during TLS scanning")
                    return
                
                host = endpoint.get('host')
                port = endpoint.get('port', 443)
                self._log(f"  Scanning {host}:{port}...")
                endpoints_scanned += 1
                
                try:
                    result = ConnectorService.scan_tls_endpoint(host, port, timeout)
                    if result:
                        # Note: Enrichment (environment + security analysis) happens in Phase 6.5
                        # after normalization to ensure consistent timing across all collectors
                        self.scan_results.tls_results.append(result)
                        self.scan_results.certificates.extend(result.certificate_chain)
                        endpoints_successful += 1
                        certs_discovered += len(result.certificate_chain)
                except Exception as e:
                    self._log(f"  Warning: Error scanning {host}:{port}: {str(e)}")
            
            # Update collector stats
            self.collector_stats['tls']['endpoints_scanned'] = endpoints_scanned
            self.collector_stats['tls']['endpoints_successful'] = endpoints_successful
            self.collector_stats['tls']['certificates_discovered'] = certs_discovered
            
            self._log(f"  TLS scanning complete. Found {certs_discovered} certificates from {endpoints_successful}/{endpoints_scanned} endpoints")
        except Exception as e:
            self._log(f"ERROR in TLS scanning: {str(e)}")
    
    def _generate_tls_endpoints(self, tls_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate list of TLS endpoints from hostnames and subnets"""
        tls_endpoints = []
        ports = tls_config.get('ports', [443])
        
        # Add hostname-based endpoints
        hostnames = tls_config.get('hostnames', [])
        for hostname in hostnames:
            for port in ports:
                tls_endpoints.append({'host': hostname, 'port': int(port)})
        
        # Add subnet-based endpoints
        subnets = tls_config.get('subnets', [])
        for subnet in subnets:
            try:
                network = ipaddress.ip_network(subnet, strict=False)
                for ip in network.hosts():
                    for port in ports:
                        tls_endpoints.append({'host': str(ip), 'port': int(port)})
            except Exception as subnet_error:
                self._log(f"  Warning: Invalid subnet {subnet}: {str(subnet_error)}")
        
        return tls_endpoints
    
    # =========================================================================
    # PHASE 2: AZURE KEY VAULT COLLECTION
    # =========================================================================
    
    def _phase_2_azure_keyvault(self):
        """Execute Azure Key Vault collection phase"""
        azure_config = self.config.get('azure_keyvault', {})
        if not azure_config.get('enabled', False):
            return
        
        self._log("[Phase 2] Collecting from Azure Key Vault...")
        
        # Initialize collector stats
        self.collector_stats['azure_keyvault']['enabled'] = True
        
        try:
            tenancies_data = []
            total_tenancies = 0
            total_sps = 0
            total_vaults_configured = 0
            total_vaults_successful = 0
            total_certs = 0
            total_keys = 0
            
            for tenancy in azure_config.get('tenancies', []):
                # Check for cancellation
                if self._check_cancelled():
                    self._log("  Scan cancelled by user during Azure Key Vault collection")
                    return
                
                tenancy_name = tenancy.get('name', 'default')
                self._log(f"  Processing tenancy: {tenancy_name}")
                total_tenancies += 1
                
                tenancy_data = {
                    'name': tenancy_name,
                    'service_principals': []
                }
                
                for service_principal in tenancy.get('service_principals', []):
                    sp_name = service_principal.get('name', 'Unknown')
                    self._log(f"    Using service principal: {sp_name}")
                    total_sps += 1
                    
                    sp_data = {
                        'name': sp_name,
                        'vaults': []
                    }
                    
                    for vault in service_principal.get('vaults', []):
                        vault_url = vault.get('url')
                        self._log(f"      Collecting from vault: {vault_url}")
                        total_vaults_configured += 1
                        
                        vault_data = {
                            'url': vault_url,
                            'certificates_collected': 0,
                            'keys_collected': 0,
                            'status': 'pending'
                        }
                        
                        try:
                            # Build config for ConnectorService
                            vault_config = {
                                'vault_url': vault_url,
                                'tenant_id': service_principal.get('tenant_id'),
                                'client_id': service_principal.get('client_id'),
                                'client_secret': service_principal.get('client_secret')
                            }
                            
                            azure_certs, azure_keys = ConnectorService.collect_from_azure_keyvault(
                                vault_config, tenancy_name, sp_name
                            )
                            
                            self.scan_results.certificates.extend(azure_certs)
                            self.scan_results.azure_keys.extend(azure_keys)
                            
                            vault_data['certificates_collected'] = len(azure_certs)
                            vault_data['keys_collected'] = len(azure_keys)
                            vault_data['status'] = 'success'
                            total_vaults_successful += 1
                            total_certs += len(azure_certs)
                            total_keys += len(azure_keys)
                            
                            self._log(f"        Found {len(azure_certs)} certs and {len(azure_keys)} keys")
                            
                        except Exception as e:
                            vault_data['status'] = 'error'
                            vault_data['error'] = str(e)
                            self._log(f"        ERROR collecting from {vault_url}: {str(e)}")
                        
                        sp_data['vaults'].append(vault_data)
                    
                    tenancy_data['service_principals'].append(sp_data)
                
                tenancies_data.append(tenancy_data)
            
            # Update collector stats
            self.collector_stats['azure_keyvault']['tenancies'] = tenancies_data
            self.collector_stats['azure_keyvault']['total_tenancies'] = total_tenancies
            self.collector_stats['azure_keyvault']['total_service_principals'] = total_sps
            self.collector_stats['azure_keyvault']['total_vaults_configured'] = total_vaults_configured
            self.collector_stats['azure_keyvault']['total_vaults_successful'] = total_vaults_successful
            self.collector_stats['azure_keyvault']['total_certificates'] = total_certs
            self.collector_stats['azure_keyvault']['total_keys'] = total_keys
            
            self._log(f"  Azure Key Vault collection complete. Found {total_certs} certificates and {total_keys} keys from {total_vaults_successful}/{total_vaults_configured} vaults")
        except Exception as e:
            self._log(f"ERROR in Azure Key Vault collection: {str(e)}")
    
    # =========================================================================
    # PHASE 3: LUNA HSM COLLECTION
    # =========================================================================
    
    def _phase_3_luna_hsm(self):
        """Execute Luna HSM collection phase"""
        luna_config = self.config.get('luna_hsm', {})
        if not luna_config.get('enabled', False):
            return
        
        # Extract default timeout (120 seconds per partition unless overridden)
        default_timeout = self.config.get('luna_hsm', {}).get('timeout_seconds', 120)
        self._log(f"[Phase 3] Collecting from Luna HSM (timeout: {default_timeout}s per partition)...")

        # Initialize collector stats
        self.collector_stats['luna_hsm']['enabled'] = True
        
        try:
            hsms_data = []
            total_hsms = 0
            total_partitions = 0
            total_keys = 0
            total_certs = 0
            
            for hsm in luna_config.get('hsms', []):
                # Check for cancellation
                if self._check_cancelled():
                    self._log("  Scan cancelled by user during Luna HSM collection")
                    return
                
                hsm_name = hsm.get('name', 'Unknown HSM')
                total_hsms += 1
                
                self._log(f"  Connecting to Luna HSM: {hsm_name}")
                
                hsm_data = {
                    'name': hsm_name,
                    'partitions': [],
                    'status': 'pending'
                }
                
                try:
                    # Build config for ConnectorService (includes partitions)
                    hsm_config = {
                        'pkcs11_module_path': hsm.get('pkcs11_module_path'),
                        'partitions': hsm.get('partitions', [])
                    }
                    
                    # Track partition count
                    partition_count = len(hsm.get('partitions', []))
                    total_partitions += partition_count

                    # Extract timeout from config (default: 120 seconds per partition)
                    hsm_timeout = hsm.get('timeout_seconds', 120)

                    luna_keys, luna_certs = ConnectorService.collect_from_luna_hsm(
                        hsm_config,
                        hsm_name,
                        timeout_seconds=hsm_timeout
                    )
                    
                    # Extend scan results with Luna HSM keys
                    self.scan_results.keys.extend(luna_keys)
                    self.scan_results.certificates.extend(luna_certs)
                    
                    # Build partition data from results
                    for partition in hsm.get('partitions', []):
                        partition_name = partition.get('name', 'Unknown')
                        # Count keys/certs for this partition (approximate - based on source matching)
                        partition_keys = len([k for k in luna_keys if partition_name in str(k.source)])
                        hsm_data['partitions'].append({
                            'name': partition_name,
                            'keys_collected': partition_keys
                        })
                    
                    hsm_data['status'] = 'success'
                    hsm_data['keys_collected'] = len(luna_keys)
                    hsm_data['certificates_collected'] = len(luna_certs)
                    total_keys += len(luna_keys)
                    total_certs += len(luna_certs)
                    
                    self._log(f"    Found {len(luna_keys)} keys and {len(luna_certs)} associated certificates")
                    
                except Exception as e:
                    hsm_data['status'] = 'error'
                    hsm_data['error'] = str(e)
                    self._log(f"    ERROR collecting from {hsm_name}: {str(e)}")
                
                hsms_data.append(hsm_data)
            
            # Update collector stats
            self.collector_stats['luna_hsm']['hsms'] = hsms_data
            self.collector_stats['luna_hsm']['total_hsms'] = total_hsms
            self.collector_stats['luna_hsm']['total_partitions'] = total_partitions
            self.collector_stats['luna_hsm']['total_keys'] = total_keys
            self.collector_stats['luna_hsm']['total_certificates'] = total_certs
            
            self._log(f"  Luna HSM collection complete. Found {total_keys} keys and {total_certs} certificates from {total_hsms} HSMs")
        except Exception as e:
            self._log(f"ERROR in Luna HSM collection: {str(e)}")
    
    # =========================================================================
    # PHASE 4: EJBCA COLLECTION
    # =========================================================================
    
    def _phase_4_ejbca(self):
        """Execute EJBCA collection phase"""
        ejbca_config = self.config.get('ejbca', {})
        if not ejbca_config.get('enabled', False):
            return
        
        self._log("[Phase 4] Collecting from EJBCA...")
        
        # Initialize collector stats
        self.collector_stats['ejbca']['enabled'] = True
        
        try:
            servers_data = []
            total_servers_configured = 0
            total_servers_successful = 0
            total_certs = 0
            total_cas = 0
            
            for server in ejbca_config.get('servers', []):
                # Check for cancellation
                if self._check_cancelled():
                    self._log("  Scan cancelled by user during EJBCA collection")
                    return

                server_url = server.get('url')
                server_name = server.get('name', server_url)
                total_servers_configured += 1
                
                self._log(f"  Connecting to EJBCA server: {server_url}")
                
                server_data = {
                    'name': server_name,
                    'url': server_url,
                    'certificates_collected': 0,
                    'cas': [],
                    'status': 'pending'
                }
                
                try:
                    # Build config for ConnectorService
                    p12_password = server.get('p12_password')
                    p12_path = server.get('p12_path')

                    # Debug logging for credential resolution
                    self._log(f"    P12 password type: {type(p12_password).__name__}")
                    if p12_password is None:
                        self._log(f"    WARNING: P12 password is None")
                    elif isinstance(p12_password, str):
                        self._log(f"    P12 password length: {len(p12_password)} chars")
                    else:
                        self._log(f"    WARNING: P12 password is not string: {type(p12_password)}")

                    server_config = {
                        'url': server_url,
                        'p12_path': p12_path,
                        'p12_password': p12_password
                    }

                    # Get certificates and CA names
                    ejbca_certs, ca_names = ConnectorService.collect_from_ejbca(server_config, return_ca_info=True)
                    self.scan_results.certificates.extend(ejbca_certs)
                    
                    server_data['certificates_collected'] = len(ejbca_certs)
                    server_data['cas'] = ca_names
                    server_data['status'] = 'success'
                    total_servers_successful += 1
                    total_certs += len(ejbca_certs)
                    total_cas += len(ca_names)
                    
                    self._log(f"    Found {len(ca_names)} CAs, {len(ejbca_certs)} certificates")
                    
                except Exception as e:
                    server_data['status'] = 'error'
                    server_data['error'] = str(e)
                    self._log(f"    ERROR collecting from {server_url}: {str(e)}")
                
                servers_data.append(server_data)
            
            # Update collector stats
            self.collector_stats['ejbca']['servers'] = servers_data
            self.collector_stats['ejbca']['total_servers_configured'] = total_servers_configured
            self.collector_stats['ejbca']['total_servers_successful'] = total_servers_successful
            self.collector_stats['ejbca']['total_certificates'] = total_certs
            self.collector_stats['ejbca']['total_cas'] = total_cas
            
            self._log(f"  EJBCA collection complete. Found {total_certs} certificates from {total_servers_successful}/{total_servers_configured} servers")
        except Exception as e:
            self._log(f"ERROR in EJBCA collection: {str(e)}")
    
    # =========================================================================
    # PHASE 5: CRL CHECKING
    # =========================================================================
    
    def _phase_5_crl_checking(self):
        """Execute CRL checking phase"""
        crl_config = self.config.get('crl_check', {})
        if not crl_config.get('enabled', False):
            return
        
        self._log("[Phase 5] Collecting CRL endpoints from certificates...")
        
        # Initialize collector stats
        self.collector_stats['crl']['enabled'] = True
        
        try:
            if self.scan_results.certificates:
                # Count unique CRL URLs from certificates
                crl_urls = set()
                for cert in self.scan_results.certificates:
                    if cert.crl_distribution_points:
                        crl_urls.update(cert.crl_distribution_points)
                
                self.collector_stats['crl']['total_urls_discovered'] = len(crl_urls)
                
                timeout = crl_config.get('timeout', 30)
                crl_results = ConnectorService.collect_crls_for_certificates(
                    self.scan_results.certificates, timeout
                )
                self.scan_results.crls = crl_results
                
                # Update collector stats
                self.collector_stats['crl']['total_crls_fetched'] = len(crl_results)
                self.collector_stats['crl']['total_crls_failed'] = len(crl_urls) - len(crl_results)
                
                self._log(f"  CRL collection complete. Retrieved {len(crl_results)}/{len(crl_urls)} CRLs")
            else:
                self._log("  No certificates found for CRL checking")
        except Exception as e:
            self._log(f"ERROR in CRL collection: {str(e)}")
    
    # =========================================================================
    # PHASE 6: FILE SCANNING
    # =========================================================================
    
    def _phase_6_file_scanning(self):
        """Execute file scanning phase"""
        file_config = self.config.get('file_scan', {})
        if not file_config.get('enabled', False):
            return
        
        self._log("[Phase 6] Scanning filesystem...")
        
        # Initialize collector stats
        self.collector_stats['file_scan']['enabled'] = True
        configured_paths = file_config.get('paths', [])
        self.collector_stats['file_scan']['total_paths_configured'] = len(configured_paths)
        
        try:
            # Log paths being scanned
            for path in configured_paths:
                self._log(f"  Scanning path: {path}")
            
            # Use FileShareScanner directly
            from caip_scanning_functions.collectors.file_share import FileShareScanner
            
            scanner = FileShareScanner(config=file_config)
            paths_data = []
            total_files = 0
            paths_scanned = 0
            
            for path in configured_paths:
                # Check for cancellation
                if self._check_cancelled():
                    self._log("  Scan cancelled by user during file scanning")
                    return
                
                path_data = {
                    'path': path,
                    'files_found': 0,
                    'status': 'pending'
                }
                
                try:
                    results = scanner.scan_path(path)
                    path_data['files_found'] = len(results)
                    path_data['status'] = 'success'
                    total_files += len(results)
                    paths_scanned += 1
                    self._log(f"    Found {len(results)} cryptographic files in {path}")
                except PermissionError:
                    path_data['status'] = 'permission_denied'
                    self._log(f"    Permission denied: {path}")
                except Exception as e:
                    path_data['status'] = 'error'
                    path_data['error'] = str(e)
                    self._log(f"    ERROR scanning {path}: {str(e)}")
                
                paths_data.append(path_data)
            
            # Get summary from scanner
            summary = scanner.get_results_summary()
            
            # Store raw file scan results
            self.scan_results.file_scan_results = summary.get('files', [])
            
            # Convert to findings
            findings = scanner.convert_results_to_findings()
            self.scan_results.findings.extend(findings)
            
            # Update collector stats
            self.collector_stats['file_scan']['paths'] = paths_data
            self.collector_stats['file_scan']['total_paths_scanned'] = paths_scanned
            self.collector_stats['file_scan']['total_files_found'] = summary.get('total_files_found', 0)
            self.collector_stats['file_scan']['high_confidence'] = summary.get('high_confidence', 0)
            self.collector_stats['file_scan']['medium_confidence'] = summary.get('medium_confidence', 0)
            
            self._log(f"  File scanning complete. Found {summary.get('total_files_found', 0)} total files ({summary.get('high_confidence', 0)} high confidence, {summary.get('medium_confidence', 0)} medium confidence)")
            
        except Exception as e:
            self._log(f"ERROR in file scanning: {str(e)}")
            raise

    def _detect_source_type(self, cert_dict: Dict) -> str:
        """
        Detect certificate source type based on metadata.

        Returns the appropriate enricher type:
        - 'ejbca' for EJBCA certificates
        - 'azure' for Azure Key Vault certificates
        - 'luna' for Luna HSM certificates
        - 'tls' for TLS scan certificates (default)
        """
        # Check for EJBCA metadata
        if 'ejbca_metadata' in cert_dict and cert_dict['ejbca_metadata']:
            return 'ejbca'

        # Check for Azure metadata
        if 'azure_metadata' in cert_dict and cert_dict['azure_metadata']:
            return 'azure'

        # Check for Luna metadata
        if 'luna_metadata' in cert_dict and cert_dict['luna_metadata']:
            return 'luna'

        # Check for other source indicators in origin field
        origin = cert_dict.get('origin', '').lower()
        if 'ejbca' in origin:
            return 'ejbca'
        if 'azure' in origin:
            return 'azure'
        if 'luna' in origin:
            return 'luna'

        # Default to TLS for scanning-discovered certificates
        return 'tls'

# =========================================================================
    # PHASE 6.5: DATA NORMALISATION
    # =========================================================================

    def _phase_6_5_normalisation(self):
        """Normalise collected data into unified format for assessment"""
        from dataclasses import asdict
        from caip_service_layer.key_normalisation_service import KeyNormalisationService
        
        total_keys = len(self.scan_results.keys) + len(self.scan_results.azure_keys)
        total_certs = len(self.scan_results.certificates)
        
        if total_keys == 0 and total_certs == 0:
            return
        
        self._log("[Phase 6.5] Normalising collected data...")
        
        # Normalise keys
        if total_keys > 0:
            try:
                all_keys = []

                for key in self.scan_results.keys:
                    key_dict = asdict(key)

                    # Extract Azure metadata (Phase 2-4)
                    if key.azure_metadata:
                        azure_meta = key.azure_metadata
                        key_dict['azure_metadata'] = azure_meta

                    # Extract environment metadata (Phase 2-4)
                    if key.environment_metadata:
                        env_meta = key.environment_metadata
                        key_dict['environment_type'] = env_meta.get('environment_type')
                        key_dict['service_name'] = env_meta.get('service_name')
                        key_dict['application_name'] = env_meta.get('application_name')
                        key_dict['discovery_metadata'] = {
                            'discovery_method': env_meta.get('discovery_method'),
                            'discovery_confidence': env_meta.get('discovery_confidence')
                        }

                    all_keys.append(key_dict)

                for key in self.scan_results.azure_keys:
                    key_dict = asdict(key)

                    # Extract Azure metadata (Phase 2-4)
                    if key.azure_metadata:
                        azure_meta = key.azure_metadata
                        key_dict['azure_metadata'] = azure_meta

                    # Extract environment metadata (Phase 2-4)
                    if key.environment_metadata:
                        env_meta = key.environment_metadata
                        key_dict['environment_type'] = env_meta.get('environment_type')
                        key_dict['service_name'] = env_meta.get('service_name')
                        key_dict['application_name'] = env_meta.get('application_name')
                        key_dict['discovery_metadata'] = {
                            'discovery_method': env_meta.get('discovery_method'),
                            'discovery_confidence': env_meta.get('discovery_confidence')
                        }

                    all_keys.append(key_dict)
                
                self.scan_results.normalised_keys = KeyNormalisationService.normalise_keys(all_keys)
                self._log(f"  Normalised {len(self.scan_results.normalised_keys)} keys")
                
            except Exception as e:
                self._log(f"WARNING in key normalisation: {str(e)} - falling back to legacy processing")
        
        # Normalise certificates
        if total_certs > 0:
            try:
                # Build certificate dicts with enrichment data from TLSScanResult
                all_certs = []

                # Process TLS certificates with their enrichment metadata
                tls_cert_fps = set()  # Track which certs came from TLS to avoid duplicates
                for tls_result in self.scan_results.tls_results:
                    for cert_info in tls_result.certificate_chain:
                        cert_dict = asdict(cert_info)
                        tls_cert_fps.add(cert_info.fingerprint_sha256)

                        # Merge Phase 1 environment metadata
                        if tls_result.environment_metadata:
                            env_meta = tls_result.environment_metadata
                            cert_dict['environment_type'] = env_meta.get('environment_type')
                            cert_dict['service_name'] = env_meta.get('service_name')
                            cert_dict['application_name'] = env_meta.get('application_name')
                            # Build discovery_metadata as nested dict from flat keys
                            cert_dict['discovery_metadata'] = {
                                'discovery_method': env_meta.get('discovery_method'),
                                'discovery_confidence': env_meta.get('discovery_confidence')
                            }

                        # Merge Phase 1.5 security metadata
                        if hasattr(tls_result, 'security_metadata') and tls_result.security_metadata:
                            sec_meta = tls_result.security_metadata
                            cert_dict['signature_algorithm_analysis'] = sec_meta.get('signature_algorithm_analysis')
                            cert_dict['key_strength_analysis'] = sec_meta.get('key_strength_analysis')
                            cert_dict['pqc_readiness'] = sec_meta.get('pqc_readiness')
                            cert_dict['revocation_status'] = sec_meta.get('revocation_status')

                        all_certs.append(cert_dict)

                # Process non-TLS certificates (EJBCA, Azure, Luna, CRL, File)
                for cert in self.scan_results.certificates:
                    if cert.fingerprint_sha256 not in tls_cert_fps:
                        cert_dict = asdict(cert)

                        # Extract Azure metadata (Phase 2-4)
                        if cert.azure_metadata:
                            azure_meta = cert.azure_metadata
                            cert_dict['azure_metadata'] = azure_meta

                        # Extract environment metadata (Phase 2-4)
                        if cert.environment_metadata:
                            env_meta = cert.environment_metadata
                            cert_dict['environment_type'] = env_meta.get('environment_type')
                            cert_dict['service_name'] = env_meta.get('service_name')
                            cert_dict['application_name'] = env_meta.get('application_name')
                            cert_dict['discovery_metadata'] = {
                                'discovery_method': env_meta.get('discovery_method'),
                                'discovery_confidence': env_meta.get('discovery_confidence')
                            }

                        # Phase 6.5: Add security analysis enrichment (signature, key strength, PQC)
                        # All certificates get enriched uniformly, regardless of source
                        try:
                            enricher = MetadataEnrichmentService.get_enricher('tls_security')
                            security_config = {'capture_security_analysis': True}
                            enriched_cert_dict = enricher.enrich(cert_dict, security_config)

                            cert_dict['signature_algorithm_analysis'] = enriched_cert_dict.get('signature_algorithm_analysis')
                            cert_dict['key_strength_analysis'] = enriched_cert_dict.get('key_strength_analysis')
                            cert_dict['pqc_readiness'] = enriched_cert_dict.get('pqc_readiness')
                            cert_dict['revocation_status'] = enriched_cert_dict.get('revocation_status')
                        except Exception as e:
                            self._log(f"WARNING: Could not compute security analysis: {e}")

                        all_certs.append(cert_dict)

                # Phase 6.5: Use standardized normalization layer with source-specific enrichment
                # Group certificates by detected source type for source-specific enrichment
                all_certs_by_source = {}  # {source_type: [certs]}
                for cert_dict in all_certs:
                    source_type = self._detect_source_type(cert_dict)
                    if source_type not in all_certs_by_source:
                        all_certs_by_source[source_type] = []
                    all_certs_by_source[source_type].append(cert_dict)

                # Enrich each group with appropriate enricher type
                all_normalised = []
                for source_type, certs_for_source in all_certs_by_source.items():
                    self._log(f"  Enriching {len(certs_for_source)} certificates from source: {source_type}")

                    normalised = KeyNormalisationService.normalise_and_enrich_certificates(
                        certs_for_source,
                        enrichment_config={
                            'enable_security_analysis': True,
                            'enable_environment_analysis': True,
                            'environment_enricher_type': source_type,  # Dynamic: adapt enricher to source
                            'source_type': source_type,  # Dynamic: track actual source
                            'capture_enrichment': True,  # Enable metadata extraction (service identity, purpose, crypto, ha)
                            'capture_security_analysis': True,
                            'capture_environment': True
                        }
                    )
                    all_normalised.extend(normalised)

                self.scan_results.normalised_certificates = all_normalised
                self._log(f"  Normalised and enriched {len(self.scan_results.normalised_certificates)} certificates with flat structure (from {len(all_certs_by_source)} sources)")

                # Phase 6.5: Apply environment inference signal fusion to all certificates
                if ENVIRONMENT_INFERENCE_AVAILABLE and len(self.scan_results.normalised_certificates) > 0:
                    try:
                        self._log("  Applying environment inference signal fusion...")
                        for i, cert in enumerate(self.scan_results.normalised_certificates):
                            # Try to infer from certificate subject CN
                            if 'subject' in cert and isinstance(cert['subject'], dict):
                                subject_cn = cert['subject'].get('CN', '')
                                if subject_cn:
                                    inferred = EnvironmentInferenceService.infer_from_source_string(subject_cn)

                                    # Use inferred metadata if confidence is higher than existing
                                    existing_confidence = cert.get('inferred_discovery_confidence', 0) if isinstance(cert.get('inferred_discovery_confidence'), (int, float)) else 0
                                    inferred_confidence = inferred.get('discovery_confidence', 0)

                                    if inferred_confidence > existing_confidence:
                                        # Update inferred fields with higher-confidence inference
                                        cert['inferred_environment_type'] = inferred.get('environment_type')
                                        cert['inferred_service_name'] = inferred.get('service_name')
                                        cert['inferred_application_name'] = inferred.get('application_name')
                                        cert['inferred_discovery_method'] = inferred.get('discovery_method')
                                        cert['inferred_discovery_confidence'] = inferred_confidence

                        self._log(f"  Environment inference signal fusion applied to {len(self.scan_results.normalised_certificates)} certificates")
                    except Exception as e:
                        self._log(f"  WARNING: Environment inference failed: {str(e)}")
                else:
                    if not ENVIRONMENT_INFERENCE_AVAILABLE:
                        self._log("  Skipping environment inference: service not available")

            except Exception as e:
                self._log(f"WARNING in certificate normalisation: {str(e)} - falling back to legacy processing")
    
    def _phase_7_policy_assessment(self):
        """Execute policy assessment phase with optional scoring (PKI health check only)"""
        self._log("[Phase 7] Assessing against policy...")
        try:
            # Log what will be assessed
            self._log(f"  Certificates to assess: {len(self.scan_results.certificates)}")
            self._log(f"  Keys to assess: {len(self.scan_results.keys) + len(self.scan_results.azure_keys)}")
            self._log(f"  CRLs to assess: {len(self.scan_results.crls)}")
            self._log(f"  File results to assess: {len(self.scan_results.file_scan_results)}")
            self._log(f"  Assessment type: {self.assessment_type}")
            
            # Check if scoring should be applied (PKI health check only)
            scoring_enabled = (
                self.assessment_type == 'pki_health_check' and 
                PolicyAssessmentService.is_scoring_available()
            )
            
            if scoring_enabled:
                # Use scoring-enabled assessment for PKI health checks
                self._log("  PKI health check with scoring enabled")
                
                # Build report data structure for the scoring method
                # Use normalised data which includes computed fields like days_until_expiration
                report_data = {
                    'certificates': self.scan_results.normalised_certificates or [],
                    'keys': self.scan_results.normalised_keys or [],
                    'azure_keys': [],  # Already included in normalised_keys
                    'crls': self.scan_results.crls,
                    'file_scan': self.scan_results.file_scan_results
                }
                
                # Calculate total assets for health index (use normalised counts)
                total_assets = (
                    len(self.scan_results.normalised_certificates or []) + 
                    len(self.scan_results.normalised_keys or [])
                )
                
                # Run assessment with scoring
                findings_list, summary, assessment_score = PolicyAssessmentService.assess_report_data_with_scoring(
                    report_data=report_data,
                    policy=self.policy,
                    asset_contexts=None,  # TODO: Load from DB if engagement_id available
                    enable_scoring=True
                )
                
                # Store results
                self.scan_results.findings = findings_list
                self.assessment_score = assessment_score
                
                # Log scoring summary
                if assessment_score:
                    self._log(f"  Assessment complete: Grade {assessment_score.grade} ({assessment_score.health_index:.1f}%)")
                    self._log(f"  Found {summary['total_findings']} findings (weighted exposure: {assessment_score.total_weighted_exposure:.1f})")
                else:
                    self._log(f"  Policy assessment complete. Found {summary['total_findings']} findings")
            else:
                # Standard assessment without scoring (PQC assessments or scoring unavailable)
                if self.assessment_type == 'pqc_assessment':
                    self._log("  PQC assessment - scoring handled by PQC reporting service")
                else:
                    self._log("  Scoring service not available - using standard assessment")
                    
                findings_list, summary = PolicyAssessmentService.assess_scan_results(
                    self.scan_results, self.policy
                )
                self.scan_results.findings = findings_list
                self._log(f"  Policy assessment complete. Found {summary['total_findings']} findings")

                # Phase 2.5: Update revocation status from findings
                self._phase_2_5_update_revocation_status()
            
        except Exception as e:
            self._log(f"ERROR in policy assessment: {str(e)}")
            logger.error(f"Assessment error: {traceback.format_exc()}")
            raise

    def _phase_2_5_update_revocation_status(self):
        """
        After assessment completes, populate revocation_status with actual validation result.

        Maps revocation Findings back to certificate's revocation_status dict.
        This bridges the gap between assessment layer (which determines revocation) and
        display layer (which shows revocation_status field).
        """
        self._log("[Phase 2.5] Updating revocation status from assessment findings...")

        try:
            if not self.scan_results.normalised_certificates or not self.scan_results.findings:
                return

            # Create lookup: unique_id → Finding details
            revoked_certs = {}
            for finding in self.scan_results.findings:
                if 'REVOKED' in finding.id:
                    # Extract unique_id from finding ID (format: CERT-{unique_id}-REVOKED)
                    parts = finding.id.split('-')
                    if len(parts) >= 2:
                        cert_id = parts[1]
                        revoked_certs[cert_id] = {
                            'finding_id': finding.id,
                            'description': finding.description,
                            'remediation': finding.remediation,
                            'severity': finding.severity
                        }

            # Update each certificate's revocation_status
            for cert_dict in self.scan_results.normalised_certificates:
                if not isinstance(cert_dict, dict):
                    continue

                unique_id = cert_dict.get('unique_id')

                if not cert_dict.get('revocation_status'):
                    cert_dict['revocation_status'] = {}

                # Check if this certificate has a revocation finding
                if unique_id in revoked_certs:
                    cert_dict['revocation_status']['validation_status'] = 'revoked'
                    cert_dict['revocation_status']['revocation_finding'] = revoked_certs[unique_id]
                else:
                    # No revocation finding = valid
                    cert_dict['revocation_status']['validation_status'] = 'valid'
                    cert_dict['revocation_status']['revocation_finding'] = None

            self._log(f"  Updated revocation status for {len(self.scan_results.normalised_certificates)} certificates")

        except Exception as e:
            self._log(f"WARNING in revocation status update: {str(e)}")

    def _phase_8_report_generation(self):
        """Execute report generation phase"""
        self._log("[Phase 8] Generating reports...")
        try:
            import os
            
            # Generate report path
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            scan_name_safe = self.scan_name.replace(' ', '_').replace('/', '_')
            self.report_path = os.path.join(self.reports_folder, f'{scan_name_safe}_run{self.run_number}_{timestamp}.json')
            
            # Generate report data using ReportingService
            report_data = ReportingService.build_report_data(
                scan_results=self.scan_results,
                collector_stats=self.collector_stats,
                policy=self.policy
            )
            
            # Add scoring data for PKI health check assessments only
            if self.assessment_type == 'pki_health_check' and self.assessment_score:
                report_data['scoring'] = {
                    'enabled': True,
                    'health_index': round(self.assessment_score.health_index, 2),
                    'grade': self.assessment_score.grade,
                    'grade_description': self.assessment_score.grade_description,
                    'total_weighted_exposure': round(self.assessment_score.total_weighted_exposure, 2),
                    # Risk exposure metrics
                    'total_assets_assessed': self.assessment_score.total_assets_assessed,
                    'assets_at_risk': self.assessment_score.assets_at_risk,
                    'assets_at_risk_percent': round(self.assessment_score.assets_at_risk_percent, 1),
                    'compliant_assets': self.assessment_score.compliant_assets,
                    'risk_exposure_percent': round(100 - self.assessment_score.health_index, 1),
                    'severity_breakdown': {
                        sev: {
                            'count': breakdown['count'],
                            'total_weighted_score': round(breakdown['total_weighted_score'], 2),
                            'average_weight': round(breakdown['average_weight'], 2)
                        }
                        for sev, breakdown in self.assessment_score.to_dict()['severity_breakdown'].items()
                    },
                    'priority_queue': self.assessment_score.priority_queue[:20],  # Top 20
                    'executive_summary': self.assessment_score.get_executive_summary()
                }
                self._log(f"  Scoring data included: Grade {self.assessment_score.grade}")
            elif self.assessment_type == 'pki_health_check':
                # PKI health check but scoring unavailable
                report_data['scoring'] = {
                    'enabled': False,
                    'reason': 'Scoring service unavailable'
                }
            # PQC assessments don't include scoring block - they use asset-level priority_score
            
            # Save JSON report
            self._log(f"Saving JSON report to {self.report_path}")
            ReportingService.save_json_report(report_data, self.report_path)
            
            self._log("Report generation complete")
            
        except Exception as e:
            self._log(f"ERROR in report generation: {str(e)}")
            raise
