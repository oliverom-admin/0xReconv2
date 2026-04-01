# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: caip_scanning_functions/collectors/azure_keyvault.py
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
Azure Key Vault certificate and key collector
"""

import hashlib
import logging
from typing import Dict, List, Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID

from ..models import CertificateInfo, AzureKeyVaultKeyInfo, DEPENDENCIES_AVAILABLE
from caip_pqc_functions.pqc_detector import get_detector

logger = logging.getLogger('caip.operational')


def extract_subscription_id_from_vault_id(vault_id: str) -> Optional[str]:
    """
    Extract subscription ID from Azure resource ID.

    Format: /subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/Microsoft.KeyVault/vaults/{vault-name}

    Args:
        vault_id: Full Azure resource ID

    Returns:
        Subscription ID or None if extraction fails
    """
    try:
        parts = vault_id.split('/')
        subscription_idx = parts.index('subscriptions')
        if subscription_idx + 1 < len(parts):
            return parts[subscription_idx + 1]
    except (ValueError, IndexError):
        logger.debug(f"Could not extract subscription ID from vault_id: {vault_id}")
    return None


class AzureKeyVaultCollector:
    """
    Collects certificates and keys from Azure Key Vault with multi-tenancy support
    """
    
    def __init__(self, vault_url: str, credential_config: Optional[Dict[str, str]] = None, 
                 tenancy_name: str = "default", service_principal_name: str = "default"):
        """
        Initialize Azure Key Vault collector.
        
        Args:
            vault_url: URL of the Azure Key Vault
            credential_config: Optional dictionary with tenant_id, client_id, client_secret
            tenancy_name: Name of the tenancy for tracking
            service_principal_name: Name of the service principal for tracking
        """
        if not DEPENDENCIES_AVAILABLE['azure_keyvault'] or not DEPENDENCIES_AVAILABLE['azure_identity']:
            raise ImportError("Azure Key Vault libraries not available. Install with: pip install azure-keyvault-certificates azure-identity")
        
        from azure.keyvault.certificates import CertificateClient
        from azure.keyvault.keys import KeyClient
        from azure.identity import DefaultAzureCredential, ClientSecretCredential
        
        self.vault_url = vault_url
        self.tenancy_name = tenancy_name
        self.service_principal_name = service_principal_name
        
        # Get credential
        if credential_config and all(k in credential_config for k in ['tenant_id', 'client_id', 'client_secret']):
            logger.debug(f"Using service principal: {service_principal_name}")
            self.credential = ClientSecretCredential(
                tenant_id=credential_config['tenant_id'],
                client_id=credential_config['client_id'],
                client_secret=credential_config['client_secret']
            )
        else:
            logger.debug(f"Using default Azure credential")
            self.credential = DefaultAzureCredential()

        # Initialize clients
        self.cert_client = CertificateClient(vault_url=vault_url, credential=self.credential)
        self.key_client = KeyClient(vault_url=vault_url, credential=self.credential)

        logger.info(f"Connected to Azure Key Vault: {vault_url}")
        logger.debug(f"  - Certificate Container: Ready")
        logger.debug(f"  - Key Container: Ready")
    
    def collect_all_certificates(self) -> List[CertificateInfo]:
        """Collect all certificates from Azure Key Vault"""
        certificates = []
        
        try:
            logger.debug(f"Retrieving certificates from Azure Key Vault {self.vault_url}")
            cert_properties_list = self.cert_client.list_properties_of_certificates()
            
            for cert_properties in cert_properties_list:
                try:
                    cert_name = cert_properties.name
                    logger.debug(f"Processing certificate: {cert_name}")
                    
                    keyvault_cert = self.cert_client.get_certificate(cert_name)
                    cert_bytes = keyvault_cert.cer
                    
                    if cert_bytes:
                        cert_info = self._parse_certificate(
                            cert_bytes,
                            f"Azure Key Vault: {self.vault_url}",
                            cert_name,
                            cert_properties=keyvault_cert
                        )
                        if cert_info:
                            certificates.append(cert_info)
                            logger.debug(f"Certificate {cert_name} parsed successfully")
                    else:
                        logger.warning(f"No certificate data for {cert_name}")
                
                except Exception as e:
                    logger.error(f"Error processing key {key_name}: {e}")
                    continue
            
            logger.info(f"Collected {len(certificates)} certificates from {self.vault_url}")
            
        except Exception as e:
            logger.error(f"Error accessing Azure Key Vault {self.vault_url}: {e}")
        
        return certificates
    
    def collect_specific_certificate(self, cert_name: str) -> Optional[CertificateInfo]:
        """Collect a specific certificate by name"""
        try:
            logger.debug(f"Retrieving certificate: {cert_name}")
            keyvault_cert = self.cert_client.get_certificate(cert_name)
            cert_bytes = keyvault_cert.cer

            if cert_bytes:
                cert_info = self._parse_certificate(
                    cert_bytes,
                    f"Azure Key Vault: {self.vault_url}",
                    cert_name,
                    cert_properties=keyvault_cert
                )
                if cert_info:
                    logger.debug(f"Certificate {cert_name} retrieved successfully")
                    return cert_info
            return None
        except Exception as e:
            logger.error(f"Error retrieving certificate {cert_name}: {e}")
            return None

    def _parse_certificate(self, cert_bytes: bytes, source: str, cert_name: str, cert_properties: Optional[Any] = None) -> Optional[CertificateInfo]:
        """Parse certificate bytes into CertificateInfo"""
        try:
            try:
                cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
            except:
                cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
            
            # Extract subject and issuer
            subject = {}
            for attr in cert.subject:
                subject[attr.oid._name] = attr.value
            
            issuer = {}
            for attr in cert.issuer:
                issuer[attr.oid._name] = attr.value
            
            # Extract key usage
            key_usage = []
            try:
                ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
                if ku.digital_signature: key_usage.append("digital_signature")
                if ku.key_encipherment: key_usage.append("key_encipherment")
                if ku.data_encipherment: key_usage.append("data_encipherment")
                if ku.key_agreement: key_usage.append("key_agreement")
                if ku.key_cert_sign: key_usage.append("key_cert_sign")
                if ku.crl_sign: key_usage.append("crl_sign")
            except:
                pass
            
            # Extract extended key usage
            extended_key_usage = []
            try:
                eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
                for oid in eku:
                    extended_key_usage.append(oid._name)
            except:
                pass
            
            # Extract basic constraints
            basic_constraints = {}
            is_ca = False
            try:
                bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
                is_ca = bc.ca
                basic_constraints = {'ca': bc.ca, 'path_length': bc.path_length}
            except:
                pass
            
            # Extract SAN
            san = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
                san = [str(name) for name in san_ext]
            except:
                pass
            
            # Extract CRL distribution points
            crl_dps = []
            try:
                crl_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
                for dp in crl_ext:
                    if dp.full_name:
                        for name in dp.full_name:
                            crl_dps.append(str(name.value))
            except:
                pass
            
            # Extract OCSP responders
            ocsp_responders = []
            try:
                aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
                for desc in aia:
                    if desc.access_method._name == 'OCSP':
                        ocsp_responders.append(str(desc.access_location.value))
            except:
                pass
            
            # Extract SCTs
            scts = []
            try:
                sct_ext = cert.extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS).value
                for sct in sct_ext:
                    scts.append({
                        'version': sct.version.name,
                        'log_id': sct.log_id.hex(),
                        'timestamp': sct.timestamp.isoformat()
                    })
            except:
                pass

            # Check if self-signed
            is_self_signed = cert.issuer == cert.subject
            
            # Get fingerprint
            fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
            
            # Get public key info
            public_key = cert.public_key()
            if hasattr(public_key, 'key_size'):
                key_size = public_key.key_size
                key_algorithm = public_key.__class__.__name__
            else:
                key_size = 0
                key_algorithm = "Unknown"
            
            # PQC Analysis
            pqc_analysis = None
            try:
                pqc_detector = get_detector()
                sig_oid = cert.signature_algorithm_oid.dotted_string if hasattr(cert.signature_algorithm_oid, 'dotted_string') else None
                sig_name = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else None
                pqc_result = pqc_detector.analyze_certificate(
                    signature_algorithm_oid=sig_oid,
                    signature_algorithm_name=sig_name,
                    public_key_algorithm=key_algorithm
                )
                pqc_analysis = pqc_result.to_dict()
                if pqc_result.is_pqc:
                    logger.info(f"PQC detected in {cert_name}: {pqc_result.pqc_algorithm}")
            except Exception as e:
                pass  # PQC detection is optional
            
            # Enhanced source information
            enhanced_source = f"{source} [Tenancy: {self.tenancy_name}, SP: {self.service_principal_name}]"

            # Extract Azure metadata if certificate properties available
            azure_metadata = None
            environment_metadata = None
            if cert_properties:
                try:
                    azure_metadata = {
                        'tags': dict(cert_properties.properties.tags) if cert_properties.properties.tags else {},
                        'created_on': cert_properties.properties.created_on.isoformat() if cert_properties.properties.created_on else None,
                        'updated_on': cert_properties.properties.updated_on.isoformat() if cert_properties.properties.updated_on else None,
                        'expires_on': cert_properties.properties.expires_on.isoformat() if cert_properties.properties.expires_on else None,
                        'not_before': cert_properties.properties.not_before.isoformat() if hasattr(cert_properties.properties, 'not_before') and cert_properties.properties.not_before else None,
                        'enabled': cert_properties.properties.enabled if hasattr(cert_properties.properties, 'enabled') else None,
                        'recovery_level': str(cert_properties.properties.recovery_level) if hasattr(cert_properties.properties, 'recovery_level') else None,
                        'vault_name': self.vault_url.rstrip('/').split('/')[-1].split('.')[0],  # Extract vault name from FQDN (e.g., "thalescrypto-kv01")
                        'vault_id': f"{self.vault_url.rstrip('/')}/certificates/{cert_name}",
                        'vault_location': self.vault_url,
                        'subscription_id': extract_subscription_id_from_vault_id(self.vault_url),
                    }

                    # Infer environment from tags
                    try:
                        from caip_service_layer.environment_inference_service import EnvironmentInferenceService
                        environment_metadata = EnvironmentInferenceService.infer_from_azure_tags(
                            cert_properties.properties.tags or {}
                        )
                    except Exception as e:
                        logger.debug(f"Could not infer environment from tags: {e}")

                except Exception as e:
                    logger.debug(f"Could not extract Azure metadata: {e}")

            return CertificateInfo(
                serial_number=format(cert.serial_number, 'x'),
                subject=subject,
                issuer=issuer,
                not_before=cert.not_valid_before.isoformat(),
                not_after=cert.not_valid_after.isoformat(),
                signature_algorithm=cert.signature_algorithm_oid._name,
                public_key_algorithm=key_algorithm,
                public_key_size=key_size,
                key_usage=key_usage,
                extended_key_usage=extended_key_usage,
                basic_constraints=basic_constraints,
                san=san,
                fingerprint_sha256=fingerprint,
                source=enhanced_source,
                unique_id=f"akv_{self.tenancy_name}_{cert_name}_{fingerprint[:16]}",
                is_ca=is_ca,
                is_self_signed=is_self_signed,
                crl_distribution_points=crl_dps,
                ocsp_responders=ocsp_responders,
                certificate_transparency_scts=scts,
                found_at_destination=f"Azure Key Vault: {cert_name} (Tenancy: {self.tenancy_name})",
                found_on_port="N/A",
                pqc_analysis=pqc_analysis,
                azure_metadata=azure_metadata,
                environment_metadata=environment_metadata
            )
            
        except Exception as e:
            logger.error(f"Error parsing certificate {cert_name}: {e}")
            return None

    def collect_all_keys(self) -> List[AzureKeyVaultKeyInfo]:
        """Collect all keys from Azure Key Vault"""
        keys = []
        
        try:
            logger.debug(f"Retrieving keys from Azure Key Vault {self.vault_url}")
            key_properties_list = self.key_client.list_properties_of_keys()
            
            for key_properties in key_properties_list:
                try:
                    key_name = key_properties.name
                    logger.debug(f"Processing key: {key_name}")
                    
                    key = self.key_client.get_key(key_name)
                    key_info = self._extract_key_metadata(key)

                    if key_info:
                        # Add PQC analysis for the key
                        try:
                            from pqc_detector import get_detector
                            pqc_detector = get_detector()
                            pqc_result = pqc_detector.analyze_key(
                                key_type=key_info.key_type,
                                key_size=key_info.key_size
                            )
                            key_info.pqc_analysis = pqc_result.to_dict()
                        except Exception as e:
                            logger.debug(f"PQC analysis failed for {key_name}: {e}")
                            key_info.pqc_analysis = None
                        
                        keys.append(key_info)
                        logger.debug(f"Key {key_name} metadata extracted")
                    else:
                        logger.warning(f"No key metadata for {key_name}")
                
                except Exception as e:
                    logger.error(f"Error processing key {key_name}: {e}")
                    continue
            
            logger.info(f"Collected {len(keys)} keys from {self.vault_url}")
            return keys
        
        except Exception as e:
            logger.error(f"Error accessing Azure Key Vault {self.vault_url}: {e}")
            return []

    
    def collect_specific_key(self, key_name: str) -> Optional[AzureKeyVaultKeyInfo]:
        """Collect a specific key by name"""
        try:
            logger.debug(f"Retrieving key: {key_name}")
            key = self.key_client.get_key(key_name)
            key_info = self._extract_key_metadata(key)
            
            if key_info:
                logger.debug(f"Key {key_name} retrieved successfully")
            return key_info
        except Exception as e:
            logger.error(f"Error processing key {key_name}: {e}")
            return None
    
    def _extract_key_metadata(self, key) -> Optional[AzureKeyVaultKeyInfo]:
        """Extract comprehensive metadata from a key object"""
        try:
            # Extract key type and size
            key_type = str(key.key_type).split('.')[-1] if key.key_type else "Unknown"
            
            # Key size extraction - the actual key data is in key.key (JsonWebKey)
            # For RSA keys: size is derived from the modulus (n) length
            # For EC keys: size is derived from the curve name
            key_size = None
            key_curve = None
            
            if hasattr(key, 'key') and key.key:
                json_web_key = key.key
                
                # Try to get key size from JsonWebKey
                # RSA keys have 'n' (modulus) - size in bits = len(n) * 8
                if hasattr(json_web_key, 'n') and json_web_key.n:
                    key_size = len(json_web_key.n) * 8
                
                # EC keys have curve name which indicates size
                if hasattr(json_web_key, 'crv') and json_web_key.crv:
                    curve_name = str(json_web_key.crv).split('.')[-1]
                    key_curve = curve_name
                    # Map curve names to key sizes
                    curve_sizes = {
                        'P-256': 256, 'P_256': 256, 'P256': 256,
                        'P-384': 384, 'P_384': 384, 'P384': 384,
                        'P-521': 521, 'P_521': 521, 'P521': 521,
                        'SECP256K1': 256
                    }
                    if key_size is None:
                        key_size = curve_sizes.get(curve_name)
            
            # Fallback: try direct key_size attribute (older SDK versions)
            if key_size is None and hasattr(key, 'key_size') and key.key_size:
                key_size = key.key_size
            
            # Extract curve from key.key_curve if not already set
            if key_curve is None and hasattr(key, 'key_curve') and key.key_curve:
                key_curve = str(key.key_curve).split('.')[-1]
            
            # Determine if HSM-backed
            hsm_backed = "HSM" in key_type
            
            # Extract operations
            key_operations = [str(op).split('.')[-1] for op in (key.key_operations or [])]
            
            # Format dates
            created_on = key.properties.created_on.isoformat() if key.properties.created_on else None
            updated_on = key.properties.updated_on.isoformat() if key.properties.updated_on else None
            expires_on = key.properties.expires_on.isoformat() if key.properties.expires_on else None
            not_before = key.properties.not_before.isoformat() if key.properties.not_before else None
            
            # Get recovery level
            recovery_level = key.properties.recovery_level if hasattr(key.properties, 'recovery_level') else "Unknown"
            
            # Get tags
            tags = key.properties.tags if key.properties.tags else {}

            enhanced_source = f"Azure Key Vault: [Tenancy: {self.tenancy_name}, Vault: {self.vault_url}]"

            # Extract Azure metadata
            azure_metadata = {
                'tags': tags,
                'key_type': key_type,
                'managed': key.properties.managed if hasattr(key.properties, 'managed') else False,
                'version': key.properties.version if hasattr(key.properties, 'version') else "Unknown",
                'created_on': created_on,
                'updated_on': updated_on,
                'expires_on': expires_on,
                'not_before': not_before,
                'enabled': key.properties.enabled if hasattr(key.properties, 'enabled') else True,
                'recovery_level': str(recovery_level),
                'vault_name': self.vault_url.rstrip('/').split('/')[-1].split('.')[0],  # Extract vault name from FQDN (e.g., "thalescrypto-kv01")
                'vault_id': key.id,
                'vault_location': self.vault_url,
                'subscription_id': extract_subscription_id_from_vault_id(self.vault_url),
            }

            # Infer environment from tags
            environment_metadata = None
            try:
                from caip_service_layer.environment_inference_service import EnvironmentInferenceService
                environment_metadata = EnvironmentInferenceService.infer_from_azure_tags(tags)
            except Exception as e:
                logger.debug(f"Could not infer environment from tags: {e}")

            return AzureKeyVaultKeyInfo(
                name=key.name,
                label=key.name,
                key_id=key.id,
                vault_url=self.vault_url,
                tenancy_name=self.tenancy_name,
                service_principal_name=self.service_principal_name,
                key_type=key_type,
                key_size=key_size,
                key_operations=key_operations,
                enabled=key.properties.enabled if hasattr(key.properties, 'enabled') else True,
                created_on=created_on,
                updated_on=updated_on,
                expires_on=expires_on,
                not_before=not_before,
                recovery_level=str(recovery_level),
                key_curve=key_curve,
                tags=tags,
                managed=key.properties.managed if hasattr(key.properties, 'managed') else False,
                hsm_backed=hsm_backed,
                version=key.properties.version if hasattr(key.properties, 'version') else "Unknown",
                object_id="N/A",
                token="N/A",
                private=False,
                associated_certificate="N/A",
                public_key_fingerprint="N/A",
                source=enhanced_source,
                azure_metadata=azure_metadata,
                environment_metadata=environment_metadata
            )

        except Exception as e:
            logger.error(f"Error extracting key metadata: {e}")
            return None
