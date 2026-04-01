# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: caip_service_layer/certificate_service.py
# Copied: 2026-04-01
# Used in: Phase 11 — PKI Sub-System
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
Certificate Management Service for CAIP

Handles the complete certificate lifecycle:
- Dashboard TLS certificate generation and management
- Per-engagement CA certificate creation
- Collector certificate issuance, renewal, and revocation
- Certificate revocation list (CRL) management
- Certificate validation and status tracking

This service integrates with:
- secret_service: For encrypted storage of private keys
- database_service: For certificate tracking and audit logging
"""

import json
import logging
import os
import base64
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import hashlib

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from OpenSSL import crypto

logger = logging.getLogger('caip.operational')


def _get_cert_expiry(cert):
    """Helper to get certificate expiry date (works with old and new cryptography versions)."""
    try:
        # Try new API (cryptography >= 42.0.0) - returns timezone-aware datetime
        return cert.not_valid_after_utc
    except AttributeError:
        # Fall back to old API - returns naive datetime, convert to UTC aware
        naive_dt = cert.not_valid_after
        return naive_dt.replace(tzinfo=timezone.utc) if naive_dt.tzinfo is None else naive_dt


@dataclass
class CertificateInfo:
    """Certificate information data class."""
    serial_number: str
    subject: str
    issuer: str
    issued_at: str
    expires_at: str
    status: str  # active, renewing, revoked, expired
    pem: str
    thumbprint: str = None
    days_until_expiry: int = 0
    revoked_at: Optional[str] = None
    revocation_reason: Optional[str] = None


class CertificateService:
    """
    Centralized certificate management service.

    Provides standardized methods for:
    - Generating and managing dashboard TLS certificates
    - Creating and managing per-engagement CAs
    - Issuing and renewing collector certificates
    - Managing certificate revocation
    - Audit logging of all certificate operations
    """

    # Certificate configuration
    CERT_KEY_SIZE = 4096  # RSA 4096-bit (secure, ~112-bit equiv strength)
    CERT_HASH_ALGORITHM = hashes.SHA256()
    DASHBOARD_CERT_LIFETIME_DAYS = 365
    CA_CERT_LIFETIME_DAYS = 1825  # 5 years
    COLLECTOR_CERT_LIFETIME_DAYS = 30
    GRACE_PERIOD_DAYS = 3

    # Dashboard certificate details
    DASHBOARD_HOSTNAME = "dashboard.caip.local"
    DASHBOARD_CN = "dashboard.caip.local"
    DASHBOARD_OU = "Internal Infrastructure"
    DASHBOARD_ORG = "CAIP"
    DASHBOARD_COUNTRY = "UK"

    # File paths
    CERTS_DIR = '/etc/caip/certs'
    DASHBOARD_CERT_FILE = 'dashboard_cert.pem'
    DASHBOARD_KEY_FILE = 'dashboard_key.pem'

    def __init__(self, vault_or_secret_service, database_service):
        """
        Initialize certificate service.

        Args:
            vault_or_secret_service: Unified vault service or legacy secret service (for decrypting private keys)
            database_service: Database service (for tracking certificates)
        """
        # Store vault for decrypting CA private keys
        self.vault = vault_or_secret_service
        # Keep for backward compatibility
        self.secret_service = vault_or_secret_service
        self.database_service = database_service
        self._ensure_certs_dir()

    def _ensure_certs_dir(self):
        """Ensure certificate directory exists."""
        Path(self.CERTS_DIR).mkdir(parents=True, exist_ok=True)

    # =========================================================================
    # INTERNAL CA MANAGEMENT (Auto-provisioned at startup)
    # =========================================================================

    def ensure_internal_ca(self) -> Dict[str, str]:
        """
        Ensure internal CA exists and is valid. Creates if missing.

        The internal CA is used to issue certificates for all internal
        components (dashboard, services, etc.) and is auto-provisioned
        on first startup.

        Returns:
            Dict with 'certificate_pem', 'private_key_pem', 'serial_number'
        """
        # Check if internal CA exists in database
        try:
            conn = self.database_service.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT ca_certificate_pem, serial_number, expires_at
                FROM internal_ca
                WHERE status = 'active'
                ORDER BY created_at DESC
                LIMIT 1
            """)
            row = cursor.fetchone()

            if row:
                cert_pem = row[0]
                expires_at = row[2]

                # Check if valid
                if self.is_certificate_valid(cert_pem):
                    logger.info("Internal CA exists and is valid")
                    return {
                        'certificate_pem': cert_pem,
                        'serial_number': row[1]
                    }
                else:
                    logger.warning("Internal CA exists but is invalid or expired")

        except Exception as e:
            logger.warning(f"Could not check internal CA: {e}")

        # Generate new internal CA
        logger.info("Generating new internal CA")
        ca_cert, ca_key = self._generate_internal_ca()
        self._store_internal_ca(ca_cert, ca_key)

        logger.info("Internal CA provisioned and stored")
        return {
            'certificate_pem': ca_cert,
            'serial_number': self._extract_serial_number(ca_cert)
        }

    def _generate_internal_ca(self) -> Tuple[str, str]:
        """
        Generate internal CA certificate (10-year lifetime, RSA 4096).

        Returns:
            Tuple of (cert_pem, key_pem)
        """
        # Generate RSA 4096 private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.CERT_KEY_SIZE,  # 4096
            backend=default_backend()
        )

        # Build CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UK"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CAIP"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Internal Infrastructure"),
            x509.NameAttribute(NameOID.COMMON_NAME, "CAIP Internal CA"),
        ])

        now = datetime.now(timezone.utc)
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + timedelta(days=3650)  # 10 years
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        ).sign(private_key, self.CERT_HASH_ALGORITHM, default_backend())

        # Serialize certificate and key
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        return cert_pem, key_pem

    def _store_internal_ca(self, cert_pem: str, key_pem: str):
        """
        Store Internal CA certificate and key.

        Certificate goes to database (public key), key goes to vault (encrypted).
        """
        import base64
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from caip_service_layer.unified_vault_service import get_unified_vault_service

        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        serial_number = str(cert.serial_number)
        subject = self._get_cert_subject_string(cert)
        issued_at = _get_cert_expiry(cert) - timedelta(days=3650)
        expires_at = _get_cert_expiry(cert)

        # PRIMARY STORAGE: Store key in vault (encrypted with AES-256-GCM)
        vault_success = False
        try:
            vault = get_unified_vault_service()
            if vault:
                vault.set_key(
                    "internal_ca_private_key",
                    key_pem,
                    key_type="rsa-4096",
                    metadata={
                        "algorithm": "RSA-PSS-SHA256",
                        "rotation_count": 0,
                        "source": "bootstrap"
                    }
                )
                logger.info("✓ Stored Internal CA private key in vault (PRIMARY)")
                vault_success = True
            else:
                logger.error("✗ Vault service not initialized")
        except Exception as e:
            logger.error(f"✗ Failed to store key in vault: {e}")

        # VAULT-ONLY STORAGE: Private keys must be stored exclusively in vault
        if not vault_success:
            raise ValueError("CRITICAL: Failed to store Internal CA key in vault")

        # Store certificate in database (for audit trail and validation checks)
        try:
            conn = self.database_service.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO internal_ca (ca_certificate_pem, serial_number, subject, issued_at, expires_at, status)
                VALUES (?, ?, ?, ?, ?, 'active')
            """, (cert_pem, serial_number, subject, issued_at, expires_at))
            conn.commit()
            logger.info("✓ Stored Internal CA certificate in database")
        except Exception as e:
            logger.error(f"✗ Failed to store CA certificate in database: {e}")

    def get_internal_ca(self) -> Optional[Dict]:
        """
        Get current internal CA details.

        Returns:
            Dict with CA details or None if not found
        """
        try:
            conn = self.database_service.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT ca_certificate_pem, serial_number, subject, issued_at, expires_at,
                       rotation_count, status
                FROM internal_ca
                WHERE status = 'active'
                ORDER BY created_at DESC
                LIMIT 1
            """)
            row = cursor.fetchone()

            if not row:
                return None

            return {
                'certificate_pem': row[0],
                'serial_number': row[1],
                'subject': row[2],
                'issued_at': row[3],
                'expires_at': row[4],
                'rotation_count': row[5],
                'status': row[6]
            }
        except Exception as e:
            logger.warning(f"Could not get internal CA: {e}")
            return None
        finally:
            conn.close()

    def _get_ca_private_key_internal_ca(self) -> str:
        """
        Get Internal CA private key from vault (VAULT-ONLY - no fallback).

        Returns:
            Private key in PEM format

        Raises:
            ValueError: If key not found in vault
        """
        from caip_service_layer.unified_vault_service import get_unified_vault_service

        try:
            vault = get_unified_vault_service()
            if vault:
                key_pem = vault.get_key_pem("internal_ca_private_key")
                if key_pem:
                    logger.info("✓ Retrieved Internal CA key from vault")
                    return key_pem
                else:
                    raise ValueError("Internal CA key not found in vault")
            else:
                raise ValueError("Vault service not available")
        except Exception as e:
            logger.error(f"Failed to retrieve Internal CA key from vault: {e}")
            raise ValueError(f"Cannot retrieve Internal CA key: {e}")

    def _get_ca_private_key_vault(self, private_key_ref: str) -> str:
        """
        Get a CA private key from vault by reference.

        Args:
            private_key_ref: Vault key reference (e.g., 'engagement-ca-key-{id}')

        Returns:
            Private key in PEM format

        Raises:
            ValueError: If key not found in vault
        """
        from caip_service_layer.unified_vault_service import get_unified_vault_service

        try:
            vault = get_unified_vault_service()
            if vault:
                key_pem = vault.get_key_pem(private_key_ref)
                if key_pem:
                    logger.debug(f"Retrieved CA key from vault: {private_key_ref}")
                    return key_pem
                else:
                    raise ValueError(f"CA key '{private_key_ref}' not found in vault")
            else:
                raise ValueError("Vault service not available")
        except Exception as e:
            logger.error(f"Failed to retrieve CA key from vault: {e}")
            raise ValueError(f"Cannot retrieve CA key: {e}")

    # =========================================================================
    # DASHBOARD CERTIFICATE MANAGEMENT
    # =========================================================================

    def ensure_dashboard_certificate(self) -> Tuple[str, str]:
        """
        Ensure dashboard TLS certificate exists. Generate if missing.

        Returns:
            Tuple of (cert_path, key_path)
        """
        cert_path = Path(self.CERTS_DIR) / self.DASHBOARD_CERT_FILE
        key_path = Path(self.CERTS_DIR) / self.DASHBOARD_KEY_FILE

        # Check if certificates exist and are valid
        if cert_path.exists() and key_path.exists():
            try:
                cert_info = self.get_dashboard_certificate()
                if cert_info and int(cert_info.days_until_expiry) > 0:
                    logger.info("Dashboard certificate valid, using existing certificate")
                    return str(cert_path), str(key_path)
            except Exception as e:
                logger.warning(f"Existing dashboard certificate invalid: {e}")

        # Generate new certificate
        logger.info("Generating new dashboard TLS certificate")
        self._generate_dashboard_certificate(cert_path, key_path)
        return str(cert_path), str(key_path)

    def _generate_dashboard_certificate(self, cert_path: Path, key_path: Path):
        """
        Generate dashboard TLS certificate signed by Internal CA if available.
        Falls back to self-signed if Internal CA not accessible.
        Uses RSA 4096 to match Internal CA format.
        """
        # Generate RSA 4096 private key for the dashboard (to match Internal CA format)
        dashboard_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.CERT_KEY_SIZE,  # 4096
            backend=default_backend()
        )

        # Try to sign with Internal CA
        issuer = None
        signing_key = dashboard_private_key

        try:
            internal_ca_dict = self.get_internal_ca()
            if internal_ca_dict:
                internal_ca_pem = internal_ca_dict['certificate_pem']
                internal_ca_cert = x509.load_pem_x509_certificate(
                    internal_ca_pem.encode(), default_backend()
                )

                # Get and load Internal CA private key
                ca_key_pem = self._get_ca_private_key_internal_ca()
                try:
                    signing_key = serialization.load_pem_private_key(
                        ca_key_pem.encode(), password=None, backend=default_backend()
                    )
                    issuer = internal_ca_cert.subject
                    logger.info("Dashboard cert will be signed by Internal CA")
                except Exception as e:
                    logger.warning(f"Could not load Internal CA key ({e}), using self-signed")
        except Exception as e:
            logger.warning(f"Could not get Internal CA ({e}), using self-signed")

        # Build certificate subject using configured values
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.DASHBOARD_COUNTRY),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.DASHBOARD_ORG),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.DASHBOARD_OU),
            x509.NameAttribute(NameOID.COMMON_NAME, self.DASHBOARD_CN),
        ])

        # Use Internal CA as issuer if available, otherwise self-signed
        if issuer is None:
            issuer = subject

        now = datetime.now(timezone.utc)
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            dashboard_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + timedelta(days=self.DASHBOARD_CERT_LIFETIME_DAYS)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(self.DASHBOARD_HOSTNAME),
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
            ]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).sign(signing_key, self.CERT_HASH_ALGORITHM, default_backend())

        # Save certificate
        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # Save private key
        key_pem = dashboard_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        with open(key_path, 'wb') as f:
            f.write(key_pem)

        # Store key in vault (vault becomes authoritative managed copy)
        from caip_service_layer.unified_vault_service import get_unified_vault_service
        vault = get_unified_vault_service()
        if vault:
            vault.set_key('dashboard-cert-key-main', key_pem.decode(),
                         key_type="rsa-2048", metadata={"purpose": "dashboard_tls"})

        # Store in database - use private_key_ref for vault reference
        conn = self.database_service.get_connection()
        try:
            conn.execute("""
                INSERT INTO dashboard_certificates
                (certificate_pem, private_key_ref, serial_number, issued_at, expires_at, status)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                cert.public_bytes(serialization.Encoding.PEM).decode(),
                'dashboard-cert-key-main',
                str(cert.serial_number),
                now.isoformat(),
                (now + timedelta(days=self.DASHBOARD_CERT_LIFETIME_DAYS)).isoformat(),
                'active'
            ))
            conn.commit()
        finally:
            conn.close()

        logger.info(f"Dashboard certificate generated: {cert_path}")
        logger.info(f"Subject: {subject}")
        logger.info(f"Issuer: {issuer}")

    def get_dashboard_certificate(self) -> CertificateInfo:
        """Get dashboard certificate information."""
        conn = self.database_service.get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM dashboard_certificates WHERE status = 'active' ORDER BY issued_at DESC LIMIT 1"
            ).fetchone()

            if not row:
                raise ValueError("No active dashboard certificate found")

            cert_pem = row['certificate_pem']
            cert = x509.load_pem_x509_certificate(
                cert_pem.encode(), default_backend()
            )

            expires_at = _get_cert_expiry(cert)
            days_until_expiry = (expires_at - datetime.now(timezone.utc)).days

            return CertificateInfo(
                serial_number=str(cert.serial_number),
                subject=self._get_cert_subject_string(cert),
                issuer=self._get_cert_subject_string(cert.issuer),
                issued_at=row['issued_at'],
                expires_at=expires_at.isoformat(),
                status=row['status'],
                pem=cert_pem,
                thumbprint=self._get_cert_thumbprint(cert_pem),
                days_until_expiry=days_until_expiry
            )
        finally:
            conn.close()

    # =========================================================================
    # ENGAGEMENT CA MANAGEMENT
    # =========================================================================

    def create_engagement_ca(self, engagement_id: str, cn: str = None, ou: str = None, o: str = None, c: str = None, lifetime_days: int = None, engagement_name: str = None) -> str:
        """
        Create a new CA certificate for an engagement.

        Args:
            engagement_id: Engagement identifier (numeric database ID)
            cn: Common Name (optional, auto-generated if not provided)
            ou: Organizational Unit (optional, defaults to 'CAIP')
            o: Organization (optional, defaults to 'CAIP')
            c: Country (optional, defaults to 'US')
            lifetime_days: Lifetime in days (optional, defaults to CA_CERT_LIFETIME_DAYS)
            engagement_name: Alternative name for cn (Phase 3 compatibility)

        Returns:
            CA certificate PEM
        """
        # Support both cn and engagement_name parameter names
        if engagement_name and not cn:
            cn = engagement_name

        # Resolve the text engagement_id from either numeric ID or text engagement_id
        # If engagement_id is numeric (like "9"), look up the text engagement_id from engagements table
        # If engagement_id is text (like "ENG-2025-006"), use it directly
        text_engagement_id = None
        numeric_engagement_id = None

        conn = self.database_service.get_connection()
        try:
            # Try to determine if engagement_id is numeric or text
            try:
                numeric_id = int(engagement_id)
                # It's numeric - look up the text engagement_id
                row = conn.execute(
                    "SELECT id, engagement_id FROM engagements WHERE id = ?",
                    (numeric_id,)
                ).fetchone()
                if row:
                    numeric_engagement_id = numeric_id
                    text_engagement_id = row['engagement_id']
                else:
                    raise ValueError(f"No engagement found with numeric ID {numeric_id}")
            except (ValueError, TypeError):
                # It's text (like "ENG-2025-006") - look up the numeric ID
                row = conn.execute(
                    "SELECT id, engagement_id FROM engagements WHERE engagement_id = ?",
                    (engagement_id,)
                ).fetchone()
                if row:
                    numeric_engagement_id = row['id']
                    text_engagement_id = row['engagement_id']
                else:
                    raise ValueError(f"No engagement found with engagement_id {engagement_id}")

            logger.info(f"Resolved engagement: numeric_id={numeric_engagement_id}, text_id={text_engagement_id}")

            # Check if active CA already exists (query engagement_ca_certificates table with text ID)
            existing = conn.execute(
                "SELECT * FROM engagement_ca_certificates WHERE engagement_id = ? AND status = 'active'",
                (text_engagement_id,)
            ).fetchone()

            if existing:
                logger.info(f"Active CA already exists for engagement {text_engagement_id}")
                return existing['certificate_pem']

            # Mark any prior active CA as retired (for rotation tracking)
            conn.execute(
                "UPDATE engagement_ca_certificates SET status = 'retired' WHERE engagement_id = ? AND status = 'active'",
                (text_engagement_id,)
            )
            conn.commit()
        finally:
            conn.close()

        logger.info(f"Creating CA certificate for engagement {engagement_id}")

        # Generate CA private key using RSA 4096 (to match Internal CA format)
        ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.CERT_KEY_SIZE,  # 4096
            backend=default_backend()
        )

        # Build CA certificate subject with provided DN fields
        # Use defaults if not provided
        cn_value = cn or f"CAIP-CA-{engagement_id}"
        ou_value = ou or self.DASHBOARD_OU
        o_value = o or self.DASHBOARD_ORG
        c_value = c or self.DASHBOARD_COUNTRY
        lifetime_value = lifetime_days or self.CA_CERT_LIFETIME_DAYS

        subject_attrs = [
            x509.NameAttribute(NameOID.COMMON_NAME, cn_value),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, o_value),
            x509.NameAttribute(NameOID.COUNTRY_NAME, c_value),
        ]
        if ou_value:
            subject_attrs.insert(1, x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou_value))

        subject = x509.Name(subject_attrs)

        # Get Internal CA certificate and key for signing - MUST succeed
        internal_ca_dict = self.get_internal_ca()
        if not internal_ca_dict:
            raise ValueError("No active Internal CA found - cannot create engagement CA without it")

        internal_ca_pem = internal_ca_dict['certificate_pem']
        internal_ca_cert = x509.load_pem_x509_certificate(
            internal_ca_pem.encode(), default_backend()
        )
        issuer = internal_ca_cert.subject

        # Build unsigned engagement CA certificate first
        now = datetime.now(timezone.utc)
        ca_cert_unsigned = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            ca_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + timedelta(days=lifetime_value)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        # Sign engagement CA certificate with Internal CA key using Python cryptography
        # Load Internal CA private key
        try:
            ca_key_pem_str = self._get_ca_private_key_internal_ca()
            internal_ca_key = serialization.load_pem_private_key(
                ca_key_pem_str.encode(),
                password=None,
                backend=default_backend()
            )
            logger.info(f"✓ Loaded Internal CA private key for signing")
        except Exception as e:
            logger.error(f"Failed to load Internal CA key: {e}")
            raise RuntimeError(f"Cannot load Internal CA key: {e}")

        # Sign the engagement CA certificate with Internal CA key
        try:
            signed_cert = ca_cert_unsigned.sign(
                internal_ca_key,
                self.CERT_HASH_ALGORITHM,
                default_backend()
            )
            ca_cert_pem = signed_cert.public_bytes(serialization.Encoding.PEM).decode()
            logger.info(f"✅ Engagement CA signed by Internal CA")
            logger.info(f"   Subject: {signed_cert.subject}")
            logger.info(f"   Issuer: {signed_cert.issuer}")
        except Exception as e:
            logger.error(f"Failed to sign engagement CA certificate: {e}")
            raise RuntimeError(f"Failed to sign engagement CA: {e}")

        # Get the private key in PEM format
        # Use TraditionalOpenSSL format (RSA PRIVATE KEY) for compatibility with OpenSSL 3.x
        # PKCS8 format (PRIVATE KEY) can cause signature validation issues in OpenSSL
        try:
            ca_key_pem = ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
        except Exception as e:
            logger.error(f"Error creating engagement CA: {e}", exc_info=True)
            raise

        # Store private key in vault (primary storage)
        from caip_service_layer.unified_vault_service import get_unified_vault_service
        vault = get_unified_vault_service()
        if not vault:
            raise RuntimeError("Vault service is required to store engagement CA private keys")

        vault.set_key(f"engagement-ca-key-{numeric_engagement_id}", ca_key_pem,
                     key_type="rsa-4096", metadata={"purpose": "engagement_ca_issuance"})

        self._log_audit_event('CA_CREATED', engagement_id=str(numeric_engagement_id))

        # After creating engagement CA, issue a dashboard server certificate signed by this CA
        # This allows port 5444 to use SNI to present engagement-specific certs
        try:
            dashboard_cert_pem = self.issue_dashboard_certificate_for_engagement(numeric_engagement_id)
            logger.info(f"Issued dashboard certificate for engagement {text_engagement_id}")
        except Exception as e:
            logger.error(f"Failed to issue dashboard cert for engagement {text_engagement_id}: {e}")

        # Export all engagement CAs to ca-chain.pem for port 5444 to use for validating collector client certs
        try:
            self.export_ca_chain_to_file()
            logger.info(f"Exported CA chain to file (after creating engagement CA)")
        except Exception as e:
            logger.error(f"Failed to export CA chain: {e}")

        # Phase 3: Also create Phase 3 Engagement CA certificate in new table
        try:
            serial_hex = format(signed_cert.serial_number, 'X')
            self._insert_certificate('engagement_ca_certificates', {
                'engagement_id': text_engagement_id,
                'certificate_pem': ca_cert_pem,
                'certificate_serial': serial_hex,
                'subject': self._get_cert_subject_string(signed_cert),
                'issuer': signed_cert.issuer.rfc4514_string(),
                'public_key_pem': self._serialize_public_key(ca_private_key.public_key()),
                'private_key_ref': f"engagement-ca-key-{numeric_engagement_id}",
                'issued_at': now.isoformat(),
                'expires_at': (now + timedelta(days=lifetime_value)).isoformat(),
                'status': 'active',
                'rotation_count': 0,
                'created_at': now.isoformat(),
                'updated_at': now.isoformat()
            })

            logger.info(f"✓ Created Phase 3 Engagement CA certificate for {text_engagement_id}")

            # Phase 3: Create Report Signing Certificate
            try:
                report_signing_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=self.CERT_KEY_SIZE,
                    backend=default_backend()
                )

                report_signing_cert = x509.CertificateBuilder().subject_name(
                    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                                 f"CAIP Report Signing - {text_engagement_id}")])
                ).issuer_name(
                    signed_cert.subject  # Signed by Engagement CA
                ).public_key(
                    report_signing_key.public_key()
                ).serial_number(
                    x509.random_serial_number()
                ).not_valid_before(
                    now
                ).not_valid_after(
                    now + timedelta(days=730)  # 2 years
                ).add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=True,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False
                    ),
                    critical=True
                ).add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(report_signing_key.public_key()),
                    critical=False
                ).add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(
                        ca_private_key.public_key()
                    ),
                    critical=False
                ).sign(ca_private_key, self.CERT_HASH_ALGORITHM, default_backend())

                report_signing_cert_pem = self._serialize_certificate(report_signing_cert)
                report_signing_key_pem = self._serialize_private_key(report_signing_key)

                # Store Report Signing Cert
                serial_hex = format(report_signing_cert.serial_number, 'X')
                self._insert_certificate('report_signing_certificates', {
                    'engagement_id': text_engagement_id,
                    'certificate_pem': report_signing_cert_pem,
                    'certificate_serial': serial_hex,
                    'subject': self._get_cert_subject_string(report_signing_cert),
                    'issuer': report_signing_cert.issuer.rfc4514_string(),
                    'public_key_pem': self._serialize_public_key(report_signing_key.public_key()),
                    'private_key_ref': f"report-signing-key-{numeric_engagement_id}",
                    'issued_at': now.isoformat(),
                    'expires_at': report_signing_cert.not_valid_after.isoformat(),
                    'status': 'active',
                    'rotation_count': 0,
                    'created_at': now.isoformat(),
                    'updated_at': now.isoformat()
                })

                # Store Report Signing key in vault
                if vault:
                    vault.set_key(f"report-signing-key-{numeric_engagement_id}", report_signing_key_pem, key_type="rsa-4096",
                                 metadata={"purpose": "report_signing"})

                logger.info(f"✓ Created Phase 3 Report Signing Certificate for {text_engagement_id}")
            except Exception as e:
                logger.error(f"Failed to create Report Signing Certificate: {e}", exc_info=True)

        except Exception as e:
            logger.error(f"Failed to create Phase 3 certificates: {e}", exc_info=True)

        return ca_cert_pem

    def create_engagement_ca_stepped(self, engagement_id: str, engagement_name: str = None,
                                     cn: str = None, ou: str = None, o: str = None, c: str = None,
                                     lifetime_days: int = None) -> dict:
        """
        Create Engagement CA and Report Signing Certificate with stepped progress tracking.

        Executes each operation individually and tracks status, allowing front-end to display
        per-step progress. Returns structured dict with ca_cert_pem and steps array.

        On critical failure (steps 1-8), raises ValueError with steps attached to exception.
        Non-critical failures (steps 9-10) are logged as warnings without raising.

        Args:
            engagement_id: Engagement ID (text format, e.g., "ENG-2025-001")
            engagement_name: Customer/engagement name for certificate CN
            cn, ou, o, c: Certificate DN components (use defaults if not provided)
            lifetime_days: CA certificate lifetime (default: 1825 days / 5 years)

        Returns:
            {
                'ca_cert_pem': PEM-formatted CA certificate,
                'steps': [
                    {
                        'id': 'engagement_record', 'label': 'Engagement Record',
                        'status': 'success|failed|warning|skipped',
                        'detail': 'Details string or serial number',
                        'error': 'Error message or None'
                    },
                    ...
                ]
            }

        Raises:
            ValueError: If any critical step (1-8) fails. Exception has .steps attribute.
        """
        steps = []
        ca_cert_pem = None
        numeric_engagement_id = None
        text_engagement_id = None

        def step(step_id, label, fn):
            """Execute fn(), append result to steps. Raise on critical failure."""
            try:
                detail = fn()
                steps.append({
                    'id': step_id,
                    'label': label,
                    'status': 'success',
                    'detail': detail or '',
                    'error': None
                })
            except Exception as e:
                steps.append({
                    'id': step_id,
                    'label': label,
                    'status': 'failed',
                    'detail': '',
                    'error': str(e)
                })
                err = ValueError(str(e))
                err.steps = steps
                raise err

        def optional_step(step_id, label, fn):
            """Non-critical: failure becomes warning, never raises."""
            try:
                detail = fn()
                steps.append({
                    'id': step_id,
                    'label': label,
                    'status': 'success',
                    'detail': detail or '',
                    'error': None
                })
            except Exception as e:
                steps.append({
                    'id': step_id,
                    'label': label,
                    'status': 'warning',
                    'detail': '',
                    'error': str(e)
                })
                logger.warning(f"Non-critical step '{label}' failed: {e}")

        try:
            # Resolve engagement ID (numeric and text)
            conn = self.database_service.get_connection()
            try:
                row = conn.execute(
                    "SELECT id, engagement_id FROM engagements WHERE engagement_id = ?",
                    (engagement_id,)
                ).fetchone()
                if row:
                    numeric_engagement_id = row['id']
                    text_engagement_id = row['engagement_id']
                else:
                    raise ValueError(f"No engagement found with engagement_id {engagement_id}")
            finally:
                conn.close()

            logger.info(f"Stepped CA creation: engagement {text_engagement_id} (numeric_id={numeric_engagement_id})")

            # Step 1: Engagement Record (already exists at this point, just confirm)
            step('engagement_record', 'Engagement Record',
                 lambda: text_engagement_id)

            # Step 2: CA Key Generation
            ca_private_key = None
            def gen_ca_key():
                nonlocal ca_private_key
                ca_private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=self.CERT_KEY_SIZE,
                    backend=default_backend()
                )
                return "RSA-4096"

            step('ca_key_gen', 'CA Key Generation', gen_ca_key)

            # Step 3: CA Certificate Signing
            signed_cert = None
            def sign_ca_cert():
                nonlocal signed_cert

                # Build CA certificate subject
                cn_value = cn or f"CAIP-CA-{text_engagement_id}"
                ou_value = ou or self.DASHBOARD_OU
                o_value = o or self.DASHBOARD_ORG
                c_value = c or self.DASHBOARD_COUNTRY
                lifetime_value = lifetime_days or self.CA_CERT_LIFETIME_DAYS

                subject_attrs = [
                    x509.NameAttribute(NameOID.COMMON_NAME, cn_value),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, o_value),
                    x509.NameAttribute(NameOID.COUNTRY_NAME, c_value),
                ]
                if ou_value:
                    subject_attrs.insert(1, x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou_value))

                subject = x509.Name(subject_attrs)

                # Get Internal CA certificate and key
                internal_ca_dict = self.get_internal_ca()
                if not internal_ca_dict:
                    raise ValueError("No active Internal CA found")

                internal_ca_pem = internal_ca_dict['certificate_pem']
                internal_ca_cert = x509.load_pem_x509_certificate(
                    internal_ca_pem.encode(), default_backend()
                )
                issuer = internal_ca_cert.subject

                # Load Internal CA private key
                ca_key_pem_str = self._get_ca_private_key_internal_ca()
                internal_ca_key = serialization.load_pem_private_key(
                    ca_key_pem_str.encode(),
                    password=None,
                    backend=default_backend()
                )

                # Build and sign CA certificate
                now = datetime.now(timezone.utc)
                ca_cert_unsigned = x509.CertificateBuilder().subject_name(
                    subject
                ).issuer_name(
                    issuer
                ).public_key(
                    ca_private_key.public_key()
                ).serial_number(
                    x509.random_serial_number()
                ).not_valid_before(
                    now
                ).not_valid_after(
                    now + timedelta(days=lifetime_value)
                ).add_extension(
                    x509.BasicConstraints(ca=True, path_length=None),
                    critical=True,
                ).add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        key_cert_sign=True,
                        crl_sign=True,
                        key_encipherment=False,
                        content_commitment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )

                signed_cert = ca_cert_unsigned.sign(
                    internal_ca_key,
                    self.CERT_HASH_ALGORITHM,
                    default_backend()
                )

                return f"Serial: {format(signed_cert.serial_number, 'X')[:16]}..."

            step('ca_cert_sign', 'CA Certificate Signing', sign_ca_cert)

            # Step 4: CA Vault Storage
            ca_key_pem = None
            def store_ca_vault():
                nonlocal ca_key_pem
                # Use TraditionalOpenSSL format for OpenSSL 3.x compatibility
                ca_key_pem = ca_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode()

                if not self.vault:
                    raise RuntimeError("Vault service unavailable")

                self.vault.set_key(f"engagement-ca-key-{numeric_engagement_id}", ca_key_pem,
                                   key_type="rsa-4096", metadata={"purpose": "engagement_ca_issuance"})

                return "Stored in vault"

            step('ca_vault_store', 'CA Vault Storage', store_ca_vault)

            # Step 5: CA Database Record
            ca_cert_pem = None
            def insert_ca_db():
                nonlocal ca_cert_pem
                ca_cert_pem = signed_cert.public_bytes(serialization.Encoding.PEM).decode()
                now = datetime.now(timezone.utc)
                lifetime_value = lifetime_days or self.CA_CERT_LIFETIME_DAYS
                serial_hex = format(signed_cert.serial_number, 'X')

                self._insert_certificate('engagement_ca_certificates', {
                    'engagement_id': text_engagement_id,
                    'certificate_pem': ca_cert_pem,
                    'certificate_serial': serial_hex,
                    'subject': self._get_cert_subject_string(signed_cert),
                    'issuer': signed_cert.issuer.rfc4514_string(),
                    'public_key_pem': self._serialize_public_key(ca_private_key.public_key()),
                    'private_key_ref': f"engagement-ca-key-{numeric_engagement_id}",
                    'issued_at': now.isoformat(),
                    'expires_at': (now + timedelta(days=lifetime_value)).isoformat(),
                    'status': 'active',
                    'rotation_count': 0,
                    'created_at': now.isoformat(),
                    'updated_at': now.isoformat()
                })

                return f"Inserted with serial {serial_hex[:16]}..."

            step('ca_db_record', 'CA Database Record', insert_ca_db)

            # Step 6: Report Signing Certificate Creation
            report_signing_cert = None
            report_signing_key = None
            def create_signing_cert():
                nonlocal report_signing_cert, report_signing_key

                report_signing_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=self.CERT_KEY_SIZE,
                    backend=default_backend()
                )

                now = datetime.now(timezone.utc)
                report_signing_cert = x509.CertificateBuilder().subject_name(
                    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                                 f"CAIP Report Signing - {text_engagement_id}")])
                ).issuer_name(
                    signed_cert.subject
                ).public_key(
                    report_signing_key.public_key()
                ).serial_number(
                    x509.random_serial_number()
                ).not_valid_before(
                    now
                ).not_valid_after(
                    now + timedelta(days=730)
                ).add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=True,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False
                    ),
                    critical=True
                ).add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(report_signing_key.public_key()),
                    critical=False
                ).add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(
                        ca_private_key.public_key()
                    ),
                    critical=False
                ).sign(ca_private_key, self.CERT_HASH_ALGORITHM, default_backend())

                return "RSA-4096, 2-year validity"

            step('signing_cert_create', 'Report Signing Cert', create_signing_cert)

            # Step 7: Report Signing Key Vault Storage
            report_signing_key_pem = None
            def store_signing_vault():
                nonlocal report_signing_key_pem
                report_signing_key_pem = self._serialize_private_key(report_signing_key)

                if not self.vault:
                    raise RuntimeError("Vault service unavailable")

                self.vault.set_key(f"report-signing-key-{numeric_engagement_id}", report_signing_key_pem,
                                  key_type="rsa-4096", metadata={"purpose": "report_signing"})

                return "Stored in vault"

            step('signing_vault_store', 'Signing Key Vault Storage', store_signing_vault)

            # Step 8: Report Signing Certificate Database Record
            def insert_signing_db():
                now = datetime.now(timezone.utc)
                serial_hex = format(report_signing_cert.serial_number, 'X')

                # Use _get_cert_expiry() helper to handle both old and new cryptography API
                expiry_dt = _get_cert_expiry(report_signing_cert)

                self._insert_certificate('report_signing_certificates', {
                    'engagement_id': text_engagement_id,
                    'certificate_pem': self._serialize_certificate(report_signing_cert),
                    'certificate_serial': serial_hex,
                    'subject': self._get_cert_subject_string(report_signing_cert),
                    'issuer': report_signing_cert.issuer.rfc4514_string(),
                    'public_key_pem': self._serialize_public_key(report_signing_key.public_key()),
                    'private_key_ref': f"report-signing-key-{numeric_engagement_id}",
                    'issued_at': now.isoformat(),
                    'expires_at': expiry_dt.isoformat(),
                    'status': 'active',
                    'rotation_count': 0,
                    'created_at': now.isoformat(),
                    'updated_at': now.isoformat()
                })

                return f"Inserted with serial {serial_hex[:16]}..."

            step('signing_db_record', 'Signing Cert Database', insert_signing_db)

            # Step 9: Export CA Chain to File (for mTLS validation)
            def export_ca_chain():
                self.export_ca_chain_to_file()
                return "CA chain exported"

            optional_step('ca_chain_export', 'CA Chain Export', export_ca_chain)

            # All steps completed successfully
            return {'ca_cert_pem': ca_cert_pem, 'steps': steps}

        except ValueError as e:
            # Critical failure - steps already attached by step() function
            raise

    def get_engagement_ca(self, engagement_id: str) -> str:
        """Get CA certificate for engagement from engagement_ca_certificates table."""
        conn = self.database_service.get_connection()
        try:
            row = conn.execute(
                "SELECT certificate_pem FROM engagement_ca_certificates WHERE engagement_id = ? AND status = 'active'",
                (engagement_id,)
            ).fetchone()

            if not row:
                # Auto-create if missing
                return self.create_engagement_ca(engagement_id)

            return row['certificate_pem']
        finally:
            conn.close()

    def get_ca_chain_for_collector(self, engagement_id: str) -> str:
        """
        Get CA chain for collector to validate server certificates.

        The collector needs these CAs to validate the dashboard server certificate:
        - Internal CA (root): Signs the dashboard server cert and engagement CA
        - Engagement CA: Signs collector certificates for mutual authentication

        Args:
            engagement_id: Engagement ID

        Returns:
            PEM-formatted string with Internal CA and Engagement CA certificates (raw PEM, no comments)
        """
        ca_chain_pem = ""

        # Get internal CA (root - validates dashboard server certificate)
        internal_ca = self.get_internal_ca()
        if internal_ca:
            ca_chain_pem += internal_ca['certificate_pem']
            if not internal_ca['certificate_pem'].endswith('\n'):
                ca_chain_pem += "\n"

        # Get engagement CA (validates collector certificates for mTLS)
        engagement_ca = self.get_engagement_ca(engagement_id)
        if engagement_ca:
            ca_chain_pem += engagement_ca
            if not engagement_ca.endswith('\n'):
                ca_chain_pem += "\n"

        logger.info(f"Generated CA chain for collector in engagement {engagement_id} (Internal CA + Engagement CA)")
        return ca_chain_pem

    def _signal_gunicorn_reload_port_5444(self):
        """
        Send SIGHUP to gunicorn master process on port 5444 to gracefully reload.

        This causes:
        - New workers to spawn (reading updated ca-chain.pem)
        - Old workers to finish current requests and exit
        - Zero downtime reload
        """
        import os
        import signal
        import subprocess

        try:
            # Find gunicorn process listening on port 5444
            result = subprocess.run(
                ["pgrep", "-f", "gunicorn.*production_config_collectors"],
                capture_output=True,
                text=True,
                timeout=5
            )

            pids = result.stdout.strip().split('\n')
            if not pids or pids[0] == '':
                logger.warning("Could not find gunicorn process for port 5444. CA chain updated but process not reloaded.")
                return

            # Get the master PID (smallest PID, all others are workers)
            master_pid = min(int(pid) for pid in pids if pid)

            logger.info(f"Sending SIGHUP to gunicorn master PID {master_pid} for graceful reload")
            os.kill(master_pid, signal.SIGHUP)
            logger.info("✓ SIGHUP sent - new workers will read updated ca-chain.pem")

        except Exception as e:
            logger.warning(f"Failed to signal gunicorn reload: {e}. CA chain file updated, but process may need manual restart.")

    def export_ca_chain_to_file(self, output_path: str = '/etc/caip/certs/ca-chain.pem'):
        """
        Export all active Engagement CAs + Internal CA (root) to a single PEM file for port 5444 client validation.

        Port 5444 uses this file to validate client certificates from collectors.
        Each collector's certificate is signed by its Engagement CA, which is signed by the Internal CA.

        Args:
            output_path: Path to write CA chain PEM file

        Raises:
            IOError: If file cannot be written
            Exception: If database query fails
        """
        conn = self.database_service.get_connection()
        try:
            # Get all active Engagement CAs from engagement_ca_certificates table
            engagement_rows = conn.execute("""
                SELECT certificate_pem, engagement_id
                FROM engagement_ca_certificates
                WHERE status = 'active'
                ORDER BY created_at ASC
            """).fetchall()

            # Get the Internal CA (root)
            internal_ca_row = conn.execute("""
                SELECT ca_certificate_pem
                FROM internal_ca
                WHERE status = 'active'
                ORDER BY created_at DESC
                LIMIT 1
            """).fetchone()

            if not engagement_rows and not internal_ca_row:
                logger.warning("No active CAs to export")
                return

            # Ensure directory exists
            from pathlib import Path
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)

            # Write all CAs to chain file (Engagement CAs first, then Internal CA root)
            with open(output_path, 'w') as f:
                # Write all Engagement CAs
                for row in engagement_rows:
                    engagement_id = row['engagement_id']
                    ca_pem = row['certificate_pem']

                    f.write(f"# Engagement CA: {engagement_id}\n")
                    f.write(ca_pem)
                    f.write("\n")

                # Write Internal CA as the root (last in chain)
                if internal_ca_row:
                    f.write("# Internal CA (root)\n")
                    f.write(internal_ca_row['ca_certificate_pem'])
                    f.write("\n")

            logger.info(f"✓ Exported {len(engagement_rows)} Engagement CAs + 1 Internal CA root to {output_path}")

            # Gracefully reload gunicorn port 5444 to pick up the new CA chain
            # SIGHUP triggers: new workers spawn (reading new ca-chain.pem), old workers drain and exit
            self._signal_gunicorn_reload_port_5444()

        except Exception as e:
            logger.error(f"Failed to export CA chain: {e}")
            raise
        finally:
            conn.close()

    def issue_dashboard_certificate_for_engagement(self, engagement_id) -> str:
        """
        Issue a dashboard server certificate signed by the engagement CA.

        This allows port 5444 to use SNI to present engagement-specific certificates.
        Each engagement gets its own dashboard certificate signed by that engagement's CA.

        Args:
            engagement_id: Engagement identifier (can be string like "9" or "ENG-2025-006" for CA lookup,
                          or numeric ID for database operations)

        Returns:
            Dashboard certificate PEM signed by engagement CA

        Raises:
            ValueError: If engagement CA doesn't exist
        """
        # For CA lookup, convert to string if needed
        engagement_id_str = str(engagement_id)

        # Get engagement CA certificate and key using string ID
        ca_cert_pem = self.get_engagement_ca(engagement_id_str)
        ca_key_pem = self._get_ca_private_key(engagement_id_str)

        # Load CA certificate and key
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode(), default_backend())
        ca_private_key = serialization.load_pem_private_key(
            ca_key_pem.encode(), password=None, backend=default_backend()
        )

        # Generate new private key for dashboard cert
        dashboard_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Build dashboard certificate signed by engagement CA
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.DASHBOARD_COUNTRY),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.DASHBOARD_ORG),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.DASHBOARD_OU),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{self.DASHBOARD_CN}-{engagement_id}"),
        ])

        now = datetime.now(timezone.utc)
        dashboard_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject  # Signed by engagement CA
        ).public_key(
            dashboard_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + timedelta(days=self.DASHBOARD_CERT_LIFETIME_DAYS)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(self.DASHBOARD_HOSTNAME),
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
            ]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).sign(ca_private_key, self.CERT_HASH_ALGORITHM, default_backend())

        # Serialize certificate
        dashboard_cert_pem = dashboard_cert.public_bytes(serialization.Encoding.PEM).decode()
        dashboard_key_pem = dashboard_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        dashboard_public_key_pem = dashboard_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        # Store key in vault for engagement dashboard cert
        from caip_service_layer.unified_vault_service import get_unified_vault_service
        vault = get_unified_vault_service()
        vault_key_name = f"engagement-dashboard-key-{engagement_id}"
        if vault:
            vault.set_key(vault_key_name, dashboard_key_pem,
                         key_type="rsa-2048", metadata={"purpose": "engagement_dashboard_tls"})

        # Store in database
        conn = self.database_service.get_connection()
        try:
            # First, mark any existing active cert as inactive
            conn.execute(
                "UPDATE engagement_dashboard_certificates SET status = 'retired' WHERE engagement_id = ? AND status = 'active'",
                (engagement_id,)
            )

            # Insert new active certificate - use private_key_ref for vault reference
            conn.execute("""
                INSERT INTO engagement_dashboard_certificates
                (engagement_id, certificate_pem, private_key_ref, public_key_pem,
                 serial_number, subject, issued_at, expires_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active')
            """, (
                engagement_id,
                dashboard_cert_pem,
                vault_key_name,
                dashboard_public_key_pem,
                str(dashboard_cert.serial_number),
                self._get_cert_subject_string(dashboard_cert),
                now.isoformat(),
                (now + timedelta(days=self.DASHBOARD_CERT_LIFETIME_DAYS)).isoformat()
            ))
            conn.commit()
            logger.info(f"Stored dashboard certificate for engagement {engagement_id} in database")
        finally:
            conn.close()

        self._log_audit_event('DASHBOARD_CERT_ISSUED', engagement_id=engagement_id)

        return dashboard_cert_pem

    # =========================================================================
    # COLLECTOR CERTIFICATE ISSUANCE & RENEWAL
    # =========================================================================

    def issue_collector_certificate(
        self,
        collector_id: str,
        engagement_id: str,
        csr_pem: str
    ) -> Tuple[str, str]:
        """
        Issue a new certificate for a collector.

        Args:
            collector_id: Collector identifier
            engagement_id: Engagement identifier (determines CA)
            csr_pem: Certificate Signing Request in PEM format

        Returns:
            Tuple of (certificate_pem, ca_chain_pem)

        Raises:
            ValueError: If CSR is invalid or collector already has active cert
        """
        logger.info("="*80)
        logger.info(f"[COLLECTOR CERT ISSUANCE] Starting for {collector_id} / {engagement_id}")
        logger.info("="*80)

        # Validate CSR
        logger.info(f"[1] Validating CSR for collector {collector_id}")
        if not self.validate_csr(csr_pem, collector_id):
            logger.error(f"CSR validation failed for {collector_id}")
            raise ValueError(f"Invalid or mismatched CSR for collector {collector_id}")
        logger.info(f"✓ CSR is valid")

        # Delete any existing certificates (collector_certificates has UNIQUE(collector_id))
        # This handles re-registrations where the collector generated new keys
        # The schema only allows one cert per collector, so we must delete the old one
        logger.info(f"[2] Deleting any existing certificates for {collector_id}")
        conn = self.database_service.get_connection()
        try:
            result = conn.execute(
                "DELETE FROM collector_certificates WHERE collector_id = ?",
                (collector_id,)
            )
            conn.commit()
            logger.info(f"✓ Deleted {result.rowcount} existing certificate(s)")
        finally:
            conn.close()

        # Get engagement CA
        logger.info(f"[3] Retrieving CA certificate and key for {engagement_id}")
        ca_cert_pem = self.get_engagement_ca(engagement_id)
        logger.info(f"✓ CA certificate retrieved ({len(ca_cert_pem)} bytes)")

        logger.info(f"[4] Retrieving CA private key for {engagement_id}")
        ca_key_pem = self._get_ca_private_key(engagement_id)
        logger.info(f"✓ CA private key retrieved ({len(ca_key_pem)} bytes)")

        # Load CA certificate and key
        logger.info(f"[5] Loading CA certificate and key into cryptography objects")
        ca_cert = x509.load_pem_x509_certificate(
            ca_cert_pem.encode(), default_backend()
        )
        logger.info(f"✓ CA certificate loaded")
        logger.info(f"  Subject: {ca_cert.subject.rfc4514_string()}")
        logger.info(f"  Serial:  0x{ca_cert.serial_number:x}")

        ca_private_key = serialization.load_pem_private_key(
            ca_key_pem.encode(), password=None, backend=default_backend()
        )
        logger.info(f"✓ CA private key loaded")
        logger.info(f"  Key type: {type(ca_private_key).__name__}")
        logger.info(f"  Key size: {ca_private_key.key_size} bits")

        # CRITICAL: Verify the CA cert's public key matches the private key we loaded
        logger.info(f"[DEBUG] Verifying CA cert public key matches private key...")
        try:
            cert_public_key = ca_cert.public_key()
            key_public_key = ca_private_key.public_key()

            # Get public key numbers for comparison
            cert_pub_numbers = cert_public_key.public_numbers()
            key_pub_numbers = key_public_key.public_numbers()

            if cert_pub_numbers.e == key_pub_numbers.e and cert_pub_numbers.n == key_pub_numbers.n:
                logger.info(f"✓ CA cert public key MATCHES private key (CORRECT)")
            else:
                logger.error(f"✗ CA cert public key DOES NOT MATCH private key (MISMATCH!)")
                logger.error(f"  Certificate public key exponent: {cert_pub_numbers.e}")
                logger.error(f"  Private key public exponent: {key_pub_numbers.e}")
                logger.error(f"  This will cause signature failure during cert signing!")
                raise ValueError("CA cert public key does not match CA private key - certificate signing will fail")
        except Exception as e:
            logger.error(f"Error verifying CA key match: {e}")
            raise

        # Load CSR
        logger.info(f"[6] Loading CSR")
        csr = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
        logger.info(f"✓ CSR loaded")
        csr_public_key = csr.public_key()
        logger.info(f"  CSR subject: {csr.subject.rfc4514_string()}")
        logger.info(f"  CSR public key size: {csr_public_key.key_size} bits")

        # Build collector certificate with engagement ID in subject for SNI callback identification
        # This allows port 5444 to extract engagement_id from the validated client certificate
        logger.info(f"[7] Building collector certificate")
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"collector-{collector_id}"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"engagement-{engagement_id}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CAIP"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ])

        now = datetime.now(timezone.utc)
        logger.info(f"  Subject: {subject.rfc4514_string()}")
        logger.info(f"  Issuer: {ca_cert.subject.rfc4514_string()}")
        logger.info(f"  Valid from: {now}")
        logger.info(f"  Valid until: {now + timedelta(days=self.COLLECTOR_CERT_LIFETIME_DAYS)}")
        logger.info(f"  Signature algorithm: {self.CERT_HASH_ALGORITHM.name}")

        logger.info(f"[8] Signing certificate with CA private key")
        logger.info(f"  CA key type: {type(ca_private_key).__name__}")
        logger.info(f"  CA key size: {ca_private_key.key_size} bits")

        collector_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            csr_public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + timedelta(days=self.COLLECTOR_CERT_LIFETIME_DAYS)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).sign(ca_private_key, self.CERT_HASH_ALGORITHM, default_backend())

        logger.info(f"✓ Certificate signed successfully")
        logger.info(f"  Collector cert serial: 0x{collector_cert.serial_number:x}")

        cert_pem = collector_cert.public_bytes(serialization.Encoding.PEM).decode()
        logger.info(f"✓ Certificate converted to PEM ({len(cert_pem)} bytes)")
        logger.info(f"[9] Extracting public key from CSR")
        public_key_pem = csr.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        logger.info(f"✓ Public key extracted ({len(public_key_pem)} bytes)")

        # Store in database
        logger.info(f"[10] Storing certificate in database")
        conn = self.database_service.get_connection()
        try:
            conn.execute("""
                INSERT INTO collector_certificates
                (collector_id, engagement_id, certificate_pem, public_key_pem, serial_number,
                 subject, issuer, issued_at, expires_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                collector_id,
                engagement_id,
                cert_pem,
                public_key_pem,
                str(collector_cert.serial_number),
                self._get_cert_subject_string(collector_cert),
                self._get_cert_subject_string(collector_cert.issuer),
                now.isoformat(),
                (now + timedelta(days=self.COLLECTOR_CERT_LIFETIME_DAYS)).isoformat(),
                'active'
            ))
            conn.commit()
            logger.info(f"✓ Certificate stored in database")
        except Exception as e:
            logger.error(f"✗ Failed to store certificate in database: {e}")
            raise
        finally:
            conn.close()

        logger.info(f"[11] Logging audit event")
        self._log_audit_event('CERTIFICATE_ISSUED', collector_id=collector_id, engagement_id=engagement_id)
        logger.info(f"✓ Audit event logged")

        # Return combined CA chain (Internal CA + Engagement CA) for collectors to validate dashboard cert
        logger.info(f"[12] Building CA chain for collector")
        ca_chain = self.get_ca_chain_for_collector(engagement_id)
        logger.info(f"✓ CA chain built ({len(ca_chain)} bytes)")

        logger.info("="*80)
        logger.info(f"[COLLECTOR CERT ISSUANCE] COMPLETE")
        logger.info(f"  Collector ID: {collector_id}")
        logger.info(f"  Engagement ID: {engagement_id}")
        logger.info(f"  Cert Serial: 0x{collector_cert.serial_number:x}")
        logger.info(f"  Issuer: {collector_cert.issuer.rfc4514_string()}")
        logger.info("="*80)

        return cert_pem, ca_chain

    def renew_collector_certificate(
        self,
        collector_id: str,
        csr_pem: str
    ) -> Tuple[str, str]:
        """
        Renew a collector certificate with a new CSR.

        Args:
            collector_id: Collector identifier
            csr_pem: New Certificate Signing Request

        Returns:
            Tuple of (certificate_pem, ca_chain_pem)
        """
        # Get current certificate and engagement
        conn = self.database_service.get_connection()
        try:
            current_cert = conn.execute(
                "SELECT * FROM collector_certificates WHERE collector_id = ? AND status = 'active'",
                (collector_id,)
            ).fetchone()

            if not current_cert:
                raise ValueError(f"No active certificate found for collector {collector_id}")

            engagement_id = current_cert['engagement_id']
        finally:
            conn.close()

        # Issue new certificate
        new_cert_pem, ca_chain = self.issue_collector_certificate(
            collector_id, engagement_id, csr_pem
        )

        # Mark old certificate as having grace period
        expires_at = datetime.fromisoformat(current_cert['expires_at'])
        grace_period_end = datetime.now(timezone.utc) + timedelta(days=self.GRACE_PERIOD_DAYS)

        conn = self.database_service.get_connection()
        try:
            conn.execute("""
                UPDATE collector_certificates
                SET status = 'renewing', previous_serial_number = ?, previous_expires_at = ?
                WHERE collector_id = ? AND serial_number = ?
            """, (
                current_cert['serial_number'],
                grace_period_end.isoformat(),
                collector_id,
                current_cert['serial_number']
            ))

            # Increment renewal counter
            conn.execute("""
                UPDATE collector_certificates
                SET renewal_count = renewal_count + 1
                WHERE collector_id = ? AND status = 'active'
            """, (collector_id,))

            conn.commit()
        finally:
            conn.close()

        self._log_audit_event('CERTIFICATE_RENEWED', collector_id=collector_id, engagement_id=engagement_id)

        return new_cert_pem, ca_chain

    def revoke_collector_certificate(self, collector_id: str, reason: str = "Unspecified") -> bool:
        """
        Revoke a collector certificate.

        Args:
            collector_id: Collector identifier
            reason: Revocation reason

        Returns:
            True if revocation successful
        """
        conn = self.database_service.get_connection()
        try:
            result = conn.execute("""
                UPDATE collector_certificates
                SET status = 'revoked', revoked_at = ?, revocation_reason = ?
                WHERE collector_id = ? AND status IN ('active', 'renewing')
            """, (datetime.now(timezone.utc).isoformat(), reason, collector_id))

            # Mark old cert as revoked too
            conn.execute("""
                UPDATE collector_certificates
                SET status = 'revoked', revoked_at = ?, revocation_reason = ?
                WHERE collector_id = ? AND status = 'renewing'
            """, (datetime.now(timezone.utc).isoformat(), reason, collector_id))

            conn.commit()

            if result.rowcount > 0:
                self._log_audit_event('CERTIFICATE_REVOKED', collector_id=collector_id)
                self._update_crl()
                return True

            return False
        finally:
            conn.close()

    def get_collector_certificate(self, collector_id: str) -> Optional[CertificateInfo]:
        """Get active certificate information for a collector."""
        conn = self.database_service.get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM collector_certificates WHERE collector_id = ? AND status = 'active'",
                (collector_id,)
            ).fetchone()

            if not row:
                return None

            expires_at = datetime.fromisoformat(row['expires_at'])
            days_until_expiry = (expires_at - datetime.now(timezone.utc)).days

            return CertificateInfo(
                serial_number=row['serial_number'],
                subject=row['subject'],
                issuer=row['issuer'],
                issued_at=row['issued_at'],
                expires_at=row['expires_at'],
                status=row['status'],
                pem=row['certificate_pem'],
                thumbprint=self._get_cert_thumbprint(row['certificate_pem']),
                days_until_expiry=days_until_expiry
            )
        finally:
            conn.close()

    def get_collector_certificates(self, engagement_id: str) -> List[CertificateInfo]:
        """Get all certificates for an engagement."""
        conn = self.database_service.get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM collector_certificates WHERE engagement_id = ? ORDER BY issued_at DESC",
                (engagement_id,)
            ).fetchall()

            certs = []
            for row in rows:
                expires_at = datetime.fromisoformat(row['expires_at'])
                days_until_expiry = (expires_at - datetime.now(timezone.utc)).days

                certs.append(CertificateInfo(
                    serial_number=row['serial_number'],
                    subject=row['subject'],
                    issuer=row['issuer'],
                    issued_at=row['issued_at'],
                    expires_at=row['expires_at'],
                    status=row['status'],
                    pem=row['certificate_pem'],
                    thumbprint=self._get_cert_thumbprint(row['certificate_pem']),
                    days_until_expiry=days_until_expiry,
                    revoked_at=row.get('revoked_at'),
                    revocation_reason=row.get('revocation_reason')
                ))

            return certs
        finally:
            conn.close()

    # =========================================================================
    # REVOCATION MANAGEMENT
    # =========================================================================

    def is_certificate_revoked(self, serial_number: str) -> bool:
        """Check if a certificate is revoked."""
        conn = self.database_service.get_connection()
        try:
            row = conn.execute(
                "SELECT status FROM collector_certificates WHERE serial_number = ?",
                (serial_number,)
            ).fetchone()

            return row and row['status'] == 'revoked'
        finally:
            conn.close()

    def get_certificate_revocation_list(self, engagement_id: str) -> str:
        """
        Get revocation list for an engagement.

        Returns:
            JSON list of revoked serial numbers
        """
        conn = self.database_service.get_connection()
        try:
            rows = conn.execute(
                """SELECT serial_number FROM collector_certificates
                   WHERE engagement_id = ? AND status = 'revoked'""",
                (engagement_id,)
            ).fetchall()

            revoked_serials = [row['serial_number'] for row in rows]
            return json.dumps(revoked_serials)
        finally:
            conn.close()

    def _update_crl(self):
        """Update cached CRL for all engagements."""
        conn = self.database_service.get_connection()
        try:
            # Get all engagements with certificates
            engagements = conn.execute(
                "SELECT DISTINCT engagement_id FROM collector_certificates"
            ).fetchall()

            for eng_row in engagements:
                eng_id = eng_row['engagement_id']
                revoked = conn.execute(
                    "SELECT serial_number FROM collector_certificates WHERE engagement_id = ? AND status = 'revoked'",
                    (eng_id,)
                ).fetchall()

                revoked_list = json.dumps([r['serial_number'] for r in revoked])

                conn.execute("""
                    INSERT OR REPLACE INTO certificate_revocation_list
                    (engagement_id, serial_numbers, updated_at)
                    VALUES (?, ?, ?)
                """, (eng_id, revoked_list, datetime.now(timezone.utc).isoformat()))

            conn.commit()
        finally:
            conn.close()

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    def _extract_serial_number(self, cert_pem: str) -> str:
        """Extract serial number from certificate PEM."""
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            return str(cert.serial_number)
        except Exception as e:
            logger.warning(f"Could not extract serial number: {e}")
            return "unknown"

    # =========================================================================
    # CERTIFICATE VALIDATION
    # =========================================================================

    def validate_csr(self, csr_pem: str, expected_collector_id: str) -> bool:
        """
        Validate CSR is properly formatted and has expected subject.

        Args:
            csr_pem: CSR in PEM format
            expected_collector_id: Expected collector ID in CN

        Returns:
            True if CSR is valid and matches expected collector_id
        """
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())

            # Extract CN from subject
            cn = None
            for attr in csr.subject:
                if attr.oid == NameOID.COMMON_NAME:
                    cn = attr.value
                    break

            if not cn:
                logger.warning(f"CSR missing Common Name")
                return False

            # Verify it matches expected collector ID pattern
            expected_cn = f"collector-{expected_collector_id}"
            if cn != expected_cn:
                logger.warning(f"CSR CN mismatch: got {cn}, expected {expected_cn}")
                return False

            return True
        except Exception as e:
            logger.error(f"CSR validation failed: {e}")
            return False

    def validate_certificate_signature(self, cert_pem: str, ca_cert_pem: str) -> bool:
        """Validate certificate was signed by given CA."""
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode(), default_backend())

            # Verify signature
            ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_algorithm_oid
            )
            return True
        except Exception as e:
            logger.error(f"Certificate signature validation failed: {e}")
            return False

    def is_certificate_valid(self, cert_pem: str) -> bool:
        """Check if certificate is valid (not expired, not revoked)."""
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            now = datetime.now(timezone.utc)

            # Check expiry
            if now > _get_cert_expiry(cert):
                return False

            # Check revocation
            serial = str(cert.serial_number)
            if self.is_certificate_revoked(serial):
                return False

            return True
        except Exception as e:
            logger.error(f"Certificate validity check failed: {e}")
            return False

    # =========================================================================
    # USER IDENTITY CERTIFICATE METHODS (Phase 2)
    # =========================================================================

    def issue_user_identity_certificate(
        self,
        user_id: int,
        username: Optional[str] = None,
        role: str = 'user',
        engagement_id: Optional[str] = None,
        cert_purpose: str = 'identity',
        validity_days: int = 365
    ) -> Dict[str, Any]:
        """
        Issue an X.509 identity certificate for a user.

        Certificate can be signed by:
        - Engagement CA (if engagement_id provided)
        - Internal CA (if engagement_id is None)

        Args:
            user_id: User ID from users table
            username: User's email/username (fetched from database if None)
            role: User role (user, admin, etc.)
            engagement_id: Optional engagement ID to use Engagement CA as issuer
            cert_purpose: Certificate purpose ('identity' or 'report_viewer')
            validity_days: Certificate validity in days (default 365 for identity, typically 7/30/90 for report_viewer)

        Returns:
            Dict with certificate_pem, certificate_serial, user_id, issuing_ca, status
        """
        conn = self.database_service.get_connection()
        try:
            # Fetch username from database if not provided
            if not username:
                user_row = conn.execute(
                    "SELECT username, role FROM users WHERE id = ?",
                    (user_id,)
                ).fetchone()

                if not user_row:
                    raise ValueError(f"User {user_id} not found in database")

                username = user_row['username']
                if not role or role == 'user':
                    role = user_row['role'] or 'user'

            # Check if user already has an active or pending certificate for this engagement/purpose
            existing_cert = conn.execute(
                "SELECT certificate_serial, status FROM user_digital_identities WHERE user_id = ? AND engagement_id IS ? AND cert_purpose = ?",
                (user_id, engagement_id, cert_purpose)
            ).fetchone()

            if existing_cert:
                # User already has a certificate for this engagement/purpose - this is a rotate operation
                logger.info(f"User {user_id} already has {cert_purpose} certificate {existing_cert['certificate_serial']} with status {existing_cert['status']}")
                logger.info(f"Treating issue request as rotate for user {user_id}")
                # Delegate to rotate method instead
                return self.rotate_user_identity_certificate(
                    user_id=user_id,
                    engagement_id=engagement_id,
                    cert_purpose=cert_purpose
                )

            # Determine which CA to use as issuer
            if engagement_id:
                # Use Engagement CA
                ca_row = conn.execute(
                    "SELECT certificate_pem, private_key_ref FROM engagement_ca_certificates WHERE engagement_id = ? AND status = 'active'",
                    (engagement_id,)
                ).fetchone()

                if not ca_row:
                    raise ValueError(f"Engagement CA not found for engagement {engagement_id}")

                issuing_ca_name = f"Engagement CA - {engagement_id}"
                ca_cert_pem = ca_row['certificate_pem']

                # Get CA private key from vault using the ref stored in database
                try:
                    ca_key_pem = self._get_ca_private_key_vault(ca_row['private_key_ref'])
                except Exception as e:
                    raise ValueError(f"Failed to retrieve Engagement CA key from vault: {e}")
            else:
                # Use Internal CA
                ca_row = conn.execute(
                    "SELECT ca_certificate_pem FROM internal_ca WHERE status = 'active' ORDER BY created_at DESC LIMIT 1"
                ).fetchone()

                if not ca_row:
                    raise ValueError("Internal CA not found")

                issuing_ca_name = "Internal CA"
                ca_cert_pem = ca_row['ca_certificate_pem']

                # Get Internal CA private key from vault (vault-only, no fallback)
                try:
                    ca_key_pem = self._get_ca_private_key_internal_ca()
                except Exception as e:
                    raise ValueError(f"Failed to retrieve Internal CA key from vault: {e}")

            # Generate user key pair (RSA-4096, 1-year lifetime)
            user_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )

            user_public_key = user_private_key.public_key()

            # Load CA certificate and private key for signing
            ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode(), default_backend())
            ca_private_key = serialization.load_pem_private_key(
                ca_key_pem.encode(), password=None, backend=default_backend()
            )

            # Create user certificate subject
            user_subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, username),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CAIP"),
            ])

            # Build certificate with extensions
            now = datetime.now(timezone.utc)
            cert_builder = x509.CertificateBuilder()
            cert_builder = cert_builder.subject_name(user_subject)
            cert_builder = cert_builder.issuer_name(ca_cert.subject)
            cert_builder = cert_builder.public_key(user_public_key)
            cert_builder = cert_builder.serial_number(x509.random_serial_number())
            cert_builder = cert_builder.not_valid_before(now)
            cert_builder = cert_builder.not_valid_after(now + timedelta(days=validity_days))

            # Add extensions for audit trail and identification
            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName([x509.RFC822Name(username)]),
                critical=False
            )
            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True
            )
            cert_builder = cert_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )

            # Add custom extension for user metadata (serialize as DER octet string containing JSON)
            import binascii
            metadata_json = json.dumps({"user_id": user_id, "role": role})
            # Wrap JSON in an OCTET STRING (DER tag 0x04)
            metadata_bytes = metadata_json.encode()
            # Simple DER OCTET STRING encoding: tag (0x04) + length + data
            if len(metadata_bytes) < 128:
                der_value = bytes([0x04, len(metadata_bytes)]) + metadata_bytes
            else:
                # For lengths >= 128, use long form
                length_bytes = len(metadata_bytes).to_bytes((len(metadata_bytes).bit_length() + 7) // 8, 'big')
                der_value = bytes([0x04, 0x80 | len(length_bytes)]) + length_bytes + metadata_bytes

            user_metadata = x509.UnrecognizedExtension(
                oid=x509.ObjectIdentifier("1.2.3.4.5"),  # Custom OID for user metadata
                value=der_value
            )
            cert_builder = cert_builder.add_extension(user_metadata, critical=False)

            # Sign certificate with CA key
            user_cert = cert_builder.sign(ca_private_key, hashes.SHA256(), default_backend())

            # Serialize certificate to PEM
            user_cert_pem = user_cert.public_bytes(serialization.Encoding.PEM).decode()

            # Serialize private key to PEM
            user_private_key_pem = user_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()

            # Get certificate serial
            cert_serial = f"{user_cert.serial_number:X}"

            # Vault key name pattern: user-identity-key-{user_id}-{engagement_id_or_internal}-{cert_purpose}
            vault_engagement_label = engagement_id if engagement_id else 'internal'
            vault_key_name = f"user-identity-key-{user_id}-{vault_engagement_label}-{cert_purpose}"

            # Store private key in vault first (before database insert)
            private_key_ref = None
            try:
                self.vault.set_key(
                    vault_key_name,
                    user_private_key_pem,
                    key_type="rsa-4096",
                    metadata={
                        "user_id": user_id,
                        "engagement_id": engagement_id,
                        "cert_purpose": cert_purpose,
                        "certificate_serial": cert_serial,
                        "issuing_ca": issuing_ca_name,
                        "issued_at": datetime.now(timezone.utc).isoformat()
                    }
                )
                private_key_ref = vault_key_name
                logger.info(f"Stored user {user_id} private key in vault: {vault_key_name}")
            except Exception as e:
                logger.error(f"Failed to store user {user_id} private key in vault: {e}")
                raise ValueError(f"Cannot proceed without vault storage: {e}")

            # Store certificate in database with vault reference
            conn.execute("""
                INSERT INTO user_digital_identities
                (user_id, engagement_id, cert_purpose, report_ref, validity_days,
                 certificate_pem, certificate_serial, public_key_pem, private_key_ref,
                 issued_at, expires_at, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id,
                engagement_id,
                cert_purpose,
                None,  # report_ref only used for report_viewer certs
                validity_days,
                user_cert_pem,
                cert_serial,
                user_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode(),
                private_key_ref,
                datetime.now(timezone.utc).isoformat(),
                (datetime.now(timezone.utc) + timedelta(days=validity_days)).isoformat(),
                'pending_p12_creation',
                datetime.now(timezone.utc).isoformat()
            ))
            conn.commit()
            self._log_audit_event(
                event_type="USER_CERTIFICATE_ISSUED",
                engagement_id=audit_engagement_id,
                details={
                    "user_id": user_id,
                    "username": username,
                    "role": role,
                    "serial": cert_serial,
                    "issuing_ca": issuing_ca_name
                }
            )

            return {
                "certificate_pem": user_cert_pem,
                "certificate_serial": cert_serial,
                "user_id": user_id,
                "issuing_ca": issuing_ca_name,
                "private_key_pem": user_private_key_pem,
                "status": "pending_p12_creation"
            }

        except Exception as e:
            logger.error(f"Error issuing user identity certificate: {e}")
            raise
        finally:
            conn.close()

    def issue_report_viewer_certificate(
        self,
        user_id: int,
        engagement_id: str,
        report_type: str,
        report_id: int,
        report_name: str,
        validity_days: int = 30
    ) -> Dict[str, Any]:
        """
        Issue short-lived report-viewer certificate for a single report.

        Args:
            user_id: User to issue cert for
            engagement_id: Engagement context
            report_type: 'scan' | 'reassessment' | 'aggregation'
            report_id: Report ID
            validity_days: Validity period (7/30/90 days)

        Returns:
            {
                'certificate_pem': PEM-formatted certificate,
                'certificate_serial': Serial number (hex),
                'public_key_pem': Public key in PEM format,
                'private_key_ref': Vault key reference,
                'issued_at': ISO timestamp,
                'expires_at': ISO timestamp,
                'username': User's username
            }
        """
        conn = self.database_service.get_connection()
        try:
            # Get user details
            user_row = conn.execute(
                "SELECT username FROM users WHERE id = ?",
                (user_id,)
            ).fetchone()

            if not user_row:
                raise ValueError(f"User {user_id} not found")

            username = user_row['username']
            report_ref = f'{report_type}:{report_id}'

            # Check for existing cert (idempotent)
            existing = conn.execute(
                """SELECT id, certificate_pem, certificate_serial, public_key_pem,
                    private_key_ref, issued_at, expires_at
                FROM user_digital_identities
                WHERE user_id = ? AND cert_purpose = ? AND report_ref = ? AND revoked_at IS NULL""",
                (user_id, 'report_viewer', report_ref)
            ).fetchone()

            if existing:
                logger.info(f"Reusing existing report_viewer cert for user {user_id}, report {report_ref}")
                return {
                    'certificate_pem': existing['certificate_pem'],
                    'certificate_serial': existing['certificate_serial'],
                    'public_key_pem': existing['public_key_pem'],
                    'private_key_ref': existing['private_key_ref'],
                    'issued_at': existing['issued_at'],
                    'expires_at': existing['expires_at'],
                    'username': username
                }

            # Get Engagement CA (issuer)
            ca_cert_row = conn.execute(
                """SELECT certificate_pem, private_key_ref FROM engagement_ca_certificates
                WHERE engagement_id = ? AND status = 'active' ORDER BY issued_at DESC LIMIT 1""",
                (engagement_id,)
            ).fetchone()

            if not ca_cert_row:
                raise ValueError(f"No CA certificate found for engagement {engagement_id}")

            ca_cert_pem = ca_cert_row['certificate_pem']
            ca_private_key_ref = ca_cert_row['private_key_ref']

            # Get CA private key from vault
            ca_key_obj = self.vault.get_key(ca_private_key_ref)
            if not ca_key_obj:
                raise ValueError(f"CA private key not found in vault: {ca_private_key_ref}")

            ca_key_pem = ca_key_obj['pem'] if isinstance(ca_key_obj, dict) else ca_key_obj

            # Load CA cert and key
            ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode(), default_backend())
            ca_key = serialization.load_pem_private_key(
                ca_key_pem.encode(), password=None, backend=default_backend()
            )

            # Generate user private key (RSA-4096 for short-lived cert)
            user_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )

            user_public_key = user_private_key.public_key()

            # Create certificate builder
            subject_cn = f"viewer:{username}:report:{report_name}"
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CAIP"),
            ])

            issuer = ca_cert.subject
            now = datetime.now(timezone.utc)
            expiry = now + timedelta(days=validity_days)

            cert_builder = x509.CertificateBuilder()
            cert_builder = cert_builder.subject_name(subject)
            cert_builder = cert_builder.issuer_name(issuer)
            cert_builder = cert_builder.public_key(user_public_key)
            cert_builder = cert_builder.serial_number(x509.random_serial_number())
            cert_builder = cert_builder.not_valid_before(now)
            cert_builder = cert_builder.not_valid_after(expiry)

            # Add extensions
            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName([x509.RFC822Name(username)]),
                critical=False
            )
            cert_builder = cert_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            cert_builder = cert_builder.add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False
            )

            # Sign certificate with CA key
            user_cert = cert_builder.sign(
                private_key=ca_key,
                algorithm=hashes.SHA256(),
                backend=default_backend()
            )

            # Serialize outputs
            user_cert_pem = user_cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
            user_public_key_pem = user_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            user_private_key_pem = user_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            # Get certificate serial in hex
            cert_serial = f"{user_cert.serial_number:X}"

            # Store private key in vault
            private_key_ref = f'report-viewer-key-{user_id}-{report_type}-{report_id}'
            self.vault.set_key(private_key_ref, user_private_key_pem)

            # Insert into database
            conn.execute("""
                INSERT INTO user_digital_identities
                (user_id, engagement_id, cert_purpose, report_ref, validity_days,
                 certificate_pem, certificate_serial, public_key_pem, private_key_ref,
                 issued_at, expires_at, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id, engagement_id, 'report_viewer', report_ref, validity_days,
                user_cert_pem, cert_serial, user_public_key_pem, private_key_ref,
                now.isoformat(), expiry.isoformat(),
                'pending_p12_creation',
                now.isoformat(), now.isoformat()
            ))

            conn.commit()

            logger.info(f"Issued report_viewer cert for user {user_id}, report {report_ref}, expires {expiry.isoformat()}")

            # Reload global vault instance to ensure in-memory cache stays synchronized
            try:
                from caip_service_layer.unified_vault_service import get_unified_vault_service
                global_vault = get_unified_vault_service()
                if global_vault and hasattr(global_vault, '_reload_vault'):
                    global_vault._reload_vault()
            except Exception as reload_err:
                logger.warning(f"Failed to reload global vault: {reload_err}")

            return {
                'certificate_pem': user_cert_pem,
                'certificate_serial': cert_serial,
                'public_key_pem': user_public_key_pem,
                'private_key_ref': private_key_ref,
                'issued_at': now.isoformat(),
                'expires_at': expiry.isoformat(),
                'username': username
            }

        except Exception as e:
            logger.error(f"Error issuing report_viewer certificate: {e}")
            raise
        finally:
            conn.close()

    def export_user_certificate_to_p12(
        self,
        user_id: int,
        p12_password: str,
        admin_user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Export user certificate and private key to PKCS#12 (P12) format.

        Creates an encrypted P12 file, stores it temporarily, and returns a secure download link.
        P12 file expires and is deleted after 24 hours.

        Args:
            user_id: User ID to export certificate for
            p12_password: Password to encrypt P12 file
            admin_user_id: Admin user ID initiating export (for audit trail)

        Returns:
            Dict with download_url, token, password_hint, expires_at, file_size
        """
        conn = self.database_service.get_connection()
        try:
            # Get user certificate from database
            cert_row = conn.execute("""
                SELECT certificate_pem, certificate_serial
                FROM user_digital_identities
                WHERE user_id = ? AND status = 'pending_p12_creation'
                ORDER BY created_at DESC LIMIT 1
            """, (user_id,)).fetchone()

            if not cert_row:
                raise ValueError(f"No pending certificate found for user {user_id}")

            cert_pem = cert_row['certificate_pem']
            cert_serial = cert_row['certificate_serial']

            # Get private key from vault
            vault_key_name = f"user_identity_private_key_{user_id}"
            key_obj = self.vault.get_key(vault_key_name)
            if not key_obj:
                raise ValueError(f"No private key found in vault for user {user_id}")

            key_pem = key_obj['pem'] if isinstance(key_obj, dict) else key_obj

            # Load certificate and key for P12 creation
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            private_key = serialization.load_pem_private_key(
                key_pem.encode(), password=None, backend=default_backend()
            )

            # Create PKCS#12 object
            p12 = crypto.PKCS12()
            p12.set_certificate(crypto.X509.from_cryptography(cert))
            p12.set_privatekey(crypto.PKey.from_cryptography_key(private_key))

            # Serialize to P12 format with password encryption
            p12_bytes = p12.export(p12_password.encode() if isinstance(p12_password, str) else p12_password)

            # Create temporary file in /tmp with secure random filename
            import secrets
            random_token = secrets.token_urlsafe(32)
            p12_filename = f"user_{user_id}_{random_token}.p12"
            p12_filepath = os.path.join(tempfile.gettempdir(), p12_filename)

            # Write P12 file
            with open(p12_filepath, 'wb') as f:
                f.write(p12_bytes)

            file_size = os.path.getsize(p12_filepath)

            # Create download record with token and expiry
            download_token = secrets.token_urlsafe(32)
            expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

            conn.execute("""
                INSERT INTO temp_p12_downloads
                (user_id, p12_file_path, download_token, p12_password, status,
                 expires_at, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id,
                p12_filepath,
                download_token,
                p12_password,
                'pending',
                expires_at.isoformat(),
                admin_user_id,
                datetime.now(timezone.utc).isoformat()
            ))

            # Update certificate status
            conn.execute(
                "UPDATE user_digital_identities SET status = 'pending_download' WHERE user_id = ? AND certificate_serial = ?",
                (user_id, cert_serial)
            )
            conn.commit()

            # Log audit event
            self._log_audit_event(
                event_type="P12_EXPORT_CREATED",
                details={
                    "user_id": user_id,
                    "admin_user_id": admin_user_id,
                    "certificate_serial": cert_serial,
                    "file_size": file_size
                }
            )

            return {
                "download_url": f"/api/v1/users/{user_id}/certificates/download/{download_token}",
                "download_token": download_token,
                "p12_password": p12_password,
                "expires_at": expires_at.isoformat(),
                "file_size": file_size
            }

        except Exception as e:
            logger.error(f"Error exporting certificate to P12: {e}")
            raise
        finally:
            conn.close()

    def rotate_user_identity_certificate(
        self,
        user_id: int,
        issuing_ca_engagement_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Rotate a user's identity certificate (mark old as revoked, issue new).

        Args:
            user_id: User ID to rotate certificate for
            issuing_ca_engagement_id: Optional engagement ID for new certificate issuer

        Returns:
            Dict with new certificate info (same format as issue_user_identity_certificate)
        """
        conn = self.database_service.get_connection()
        try:
            # Get current certificate (any non-revoked status)
            current_cert = conn.execute("""
                SELECT user_id, certificate_pem, certificate_serial
                FROM user_digital_identities
                WHERE user_id = ? AND status NOT IN ('revoked')
                ORDER BY created_at DESC LIMIT 1
            """, (user_id,)).fetchone()

            if not current_cert:
                raise ValueError(f"No certificate found for user {user_id} to rotate")

            # Mark old certificate as revoked
            conn.execute("""
                UPDATE user_digital_identities
                SET status = 'revoked', revoked_at = ?
                WHERE user_id = ? AND certificate_serial = ?
            """, (datetime.now(timezone.utc).isoformat(), user_id, current_cert['certificate_serial']))
            conn.commit()

            # Get user details for re-issuance
            user_row = conn.execute(
                "SELECT username FROM users WHERE id = ?",
                (user_id,)
            ).fetchone()

            if not user_row:
                raise ValueError(f"User {user_id} not found")

            # Issue new certificate with same subject but new key/serial
            result = self.issue_user_identity_certificate(
                user_id=user_id,
                username=user_row['username'],
                role='user',
                issuing_ca_engagement_id=issuing_ca_engagement_id
            )

            # Log audit event
            self._log_audit_event(
                event_type="CERTIFICATE_ROTATED",
                engagement_id=issuing_ca_engagement_id,
                details={
                    "user_id": user_id,
                    "old_serial": current_cert['certificate_serial'],
                    "new_serial": result['certificate_serial']
                }
            )

            return result

        except Exception as e:
            logger.error(f"Error rotating user certificate: {e}")
            raise
        finally:
            conn.close()

    def bulk_rotate_expired_certificates(
        self,
        issuing_ca_engagement_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Rotate all expired user identity certificates.

        Finds certificates with status='active' and expires_at < now, marks them as revoked,
        and issues new ones. Returns detailed results with success/failure per user.

        Args:
            issuing_ca_engagement_id: Optional engagement ID for new certificates

        Returns:
            Dict with rotated list, summary (total_expired, successfully_rotated, failed)
        """
        conn = self.database_service.get_connection()
        try:
            now = datetime.now(timezone.utc)

            # Find all expired active certificates
            expired_certs = conn.execute("""
                SELECT DISTINCT user_id
                FROM user_digital_identities
                WHERE status = 'active' AND datetime(expires_at) < datetime(?)
            """, (now.isoformat(),)).fetchall()

            rotated = []
            failed_count = 0

            for cert_row in expired_certs:
                user_id = cert_row['user_id']

                try:
                    result = self.rotate_user_identity_certificate(
                        user_id=user_id,
                        issuing_ca_engagement_id=issuing_ca_engagement_id
                    )

                    # Get user info for response
                    user_info = conn.execute(
                        "SELECT username FROM users WHERE id = ?",
                        (user_id,)
                    ).fetchone()

                    rotated.append({
                        "user_id": user_id,
                        "username": user_info['username'] if user_info else "Unknown",
                        "success": True,
                        "new_serial": result['certificate_serial'],
                        "issuing_ca": result['issuing_ca']
                    })

                except Exception as e:
                    logger.error(f"Failed to rotate certificate for user {user_id}: {e}")
                    rotated.append({
                        "user_id": user_id,
                        "success": False,
                        "error": str(e)
                    })
                    failed_count += 1

            # Log audit event
            self._log_audit_event(
                event_type="BULK_ROTATION_COMPLETED",
                engagement_id=issuing_ca_engagement_id,
                details={
                    "total_expired": len(expired_certs),
                    "successfully_rotated": len(expired_certs) - failed_count,
                    "failed": failed_count
                }
            )

            return {
                "rotated": rotated,
                "summary": {
                    "total_expired": len(expired_certs),
                    "successfully_rotated": len(expired_certs) - failed_count,
                    "failed": failed_count
                }
            }

        except Exception as e:
            logger.error(f"Error in bulk certificate rotation: {e}")
            raise
        finally:
            conn.close()

    def get_user_certificate_status(self, user_id: int) -> Dict[str, Any]:
        """
        Get current certificate status for a user (both identity and report viewer certs).

        Checks user_digital_identities and temp_p12_downloads tables to determine
        overall certificate and download status.

        Args:
            user_id: User ID to check

        Returns:
            Dict with identity_cert, report_viewer_certs, and download_info
        """
        conn = self.database_service.get_connection()
        try:
            now = datetime.now(timezone.utc)

            # Get latest identity certificate
            identity_row = conn.execute("""
                SELECT certificate_pem, certificate_serial, status, issued_at, expires_at
                FROM user_digital_identities
                WHERE user_id = ? AND cert_purpose = 'identity'
                ORDER BY created_at DESC LIMIT 1
            """, (user_id,)).fetchone()

            identity_cert = None
            if identity_row:
                expires_at = datetime.fromisoformat(identity_row['expires_at'].replace('Z', '+00:00'))
                days_until = (expires_at - now).days
                identity_cert = {
                    "has_certificate": True,
                    "status": identity_row['status'],
                    "serial": identity_row['certificate_serial'],
                    "issued_at": identity_row['issued_at'],
                    "expires_at": identity_row['expires_at'],
                    "days_until_expiry": days_until
                }
            else:
                identity_cert = {
                    "has_certificate": False,
                    "status": "no_cert",
                    "serial": None,
                    "issued_at": None,
                    "expires_at": None,
                    "days_until_expiry": None
                }

            # Get all report viewer certificates for this user
            report_viewer_rows = conn.execute("""
                SELECT id, certificate_serial, report_ref, status, issued_at, expires_at
                FROM user_digital_identities
                WHERE user_id = ? AND cert_purpose = 'report_viewer'
                ORDER BY created_at DESC
            """, (user_id,)).fetchall()

            report_viewer_certs = []
            for row in report_viewer_rows:
                expires_at = datetime.fromisoformat(row['expires_at'].replace('Z', '+00:00'))
                days_until = (expires_at - now).days
                report_viewer_certs.append({
                    "id": row['id'],
                    "serial": row['certificate_serial'],
                    "report_ref": row['report_ref'],
                    "status": row['status'],
                    "issued_at": row['issued_at'],
                    "expires_at": row['expires_at'],
                    "days_until_expiry": days_until
                })

            # Check for pending downloads (for identity cert)
            download_row = conn.execute("""
                SELECT download_token, expires_at, p12_password
                FROM temp_p12_downloads
                WHERE user_id = ? AND status IN ('pending', 'downloaded') AND p12_password IS NOT NULL
                ORDER BY created_at DESC LIMIT 1
            """, (user_id,)).fetchone()

            download_info = None
            if download_row:
                download_expires = datetime.fromisoformat(download_row['expires_at'].replace('Z', '+00:00'))
                if download_expires > now:
                    download_info = {
                        "download_url": f"/api/v1/users/{user_id}/certificates/download/{download_row['download_token']}",
                        "expires_at": download_row['expires_at'],
                        "hours_remaining": int((download_expires - now).total_seconds() / 3600)
                    }

            return {
                "identity_cert": identity_cert,
                "report_viewer_certs": report_viewer_certs,
                "download_info": download_info
            }

        except Exception as e:
            logger.error(f"Error getting certificate status: {e}")
            raise
        finally:
            conn.close()

    def revoke_user_certificate(self, user_id: int, reason: str = "User requested revocation") -> Dict[str, Any]:
        """
        Revoke a user's identity certificate.

        Marks the user's active certificate as 'revoked' and logs the revocation.

        Args:
            user_id: User ID to revoke certificate for
            reason: Reason for revocation (default: "User requested revocation")

        Returns:
            Dict with revoked_serial, revoked_at, previous_status
        """
        conn = self.database_service.get_connection()
        try:
            # Find the active (non-revoked) certificate
            cert_row = conn.execute("""
                SELECT certificate_serial, status, issued_at
                FROM user_digital_identities
                WHERE user_id = ? AND status NOT IN ('revoked')
                ORDER BY created_at DESC LIMIT 1
            """, (user_id,)).fetchone()

            if not cert_row:
                raise ValueError(f"No active certificate found for user {user_id} to revoke")

            cert_serial = cert_row['certificate_serial']
            previous_status = cert_row['status']
            now = datetime.now(timezone.utc)

            # Mark certificate as revoked
            conn.execute("""
                UPDATE user_digital_identities
                SET status = 'revoked', revoked_at = ?
                WHERE user_id = ? AND certificate_serial = ?
            """, (now.isoformat(), user_id, cert_serial))

            # Clear any pending P12 downloads for this certificate
            conn.execute("""
                UPDATE temp_p12_downloads
                SET p12_password = NULL, status = 'deleted', deleted_at = ?
                WHERE user_id = ? AND status IN ('pending', 'downloaded')
            """, (now.isoformat(), user_id))

            conn.commit()

            # Log audit event
            self._log_audit_event(
                event_type="USER_CERTIFICATE_REVOKED",
                details={
                    "user_id": user_id,
                    "certificate_serial": cert_serial,
                    "reason": reason,
                    "revoked_at": now.isoformat()
                }
            )

            logger.info(f"Revoked certificate {cert_serial} for user {user_id}: {reason}")

            return {
                "revoked_serial": cert_serial,
                "revoked_at": now.isoformat(),
                "previous_status": previous_status,
                "reason": reason
            }

        except Exception as e:
            logger.error(f"Error revoking user certificate: {e}")
            raise
        finally:
            conn.close()

    def generate_p12_with_password(
        self,
        user_id: int,
        engagement_id: str = None
    ) -> Dict[str, Any]:
        """
        Generate P12 file for user with secure random password.

        Returns P12 file and password for display to admin.
        Password should be communicated to recipient via separate secure channel.

        Args:
            user_id: User ID
            engagement_id: Optional engagement context

        Returns:
            {
                'username': user's username,
                'p12_bytes': raw P12 file bytes,
                'p12_password': password (show to admin once),
                'expires_at': certificate expiry timestamp
            }
        """
        conn = self.database_service.get_connection()
        try:
            # Get user and certificate
            user_row = conn.execute(
                "SELECT username FROM users WHERE id = ?",
                (user_id,)
            ).fetchone()

            if not user_row:
                raise ValueError(f"User {user_id} not found")

            username = user_row['username']

            # Get most recent report_viewer cert (prefer over identity certs)
            cert_row = conn.execute("""
                SELECT certificate_pem, private_key_ref, expires_at
                FROM user_digital_identities
                WHERE user_id = ? AND revoked_at IS NULL
                ORDER BY CASE WHEN cert_purpose='report_viewer' THEN 0 ELSE 1 END ASC,
                         issued_at DESC LIMIT 1
            """, (user_id,)).fetchone()

            if not cert_row or not cert_row['private_key_ref']:
                raise ValueError(f"No valid certificate found for user {user_id}")

            cert_pem = cert_row['certificate_pem']
            private_key_ref = cert_row['private_key_ref']
            expires_at = cert_row['expires_at']

            # Get private key from vault
            key_obj = self.vault.get_key(private_key_ref)
            if not key_obj:
                raise ValueError(f"Private key not found in vault: {private_key_ref}")

            key_pem = key_obj['pem'] if isinstance(key_obj, dict) else key_obj

            # Generate random P12 password
            import secrets
            p12_password = secrets.token_urlsafe(20)

            # Load certificate and key
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            private_key = serialization.load_pem_private_key(
                key_pem.encode(), password=None, backend=default_backend()
            )

            # Create PKCS#12 object
            p12 = crypto.PKCS12()
            p12.set_certificate(crypto.X509.from_cryptography(cert))
            p12.set_privatekey(crypto.PKey.from_cryptography_key(private_key))

            # Serialize to P12 format with password
            p12_bytes = p12.export(p12_password.encode())

            logger.info(f"Generated P12 for user {user_id} ({username})")

            return {
                'username': username,
                'p12_bytes': p12_bytes,
                'p12_password': p12_password,
                'expires_at': expires_at
            }

        except Exception as e:
            logger.error(f"Error generating P12 for user {user_id}: {e}")
            raise
        finally:
            conn.close()

    def cleanup_expired_report_viewer_certs(self) -> Dict[str, Any]:
        """
        Find and cleanup expired report_viewer certificates.

        Runs periodically (e.g., every 6 hours) to:
        - Find certs with cert_purpose='report_viewer' and expires_at < NOW
        - Delete private keys from vault
        - Mark certs as revoked (soft delete)
        - Clean up associated P12 downloads

        Returns:
            Dict with cleanup stats (deleted_count, vault_keys_deleted, errors)
        """
        conn = self.database_service.get_connection()
        try:
            now = datetime.now(timezone.utc)
            deleted_count = 0
            vault_deleted = 0
            errors = 0

            # Find expired report_viewer certs
            expired = conn.execute("""
                SELECT id, user_id, report_ref, private_key_ref
                FROM user_digital_identities
                WHERE cert_purpose = 'report_viewer'
                AND expires_at < ?
                AND revoked_at IS NULL
            """, (now.isoformat(),)).fetchall()

            for cert in expired:
                try:
                    # Delete from vault
                    if cert['private_key_ref']:
                        try:
                            self.vault.delete_key(cert['private_key_ref'])
                            vault_deleted += 1
                        except Exception as e:
                            logger.warning(f"Failed to delete vault key {cert['private_key_ref']}: {e}")

                    # Mark as revoked in database (soft delete)
                    conn.execute("""
                        UPDATE user_digital_identities
                        SET revoked_at = ?, revocation_reason = ?, private_key_ref = NULL
                        WHERE id = ?
                    """, (now.isoformat(), 'Automatic expiry cleanup', cert['id']))

                    # Delete temp P12 downloads for this user
                    conn.execute("""
                        DELETE FROM temp_p12_downloads
                        WHERE user_id = ? AND expires_at < ?
                    """, (cert['user_id'], now.isoformat()))

                    deleted_count += 1
                    logger.info(f"Cleaned up expired report_viewer cert for user {cert['user_id']}, report {cert['report_ref']}")

                except Exception as e:
                    logger.error(f"Error cleaning up cert {cert['id']}: {e}")
                    errors += 1

            conn.commit()

            return {
                'deleted_count': deleted_count,
                'vault_keys_deleted': vault_deleted,
                'errors': errors
            }

        except Exception as e:
            logger.error(f"Cleanup expired report_viewer certs failed: {e}")
            raise
        finally:
            conn.close()

    def get_p12_download_info(self, user_id: int, download_token: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve P12 download info and password (within 24 hours).

        Args:
            user_id: User ID
            download_token: Download token for the P12 file

        Returns:
            Dict with download_url, p12_password, expires_at, hours_remaining, or None if expired
        """
        conn = self.database_service.get_connection()
        try:
            download_row = conn.execute("""
                SELECT download_token, p12_password, expires_at, p12_file_path
                FROM temp_p12_downloads
                WHERE user_id = ? AND download_token = ? AND status IN ('pending', 'downloaded')
            """, (user_id, download_token)).fetchone()

            if not download_row:
                logger.warning(f"P12 download not found for user {user_id} token {download_token}")
                return None

            now = datetime.now(timezone.utc)
            expires_at = datetime.fromisoformat(download_row['expires_at'].replace('Z', '+00:00'))

            if expires_at < now:
                logger.warning(f"P12 download expired for user {user_id}")
                return None

            return {
                "download_url": f"/api/v1/users/{user_id}/certificates/download/{download_token}",
                "p12_password": download_row['p12_password'],
                "expires_at": download_row['expires_at'],
                "hours_remaining": int((expires_at - now).total_seconds() / 3600),
                "file_exists": os.path.exists(download_row['p12_file_path']) if download_row['p12_file_path'] else False
            }

        except Exception as e:
            logger.error(f"Error getting P12 download info: {e}")
            return None
        finally:
            conn.close()

    def cleanup_expired_p12_files(self) -> Dict[str, Any]:
        """
        Clean up expired P12 download records and delete temporary files.

        Runs periodically (e.g., hourly) to remove:
        - P12 files from /tmp that are older than 24 hours
        - Database records with expired tokens
        - Clear passwords from database after deletion

        Returns:
            Dict with cleanup stats (files_deleted, records_deleted, errors)
        """
        conn = self.database_service.get_connection()
        try:
            now = datetime.now(timezone.utc)
            files_deleted = 0
            records_deleted = 0
            errors = []

            # Find expired download records
            expired_records = conn.execute("""
                SELECT id, p12_file_path, download_token, user_id
                FROM temp_p12_downloads
                WHERE datetime(expires_at) < datetime(?)
            """, (now.isoformat(),)).fetchall()

            for record in expired_records:
                try:
                    # Delete P12 file from disk
                    if record['p12_file_path'] and os.path.exists(record['p12_file_path']):
                        os.remove(record['p12_file_path'])
                        files_deleted += 1
                        logger.info(f"Deleted P12 file: {record['p12_file_path']}")
                except Exception as e:
                    error_msg = f"Failed to delete P12 file for user {record['user_id']}: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)

                try:
                    # Delete database record and clear password
                    conn.execute("""
                        UPDATE temp_p12_downloads
                        SET p12_password = NULL, status = 'deleted', deleted_at = ?
                        WHERE id = ?
                    """, (now.isoformat(), record['id']))
                    records_deleted += 1
                    logger.info(f"Deleted P12 download record for user {record['user_id']} token {record['download_token']}")
                except Exception as e:
                    error_msg = f"Failed to delete P12 record {record['id']}: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)

            conn.commit()

            logger.info(f"P12 cleanup complete: {files_deleted} files deleted, {records_deleted} records marked deleted")

            return {
                "status": "success" if not errors else "partial",
                "files_deleted": files_deleted,
                "records_deleted": records_deleted,
                "errors": errors
            }

        except Exception as e:
            logger.error(f"Error during P12 cleanup: {e}")
            return {
                "status": "failed",
                "files_deleted": 0,
                "records_deleted": 0,
                "errors": [str(e)]
            }
        finally:
            conn.close()

    # =========================================================================
    # UTILITY METHODS
    # =========================================================================

    def _get_ca_private_key(self, engagement_id: str) -> str:
        """Get CA private key for an engagement from vault."""
        # Resolve numeric ID if engagement_id is text
        numeric_id = engagement_id
        try:
            int_check = int(engagement_id)
        except (ValueError, TypeError):
            # It's text engagement_id, need to look up numeric ID
            conn = self.database_service.get_connection()
            try:
                row = conn.execute(
                    "SELECT id FROM engagements WHERE engagement_id = ?",
                    (engagement_id,)
                ).fetchone()
                if not row:
                    raise ValueError(f"No engagement found with engagement_id {engagement_id}")
                numeric_id = row['id']
            finally:
                conn.close()

        # Retrieve from vault
        from caip_service_layer.unified_vault_service import get_unified_vault_service
        vault = get_unified_vault_service()
        if not vault:
            raise RuntimeError("Vault service is required to retrieve CA private keys")

        vault_key_name = f"engagement-ca-key-{numeric_id}"
        logger.info(f"[KEY RETRIEVAL] Retrieving key from vault: {vault_key_name}")
        key_obj = vault.get_key(vault_key_name)
        if not key_obj:
            raise ValueError(f"No private key found in vault for engagement {engagement_id}")

        pem_key = key_obj['pem'] if isinstance(key_obj, dict) else key_obj

        # DIAGNOSTIC LOGGING
        logger.info(f"[KEY RETRIEVAL] Key object retrieved successfully")
        logger.info(f"[KEY RETRIEVAL] Key type: {type(pem_key).__name__}")
        logger.info(f"[KEY RETRIEVAL] Key length: {len(pem_key)} bytes")
        logger.info(f"[KEY RETRIEVAL] First 100 chars: {repr(pem_key[:100])}")
        logger.info(f"[KEY RETRIEVAL] Last 100 chars: {repr(pem_key[-100:])}")
        logger.info(f"[KEY RETRIEVAL] Newline count (\\n): {pem_key.count(chr(10))}")
        logger.info(f"[KEY RETRIEVAL] Literal backslash-n count (\\\\n as string): {pem_key.count(r'\\n')}")
        logger.info(f"[KEY RETRIEVAL] Contains 'BEGIN PRIVATE KEY': {'BEGIN PRIVATE KEY' in pem_key}")
        logger.info(f"[KEY RETRIEVAL] Contains 'END PRIVATE KEY': {'END PRIVATE KEY' in pem_key}")

        return pem_key

    def _get_cert_subject_string(self, cert_or_name) -> str:
        """Convert certificate or name to string representation."""
        try:
            if isinstance(cert_or_name, x509.Certificate):
                name = cert_or_name.subject
            elif isinstance(cert_or_name, x509.Name):
                name = cert_or_name
            else:
                return str(cert_or_name)

            parts = []
            for attr in name:
                parts.append(f"{attr.oid._name}={attr.value}")

            return ", ".join(parts)
        except Exception as e:
            logger.error(f"Error getting subject string: {e}")
            return "Unknown"

    def _get_cert_thumbprint(self, cert_pem: str) -> str:
        """Get SHA256 thumbprint of certificate."""
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            thumbprint = hashlib.sha256(cert_der).hexdigest()
            return thumbprint.upper()
        except Exception as e:
            logger.error(f"Error getting thumbprint: {e}")
            return "UNKNOWN"

    def _log_audit_event(
        self,
        event_type: str,
        collector_id: str = None,
        engagement_id: str = None,
        details: Dict = None
    ):
        """Log certificate event to audit log."""
        conn = self.database_service.get_connection()
        try:
            conn.execute("""
                INSERT INTO certificate_audit_log
                (event_type, collector_id, engagement_id, details, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (
                event_type,
                collector_id,
                engagement_id,
                json.dumps(details or {}),
                datetime.now(timezone.utc).isoformat()
            ))
            conn.commit()
        finally:
            conn.close()

    def _serialize_certificate(self, cert: x509.Certificate) -> str:
        """
        Serialize X.509 certificate to PEM format.

        Args:
            cert: X.509 certificate object

        Returns:
            PEM-formatted certificate string
        """
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    def _serialize_private_key(self, private_key) -> str:
        """
        Serialize private key to PEM format (TraditionalOpenSSL for OpenSSL 3.x compatibility).

        Args:
            private_key: RSA private key object

        Returns:
            PEM-formatted private key string
        """
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

    def _serialize_public_key(self, public_key) -> str:
        """
        Serialize public key to PEM format.

        Args:
            public_key: RSA public key object

        Returns:
            PEM-formatted public key string
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def _get_private_key_from_vault(self, key_name: str) -> str:
        """
        Get private key from vault (vault first, then database fallback).

        Args:
            key_name: Vault key name (e.g., "internal_ca_private_key", "engagement-ca-key-ENG-001")

        Returns:
            Private key in PEM format

        Raises:
            ValueError: If key not found in vault or database
        """
        from caip_service_layer.unified_vault_service import get_unified_vault_service

        # Try vault first (PRIMARY)
        try:
            vault = get_unified_vault_service()
            if vault:
                key_pem = vault.get_key_pem(key_name)
                if key_pem:
                    logger.info(f"✓ Retrieved {key_name} from vault (PRIMARY)")
                    return key_pem
        except Exception as e:
            logger.debug(f"Failed to retrieve {key_name} from vault: {e}")

        # Fall back to database (for backward compatibility with Internal CA)
        try:
            conn = self.database_service.get_connection()
            row = conn.execute(
                "SELECT ca_private_key_encrypted FROM internal_ca WHERE status = 'active' LIMIT 1"
            ).fetchone()
            conn.close()

            if row and row['ca_private_key_encrypted']:
                key_data = row['ca_private_key_encrypted']
                if not key_data.startswith('-----BEGIN'):
                    key_data = base64.b64decode(key_data).decode('utf-8')
                logger.warning(f"⚠ Retrieved {key_name} from database (FALLBACK)")
                return key_data
        except Exception as e:
            logger.debug(f"Database fallback failed: {e}")

        raise ValueError(f"Private key '{key_name}' not found in vault or database")

    def encrypt_report_data(
        self,
        report_data: Dict[str, Any],
        recipient_user_ids: List[int],
        engagement_id: str
    ) -> Dict[str, Dict]:
        """
        Encrypt entire JSON report using hybrid encryption (AES-256-GCM + RSA-OAEP-SHA256).

        Phase 4: Full payload encryption - entire report encrypted before signing.

        Uses hybrid encryption:
        - Generate random AES-256 key
        - Encrypt report JSON with AES-256-GCM
        - Encrypt AES key with RSA-OAEP for each recipient

        Args:
            report_data: Complete report as dictionary
            recipient_user_ids: List of user IDs who will receive encrypted blobs
            engagement_id: Engagement context for logging

        Returns:
            Dictionary mapping username -> {encrypted_aes_key, encrypted_report, iv, tag}

        Raises:
            ValueError: If public key not found for recipient
            Exception: If encryption fails
        """
        try:
            import os
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            # Convert report to deterministic JSON for consistent encryption
            report_json = json.dumps(report_data, sort_keys=True).encode('utf-8')
            logger.info(f"Report encryption: Converting {len(report_json)} bytes to encrypted blobs for {len(recipient_user_ids)} recipients")

            # Generate random AES-256 key (used once for all recipients)
            aes_key = os.urandom(32)
            aes_iv = os.urandom(12)

            # Encrypt report once with AES-256-GCM
            cipher = AESGCM(aes_key)
            encrypted_report = cipher.encrypt(aes_iv, report_json, None)

            encrypted_blobs = {}

            for user_id in recipient_user_ids:
                try:
                    # Get user's public key from most recent non-revoked certificate
                    # Prefer report_viewer certs (short-lived) over identity certs
                    conn = self.database_service.get_connection()
                    user_cert = conn.execute('''
                        SELECT certificate_serial, public_key_pem,
                               (SELECT username FROM users WHERE id=?) as username
                        FROM user_digital_identities
                        WHERE user_id = ? AND revoked_at IS NULL
                        ORDER BY CASE WHEN cert_purpose='report_viewer' THEN 0 ELSE 1 END ASC,
                                 issued_at DESC LIMIT 1
                    ''', (user_id, user_id)).fetchone()
                    conn.close()

                    if not user_cert or not user_cert['public_key_pem']:
                        logger.warning(f"No valid public key found for user_id {user_id}")
                        continue

                    username = user_cert['username']

                    # Load public key from PEM
                    public_key = serialization.load_pem_public_key(
                        user_cert['public_key_pem'].encode('utf-8'),
                        backend=default_backend()
                    )

                    # Encrypt AES key with RSA-OAEP-SHA256 for this recipient
                    encrypted_aes_key = public_key.encrypt(
                        aes_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )

                    # Build encrypted blob structure
                    encrypted_blobs[username] = {
                        'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
                        'encrypted_report': base64.b64encode(encrypted_report).decode('utf-8'),
                        'iv': base64.b64encode(aes_iv).decode('utf-8'),
                        'tag': 'aes-256-gcm'
                    }

                    logger.info(f"Encrypted report for {username} (user_id {user_id}): hybrid encryption succeeded")

                except Exception as e:
                    logger.error(f"Failed to encrypt report for user_id {user_id}: {e}")
                    # Continue with next recipient (graceful degradation)
                    continue

            if not encrypted_blobs:
                raise ValueError(f"Failed to encrypt report for any of {len(recipient_user_ids)} recipients")

            logger.info(f"Report encryption complete: {len(encrypted_blobs)} recipients encrypted successfully")
            return encrypted_blobs

        except Exception as e:
            logger.error(f"Report encryption failed: {e}")
            raise

    def sign_encrypted_blob(
        self,
        encrypted_blob_b64: str,
        engagement_id: str,
        user_id: int,
        report_id: int,
        report_type: str
    ) -> Dict[str, Any]:
        """
        Sign encrypted report blob using Report Signing Certificate (RSA-PSS-SHA256).

        Phase 4: Sign the encrypted payload (not plaintext).
        Signature proves authenticity and tampering protection of encrypted data.

        Args:
            encrypted_blob_b64: Base64-encoded encrypted report
            engagement_id: Engagement context
            user_id: User who initiated report generation
            report_id: Report record ID
            report_type: Type of report ('pki', 'pqc', 'aggregation')

        Returns:
            Dictionary with:
            - signature: Base64-encoded signature
            - signature_algorithm: 'RSA-PSS-SHA256'
            - certificate_pem: Signing certificate in PEM format
            - certificate_serial: Certificate serial number
            - signed_timestamp: ISO8601 timestamp
            - metadata: Additional context (user, report info, etc.)

        Raises:
            ValueError: If signing certificate or key not found
            Exception: If signing operation fails
        """
        try:
            logger.info(f"Signing encrypted blob for report {report_id} (type: {report_type})")

            # Decode base64 blob to bytes
            encrypted_blob_bytes = base64.b64decode(encrypted_blob_b64.encode('utf-8'))

            # Get Report Signing Certificate for engagement and numeric engagement ID
            conn = self.database_service.get_connection()
            signing_cert_row = conn.execute('''
                SELECT id, certificate_pem, certificate_serial, public_key_pem
                FROM report_signing_certificates
                WHERE engagement_id = ? AND status = 'active'
                ORDER BY issued_at DESC LIMIT 1
            ''', (engagement_id,)).fetchone()

            if not signing_cert_row:
                conn.close()
                raise ValueError(f"No valid Report Signing Certificate found for engagement {engagement_id}")

            # Look up numeric engagement ID
            numeric_engagement_id = conn.execute(
                "SELECT id FROM engagements WHERE engagement_id = ?",
                (engagement_id,)
            ).fetchone()
            conn.close()

            if not numeric_engagement_id:
                raise ValueError(f"Engagement {engagement_id} not found")

            numeric_id = numeric_engagement_id['id']
            signing_cert_pem = signing_cert_row['certificate_pem']
            cert_serial = signing_cert_row['certificate_serial']

            # Get private key from vault using numeric ID (matches how it was stored)
            vault_key_name = f'report-signing-key-{numeric_id}'
            private_key_pem = self._get_private_key_from_vault(vault_key_name)

            # Load private key
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )

            # Sign encrypted blob with RSA-PSS-SHA256 (32-byte salt)
            signature_bytes = private_key.sign(
                encrypted_blob_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=32
                ),
                hashes.SHA256()
            )

            # Base64 encode signature
            signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')

            # Build metadata
            signed_at = datetime.now(timezone.utc).isoformat()
            metadata = {
                'signed_by_user_id': user_id,
                'report_id': report_id,
                'report_type': report_type,
                'engagement_id': engagement_id,
                'signed_at': signed_at,
                'signature_algorithm': 'RSA-PSS-SHA256',
                'salt_length_bytes': 32
            }

            # Log signing operation
            logger.info(f"Encrypted blob signed: {len(signature_bytes)} signature bytes, cert serial {cert_serial}")

            return {
                'signature': signature_b64,
                'signature_algorithm': 'RSA-PSS-SHA256',
                'certificate_pem': signing_cert_pem,
                'certificate_serial': cert_serial,
                'signed_timestamp': signed_at,
                'metadata': metadata
            }

        except Exception as e:
            logger.error(f"Failed to sign encrypted blob: {e}")
            raise

    def _insert_certificate(self, table: str, data: Dict[str, Any]):
        """
        Generic certificate insertion helper.

        Args:
            table: Table name (engagement_ca_certificates, report_signing_certificates, etc.)
            data: Dict of column -> value pairs to insert

        Raises:
            Exception: If insertion fails
        """
        columns = ', '.join(data.keys())
        placeholders = ', '.join(['?' for _ in data])
        values = tuple(data.values())

        conn = self.database_service.get_connection()
        try:
            conn.execute(f'''
                INSERT INTO {table} ({columns})
                VALUES ({placeholders})
            ''', values)
            conn.commit()
            logger.info(f"✓ Inserted certificate into {table}")
        finally:
            conn.close()
