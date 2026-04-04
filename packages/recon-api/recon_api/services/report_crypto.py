"""
ReportCryptoService — hybrid encryption and RSA-PSS signing for reports.

CRITICAL: All crypto parameters are ported exactly from the legacy system.
Changing any parameter breaks compatibility with distributed reports.

Parameters (immutable):
  Payload encryption:   AES-256-GCM (AESGCM)
  Symmetric key size:   32 bytes (os.urandom(32))
  GCM nonce/IV:         12 bytes (os.urandom(12))
  GCM AAD:              None
  Key wrapping:         RSA-OAEP (MGF1-SHA256, SHA256, label=None)
  RSA key size:         4096-bit recipient key
  Signing algorithm:    RSA-PSS (MGF1-SHA256, salt_length=32)
  PSS salt length:      32 bytes — NOT PSS.AUTO
"""
from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from typing import Any

import asyncpg
import structlog
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = structlog.get_logger("recon.report_crypto")


class ReportCryptoService:
    def __init__(self, db: asyncpg.Connection) -> None:
        self._db = db

    # ── Encryption ────────────────────────────────────────────

    async def encrypt_report_data(
        self,
        report_data: dict,
        recipient_user_ids: list[str],
        project_id: str,
    ) -> dict:
        """
        Encrypt report JSON for multiple recipients using hybrid encryption.

        AES-256-GCM encrypts the report once. Each recipient's RSA-4096
        public key wraps the AES key via RSA-OAEP.
        """
        # 1. Serialise report to JSON
        report_json = json.dumps(report_data, sort_keys=True).encode("utf-8")

        # 2. Generate single random AES-256 key and 12-byte nonce
        aes_key = os.urandom(32)
        aes_iv = os.urandom(12)

        # 3. Encrypt report once with AES-256-GCM, no AAD
        cipher = AESGCM(aes_key)
        encrypted_report = cipher.encrypt(aes_iv, report_json, None)

        # 4. For each recipient: RSA-OAEP wrap the AES key
        encrypted_blobs: dict[str, dict] = {}
        for user_id in recipient_user_ids:
            row = await self._db.fetchrow(
                """SELECT udi.public_key_pem, u.username
                   FROM user_digital_identities udi
                   JOIN users u ON u.id = udi.user_id
                   WHERE udi.user_id = $1 AND udi.project_id = $2
                     AND udi.revoked_at IS NULL
                   ORDER BY
                     CASE WHEN udi.cert_purpose='report_viewer'
                          THEN 0 ELSE 1 END ASC,
                     udi.issued_at DESC
                   LIMIT 1""",
                user_id, project_id,
            )
            if not row:
                logger.warning("no_viewer_cert", user_id=user_id)
                continue

            public_key = serialization.load_pem_public_key(
                row["public_key_pem"].encode()
            )
            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            username = row["username"]
            encrypted_blobs[username] = {
                "encrypted_aes_key": base64.b64encode(
                    encrypted_aes_key
                ).decode("utf-8"),
                "encrypted_report": base64.b64encode(
                    encrypted_report
                ).decode("utf-8"),
                "iv": base64.b64encode(aes_iv).decode("utf-8"),
                "tag": "aes-256-gcm",
            }

        if not encrypted_blobs:
            raise ValueError(
                f"Failed to encrypt for any of "
                f"{len(recipient_user_ids)} recipients"
            )

        logger.info("report_encrypted",
                     recipients=len(encrypted_blobs),
                     project_id=project_id)
        return encrypted_blobs

    # ── Signing ───────────────────────────────────────────────

    async def sign_encrypted_blob(
        self,
        encrypted_blobs: dict,
        project_id: str,
        report_id: str,
        report_type: str,
        signed_by_user_id: str,
    ) -> dict:
        """
        Sign the encrypted blobs dict with RSA-PSS-SHA256.

        Uses the project's signing certificate. salt_length=32 (not AUTO).
        """
        from recon_api.services.certificate import CertificateService

        cert_svc = CertificateService(self._db, None)
        cert_pem, private_key_pem, cert_serial = \
            await cert_svc.load_project_signing_cert(project_id)

        # Serialise → base64 → bytes (matching legacy exactly)
        encrypted_blobs_json = json.dumps(encrypted_blobs)
        encrypted_blobs_b64 = base64.b64encode(
            encrypted_blobs_json.encode("utf-8")
        ).decode("utf-8")
        encrypted_blob_bytes = base64.b64decode(
            encrypted_blobs_b64.encode("utf-8")
        )

        # Sign with RSA-PSS-SHA256, salt_length=32
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"), password=None,
        )
        signature_bytes = private_key.sign(
            encrypted_blob_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32,
            ),
            hashes.SHA256(),
        )
        signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")

        signed_at = datetime.now(timezone.utc).isoformat()

        logger.info("report_signed",
                     project_id=project_id, report_id=report_id,
                     cert_serial=cert_serial[:16])

        return {
            "signature": signature_b64,
            "signature_algorithm": "RSA-PSS-SHA256",
            "certificate_pem": cert_pem,
            "certificate_serial": cert_serial,
            "signed_timestamp": signed_at,
            "metadata": {
                "signed_by_user_id": signed_by_user_id,
                "report_id": report_id,
                "report_type": report_type,
                "project_id": project_id,
                "signed_at": signed_at,
                "signature_algorithm": "RSA-PSS-SHA256",
                "salt_length_bytes": 32,
            },
        }

    # ── Signature verification ────────────────────────────────

    @staticmethod
    def verify_signature(
        encrypted_blobs: dict,
        signing_result: dict,
    ) -> bool:
        """
        Verify RSA-PSS signature over the encrypted blobs.

        Returns True if valid, False if signature is invalid.
        Other exceptions propagate.
        """
        # Reconstruct signed bytes (same serialisation as sign)
        encrypted_blobs_json = json.dumps(encrypted_blobs)
        encrypted_blobs_b64 = base64.b64encode(
            encrypted_blobs_json.encode("utf-8")
        ).decode("utf-8")
        signed_bytes = base64.b64decode(
            encrypted_blobs_b64.encode("utf-8")
        )

        # Extract public key from signing certificate PEM
        cert_pem = signing_result["certificate_pem"]
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        public_key = cert.public_key()

        # Verify RSA-PSS signature
        signature = base64.b64decode(
            signing_result["signature"].encode("utf-8")
        )
        try:
            public_key.verify(
                signature,
                signed_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=32,
                ),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            return False

    # ── Test helper: decrypt ──────────────────────────────────

    @staticmethod
    def decrypt_report_for_testing(
        encrypted_blobs: dict,
        username: str,
        private_key_pem: str,
    ) -> dict:
        """
        Decrypt a report blob for testing the round-trip.

        Not used in production — clients decrypt client-side with forge.js.
        """
        blob = encrypted_blobs[username]
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(), password=None,
        )

        # RSA-OAEP unwrap the AES key
        aes_key = private_key.decrypt(
            base64.b64decode(blob["encrypted_aes_key"]),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # AES-256-GCM decrypt
        iv = base64.b64decode(blob["iv"])
        ciphertext = base64.b64decode(blob["encrypted_report"])
        cipher = AESGCM(aes_key)
        plaintext = cipher.decrypt(iv, ciphertext, None)

        return json.loads(plaintext.decode("utf-8"))
