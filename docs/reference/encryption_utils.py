"""
Native AES-256-GCM Encryption Utilities

Provides self-contained encryption/decryption without external tools.
Replaces age CLI dependency with native Python cryptography.

Supports two unlock methods:
1. Passphrase-based: Uses PBKDF2-SHA256 for key derivation
2. Key-file-based: Reads encryption key from file (256-bit key)

File Format (JSON):
{
    "version": 1,
    "algorithm": "AES-256-GCM",
    "kdf": "PBKDF2-SHA256",
    "kdf_iterations": 100000,
    "salt": "<base64-encoded-salt>",
    "nonce": "<base64-encoded-nonce>",
    "ciphertext": "<base64-encoded-ciphertext>",
    "tag": "<base64-encoded-auth-tag>"
}
"""

import json
import os
import base64
import logging
from typing import Dict, Tuple, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger('caip.operational')

# Encryption constants
ALGORITHM = 'AES-256-GCM'
KDF_ALGORITHM = 'PBKDF2-SHA256'
KDF_ITERATIONS = 100000
SALT_LENGTH = 16  # 128 bits
NONCE_LENGTH = 12  # 96 bits (recommended for GCM)
KEY_LENGTH = 32  # 256 bits


class EncryptionError(Exception):
    """Base encryption error."""
    pass


class DecryptionError(EncryptionError):
    """Decryption failed."""
    pass


class KeyDerivationError(EncryptionError):
    """Key derivation failed."""
    pass


def derive_key_from_passphrase(passphrase: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """
    Derive encryption key from passphrase using PBKDF2-SHA256.

    Args:
        passphrase: User-provided passphrase
        salt: Optional salt bytes. If None, generates random salt.

    Returns:
        Tuple of (derived_key, salt)
    """
    try:
        if not passphrase:
            raise KeyDerivationError("Passphrase cannot be empty")

        # Generate salt if not provided
        if salt is None:
            salt = os.urandom(SALT_LENGTH)

        # Derive key using PBKDF2-SHA256
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=KDF_ITERATIONS,
            backend=default_backend()
        )

        key = kdf.derive(passphrase.encode('utf-8'))
        return key, salt

    except Exception as e:
        raise KeyDerivationError(f"Failed to derive key from passphrase: {e}")


def load_key_from_file(key_file_path: str) -> bytes:
    """
    Load encryption key from file.

    Key file should contain a 256-bit (32 byte) key in one of these formats:
    - Raw binary (32 bytes)
    - Hex-encoded (64 hex characters)
    - Base64-encoded (44 characters with padding)

    Args:
        key_file_path: Path to key file

    Returns:
        32-byte encryption key
    """
    try:
        if not os.path.exists(key_file_path):
            raise FileNotFoundError(f"Key file not found: {key_file_path}")

        with open(key_file_path, 'rb') as f:
            key_data = f.read()

        # Try to detect format
        if len(key_data) == KEY_LENGTH:
            # Raw binary format
            return key_data

        # Try hex decoding
        try:
            hex_key = key_data.decode('utf-8').strip()
            if len(hex_key) == KEY_LENGTH * 2:
                return bytes.fromhex(hex_key)
        except (ValueError, UnicodeDecodeError):
            pass

        # Try base64 decoding
        try:
            b64_key = key_data.decode('utf-8').strip()
            decoded = base64.b64decode(b64_key)
            if len(decoded) == KEY_LENGTH:
                return decoded
        except (ValueError, UnicodeDecodeError):
            pass

        raise ValueError(f"Key file must contain 256-bit (32-byte) key in raw, hex, or base64 format")

    except Exception as e:
        raise KeyDerivationError(f"Failed to load key from file: {e}")


def encrypt_content(content: str, key: bytes) -> Dict[str, str]:
    """
    Encrypt content using AES-256-GCM.

    Args:
        content: Plaintext content to encrypt
        key: 256-bit encryption key

    Returns:
        Dictionary with encrypted vault metadata and ciphertext
    """
    try:
        if not key or len(key) != KEY_LENGTH:
            raise EncryptionError(f"Key must be exactly {KEY_LENGTH} bytes")

        # Generate random nonce (IV)
        nonce = os.urandom(NONCE_LENGTH)

        # Create cipher
        cipher = AESGCM(key)

        # Encode content
        plaintext = content.encode('utf-8')

        # Encrypt
        ciphertext = cipher.encrypt(nonce, plaintext, None)

        # In GCM, the last 16 bytes are the authentication tag
        # Extract tag and ciphertext
        tag = ciphertext[-16:]
        actual_ciphertext = ciphertext[:-16]

        # Build encrypted vault structure
        encrypted_vault = {
            'version': 1,
            'algorithm': ALGORITHM,
            'kdf': KDF_ALGORITHM,
            'kdf_iterations': KDF_ITERATIONS,
            'salt': base64.b64encode(b'').decode('utf-8'),  # Empty for key-file, filled by caller for passphrase
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(actual_ciphertext).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8')
        }

        return encrypted_vault

    except EncryptionError:
        raise
    except Exception as e:
        raise EncryptionError(f"Encryption failed: {e}")


def decrypt_content(encrypted_vault: Dict[str, str], key: bytes) -> str:
    """
    Decrypt content using AES-256-GCM.

    Args:
        encrypted_vault: Dictionary with encrypted vault metadata
        key: 256-bit encryption key

    Returns:
        Decrypted plaintext content
    """
    try:
        if not key or len(key) != KEY_LENGTH:
            raise DecryptionError(f"Key must be exactly {KEY_LENGTH} bytes")

        # Validate vault format
        required_fields = ['algorithm', 'nonce', 'ciphertext', 'tag']
        for field in required_fields:
            if field not in encrypted_vault:
                raise DecryptionError(f"Missing required field in encrypted vault: {field}")

        if encrypted_vault.get('algorithm') != ALGORITHM:
            raise DecryptionError(f"Unsupported algorithm: {encrypted_vault.get('algorithm')}")

        # Decode components
        nonce = base64.b64decode(encrypted_vault['nonce'])
        ciphertext = base64.b64decode(encrypted_vault['ciphertext'])
        tag = base64.b64decode(encrypted_vault['tag'])

        # Reconstruct full ciphertext with tag
        full_ciphertext = ciphertext + tag

        # Create cipher
        cipher = AESGCM(key)

        # Decrypt
        plaintext = cipher.decrypt(nonce, full_ciphertext, None)

        return plaintext.decode('utf-8')

    except DecryptionError:
        raise
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {e}")


def encrypt_file(file_path: str, content: str, key: bytes, salt: bytes = None) -> None:
    """
    Encrypt content and save to file with metadata.

    For passphrase-based encryption, include salt in file.
    For key-file-based encryption, salt is empty.

    Args:
        file_path: Path where encrypted file will be saved
        content: Plaintext content to encrypt
        key: Encryption key (from passphrase or key file)
        salt: Optional salt (for passphrase-based encryption)
    """
    try:
        # Encrypt content
        encrypted_vault = encrypt_content(content, key)

        # Include salt if provided (passphrase-based)
        if salt:
            encrypted_vault['salt'] = base64.b64encode(salt).decode('utf-8')

        # Write to file
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(encrypted_vault, f, indent=2)

        logger.info(f"Encrypted content saved to: {file_path}")

    except Exception as e:
        raise EncryptionError(f"Failed to encrypt and save file: {e}")


def decrypt_file(file_path: str, key: bytes) -> str:
    """
    Load and decrypt file.

    Args:
        file_path: Path to encrypted file
        key: Decryption key

    Returns:
        Decrypted plaintext content
    """
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Encrypted file not found: {file_path}")

        with open(file_path, 'r', encoding='utf-8') as f:
            encrypted_vault = json.load(f)

        # Decrypt content
        plaintext = decrypt_content(encrypted_vault, key)

        logger.info(f"Decrypted content from: {file_path}")
        return plaintext

    except FileNotFoundError:
        raise
    except json.JSONDecodeError as e:
        raise DecryptionError(f"Invalid encrypted file format: {e}")
    except Exception as e:
        raise EncryptionError(f"Failed to decrypt file: {e}")
