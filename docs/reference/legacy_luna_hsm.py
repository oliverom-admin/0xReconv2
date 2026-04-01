# =============================================================================
# LEGACY REFERENCE FILE — READ ONLY
# =============================================================================
# This file is copied from the original 0xRecon (CAIP) codebase for reference
# during the 0xRecon v2 rebuild. It must NOT be imported or executed.
#
# Source: caip_scanning_functions/collectors/luna_hsm.py
# Copied: 2026-04-01
# Used in: Phase 5 — Collector Framework + Luna HSM
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
Thales Luna HSM (PKCS#11) key collector
"""

import hashlib
from typing import Dict, List, Any, Optional
from binascii import hexlify

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Try to import PyKCS11 (optional dependency for Luna HSM)
try:
    from PyKCS11.LowLevel import (
        CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_CERTIFICATE, CKO_SECRET_KEY,
        CKA_LABEL, CKA_ID, CKA_KEY_TYPE, CKA_MODULUS_BITS, CKA_EC_PARAMS, CKA_VALUE,
        CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_MODIFIABLE,
        CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE, CKA_LOCAL,
        CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY, CKA_WRAP, CKA_UNWRAP, CKA_DERIVE,
        CKA_START_DATE, CKA_END_DATE
    )
    PYKCS11_AVAILABLE = True
except ImportError:
    PYKCS11_AVAILABLE = False
    # Define stub values so module imports successfully
    CKO_PRIVATE_KEY = CKO_PUBLIC_KEY = CKO_CERTIFICATE = CKO_SECRET_KEY = None
    CKA_LABEL = CKA_ID = CKA_KEY_TYPE = CKA_MODULUS_BITS = CKA_EC_PARAMS = CKA_VALUE = None
    CKA_SENSITIVE = CKA_EXTRACTABLE = CKA_MODIFIABLE = None
    CKA_ALWAYS_SENSITIVE = CKA_NEVER_EXTRACTABLE = CKA_LOCAL = None
    CKA_ENCRYPT = CKA_DECRYPT = CKA_SIGN = CKA_VERIFY = CKA_WRAP = CKA_UNWRAP = CKA_DERIVE = None
    CKA_START_DATE = CKA_END_DATE = None

from ..models import CertificateInfo, AzureKeyVaultKeyInfo, KeyInfo, DEPENDENCIES_AVAILABLE
from caip_pqc_functions.pqc_detector import get_detector


class LunaHSMCollector:
    """
    Collect key metadata from Thales Luna (PKCS#11) using a password-enabled partition.
    """

    def _safe_get(self, session, obj, attr):
        """Safely get an attribute from a PKCS#11 object"""
        try:
            result = session.getAttributeValue(obj, [attr], skipNotSupported=True)
            if not result:
                return None
            return result[0]
        except Exception:
            return None

    def __init__(self, pkcs11_module_path: str, hsm_name: str = "Unknown HSM"):
        """
        Initialize Luna HSM Collector

        Args:
            pkcs11_module_path: Path to PKCS#11 module library
            hsm_name: Name identifier for this HSM
        """
        if not DEPENDENCIES_AVAILABLE['PyKCS11']:
            raise ImportError("PyKCS11 not available. Install with: pip install PyKCS11")

        from PyKCS11 import PyKCS11Lib

        self.lib = PyKCS11Lib()
        self.module_path = pkcs11_module_path
        self.hsm_name = hsm_name

        try:
            self.lib.load(self.module_path)
            print(f"  Loaded PKCS#11 module: {self.module_path}")
        except Exception as e:
            raise RuntimeError(f"Failed to load PKCS11 module at {self.module_path}: {e}")

    def _open_session_and_login(self, slot: int, password: str):
        """Open a session and login to the HSM"""
        from PyKCS11 import PyKCS11Error

        try:
            print(f"      Opening session on slot {slot}...")
            session = self.lib.openSession(slot)
            print(f"      Session opened successfully")
            print(f"      Attempting login with password of length {len(password) if password else 0}...")
            session.login(password)
            print(f"      Login successful")
            return session
        except PyKCS11Error as e:
            error_msg = str(e) if str(e) else f"PyKCS11Error (code: {e.code if hasattr(e, 'code') else 'unknown'})"
            print(f"      Login failed: {error_msg}")
            raise RuntimeError(f"Failed to open session/login on slot {slot}: {error_msg}")

    def collect_keys_from_partition(self, partition_password: str, slot_index: Optional[int] = None, partition_label: Optional[str] = None) -> List[KeyInfo]:
        """
        Connect to PKCS#11 module, find key objects and any certificate objects, and return list of KeyInfo.
        """
        from PyKCS11 import PyKCS11, PyKCS11Error
        from PyKCS11.LowLevel import CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_CERTIFICATE, CKA_LABEL, CKA_ID, CKA_KEY_TYPE, CKA_MODULUS_BITS, CKA_EC_PARAMS, CKA_VALUE

        keys: List[KeyInfo] = []

        # Display partition being processed
        partition_display = partition_label if partition_label else f"Slot {slot_index}" if slot_index is not None else "Default"
        print(f"    Processing partition: {partition_display}")

        # Find a slot
        try:
            print(f"      Getting slot list with tokenPresent=True, slot_index={slot_index}...")
            slots = self.lib.getSlotList(tokenPresent=True)
            print(f"      Got slots: {slots}")
            if not slots:
                print(f"      ✗ No slots with token present")
                return keys
            if slot_index is None:
                slot = slots[0]
            else:
                # Handle slot_index - can be either an actual slot number or index into slots list
                # For DPoD, slot_index is the actual slot number (e.g., 3)
                if slot_index in slots:
                    slot = slot_index
                # Backward compatibility: if slot_index < len(slots), treat as index
                elif slot_index < len(slots):
                    slot = slots[slot_index]
                else:
                    raise RuntimeError(f"Requested slot_index {slot_index} not found. Available slots: {slots}")
        except Exception as e:
            print(f"      ✗ Error enumerating slots: {e}")
            return keys

        session = None
        try:
            session = self._open_session_and_login(slot, partition_password)

            # Search for keys and certificates by class
            key_templates = [
                (CKO_PRIVATE_KEY, "private"),
                (CKO_PUBLIC_KEY, "public"),
                (CKO_SECRET_KEY, "secret"),
            ]

            for cko, kind in key_templates:
                try:
                    objs = session.findObjects([
                        (PyKCS11.CKA_CLASS, cko)
                    ])
                    print(f"      Found {len(objs)} {kind} key objects")
                except Exception as e:
                    print(f"      ✗ Error finding {kind} keys: {e}")
                    objs = []

                for obj in objs:
                    try:
                        # Request attributes - Core + Security + Operations
                        attributes = {}
                        attrs_to_get = [
                            # Core attributes
                            PyKCS11.CKA_LABEL, PyKCS11.CKA_ID, PyKCS11.CKA_TOKEN, PyKCS11.CKA_PRIVATE,
                            # Security attributes
                            PyKCS11.CKA_SENSITIVE, PyKCS11.CKA_EXTRACTABLE, PyKCS11.CKA_MODIFIABLE,
                            PyKCS11.CKA_ALWAYS_SENSITIVE, PyKCS11.CKA_NEVER_EXTRACTABLE, PyKCS11.CKA_LOCAL,
                            # Key operation attributes
                            PyKCS11.CKA_ENCRYPT, PyKCS11.CKA_DECRYPT, PyKCS11.CKA_SIGN,
                            PyKCS11.CKA_VERIFY, PyKCS11.CKA_WRAP, PyKCS11.CKA_UNWRAP, PyKCS11.CKA_DERIVE,
                            # Lifecycle attributes
                            PyKCS11.CKA_START_DATE, PyKCS11.CKA_END_DATE
                        ]
                        raw = {}

                        for a in attrs_to_get:
                            try:
                                result = session.getAttributeValue(obj, [a])
                                if result and len(result) > 0:
                                    raw[a] = result[0]
                                else:
                                    raw[a] = None
                            except Exception:
                                raw[a] = None

                        # Detect key type & size
                        key_type = "UNKNOWN"
                        key_size = None
                        try:
                            ktype_result = session.getAttributeValue(obj, [PyKCS11.CKA_KEY_TYPE])
                            if ktype_result and ktype_result[0] is not None:
                                ktype = ktype_result[0]
                                if ktype == PyKCS11.CKK_RSA:
                                    key_type = "RSA"
                                    try:
                                        kb_result = session.getAttributeValue(obj, [PyKCS11.CKA_MODULUS_BITS])
                                        if kb_result and kb_result[0] is not None:
                                            key_size = int(kb_result[0])
                                    except Exception:
                                        key_size = None
                                elif ktype == PyKCS11.CKK_EC:
                                    key_type = "EC"
                                    try:
                                        ec_params_result = session.getAttributeValue(obj, [PyKCS11.CKA_EC_PARAMS])
                                        if ec_params_result and ec_params_result[0] is not None:
                                            key_size = 256  # default assumption for EC
                                    except Exception:
                                        key_size = None
                                elif ktype == PyKCS11.CKK_AES:
                                    key_type = "AES"
                                    try:
                                        # AES key size from CKA_VALUE_LEN (in bytes), convert to bits
                                        val_len_result = session.getAttributeValue(obj, [PyKCS11.CKA_VALUE_LEN])
                                        if val_len_result and val_len_result[0] is not None:
                                            key_size = int(val_len_result[0]) * 8
                                    except Exception:
                                        key_size = None
                                elif ktype == PyKCS11.CKK_DES3:
                                    key_type = "3DES"
                                    key_size = 168
                                elif ktype == PyKCS11.CKK_DES:
                                    key_type = "DES"
                                    key_size = 56
                                else:
                                    key_type = f"TYPE_{ktype}"
                                    key_size = None
                        except Exception:
                            key_type = "UNKNOWN"
                            key_size = None

                        # Extract label
                        label = raw.get(PyKCS11.CKA_LABEL)
                        if label is None:
                            label = ""
                        elif isinstance(label, (bytes, bytearray)):
                            try:
                                label = label.decode('utf-8')
                            except:
                                label = hexlify(label).decode()

                        # Extract object ID
                        objid = raw.get(PyKCS11.CKA_ID)
                        if objid and isinstance(objid, (bytes, bytearray)):
                            objid_hex = hexlify(objid).decode()
                        elif objid:
                            objid_hex = str(objid)
                        else:
                            objid_hex = "unknown"

                        # Attempt to fetch an associated certificate object
                        associated_cert = None
                        try:
                            if objid:
                                cert_objs = session.findObjects([(PyKCS11.CKA_CLASS, CKO_CERTIFICATE), (PyKCS11.CKA_ID, objid)])
                                if cert_objs:
                                    cert_obj = cert_objs[0]
                                    cert_bytes = session.getAttributeValue(cert_obj, [PyKCS11.CKA_VALUE], skipNotSupported=True)[0]
                                    if cert_bytes:
                                        try:
                                            cert = x509.load_der_x509_certificate(bytes(cert_bytes), default_backend())
                                            subject = {}
                                            for attr in cert.subject:
                                                subject[attr.oid._name] = attr.value
                                            issuer = {}
                                            for attr in cert.issuer:
                                                issuer[attr.oid._name] = attr.value
                                            fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

                                            # PQC Analysis for HSM certificate
                                            pqc_analysis = None
                                            try:
                                                pqc_detector = get_detector()
                                                sig_oid = cert.signature_algorithm_oid.dotted_string if hasattr(cert.signature_algorithm_oid, 'dotted_string') else None
                                                sig_name = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else None
                                                pub_key_algo = type(cert.public_key()).__name__
                                                pqc_result = pqc_detector.analyze_certificate(
                                                    signature_algorithm_oid=sig_oid,
                                                    signature_algorithm_name=sig_name,
                                                    public_key_algorithm=pub_key_algo
                                                )
                                                pqc_analysis = pqc_result.to_dict()
                                                if pqc_result.is_pqc:
                                                    print(f"        🔐 PQC detected in HSM cert: {pqc_result.pqc_algorithm}")
                                            except Exception:
                                                pass

                                            associated_cert = CertificateInfo(
                                                serial_number=f"{cert.serial_number:X}",
                                                subject=subject,
                                                issuer=issuer,
                                                not_before=cert.not_valid_before.isoformat(),
                                                not_after=cert.not_valid_after.isoformat(),
                                                signature_algorithm=cert.signature_algorithm_oid._name,
                                                public_key_algorithm=type(cert.public_key()).__name__,
                                                public_key_size=getattr(cert.public_key(), 'key_size', 0),
                                                key_usage=[],
                                                extended_key_usage=[],
                                                basic_constraints={},
                                                san=[],
                                                fingerprint_sha256=fingerprint,
                                                source=f"Luna HSM: {self.hsm_name} - Partition: {partition_label if partition_label else slot}",
                                                unique_id=f"luna_cert_{objid_hex[:16]}",
                                                is_ca=False,
                                                is_self_signed=(cert.issuer == cert.subject),
                                                crl_distribution_points=[],
                                                ocsp_responders=[],
                                                certificate_transparency_scts=[],
                                                found_at_destination=f"Luna HSM: {self.hsm_name} - Slot {slot}",
                                                found_on_port="N/A",
                                                pqc_analysis=pqc_analysis
                                            )
                                        except Exception:
                                            associated_cert = None
                        except Exception:
                            associated_cert = None

                        # Helper to safely convert PKCS#11 date to ISO string
                        def parse_pkcs11_date(date_val):
                            if date_val and isinstance(date_val, (bytes, bytearray, list)):
                                try:
                                    date_bytes = bytes(date_val) if not isinstance(date_val, bytes) else date_val
                                    if len(date_bytes) >= 8:
                                        return date_bytes.decode('utf-8')
                                except Exception:
                                    pass
                            return None

                        # Create key info object using KeyInfo dataclass
                        keyinfo = KeyInfo(
                            label=label if label else f"slot{slot}_id{objid_hex[:8]}",
                            object_id=objid_hex,
                            token=bool(raw.get(PyKCS11.CKA_TOKEN)),
                            private=(raw.get(PyKCS11.CKA_PRIVATE) is True),
                            key_type=key_type,
                            key_size=key_size,
                            public_key_fingerprint=None,
                            associated_certificate=associated_cert,
                            source=f"Luna HSM: {self.hsm_name} - Partition: {partition_label if partition_label else slot}",
                            # PKCS#11 Security Attributes
                            is_sensitive=(raw.get(PyKCS11.CKA_SENSITIVE) is True),
                            is_extractable=(raw.get(PyKCS11.CKA_EXTRACTABLE) is True),
                            is_modifiable=(raw.get(PyKCS11.CKA_MODIFIABLE) is True),
                            is_always_sensitive=(raw.get(PyKCS11.CKA_ALWAYS_SENSITIVE) is True),
                            is_never_extractable=(raw.get(PyKCS11.CKA_NEVER_EXTRACTABLE) is True),
                            is_local=(raw.get(PyKCS11.CKA_LOCAL) is True),
                            # PKCS#11 Key Operations
                            can_encrypt=(raw.get(PyKCS11.CKA_ENCRYPT) is True),
                            can_decrypt=(raw.get(PyKCS11.CKA_DECRYPT) is True),
                            can_sign=(raw.get(PyKCS11.CKA_SIGN) is True),
                            can_verify=(raw.get(PyKCS11.CKA_VERIFY) is True),
                            can_wrap=(raw.get(PyKCS11.CKA_WRAP) is True),
                            can_unwrap=(raw.get(PyKCS11.CKA_UNWRAP) is True),
                            can_derive=(raw.get(PyKCS11.CKA_DERIVE) is True),
                            # PKCS#11 Lifecycle
                            start_date=parse_pkcs11_date(raw.get(PyKCS11.CKA_START_DATE)),
                            end_date=parse_pkcs11_date(raw.get(PyKCS11.CKA_END_DATE)),
                            # Key class
                            key_class=kind  # 'private', 'public', or 'secret'
                        )

                        # Add PQC analysis for the key
                        try:
                            try:
                                from ...caip_pqc_functions.pqc_detector import get_detector
                            except ImportError:
                                from caip_pqc_functions.pqc_detector import get_detector
                            pqc_detector = get_detector()
                            pqc_result = pqc_detector.analyze_key(
                                key_type=key_type,
                                key_size=key_size
                            )
                            keyinfo.pqc_analysis = pqc_result.to_dict()
                        except Exception as e:
                            print(f"        ⚠ PQC analysis failed: {e}")
                            keyinfo.pqc_analysis = None

                        keys.append(keyinfo)
                    except Exception as e:
                        print(f"    ✗ Error reading object: {e}")
                        continue

        except Exception as e:
            print(f"  ✗ Error collecting keys from Luna slot {slot}: {e}")
        finally:
            if session:
                try:
                    session.logout()
                except Exception:
                    pass
                try:
                    session.closeSession()
                except Exception:
                    pass

        return keys
