"""Luna HSM collector using python-pkcs11 for read-only key enumeration."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Optional

import pkcs11
import structlog

from recon_collectors.collectors.base import BaseCollector
from recon_collectors.models import KeyInfo, ScanResults

logger = structlog.get_logger("recon.collectors.luna_hsm")

# Maps PKCS#11 key type constants to human-readable names.
_KEY_TYPE_NAMES: dict[int, str] = {
    pkcs11.KeyType.RSA: "RSA",
    pkcs11.KeyType.EC: "EC",
    pkcs11.KeyType.AES: "AES",
    pkcs11.KeyType.DES3: "3DES",
    pkcs11.KeyType.DES: "DES",
}

_OBJECT_CLASS_NAMES: dict[int, str] = {
    pkcs11.ObjectClass.PRIVATE_KEY: "PRIVATE_KEY",
    pkcs11.ObjectClass.PUBLIC_KEY: "PUBLIC_KEY",
    pkcs11.ObjectClass.SECRET_KEY: "SECRET_KEY",
}

# Well-known EC named curve OIDs (DER-encoded) to key sizes.
_EC_PARAM_SIZES: dict[bytes, int] = {
    # P-256 (prime256v1 / secp256r1) OID 1.2.840.10045.3.1.7
    bytes.fromhex("06082a8648ce3d030107"): 256,
    # P-384 (secp384r1) OID 1.3.132.0.34
    bytes.fromhex("06052b81040022"): 384,
    # P-521 (secp521r1) OID 1.3.132.0.35
    bytes.fromhex("06052b81040023"): 521,
    # Ed25519 OID 1.3.101.112
    bytes.fromhex("06032b6570"): 256,
    # Ed448 OID 1.3.101.113
    bytes.fromhex("06032b6571"): 448,
}


class LunaHSMCollector(BaseCollector):
    """Enumerates cryptographic objects from a Luna HSM via PKCS#11."""

    def __init__(self, module_path: str, hsm_name: str) -> None:
        self._module_path = module_path
        self._hsm_name = hsm_name
        self._lib: Optional[pkcs11.lib] = None

    @property
    def collector_type(self) -> str:
        return "luna_hsm"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_attr(obj: Any, attr: str) -> Any:
        """Read an attribute from a PKCS#11 object defensively."""
        try:
            return getattr(obj, attr, None)
        except Exception:
            return None

    @staticmethod
    def _derive_ec_key_size(ec_params_bytes: Optional[bytes]) -> int:
        """Derive EC key size from CKA_EC_PARAMS. Falls back to 256."""
        if ec_params_bytes is None:
            return 256
        size = _EC_PARAM_SIZES.get(ec_params_bytes)
        if size is not None:
            return size
        # Heuristic: longer params tend to indicate larger curves.
        param_len = len(ec_params_bytes)
        if param_len > 12:
            return 521
        if param_len > 9:
            return 384
        return 256

    def _load_lib(self) -> pkcs11.lib:
        """Load the PKCS#11 library once."""
        if self._lib is None:
            self._lib = pkcs11.lib(self._module_path)
        return self._lib

    # ------------------------------------------------------------------
    # Certificate DER map for key-cert association
    # ------------------------------------------------------------------

    def _build_cert_map(self, session: Any) -> dict[bytes, bytes]:
        """Build a mapping of CKA_ID -> certificate DER bytes."""
        cert_map: dict[bytes, bytes] = {}
        try:
            for cert_obj in session.get_objects(
                {pkcs11.Attribute.CLASS: pkcs11.ObjectClass.CERTIFICATE}
            ):
                cka_id = self._safe_attr(cert_obj, pkcs11.Attribute.ID)
                der = self._safe_attr(cert_obj, pkcs11.Attribute.VALUE)
                if cka_id and der:
                    cert_map[bytes(cka_id)] = bytes(der)
        except Exception as exc:
            logger.warning("luna_hsm.cert_map_failed", error=str(exc))
        return cert_map

    # ------------------------------------------------------------------
    # Key extraction
    # ------------------------------------------------------------------

    def _extract_key(
        self,
        obj: Any,
        obj_class: int,
        partition_label: str,
        cert_map: dict[bytes, bytes],
    ) -> Optional[KeyInfo]:
        """Extract metadata from a single PKCS#11 key object."""
        try:
            label = self._safe_attr(obj, pkcs11.Attribute.LABEL) or ""
            key_type_raw = self._safe_attr(obj, pkcs11.Attribute.KEY_TYPE)
            key_type_name = _KEY_TYPE_NAMES.get(key_type_raw, f"UNKNOWN({key_type_raw})")

            # Key size
            key_size: Optional[int] = None
            if key_type_name == "RSA":
                modulus = self._safe_attr(obj, pkcs11.Attribute.MODULUS)
                if modulus is not None:
                    key_size = len(bytes(modulus)) * 8
                else:
                    key_size = self._safe_attr(obj, pkcs11.Attribute.MODULUS_BITS)
            elif key_type_name == "EC":
                ec_params = self._safe_attr(obj, pkcs11.Attribute.EC_PARAMS)
                key_size = self._derive_ec_key_size(
                    bytes(ec_params) if ec_params is not None else None
                )
            elif key_type_name in ("AES", "3DES", "DES"):
                value_len = self._safe_attr(obj, pkcs11.Attribute.VALUE_LEN)
                if value_len is not None:
                    key_size = int(value_len) * 8

            # CKA_ID for cert association
            cka_id = self._safe_attr(obj, pkcs11.Attribute.ID)
            associated_cert: Optional[str] = None
            if cka_id:
                cka_id_bytes = bytes(cka_id)
                if cka_id_bytes in cert_map:
                    associated_cert = cka_id_bytes.hex()

            class_name = _OBJECT_CLASS_NAMES.get(obj_class, "UNKNOWN")

            info = KeyInfo(
                key_id=cka_id.hex() if cka_id else None,
                label=str(label) if label else None,
                source_type="luna_hsm",
                source=f"{self._hsm_name}/{partition_label}",
                key_type=key_type_name,
                key_size=key_size,
                key_class=class_name,
                # Security attributes
                is_sensitive=bool(self._safe_attr(obj, pkcs11.Attribute.SENSITIVE)),
                is_extractable=bool(self._safe_attr(obj, pkcs11.Attribute.EXTRACTABLE)),
                is_local=bool(self._safe_attr(obj, pkcs11.Attribute.LOCAL)),
                is_always_sensitive=bool(
                    self._safe_attr(obj, pkcs11.Attribute.ALWAYS_SENSITIVE)
                ),
                is_never_extractable=bool(
                    self._safe_attr(obj, pkcs11.Attribute.NEVER_EXTRACTABLE)
                ),
                is_hardware_protected=True,
                # Operations
                can_encrypt=bool(self._safe_attr(obj, pkcs11.Attribute.ENCRYPT)),
                can_decrypt=bool(self._safe_attr(obj, pkcs11.Attribute.DECRYPT)),
                can_sign=bool(self._safe_attr(obj, pkcs11.Attribute.SIGN)),
                can_verify=bool(self._safe_attr(obj, pkcs11.Attribute.VERIFY)),
                can_wrap=bool(self._safe_attr(obj, pkcs11.Attribute.WRAP)),
                can_unwrap=bool(self._safe_attr(obj, pkcs11.Attribute.UNWRAP)),
                can_derive=bool(self._safe_attr(obj, pkcs11.Attribute.DERIVE)),
                associated_certificate=associated_cert,
            )
            return info
        except Exception as exc:
            logger.warning(
                "luna_hsm.key_extract_failed",
                partition=partition_label,
                error=str(exc),
            )
            return None

    # ------------------------------------------------------------------
    # Partition scan (synchronous, run via to_thread)
    # ------------------------------------------------------------------

    def _scan_partition(
        self,
        partition: dict,
    ) -> tuple[list[KeyInfo], list[str]]:
        """Scan a single partition. Returns (keys, errors)."""
        keys: list[KeyInfo] = []
        errors: list[str] = []
        label = partition.get("label", "unknown")
        password = partition.get("password", "")
        slot_index = partition.get("slot_index")

        lib = self._load_lib()

        # Resolve token
        token = None
        try:
            if slot_index is not None:
                slots = lib.get_slots()
                if slot_index < len(slots):
                    token = slots[slot_index].get_token()
                else:
                    errors.append(f"Slot index {slot_index} out of range")
                    return keys, errors
            else:
                token = lib.get_token(token_label=label)
        except Exception as exc:
            errors.append(f"Token resolution failed for '{label}': {exc}")
            return keys, errors

        session = None
        try:
            session = token.open(user_pin=password)
            logger.info("luna_hsm.session_opened", partition=label)

            cert_map = self._build_cert_map(session)

            for obj_class in (
                pkcs11.ObjectClass.PRIVATE_KEY,
                pkcs11.ObjectClass.PUBLIC_KEY,
                pkcs11.ObjectClass.SECRET_KEY,
            ):
                try:
                    for obj in session.get_objects(
                        {pkcs11.Attribute.CLASS: obj_class}
                    ):
                        key_info = self._extract_key(
                            obj, obj_class, label, cert_map
                        )
                        if key_info is not None:
                            keys.append(key_info)
                except Exception as exc:
                    class_name = _OBJECT_CLASS_NAMES.get(obj_class, "UNKNOWN")
                    errors.append(
                        f"Enumeration failed for {class_name} on '{label}': {exc}"
                    )
                    logger.warning(
                        "luna_hsm.enum_failed",
                        partition=label,
                        object_class=class_name,
                        error=str(exc),
                    )
        except Exception as exc:
            errors.append(f"Session open failed for '{label}': {exc}")
            logger.error("luna_hsm.session_failed", partition=label, error=str(exc))
        finally:
            if session is not None:
                try:
                    session.close()
                    logger.info("luna_hsm.session_closed", partition=label)
                except Exception as close_exc:
                    logger.warning(
                        "luna_hsm.session_close_failed",
                        partition=label,
                        error=str(close_exc),
                    )

        return keys, errors

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def collect(self, config: dict) -> ScanResults:
        """Enumerate keys across configured Luna HSM partitions."""
        partitions = config.get("partitions", [])
        results = ScanResults()
        start = datetime.now(tz=timezone.utc)

        for partition in partitions:
            partition_keys, partition_errors = await asyncio.to_thread(
                self._scan_partition, partition
            )
            results.keys.extend(partition_keys)
            results.errors.extend(partition_errors)

        elapsed = (datetime.now(tz=timezone.utc) - start).total_seconds()
        results.collector_stats = {
            "collector_type": self.collector_type,
            "hsm_name": self._hsm_name,
            "partitions_scanned": len(partitions),
            "keys_found": len(results.keys),
            "errors": len(results.errors),
            "elapsed_seconds": round(elapsed, 3),
        }
        logger.info(
            "luna_hsm.collect_complete",
            keys_found=len(results.keys),
            partitions=len(partitions),
            elapsed=round(elapsed, 3),
        )
        return results

    async def health_check(self) -> dict:
        """Verify the PKCS#11 library can be loaded and slots enumerated."""
        try:
            lib = await asyncio.to_thread(self._load_lib)
            slots = await asyncio.to_thread(lib.get_slots)
            return {
                "status": "ok",
                "details": {
                    "module_path": self._module_path,
                    "hsm_name": self._hsm_name,
                    "slots_available": len(slots),
                },
            }
        except Exception as exc:
            logger.error("luna_hsm.health_check_failed", error=str(exc))
            return {
                "status": "error",
                "details": {"error": str(exc)},
            }
