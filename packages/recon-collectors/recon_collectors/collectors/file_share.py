"""File share scanner for discovering PKI-related files on disk."""

from __future__ import annotations

import asyncio
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import structlog
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from recon_collectors.collectors.base import BaseCollector
from recon_collectors.models import CertificateInfo, ScanResults

logger = structlog.get_logger("recon.collectors.file_share")

CERT_EXTENSIONS: set[str] = {
    ".pem", ".crt", ".cer", ".p12", ".pfx", ".key", ".pub",
    ".der", ".p7b", ".jks", ".keystore", ".pkcs8", ".pks",
    ".pvk", ".pssc",
}

_PEM_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"-----BEGIN CERTIFICATE-----"),
    re.compile(r"-----BEGIN PRIVATE KEY-----"),
    re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
    re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
    re.compile(r"-----BEGIN ENCRYPTED PRIVATE KEY-----"),
    re.compile(r"-----BEGIN CERTIFICATE REQUEST-----"),
    re.compile(r"-----BEGIN PUBLIC KEY-----"),
]

_DER_BASE64_PATTERN: re.Pattern[str] = re.compile(r"^MII[A-Za-z0-9+/=]{8}")

MAX_DEPTH = 20
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
CONTENT_READ_LIMIT = 10 * 1024  # 10 KB


def _dn_to_dict(name: x509.Name) -> dict[str, str]:
    result: dict[str, str] = {}
    for attr in name:
        friendly = attr.oid._name if hasattr(attr.oid, "_name") else attr.oid.dotted_string
        result[friendly] = attr.value
    return result


def _days_until(dt: Optional[datetime]) -> Optional[int]:
    if dt is None:
        return None
    now = datetime.now(tz=timezone.utc)
    target = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return (target - now).days


def _try_parse_x509(file_path: str, raw: bytes) -> Optional[CertificateInfo]:
    """Attempt to parse raw bytes as an X.509 certificate (DER or PEM)."""
    cert = None
    try:
        cert = x509.load_der_x509_certificate(raw)
    except Exception:
        try:
            cert = x509.load_pem_x509_certificate(raw)
        except Exception:
            return None

    if cert is None:
        return None

    # Key usage
    key_usage_list: list[str] = []
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        for attr_name in (
            "digital_signature", "key_encipherment", "data_encipherment",
            "key_agreement", "key_cert_sign", "crl_sign",
            "content_commitment", "encipher_only", "decipher_only",
        ):
            if getattr(ku, attr_name, False):
                key_usage_list.append(attr_name)
    except x509.ExtensionNotFound:
        pass

    # EKU
    eku_list: list[str] = []
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        for usage in eku:
            eku_list.append(usage._name if hasattr(usage, "_name") else usage.dotted_string)
    except x509.ExtensionNotFound:
        pass

    # SAN
    san_list: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san_list = san_ext.get_values_for_type(x509.DNSName)
        san_list += [str(ip) for ip in san_ext.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass

    # Basic constraints
    bc: dict[str, Any] = {}
    is_ca = False
    try:
        bc_ext = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        is_ca = bc_ext.ca
        bc = {"ca": bc_ext.ca, "path_length": bc_ext.path_length}
    except x509.ExtensionNotFound:
        pass

    # Public key
    pub = cert.public_key()
    pk_algo: Optional[str] = None
    pk_size: Optional[int] = None
    pk_curve: Optional[str] = None
    if isinstance(pub, rsa.RSAPublicKey):
        pk_algo = "RSA"
        pk_size = pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pk_algo = "EC"
        pk_size = pub.key_size
        pk_curve = pub.curve.name

    not_after = (
        cert.not_valid_after_utc
        if hasattr(cert, "not_valid_after_utc")
        else cert.not_valid_after
    )
    is_self_signed = cert.issuer == cert.subject

    return CertificateInfo(
        serial_number=format(cert.serial_number, "x"),
        fingerprint_sha256=cert.fingerprint(
            cert.signature_hash_algorithm or x509.hashes.SHA256()
        ).hex() if cert.signature_hash_algorithm else None,
        subject=_dn_to_dict(cert.subject),
        issuer=_dn_to_dict(cert.issuer),
        not_before=(
            cert.not_valid_before_utc
            if hasattr(cert, "not_valid_before_utc")
            else cert.not_valid_before
        ),
        not_after=not_after,
        days_until_expiry=_days_until(not_after),
        is_expired=(_days_until(not_after) or 0) < 0,
        signature_algorithm=(
            cert.signature_algorithm_oid._name
            if hasattr(cert.signature_algorithm_oid, "_name")
            else cert.signature_algorithm_oid.dotted_string
        ),
        public_key_algorithm=pk_algo,
        public_key_size=pk_size,
        key_curve=pk_curve,
        key_usage=key_usage_list,
        extended_key_usage=eku_list,
        san=san_list,
        basic_constraints=bc,
        is_ca=is_ca,
        is_self_signed=is_self_signed,
        source=f"file_share:{file_path}",
    )


class FileShareCollector(BaseCollector):
    """Scans filesystem paths for PKI-related files."""

    @property
    def collector_type(self) -> str:
        return "file"

    # ------------------------------------------------------------------
    # Content detection
    # ------------------------------------------------------------------

    @staticmethod
    def _has_pem_content(text: str) -> bool:
        """Check if text contains PEM markers."""
        for pat in _PEM_PATTERNS:
            if pat.search(text):
                return True
        return False

    @staticmethod
    def _has_der_base64(text: str) -> bool:
        """Check if text looks like base64-encoded DER."""
        return bool(_DER_BASE64_PATTERN.search(text))

    # ------------------------------------------------------------------
    # Synchronous scan (run via to_thread)
    # ------------------------------------------------------------------

    def _scan_path(
        self,
        root: str,
        max_depth: int,
        follow_symlinks: bool,
    ) -> tuple[list[dict], list[CertificateInfo], list[str]]:
        """Walk a directory tree and identify PKI files."""
        file_results: list[dict] = []
        certificates: list[CertificateInfo] = []
        errors: list[str] = []

        root_path = Path(root)
        if not root_path.exists():
            errors.append(f"Path does not exist: {root}")
            return file_results, certificates, errors
        if not root_path.is_dir():
            errors.append(f"Path is not a directory: {root}")
            return file_results, certificates, errors

        root_depth = len(root_path.parts)

        for dirpath, dirnames, filenames in os.walk(
            root, followlinks=follow_symlinks
        ):
            current_depth = len(Path(dirpath).parts) - root_depth
            if current_depth >= max_depth:
                dirnames.clear()
                continue

            for fname in filenames:
                file_path = os.path.join(dirpath, fname)
                try:
                    stat = os.stat(file_path)
                except OSError as exc:
                    errors.append(f"Stat failed for {file_path}: {exc}")
                    continue

                if stat.st_size > MAX_FILE_SIZE:
                    continue

                ext = Path(fname).suffix.lower()
                ext_match = ext in CERT_EXTENSIONS

                # Try content detection
                content_match = False
                content_type: Optional[str] = None
                try:
                    with open(file_path, "rb") as fh:
                        head = fh.read(CONTENT_READ_LIMIT)
                    try:
                        text = head.decode("utf-8", errors="replace")
                        if self._has_pem_content(text):
                            content_match = True
                            content_type = "pem"
                        elif self._has_der_base64(text):
                            content_match = True
                            content_type = "der_base64"
                    except Exception:
                        pass
                except OSError as exc:
                    errors.append(f"Read failed for {file_path}: {exc}")
                    continue

                if not ext_match and not content_match:
                    continue

                confidence = "high" if content_match else "medium"

                entry: dict[str, Any] = {
                    "path": file_path,
                    "filename": fname,
                    "extension": ext,
                    "size_bytes": stat.st_size,
                    "confidence": confidence,
                    "match_type": "content" if content_match else "extension",
                    "content_type": content_type,
                }
                file_results.append(entry)

                # For high-confidence cert-like files, attempt X.509 parse
                if confidence == "high" and ext in (".pem", ".crt", ".cer", ".der"):
                    try:
                        with open(file_path, "rb") as fh:
                            raw = fh.read()
                        cert_info = _try_parse_x509(file_path, raw)
                        if cert_info is not None:
                            certificates.append(cert_info)
                            entry["parsed"] = True
                    except OSError as exc:
                        errors.append(f"Full read failed for {file_path}: {exc}")

                logger.debug(
                    "file_share.found",
                    path=file_path,
                    confidence=confidence,
                    content_type=content_type,
                )

        return file_results, certificates, errors

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def collect(self, config: dict) -> ScanResults:
        """Scan configured paths for PKI-related files."""
        paths: list[str] = config.get("paths", [])
        max_depth: int = min(config.get("max_depth", MAX_DEPTH), MAX_DEPTH)
        follow_symlinks: bool = config.get("follow_symlinks", False)

        results = ScanResults()
        start = datetime.now(tz=timezone.utc)

        for scan_path in paths:
            file_results, certs, errors = await asyncio.to_thread(
                self._scan_path, scan_path, max_depth, follow_symlinks
            )
            results.file_scan_results.extend(file_results)
            results.certificates.extend(certs)
            results.errors.extend(errors)

        elapsed = (datetime.now(tz=timezone.utc) - start).total_seconds()
        results.collector_stats = {
            "collector_type": self.collector_type,
            "paths_scanned": len(paths),
            "files_found": len(results.file_scan_results),
            "certificates_parsed": len(results.certificates),
            "errors": len(results.errors),
            "elapsed_seconds": round(elapsed, 3),
        }
        logger.info(
            "file_share.collect_complete",
            files_found=len(results.file_scan_results),
            certificates_parsed=len(results.certificates),
            paths=len(paths),
            elapsed=round(elapsed, 3),
        )
        return results

    async def health_check(self) -> dict:
        """Verify filesystem access is operational."""
        return {"status": "ok", "details": {"type": "file_share"}}
