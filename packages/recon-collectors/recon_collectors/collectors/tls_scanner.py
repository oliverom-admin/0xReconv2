"""TLS/SSL certificate scanner collector.

Scans network endpoints for TLS certificates and connection metadata.
All blocking I/O is wrapped in ``asyncio.to_thread`` so the collector
integrates cleanly with the async scan orchestrator.
"""

from __future__ import annotations

import asyncio
import hashlib
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Optional

import structlog

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa, ed25519, ed448
from cryptography.x509.oid import ExtensionOID

try:
    from OpenSSL import SSL as _ossl_SSL
    from OpenSSL import crypto as _ossl_crypto
    PYOPENSSL_AVAILABLE = True
except ImportError:  # pragma: no cover
    PYOPENSSL_AVAILABLE = False

from recon_collectors.collectors.base import BaseCollector
from recon_collectors.models import (
    CertificateInfo,
    ScanResults,
    TLSScanResult,
)

logger = structlog.get_logger("recon.collector.tls")

# Well-known extension OIDs not in cryptography's ExtensionOID constants.
_OID_CT_SCTS = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
_OID_PRECERT_POISON = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.3")
_OID_FRESHEST_CRL = x509.ObjectIdentifier("2.5.29.46")


# ---------------------------------------------------------------------------
# Helper: certificate parsing
# ---------------------------------------------------------------------------

def _extract_name_dict(name: x509.Name) -> dict[str, str]:
    """Convert an x509 Name to a simple dict."""
    result: dict[str, str] = {}
    for attr in name:
        result[attr.oid._name] = attr.value
    return result


def _parse_certificate(cert_der: bytes) -> CertificateInfo:
    """Parse a DER-encoded certificate into a ``CertificateInfo``."""
    cert = x509.load_der_x509_certificate(cert_der)

    subject = _extract_name_dict(cert.subject)
    issuer = _extract_name_dict(cert.issuer)

    fingerprint = hashlib.sha256(cert_der).hexdigest()
    serial_hex = f"{cert.serial_number:X}"
    unique_id = hashlib.sha256(
        f"{cert.serial_number}{subject.get('commonName', '')}".encode()
    ).hexdigest()[:16]

    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    days_until_expiry = (not_after - now).days
    is_expired = now > not_after

    # --- Public key info ---
    pub_key = cert.public_key()
    pub_key_algo = type(pub_key).__name__
    pub_key_size: Optional[int] = getattr(pub_key, "key_size", None)
    key_curve: Optional[str] = None
    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_curve = pub_key.curve.name

    # --- Extensions ---
    key_usage: list[str] = []
    try:
        ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        ku = ku_ext.value
        for flag in (
            "digital_signature",
            "content_commitment",
            "key_encipherment",
            "data_encipherment",
            "key_agreement",
            "key_cert_sign",
            "crl_sign",
        ):
            try:
                if getattr(ku, flag):
                    key_usage.append(flag)
            except ValueError:
                pass
        # encipher_only / decipher_only only meaningful when key_agreement set
        if ku.key_agreement:
            try:
                if ku.encipher_only:
                    key_usage.append("encipher_only")
            except ValueError:
                pass
            try:
                if ku.decipher_only:
                    key_usage.append("decipher_only")
            except ValueError:
                pass
    except x509.ExtensionNotFound:
        pass

    eku: list[str] = []
    try:
        eku_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        )
        eku = [usage.dotted_string for usage in eku_ext.value]
    except x509.ExtensionNotFound:
        pass

    san: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san = [str(name) for name in san_ext.value]
    except (x509.ExtensionNotFound, AttributeError, ValueError):
        pass

    basic_constraints: dict[str, Any] = {}
    is_ca = False
    try:
        bc_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        basic_constraints = {
            "ca": bc_ext.value.ca,
            "path_length": bc_ext.value.path_length,
        }
        is_ca = bc_ext.value.ca
    except x509.ExtensionNotFound:
        pass

    crl_dps: list[str] = []
    try:
        crl_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        )
        for dp in crl_ext.value:
            if dp.full_name:
                for name in dp.full_name:
                    crl_dps.append(str(name.value))
    except x509.ExtensionNotFound:
        pass

    ocsp_responders: list[str] = []
    try:
        aia_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
        for desc in aia_ext.value:
            if desc.access_method.dotted_string == "1.3.6.1.5.5.7.48.1":
                ocsp_responders.append(str(desc.access_location.value))
    except x509.ExtensionNotFound:
        pass

    aki: Optional[str] = None
    try:
        aki_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        )
        aki_bytes = aki_ext.value.key_identifier
        aki = aki_bytes.hex() if aki_bytes else None
    except x509.ExtensionNotFound:
        pass

    ski: Optional[str] = None
    try:
        ski_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        ski_bytes = ski_ext.value.digest
        ski = ski_bytes.hex() if ski_bytes else None
    except x509.ExtensionNotFound:
        pass

    scts: list[dict] = []
    try:
        cert.extensions.get_extension_for_oid(_OID_CT_SCTS)
        scts.append({"status": "present"})
    except x509.ExtensionNotFound:
        pass

    precert_poison = False
    try:
        cert.extensions.get_extension_for_oid(_OID_PRECERT_POISON)
        precert_poison = True
    except x509.ExtensionNotFound:
        pass

    freshest_crl: list[str] = []
    try:
        fcrl_ext = cert.extensions.get_extension_for_oid(_OID_FRESHEST_CRL)
        for dp in fcrl_ext.value:
            if dp.full_name:
                for name in dp.full_name:
                    freshest_crl.append(str(name.value))
    except x509.ExtensionNotFound:
        pass

    is_self_signed = cert.issuer == cert.subject

    return CertificateInfo(
        serial_number=serial_hex,
        fingerprint_sha256=fingerprint,
        unique_id=unique_id,
        subject=subject,
        issuer=issuer,
        not_before=not_before.isoformat(),
        not_after=not_after.isoformat(),
        days_until_expiry=days_until_expiry,
        is_expired=is_expired,
        signature_algorithm=cert.signature_algorithm_oid._name,
        public_key_algorithm=pub_key_algo,
        public_key_size=pub_key_size,
        key_curve=key_curve,
        key_usage=key_usage,
        extended_key_usage=eku,
        san=san,
        basic_constraints=basic_constraints,
        crl_distribution_points=crl_dps,
        ocsp_responders=ocsp_responders,
        certificate_transparency_scts=scts,
        authority_key_identifier=aki,
        subject_key_identifier=ski,
        freshest_crl_urls=freshest_crl,
        precert_poison_present=precert_poison,
        is_ca=is_ca,
        is_self_signed=is_self_signed,
        source="TLS",
    )


# ---------------------------------------------------------------------------
# Sync helpers executed inside ``asyncio.to_thread``
# ---------------------------------------------------------------------------

def _rate_cipher_strength(cipher_name: Optional[str], key_bits: Optional[int]) -> str:
    """Rate cipher strength: A (>=256), B (>=128), C (>=64), F (else)."""
    if not cipher_name or key_bits is None:
        return "Unknown"
    if key_bits >= 256:
        return "A"
    if key_bits >= 128:
        return "B"
    if key_bits >= 64:
        return "C"
    return "F"


def _has_forward_secrecy(cipher_name: Optional[str]) -> bool:
    if not cipher_name:
        return False
    upper = cipher_name.upper()
    return "ECDHE" in upper or "DHE" in upper or "PSK" in upper


def _detect_tls_library() -> str:
    """Return the name of the SSL library backing Python's ssl module."""
    try:
        return ssl.OPENSSL_VERSION
    except Exception:
        return "Unknown"


def _extract_chain_pyopenssl(
    host: str, port: int, timeout: float
) -> list[bytes]:
    """Use pyOpenSSL to extract the full certificate chain as DER bytes."""
    if not PYOPENSSL_AVAILABLE:
        return []

    chain_der: list[bytes] = []
    ssl_sock = None
    raw_sock = None
    try:
        ctx = _ossl_SSL.Context(_ossl_SSL.TLS_METHOD)
        ctx.set_verify(_ossl_SSL.VERIFY_NONE, lambda *a: True)

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        ssl_sock = _ossl_SSL.Connection(ctx, raw_sock)
        ssl_sock.set_tlsext_host_name(host.encode())
        ssl_sock.connect((host, port))
        ssl_sock.do_handshake()

        peer_chain = ssl_sock.get_peer_cert_chain()
        if peer_chain:
            for cert in peer_chain:
                chain_der.append(
                    _ossl_crypto.dump_certificate(
                        _ossl_crypto.FILETYPE_ASN1, cert
                    )
                )
    except Exception:
        # Chain extraction is best-effort; caller handles missing chain.
        pass
    finally:
        try:
            if ssl_sock is not None:
                ssl_sock.shutdown()
                ssl_sock.close()
        except Exception:
            pass
        try:
            if raw_sock is not None:
                raw_sock.close()
        except Exception:
            pass

    return chain_der


def _enumerate_tls_versions(
    host: str, port: int, timeout: float
) -> dict[str, Any]:
    """Test individual TLS protocol versions against the endpoint."""
    supported: list[str] = []
    vulnerabilities: list[str] = []
    client_cert_required = False
    session_ticket = False

    version_map: list[tuple[int, str]] = []
    # TLS 1.0 / 1.1 use minimum_version/maximum_version on modern Python
    for proto_const, label in [
        ("PROTOCOL_TLSv1", "TLSv1.0"),
        ("PROTOCOL_TLSv1_1", "TLSv1.1"),
        ("PROTOCOL_TLSv1_2", "TLSv1.2"),
    ]:
        val = getattr(ssl, proto_const, None)
        if val is not None:
            version_map.append((val, label))

    # For TLS 1.3 we try using TLS_CLIENT_METHOD with min/max version.
    tls13_min = getattr(ssl, "TLSVersion", None)

    for proto_const, label in version_map:
        try:
            ctx = ssl.SSLContext(proto_const)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    supported.append(label)
                    if hasattr(ssock, "session"):
                        session_ticket = True
        except ssl.SSLError as exc:
            if "CERTIFICATE_REQUIRED" in str(exc) or "certificate required" in str(exc).lower():
                client_cert_required = True
        except (socket.timeout, OSError):
            pass

    # TLS 1.3 probe
    if tls13_min is not None:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    supported.append("TLSv1.3")
                    if hasattr(ssock, "session"):
                        session_ticket = True
        except ssl.SSLError as exc:
            if "CERTIFICATE_REQUIRED" in str(exc) or "certificate required" in str(exc).lower():
                client_cert_required = True
        except (socket.timeout, OSError):
            pass

    if "TLSv1.0" in supported or "TLSv1.1" in supported:
        vulnerabilities.append("Legacy TLS versions supported (TLS 1.0/1.1)")

    return {
        "supported_versions": supported,
        "vulnerabilities": vulnerabilities,
        "client_cert_required": client_cert_required,
        "session_ticket": session_ticket,
    }


def _scan_endpoint_sync(
    host: str, port: int, timeout: float
) -> TLSScanResult:
    """Perform the full TLS scan for a single endpoint (blocking)."""
    log = logger.bind(host=host, port=port)
    log.info("tls_scan_start")

    handshake_start = time.monotonic()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                protocol = ssock.version()
                cipher = ssock.cipher()

        handshake_ms = (time.monotonic() - handshake_start) * 1000

        if cert_der is None:
            return TLSScanResult(
                host=host,
                port=port,
                timestamp=datetime.now(timezone.utc).isoformat(),
                error="No certificate returned by server",
            )

        # Parse leaf certificate.
        leaf = _parse_certificate(cert_der)
        leaf.found_at_destination = host
        leaf.found_on_port = port
        leaf.tls_version = protocol or "Unknown"
        leaf.tls_library = _detect_tls_library()
        leaf.tls_handshake_time_ms = handshake_ms

        cipher_name = cipher[0] if cipher and len(cipher) > 0 else None
        sym_bits = cipher[2] if cipher and len(cipher) > 2 else None

        leaf.symmetric_key_bits = sym_bits
        leaf.cipher_strength_rating = _rate_cipher_strength(cipher_name, sym_bits)
        leaf.has_forward_secrecy = _has_forward_secrecy(cipher_name)

        # Protocol version enumeration.
        ver_info = _enumerate_tls_versions(host, port, timeout)
        leaf.supported_tls_versions = ver_info["supported_versions"]
        leaf.protocol_vulnerabilities = ver_info["vulnerabilities"]
        leaf.client_cert_required = ver_info["client_cert_required"]
        leaf.session_ticket_supported = ver_info["session_ticket"]

        # Certificate chain via pyOpenSSL (fallback).
        chain_infos: list[CertificateInfo] = []
        chain_ders = _extract_chain_pyopenssl(host, port, timeout)
        for chain_der_bytes in chain_ders:
            try:
                chain_infos.append(_parse_certificate(chain_der_bytes))
            except Exception as exc:
                log.warning("chain_cert_parse_error", error=str(exc))

        # Build security metadata dict.
        security_metadata: dict[str, Any] = {
            "cipher_name": cipher_name,
            "cipher_bits": sym_bits,
            "cipher_strength": leaf.cipher_strength_rating,
            "forward_secrecy": leaf.has_forward_secrecy,
            "supported_tls_versions": ver_info["supported_versions"],
            "vulnerabilities": ver_info["vulnerabilities"],
            "client_cert_required": ver_info["client_cert_required"],
            "session_ticket": ver_info["session_ticket"],
            "handshake_time_ms": handshake_ms,
        }

        result = TLSScanResult(
            host=host,
            port=port,
            timestamp=datetime.now(timezone.utc).isoformat(),
            supported_protocols=ver_info["supported_versions"],
            cipher_suite=cipher_name,
            certificate=leaf,
            certificate_chain=chain_infos,
            security_metadata=security_metadata,
        )
        log.info(
            "tls_scan_complete",
            cipher=cipher_name,
            protocol=protocol,
            chain_length=len(chain_infos),
            handshake_ms=round(handshake_ms, 1),
        )
        return result

    except socket.timeout:
        log.error("tls_scan_timeout")
        return TLSScanResult(
            host=host,
            port=port,
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=f"Connection timed out after {timeout}s",
        )
    except socket.gaierror as exc:
        log.error("tls_scan_dns_error", error=str(exc))
        return TLSScanResult(
            host=host,
            port=port,
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=f"DNS resolution failed: {exc}",
        )
    except ConnectionRefusedError:
        log.error("tls_scan_connection_refused")
        return TLSScanResult(
            host=host,
            port=port,
            timestamp=datetime.now(timezone.utc).isoformat(),
            error="Connection refused",
        )
    except ConnectionResetError:
        log.error("tls_scan_connection_reset")
        return TLSScanResult(
            host=host,
            port=port,
            timestamp=datetime.now(timezone.utc).isoformat(),
            error="Connection reset by peer",
        )
    except ssl.SSLError as exc:
        log.error("tls_scan_ssl_error", error=str(exc))
        return TLSScanResult(
            host=host,
            port=port,
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=f"SSL/TLS error: {exc}",
        )
    except OSError as exc:
        log.error("tls_scan_os_error", error=str(exc))
        return TLSScanResult(
            host=host,
            port=port,
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=f"OS error: {exc}",
        )
    except Exception as exc:
        log.exception("tls_scan_unexpected_error")
        return TLSScanResult(
            host=host,
            port=port,
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=f"Unexpected error: {type(exc).__name__}: {exc}",
        )


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class TLSCollector(BaseCollector):
    """TLS/SSL certificate scanner collector.

    Scans a list of ``{host, port}`` endpoints for TLS certificate and
    connection metadata.  All blocking socket I/O is executed inside
    ``asyncio.to_thread`` so the event loop is never blocked.
    """

    @property
    def collector_type(self) -> str:  # noqa: D401
        return "tls"

    async def collect(self, config: dict) -> ScanResults:
        """Scan all configured TLS endpoints concurrently.

        ``config`` must contain:
            endpoints  – list of ``{"host": str, "port": int}`` dicts
            timeout    – (optional) float seconds, default 5.0
        """
        endpoints: list[dict] = config.get("endpoints", [])
        timeout: float = float(config.get("timeout", 5.0))

        log = logger.bind(
            collector="tls",
            endpoint_count=len(endpoints),
            timeout=timeout,
        )
        log.info("tls_collect_start")

        results = ScanResults()
        results.collector_stats["tls"] = {
            "enabled": True,
            "endpoints_configured": len(endpoints),
            "endpoints_successful": 0,
            "endpoints_failed": 0,
            "certificates_discovered": 0,
            "errors": [],
        }
        stats = results.collector_stats["tls"]

        if not endpoints:
            log.warning("tls_collect_no_endpoints")
            return results

        # Fire all endpoint scans concurrently via asyncio.gather.
        tasks = [
            asyncio.to_thread(
                _scan_endpoint_sync,
                ep.get("host", ""),
                int(ep.get("port", 443)),
                timeout,
            )
            for ep in endpoints
        ]
        scan_outcomes: list[TLSScanResult] = await asyncio.gather(
            *tasks, return_exceptions=True
        )

        for idx, outcome in enumerate(scan_outcomes):
            ep = endpoints[idx]
            ep_host = ep.get("host", "unknown")
            ep_port = ep.get("port", 443)

            if isinstance(outcome, BaseException):
                # asyncio.gather returned an unhandled exception object.
                error_msg = f"{ep_host}:{ep_port} — {type(outcome).__name__}: {outcome}"
                log.error("tls_endpoint_exception", endpoint=f"{ep_host}:{ep_port}", error=str(outcome))
                stats["endpoints_failed"] += 1
                stats["errors"].append(error_msg)
                results.errors.append(error_msg)
                results.tls_results.append(
                    TLSScanResult(
                        host=ep_host,
                        port=ep_port,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        error=error_msg,
                    )
                )
                continue

            results.tls_results.append(outcome)

            if outcome.error:
                stats["endpoints_failed"] += 1
                stats["errors"].append(f"{ep_host}:{ep_port} — {outcome.error}")
                results.errors.append(f"{ep_host}:{ep_port} — {outcome.error}")
            else:
                stats["endpoints_successful"] += 1
                # Count certificates: leaf + chain.
                if outcome.certificate:
                    results.certificates.append(outcome.certificate)
                    stats["certificates_discovered"] += 1
                for chain_cert in (outcome.certificate_chain or []):
                    results.certificates.append(chain_cert)
                    stats["certificates_discovered"] += 1

        log.info(
            "tls_collect_complete",
            successful=stats["endpoints_successful"],
            failed=stats["endpoints_failed"],
            certificates=stats["certificates_discovered"],
        )
        return results

    async def health_check(self) -> dict:
        """Return basic health status for the TLS collector.

        The TLS collector has no persistent backend to probe; it simply
        reports that the ssl module is available and which TLS library
        is backing it.
        """
        return {
            "status": "ok",
            "details": {
                "ssl_available": True,
                "tls_library": _detect_tls_library(),
                "pyopenssl_available": PYOPENSSL_AVAILABLE,
            },
        }
