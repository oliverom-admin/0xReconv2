"""EJBCA collector using httpx with P12 client certificate (mTLS)."""

from __future__ import annotations

import ssl
import tempfile
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
import structlog
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption

from recon_collectors.collectors.base import BaseCollector
from recon_collectors.models import CertificateInfo, ScanResults

logger = structlog.get_logger("recon.collectors.ejbca")


def _dn_to_dict(name: x509.Name) -> dict[str, str]:
    """Convert an x509.Name to a flat dict."""
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


def _parse_x509_cert(
    cert: x509.Certificate,
    source: str,
) -> CertificateInfo:
    """Build a CertificateInfo from a cryptography x509.Certificate."""
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

    # CRL distribution points
    crl_dps: list[str] = []
    try:
        dp_ext = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        for dp in dp_ext:
            if dp.full_name:
                for name in dp.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        crl_dps.append(name.value)
    except x509.ExtensionNotFound:
        pass

    # OCSP
    ocsp_urls: list[str] = []
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
        for desc in aia:
            if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                ocsp_urls.append(desc.access_location.value)
    except x509.ExtensionNotFound:
        pass

    # AKI / SKI
    aki: Optional[str] = None
    try:
        aki_ext = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
        if aki_ext.key_identifier:
            aki = aki_ext.key_identifier.hex()
    except x509.ExtensionNotFound:
        pass

    ski: Optional[str] = None
    try:
        ski_ext = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        ski = ski_ext.digest.hex()
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
        crl_distribution_points=crl_dps,
        ocsp_responders=ocsp_urls,
        authority_key_identifier=aki,
        subject_key_identifier=ski,
        is_ca=is_ca,
        is_self_signed=is_self_signed,
        source=source,
    )


def _build_ssl_context(
    p12_path: str,
    p12_password: str,
    verify_ssl: bool,
) -> ssl.SSLContext:
    """Load a PKCS#12 file and build an SSLContext for mTLS."""
    with open(p12_path, "rb") as fh:
        p12_data = fh.read()

    private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
        p12_data, p12_password.encode("utf-8") if p12_password else None
    )

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

    # Write key and cert to temporary files for load_cert_chain.
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as cert_file:
        cert_file.write(certificate.public_bytes(Encoding.PEM))
        if additional_certs:
            for ac in additional_certs:
                cert_file.write(ac.public_bytes(Encoding.PEM))
        cert_path = cert_file.name

    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as key_file:
        key_file.write(
            private_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
        )
        key_path = key_file.name

    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx


class EJBCACollector(BaseCollector):
    """Enumerates CA certificates from an EJBCA instance via REST API."""

    @property
    def collector_type(self) -> str:
        return "ejbca"

    async def collect(self, config: dict) -> ScanResults:
        """Fetch CA list and certificate chains from EJBCA servers."""
        servers = config.get("servers", [])
        results = ScanResults()
        start = datetime.now(tz=timezone.utc)

        for server in servers:
            base_url = server.get("base_url", "").rstrip("/")
            p12_path = server.get("p12_path", "")
            p12_password = server.get("p12_password", "")
            verify_ssl = server.get("verify_ssl", True)

            try:
                ssl_ctx = _build_ssl_context(p12_path, p12_password, verify_ssl)
            except Exception as exc:
                msg = f"SSL context build failed for {base_url}: {exc}"
                results.errors.append(msg)
                logger.error("ejbca.ssl_context_failed", server=base_url, error=str(exc))
                continue

            api_base = f"{base_url}/ejbca/ejbca-rest-api/v1"

            async with httpx.AsyncClient(verify=ssl_ctx, timeout=30.0) as client:
                # Fetch CA list
                try:
                    resp = await client.get(f"{api_base}/ca")
                    resp.raise_for_status()
                    ca_list = resp.json().get("certificate_authorities", [])
                except Exception as exc:
                    msg = f"CA list fetch failed for {base_url}: {exc}"
                    results.errors.append(msg)
                    logger.error("ejbca.ca_list_failed", server=base_url, error=str(exc))
                    continue

                # For each CA, fetch the certificate chain
                for ca in ca_list:
                    ca_name = ca.get("name", "unknown")
                    ca_id = ca.get("id", ca_name)
                    try:
                        chain_resp = await client.get(
                            f"{api_base}/ca/{ca_id}/certificate/download",
                            headers={"Accept": "application/x-pem-file"},
                        )
                        chain_resp.raise_for_status()
                        pem_chain = chain_resp.text

                        pem_certs = self._split_pem_chain(pem_chain)
                        for idx, pem_block in enumerate(pem_certs):
                            try:
                                cert_obj = x509.load_pem_x509_certificate(
                                    pem_block.encode("utf-8")
                                )
                                info = _parse_x509_cert(
                                    cert_obj,
                                    source=f"ejbca/{base_url}/{ca_name}",
                                )
                                info.certificate_pem = pem_block
                                info.certificate_chain = [
                                    f"chain_index_{idx}"
                                ]
                                results.certificates.append(info)
                            except Exception as parse_exc:
                                results.errors.append(
                                    f"PEM parse failed for CA '{ca_name}' cert {idx}: {parse_exc}"
                                )
                    except Exception as exc:
                        results.errors.append(
                            f"Chain fetch failed for CA '{ca_name}' on {base_url}: {exc}"
                        )
                        logger.warning(
                            "ejbca.chain_fetch_failed",
                            server=base_url,
                            ca=ca_name,
                            error=str(exc),
                        )

        elapsed = (datetime.now(tz=timezone.utc) - start).total_seconds()
        results.collector_stats = {
            "collector_type": self.collector_type,
            "servers_scanned": len(servers),
            "certificates_found": len(results.certificates),
            "errors": len(results.errors),
            "elapsed_seconds": round(elapsed, 3),
        }
        logger.info(
            "ejbca.collect_complete",
            certificates=len(results.certificates),
            servers=len(servers),
            elapsed=round(elapsed, 3),
        )
        return results

    async def health_check(self) -> dict:
        """Verify httpx and cryptography imports are available."""
        try:
            import httpx as _httpx  # noqa: F401
            from cryptography.hazmat.primitives.serialization import pkcs12 as _p12  # noqa: F401

            return {"status": "ok", "details": {"dependencies": "available"}}
        except ImportError as exc:
            return {"status": "error", "details": {"error": str(exc)}}

    @staticmethod
    def _split_pem_chain(pem_text: str) -> list[str]:
        """Split a PEM bundle into individual PEM blocks."""
        blocks: list[str] = []
        current: list[str] = []
        for line in pem_text.splitlines():
            if line.strip().startswith("-----BEGIN"):
                current = [line]
            elif line.strip().startswith("-----END"):
                current.append(line)
                blocks.append("\n".join(current))
                current = []
            elif current:
                current.append(line)
        return blocks
