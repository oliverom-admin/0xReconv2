"""Azure Key Vault collector using the async Azure SDK."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

import structlog
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from recon_collectors.collectors.base import BaseCollector
from recon_collectors.models import CertificateInfo, KeyInfo, ScanResults

logger = structlog.get_logger("recon.collectors.azure_keyvault")


def _dn_to_dict(name: x509.Name) -> dict[str, str]:
    """Convert an x509.Name to a flat dict of its attributes."""
    result: dict[str, str] = {}
    for attr in name:
        oid_dot = attr.oid.dotted_string
        friendly = attr.oid._name if hasattr(attr.oid, "_name") else oid_dot
        result[friendly] = attr.value
    return result


def _days_until(dt: Optional[datetime]) -> Optional[int]:
    """Return days from now until *dt*, or None."""
    if dt is None:
        return None
    now = datetime.now(tz=timezone.utc)
    target = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return (target - now).days


def _parse_x509(
    der_bytes: bytes,
    source: str,
    vault_name: str,
) -> Optional[CertificateInfo]:
    """Parse DER-encoded X.509 bytes into a CertificateInfo."""
    try:
        cert = x509.load_der_x509_certificate(der_bytes)
    except Exception as exc:
        logger.warning("azure_keyvault.x509_parse_failed", source=source, error=str(exc))
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

    # Extended key usage
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
        san_list += san_ext.get_values_for_type(x509.RFC822Name)
        san_list += san_ext.get_values_for_type(x509.UniformResourceIdentifier)
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

    # OCSP responders
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

    # Public key info
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

    is_self_signed = cert.issuer == cert.subject

    return CertificateInfo(
        serial_number=format(cert.serial_number, "x"),
        fingerprint_sha256=cert.fingerprint(
            cert.signature_hash_algorithm or x509.hashes.SHA256()
        ).hex() if cert.signature_hash_algorithm else None,
        subject=_dn_to_dict(cert.subject),
        issuer=_dn_to_dict(cert.issuer),
        not_before=cert.not_valid_before_utc
        if hasattr(cert, "not_valid_before_utc")
        else cert.not_valid_before,
        not_after=cert.not_valid_after_utc
        if hasattr(cert, "not_valid_after_utc")
        else cert.not_valid_after,
        days_until_expiry=_days_until(
            cert.not_valid_after_utc
            if hasattr(cert, "not_valid_after_utc")
            else cert.not_valid_after
        ),
        is_expired=(
            _days_until(
                cert.not_valid_after_utc
                if hasattr(cert, "not_valid_after_utc")
                else cert.not_valid_after
            )
            or 0
        )
        < 0,
        signature_algorithm=cert.signature_algorithm_oid._name
        if hasattr(cert.signature_algorithm_oid, "_name")
        else cert.signature_algorithm_oid.dotted_string,
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
        azure_metadata={"vault_name": vault_name},
    )


class AzureKeyVaultCollector(BaseCollector):
    """Enumerates certificates and keys from Azure Key Vault."""

    @property
    def collector_type(self) -> str:
        return "azure_keyvault"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_credential(tenancy: dict) -> Any:
        """Build an async Azure credential for the given tenancy config."""
        tenant_id = tenancy.get("tenant_id")
        client_id = tenancy.get("client_id")
        client_secret = tenancy.get("client_secret")

        if tenant_id and client_id and client_secret:
            from azure.identity.aio import ClientSecretCredential

            return ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )
        from azure.identity.aio import DefaultAzureCredential

        return DefaultAzureCredential()

    async def _collect_certificates(
        self,
        vault_url: str,
        vault_name: str,
        credential: Any,
    ) -> tuple[list[CertificateInfo], list[str]]:
        """Enumerate certificates in a single vault."""
        from azure.keyvault.certificates.aio import CertificateClient

        certs: list[CertificateInfo] = []
        errors: list[str] = []
        client = CertificateClient(vault_url=vault_url, credential=credential)
        try:
            async for props in client.list_properties_of_certificates():
                try:
                    cert_bundle = await client.get_certificate(props.name)
                    der_bytes = cert_bundle.cer
                    if der_bytes:
                        info = _parse_x509(
                            der_bytes,
                            source=f"azure_keyvault/{vault_name}/{props.name}",
                            vault_name=vault_name,
                        )
                        if info is not None:
                            info.azure_metadata.update(
                                {
                                    "certificate_name": props.name,
                                    "vault_url": vault_url,
                                    "enabled": props.enabled,
                                    "version": cert_bundle.properties.version,
                                }
                            )
                            certs.append(info)
                except Exception as exc:
                    errors.append(f"Certificate '{props.name}' in {vault_name}: {exc}")
                    logger.warning(
                        "azure_keyvault.cert_failed",
                        vault=vault_name,
                        cert=props.name,
                        error=str(exc),
                    )
        except Exception as exc:
            errors.append(f"Certificate listing for {vault_name}: {exc}")
            logger.error(
                "azure_keyvault.cert_list_failed", vault=vault_name, error=str(exc)
            )
        finally:
            await client.close()
        return certs, errors

    async def _collect_keys(
        self,
        vault_url: str,
        vault_name: str,
        credential: Any,
    ) -> tuple[list[KeyInfo], list[str]]:
        """Enumerate keys in a single vault."""
        from azure.keyvault.keys.aio import KeyClient

        keys: list[KeyInfo] = []
        errors: list[str] = []
        client = KeyClient(vault_url=vault_url, credential=credential)
        try:
            async for props in client.list_properties_of_keys():
                try:
                    key_bundle = await client.get_key(props.name)
                    jwk = key_bundle.key

                    key_type = jwk.kty.value if jwk and jwk.kty else None
                    key_size: Optional[int] = None
                    key_curve: Optional[str] = None

                    if jwk and jwk.n:
                        key_size = len(jwk.n) * 8
                    if jwk and hasattr(jwk, "crv") and jwk.crv:
                        key_curve = jwk.crv.value if hasattr(jwk.crv, "value") else str(jwk.crv)

                    ops = [op.value if hasattr(op, "value") else str(op) for op in (props.key_operations or [])]

                    info = KeyInfo(
                        key_id=props.id,
                        label=props.name,
                        source_type="azure_keyvault",
                        source=f"azure_keyvault/{vault_name}/{props.name}",
                        key_type=key_type,
                        key_size=key_size,
                        key_curve=key_curve,
                        is_enabled=props.enabled or False,
                        is_hardware_protected=(
                            key_type.endswith("-HSM") if key_type else False
                        ),
                        can_encrypt="encrypt" in ops,
                        can_decrypt="decrypt" in ops,
                        can_sign="sign" in ops,
                        can_verify="verify" in ops,
                        can_wrap="wrapKey" in ops,
                        can_unwrap="unwrapKey" in ops,
                        created_on=props.created_on,
                        expires_on=props.expires_on,
                        not_before=props.not_before,
                        days_until_expiry=_days_until(props.expires_on),
                        azure_metadata={
                            "vault_name": vault_name,
                            "vault_url": vault_url,
                            "version": props.version,
                            "key_operations": ops,
                        },
                    )
                    keys.append(info)
                except Exception as exc:
                    errors.append(f"Key '{props.name}' in {vault_name}: {exc}")
                    logger.warning(
                        "azure_keyvault.key_failed",
                        vault=vault_name,
                        key=props.name,
                        error=str(exc),
                    )
        except Exception as exc:
            errors.append(f"Key listing for {vault_name}: {exc}")
            logger.error(
                "azure_keyvault.key_list_failed", vault=vault_name, error=str(exc)
            )
        finally:
            await client.close()
        return keys, errors

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def collect(self, config: dict) -> ScanResults:
        """Enumerate certificates and keys across configured Azure tenancies."""
        tenancies = config.get("tenancies", [])
        results = ScanResults()
        start = datetime.now(tz=timezone.utc)

        for tenancy in tenancies:
            credential = self._build_credential(tenancy)
            try:
                for vault in tenancy.get("vaults", []):
                    vault_url = vault.get("url", "")
                    vault_name = vault.get("name", vault_url)

                    certs, cert_errors = await self._collect_certificates(
                        vault_url, vault_name, credential
                    )
                    results.certificates.extend(certs)
                    results.errors.extend(cert_errors)

                    keys, key_errors = await self._collect_keys(
                        vault_url, vault_name, credential
                    )
                    results.keys.extend(keys)
                    results.errors.extend(key_errors)
            finally:
                await credential.close()

        elapsed = (datetime.now(tz=timezone.utc) - start).total_seconds()
        results.collector_stats = {
            "collector_type": self.collector_type,
            "tenancies_scanned": len(tenancies),
            "certificates_found": len(results.certificates),
            "keys_found": len(results.keys),
            "errors": len(results.errors),
            "elapsed_seconds": round(elapsed, 3),
        }
        logger.info(
            "azure_keyvault.collect_complete",
            certificates=len(results.certificates),
            keys=len(results.keys),
            elapsed=round(elapsed, 3),
        )
        return results

    async def health_check(self) -> dict:
        """Verify Azure SDK imports are available."""
        try:
            from azure.identity.aio import DefaultAzureCredential  # noqa: F401
            from azure.keyvault.certificates.aio import CertificateClient  # noqa: F401
            from azure.keyvault.keys.aio import KeyClient  # noqa: F401

            return {"status": "ok", "details": {"sdk": "available"}}
        except ImportError as exc:
            return {"status": "error", "details": {"error": f"Missing SDK: {exc}"}}
