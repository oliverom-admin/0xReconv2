"""
CBOMExportService — CycloneDX 1.6+ Cryptographic Bill of Materials export.

Pure data transformation: no database calls, no async.
All methods are @classmethod on the class.

Reference: docs/reference/legacy_cbom_export_service.py
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger("recon.cbom")


class CBOMExportService:
    SPEC_VERSION = "1.6"
    BOM_FORMAT = "CycloneDX"

    # ── Signature algorithm OIDs ──────────────────────────────
    SIGNATURE_ALGORITHM_OIDS: dict[str, str] = {
        "sha1WithRSAEncryption": "1.2.840.113549.1.1.5",
        "sha256WithRSAEncryption": "1.2.840.113549.1.1.11",
        "sha384WithRSAEncryption": "1.2.840.113549.1.1.12",
        "sha512WithRSAEncryption": "1.2.840.113549.1.1.13",
        "RSASSA-PSS": "1.2.840.113549.1.1.10",
        "rsaEncryption": "1.2.840.113549.1.1.1",
        "ecdsa-with-SHA1": "1.2.840.10045.4.1",
        "ecdsa-with-SHA256": "1.2.840.10045.4.3.2",
        "ecdsa-with-SHA384": "1.2.840.10045.4.3.3",
        "ecdsa-with-SHA512": "1.2.840.10045.4.3.4",
        "Ed25519": "1.3.101.112",
        "ED25519": "1.3.101.112",
        "Ed448": "1.3.101.113",
        "ED448": "1.3.101.113",
        "dsa-with-sha1": "1.2.840.10040.4.3",
        "dsa-with-sha224": "2.16.840.1.101.3.4.3.1",
        "dsa-with-sha256": "2.16.840.1.101.3.4.3.2",
        "ML-DSA-44": "2.16.840.1.101.3.4.3.17",
        "ML-DSA-65": "2.16.840.1.101.3.4.3.18",
        "ML-DSA-87": "2.16.840.1.101.3.4.3.19",
        "SLH-DSA-SHA2-128s": "2.16.840.1.101.3.4.3.20",
        "SLH-DSA-SHA2-128f": "2.16.840.1.101.3.4.3.21",
        "SLH-DSA-SHA2-192s": "2.16.840.1.101.3.4.3.22",
        "SLH-DSA-SHA2-192f": "2.16.840.1.101.3.4.3.23",
        "SLH-DSA-SHA2-256s": "2.16.840.1.101.3.4.3.24",
        "SLH-DSA-SHA2-256f": "2.16.840.1.101.3.4.3.25",
        "SLH-DSA-SHAKE-128s": "2.16.840.1.101.3.4.3.26",
        "SLH-DSA-SHAKE-128f": "2.16.840.1.101.3.4.3.27",
        "SLH-DSA-SHAKE-192s": "2.16.840.1.101.3.4.3.28",
        "SLH-DSA-SHAKE-192f": "2.16.840.1.101.3.4.3.29",
        "SLH-DSA-SHAKE-256s": "2.16.840.1.101.3.4.3.30",
        "SLH-DSA-SHAKE-256f": "2.16.840.1.101.3.4.3.31",
        "ECDSA-P256-ML-DSA-44": "2.16.840.1.114027.80.8.1.1",
        "ECDSA-P384-ML-DSA-65": "2.16.840.1.114027.80.8.1.2",
        "ECDSA-P521-ML-DSA-87": "2.16.840.1.114027.80.8.1.3",
    }

    # ── Key algorithm OIDs ────────────────────────────────────
    KEY_ALGORITHM_OIDS: dict[str, str] = {
        "RSA": "1.2.840.113549.1.1.1",
        "rsaEncryption": "1.2.840.113549.1.1.1",
        "EC": "1.2.840.10045.2.1",
        "id-ecPublicKey": "1.2.840.10045.2.1",
        "ECDSA": "1.2.840.10045.2.1",
        "secp256r1": "1.2.840.10045.3.1.7",
        "P-256": "1.2.840.10045.3.1.7",
        "prime256v1": "1.2.840.10045.3.1.7",
        "secp384r1": "1.3.132.0.34",
        "P-384": "1.3.132.0.34",
        "secp521r1": "1.3.132.0.35",
        "P-521": "1.3.132.0.35",
        "Ed25519": "1.3.101.112",
        "Ed448": "1.3.101.113",
        "X25519": "1.3.101.110",
        "X448": "1.3.101.111",
        "ML-KEM-512": "2.16.840.1.101.3.4.4.1",
        "ML-KEM-768": "2.16.840.1.101.3.4.4.2",
        "ML-KEM-1024": "2.16.840.1.101.3.4.4.3",
    }

    # ── TLS protocol info ─────────────────────────────────────
    TLS_PROTOCOL_INFO: dict[str, dict[str, Any]] = {
        "TLSv1.0": {"version": "1.0", "oid": None, "deprecated": True},
        "TLSv1.1": {"version": "1.1", "oid": None, "deprecated": True},
        "TLSv1.2": {"version": "1.2", "oid": None, "deprecated": False},
        "TLSv1.3": {"version": "1.3", "oid": None, "deprecated": False},
        "TLS 1.0": {"version": "1.0", "oid": None, "deprecated": True},
        "TLS 1.1": {"version": "1.1", "oid": None, "deprecated": True},
        "TLS 1.2": {"version": "1.2", "oid": None, "deprecated": False},
        "TLS 1.3": {"version": "1.3", "oid": None, "deprecated": False},
    }

    # ── Public interface ──────────────────────────────────────

    @classmethod
    def export_scan_results(
        cls,
        certificates: list[dict],
        keys: list[dict] | None = None,
        tls_results: list[dict] | None = None,
        metadata: dict | None = None,
    ) -> dict[str, Any]:
        """Export scan results to CycloneDX 1.6+ CBOM format."""
        keys = keys or []
        tls_results = tls_results or []
        metadata = metadata or {}

        components: list[dict] = []
        dependencies: list[dict] = []
        algorithm_tracker: dict[str, dict] = {}
        protocol_tracker: dict[str, dict] = {}

        # Process certificates
        for cert in certificates:
            try:
                comp, algos, protos = cls._build_certificate_component(cert)
                if comp:
                    components.append(comp)
                    dep_refs = []
                    for algo_key, algo_data in algos.items():
                        if algo_key not in algorithm_tracker:
                            algorithm_tracker[algo_key] = algo_data
                        dep_refs.append(algo_key)
                    for proto_key, proto_data in protos.items():
                        if proto_key not in protocol_tracker:
                            protocol_tracker[proto_key] = proto_data
                        dep_refs.append(proto_key)
                    if dep_refs:
                        dependencies.append({
                            "ref": comp["bom-ref"],
                            "dependsOn": dep_refs,
                        })
            except (KeyError, TypeError, ValueError) as exc:
                logger.warning("cbom_cert_build_failed", error=str(exc))

        # Process keys
        for key in keys:
            try:
                comp, algos = cls._build_key_component(key)
                if comp:
                    components.append(comp)
                    dep_refs = []
                    for algo_key, algo_data in algos.items():
                        if algo_key not in algorithm_tracker:
                            algorithm_tracker[algo_key] = algo_data
                        dep_refs.append(algo_key)
                    if dep_refs:
                        dependencies.append({
                            "ref": comp["bom-ref"],
                            "dependsOn": dep_refs,
                        })
            except (KeyError, TypeError, ValueError) as exc:
                logger.warning("cbom_key_build_failed", error=str(exc))

        # Process TLS results for protocol extraction
        for tls in tls_results:
            protos = cls._extract_tls_protocols(tls)
            for proto_key, proto_data in protos.items():
                if proto_key not in protocol_tracker:
                    protocol_tracker[proto_key] = proto_data

        # Build algorithm components (deduplicated)
        for algo_ref, algo_data in algorithm_tracker.items():
            try:
                algo_comp = cls._build_algorithm_component(algo_ref, algo_data)
                if algo_comp:
                    components.append(algo_comp)
            except (KeyError, TypeError, ValueError) as exc:
                logger.warning("cbom_algo_build_failed",
                               algo_ref=algo_ref, error=str(exc))

        # Build protocol components (deduplicated)
        for proto_ref, proto_data in protocol_tracker.items():
            try:
                proto_comp = cls._build_protocol_component(proto_ref, proto_data)
                if proto_comp:
                    components.append(proto_comp)
            except (KeyError, TypeError, ValueError) as exc:
                logger.warning("cbom_proto_build_failed",
                               proto_ref=proto_ref, error=str(exc))

        bom: dict[str, Any] = {
            "bomFormat": cls.BOM_FORMAT,
            "specVersion": cls.SPEC_VERSION,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": cls._build_metadata(metadata, certificates, keys),
            "components": components,
            "dependencies": dependencies,
        }
        return bom

    # ── Component builders ────────────────────────────────────

    @classmethod
    def _build_certificate_component(
        cls, cert: dict,
    ) -> tuple[dict, dict, dict]:
        """Build a certificate component. Returns (component, algos, protocols)."""
        fp = (cert.get("fingerprint_sha256") or cert.get("fingerprint") or "")
        fp = fp.lower().replace(":", "")
        bom_ref = f"cert-{fp[:16]}" if fp else f"cert-{uuid.uuid4().hex[:16]}"

        subject_dn = cls._format_dn(cert.get("subject"))
        issuer_dn = cls._format_dn(cert.get("issuer"))
        subject_cn = cert.get("subject_cn") or ""
        if not subject_cn and isinstance(cert.get("subject"), dict):
            subject_cn = cert["subject"].get("CN", "")

        component: dict[str, Any] = {
            "type": "crypto-asset",
            "bom-ref": bom_ref,
            "name": subject_cn or subject_dn or "Unknown Certificate",
            "cryptoProperties": {
                "assetType": "certificate",
                "certificateProperties": {
                    "subjectName": subject_dn,
                    "issuerName": issuer_dn,
                    "notValidBefore": cert.get("not_before") or cert.get("not_valid_before", ""),
                    "notValidAfter": cert.get("not_after") or cert.get("not_valid_after", ""),
                    "signatureAlgorithm": cert.get("signature_algorithm", ""),
                    "subjectPublicKeyAlgorithm": cert.get("public_key_algorithm", ""),
                },
            },
        }

        # Add fingerprint as property
        if fp:
            component["properties"] = [
                {"name": "fingerprint:sha256", "value": fp},
            ]

        # Evidence
        evidence = cls._build_evidence(cert)
        if evidence:
            component["evidence"] = evidence

        # Collect algorithms for this cert
        algos: dict[str, dict] = {}
        sig_algo = cert.get("signature_algorithm", "")
        if sig_algo:
            algo_ref = f"algo-sig-{cls._normalize_algo_name(sig_algo)}"
            algos[algo_ref] = {
                "name": sig_algo,
                "type": "signature",
                "oid": cls._get_algorithm_oid(sig_algo, "signature"),
            }

        key_algo = cert.get("public_key_algorithm", "")
        if key_algo:
            key_size = cert.get("public_key_size") or cert.get("key_size")
            ref_suffix = f"-{key_size}" if key_size else ""
            algo_ref = f"algo-key-{cls._normalize_algo_name(key_algo)}{ref_suffix}"
            algos[algo_ref] = {
                "name": key_algo,
                "type": "key",
                "oid": cls._get_algorithm_oid(key_algo, "key"),
                "key_size": key_size,
            }

        # Collect protocols
        protos: dict[str, dict] = {}
        tls_ver = cert.get("tls_version")
        if tls_ver and tls_ver in cls.TLS_PROTOCOL_INFO:
            proto_ref = f"proto-tls-{tls_ver.replace('.', '-').replace(' ', '')}"
            protos[proto_ref] = cls.TLS_PROTOCOL_INFO[tls_ver]

        return component, algos, protos

    @classmethod
    def _build_key_component(
        cls, key: dict,
    ) -> tuple[dict, dict]:
        """Build a key component. Returns (component, algos)."""
        kid = (key.get("key_id") or key.get("name") or
               key.get("label") or key.get("id") or "")
        bom_ref = f"key-{kid[-32:]}" if kid else f"key-{uuid.uuid4().hex[:16]}"

        key_type = key.get("key_type") or key.get("kty") or "Unknown"
        key_size = key.get("key_size")
        name = key.get("name") or key.get("label") or kid or "Unknown Key"

        component: dict[str, Any] = {
            "type": "crypto-asset",
            "bom-ref": bom_ref,
            "name": name,
            "cryptoProperties": {
                "assetType": "related-crypto-material",
                "relatedCryptoMaterialProperties": {
                    "type": key_type,
                    "size": key_size,
                },
            },
        }

        # HSM-backed key
        if key.get("is_hardware_protected") or key.get("hsm_backed") or key.get("is_hsm_backed"):
            component["cryptoProperties"]["relatedCryptoMaterialProperties"]["securedBy"] = {
                "mechanism": "hardware-security-module",
            }

        # PQC properties
        pqc = key.get("pqc_analysis")
        if pqc:
            props = cls._build_pqc_properties(pqc)
            if props:
                component.setdefault("properties", []).extend(props)

        # Evidence
        evidence = cls._build_key_evidence(key)
        if evidence:
            component["evidence"] = evidence

        # Algorithms
        algos: dict[str, dict] = {}
        if key_type and key_type != "Unknown":
            ref_suffix = f"-{key_size}" if key_size else ""
            algo_ref = f"algo-key-{cls._normalize_algo_name(key_type)}{ref_suffix}"
            algos[algo_ref] = {
                "name": key_type,
                "type": "key",
                "oid": cls._get_algorithm_oid(key_type, "key"),
                "key_size": key_size,
            }

        return component, algos

    @classmethod
    def _build_algorithm_component(
        cls, algo_ref: str, algo_data: dict,
    ) -> dict[str, Any]:
        """Build an algorithm component."""
        name = algo_data.get("name", "Unknown")
        oid = algo_data.get("oid")
        algo_type = algo_data.get("type", "signature")
        key_size = algo_data.get("key_size")

        component: dict[str, Any] = {
            "type": "crypto-asset",
            "bom-ref": algo_ref,
            "name": name,
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": cls._get_algorithm_primitive(name),
                    "cryptoFunctions": cls._infer_crypto_functions(name, algo_type),
                },
            },
        }

        if oid:
            component["cryptoProperties"]["oid"] = oid

        if key_size:
            sec_level = cls._estimate_classical_security_level(name, key_size)
            if sec_level:
                component["cryptoProperties"]["algorithmProperties"][
                    "classicalSecurityLevel"
                ] = sec_level

        return component

    @classmethod
    def _build_protocol_component(
        cls, proto_ref: str, proto_data: dict,
    ) -> dict[str, Any]:
        """Build a protocol component."""
        version = proto_data.get("version", "")
        deprecated = proto_data.get("deprecated", False)

        return {
            "type": "crypto-asset",
            "bom-ref": proto_ref,
            "name": f"TLS {version}",
            "cryptoProperties": {
                "assetType": "protocol",
                "protocolProperties": {
                    "type": "tls",
                    "version": version,
                },
            },
            "properties": [
                {"name": "deprecated", "value": str(deprecated).lower()},
            ],
        }

    # ── Metadata builder ──────────────────────────────────────

    @classmethod
    def _build_metadata(
        cls, metadata: dict, certificates: list, keys: list,
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        return {
            "timestamp": now,
            "tools": [{
                "vendor": "0xRecon",
                "name": "0xRecon CBOM Generator",
                "version": "1.0.0",
            }],
            "component": {
                "type": "application",
                "name": metadata.get("project_name", "0xRecon Scan"),
                "version": "1.0.0",
            },
            "properties": [
                {"name": "certificates_count", "value": str(len(certificates))},
                {"name": "keys_count", "value": str(len(keys))},
            ],
        }

    # ── Evidence builders ─────────────────────────────────────

    @classmethod
    def _build_evidence(cls, cert: dict) -> dict | None:
        occurrences = []
        host = cert.get("found_at_destination") or cert.get("host")
        port = cert.get("found_on_port") or cert.get("port")
        if host:
            loc = f"{host}:{port}" if port else host
            occurrences.append({"location": loc})

        source = cert.get("source") or cert.get("source_type")
        if source:
            occurrences.append({"location": f"source:{source}"})

        return {"occurrences": occurrences} if occurrences else None

    @classmethod
    def _build_key_evidence(cls, key: dict) -> dict | None:
        occurrences = []
        source = key.get("source") or key.get("source_type")
        if source:
            occurrences.append({"location": f"source:{source}"})
        vault = key.get("azure_vault_name")
        if vault:
            occurrences.append({"location": f"azure-keyvault:{vault}"})
        return {"occurrences": occurrences} if occurrences else None

    @classmethod
    def _build_pqc_properties(cls, pqc: dict) -> list[dict]:
        props = []
        if pqc.get("classification"):
            props.append({"name": "pqc:classification",
                          "value": pqc["classification"]})
        if pqc.get("algorithm"):
            props.append({"name": "pqc:algorithm", "value": pqc["algorithm"]})
        if pqc.get("migration_status"):
            props.append({"name": "pqc:migration_status",
                          "value": pqc["migration_status"]})
        return props

    # ── Helper methods ────────────────────────────────────────

    @classmethod
    def _get_algorithm_oid(
        cls, algo_name: str, algo_type: str = "signature",
    ) -> str | None:
        if algo_type == "signature":
            return cls.SIGNATURE_ALGORITHM_OIDS.get(algo_name)
        return cls.KEY_ALGORITHM_OIDS.get(algo_name)

    @classmethod
    def _normalize_algo_name(cls, algo_name: str) -> str:
        return (algo_name.lower()
                .replace(" ", "")
                .replace("-", "")
                .replace("_", ""))

    @classmethod
    def _format_dn(cls, dn: Any) -> str:
        if dn is None:
            return ""
        if isinstance(dn, str):
            return dn
        if isinstance(dn, dict):
            parts = []
            # Preserve standard DN ordering
            order = ["CN", "commonName", "O", "organizationName",
                     "OU", "organizationalUnitName", "L", "localityName",
                     "ST", "stateOrProvinceName", "C", "countryName"]
            seen = set()
            for key in order:
                if key in dn and key not in seen:
                    parts.append(f"{key}={dn[key]}")
                    seen.add(key)
            for key, val in dn.items():
                if key not in seen:
                    parts.append(f"{key}={val}")
            return ", ".join(parts)
        return str(dn)

    @classmethod
    def _infer_crypto_functions(
        cls, algo_name: str, algo_type: str,
    ) -> list[str]:
        name = algo_name.lower()
        functions = []
        if algo_type == "signature" or "sign" in name or "dsa" in name:
            functions.append("sign")
        if "rsa" in name or "encrypt" in name or "kem" in name:
            functions.append("encrypt")
        if "sha" in name or "md5" in name or "hash" in name:
            functions.append("digest")
        if "ecdh" in name or "dh" in name or "x25519" in name or "x448" in name:
            functions.append("keyagree")
        if "kem" in name:
            functions.append("encapsulate")
        if not functions:
            functions.append("other")
        return functions

    @classmethod
    def _get_algorithm_primitive(cls, algo_name: str) -> str:
        name = algo_name.lower()
        if "rsa" in name:
            return "public-key-encryption"
        if "ec" in name or "ecdsa" in name or "ed25519" in name or "ed448" in name:
            return "signature"
        if "dsa" in name and "ec" not in name:
            return "signature"
        if "sha" in name:
            return "hash"
        if "aes" in name:
            return "block-cipher"
        if "kem" in name:
            return "key-encapsulation-mechanism"
        if "slh" in name:
            return "signature"
        if "ml-dsa" in name:
            return "signature"
        return "other"

    @classmethod
    def _estimate_classical_security_level(
        cls, algo_name: str, key_size: int | None,
    ) -> int | None:
        if key_size is None:
            return None
        name = algo_name.lower()
        if "rsa" in name:
            if key_size >= 4096:
                return 128
            if key_size >= 3072:
                return 128
            if key_size >= 2048:
                return 112
            if key_size >= 1024:
                return 80
            return 64
        if "ec" in name or "ecdsa" in name or "ed" in name:
            if key_size >= 521:
                return 256
            if key_size >= 384:
                return 192
            if key_size >= 256:
                return 128
            return 80
        return None

    @classmethod
    def _extract_tls_protocols(cls, tls_result: dict) -> dict[str, dict]:
        protos: dict[str, dict] = {}
        # Check supported_tls_versions list
        versions = tls_result.get("supported_tls_versions") or []
        if isinstance(versions, list):
            for ver in versions:
                if ver in cls.TLS_PROTOCOL_INFO:
                    ref = f"proto-tls-{ver.replace('.', '-').replace(' ', '')}"
                    protos[ref] = cls.TLS_PROTOCOL_INFO[ver]
        # Check single tls_version field
        ver = tls_result.get("tls_version")
        if ver and ver in cls.TLS_PROTOCOL_INFO:
            ref = f"proto-tls-{ver.replace('.', '-').replace(' ', '')}"
            protos[ref] = cls.TLS_PROTOCOL_INFO[ver]
        return protos
