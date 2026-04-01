"""
PQCService — Post-Quantum Cryptography detection.
Classifies algorithms as: vulnerable | transitioning | safe | unknown
Zero external dependencies — stdlib only.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

PQCStatus = Literal["vulnerable", "transitioning", "safe", "unknown"]

VULNERABLE_OIDS: dict[str, str] = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.10045.2.1": "id-ecPublicKey",
    "1.2.840.10040.4.1": "DSA",
    "1.2.840.10040.4.3": "dsa-with-sha1",
    "2.16.840.1.101.3.4.3.2": "id-dsa-with-sha256",
    "1.2.840.113549.1.3.1": "dhKeyAgreement",
}

SAFE_OIDS: dict[str, str] = {
    "2.16.840.1.101.3.4.4.1": "ML-KEM-512",
    "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
    "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
    "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
    "1.3.101.110": "X25519",
    "1.3.101.111": "X448",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}

TRANSITIONING_OIDS: dict[str, str] = {
    "1.3.6.1.4.1.44363.45.6": "id-MLKEM768-X25519-SHA256",
    "1.3.6.1.4.1.44363.45.9": "id-MLDSA65-ECDSA-P256",
}

_VULNERABLE_PATTERNS = [
    "rsa", "ec", "ecdsa", "ecdh", "dsa", "dh",
    "p-256", "p-384", "p-521", "secp256", "secp384",
    "prime256v1", "brainpool",
]
_SAFE_PATTERNS = [
    "kyber", "dilithium", "sphincs", "falcon",
    "ml-kem", "ml-dsa", "slh-dsa",
    "x25519", "x448", "ed25519", "ed448",
    "crystals", "ntru", "saber",
]
_TRANSITIONING_PATTERNS = ["hybrid", "composite", "pqc-hybrid"]


@dataclass
class PQCResult:
    status: PQCStatus
    algorithm_name: str
    oid: str | None = None
    reason: str = ""


class PQCService:
    @staticmethod
    def classify_oid(oid: str) -> PQCResult:
        if oid in SAFE_OIDS:
            return PQCResult("safe", SAFE_OIDS[oid], oid, "PQC-safe algorithm")
        if oid in TRANSITIONING_OIDS:
            return PQCResult("transitioning", TRANSITIONING_OIDS[oid], oid, "Hybrid/transitioning scheme")
        if oid in VULNERABLE_OIDS:
            return PQCResult("vulnerable", VULNERABLE_OIDS[oid], oid, "Vulnerable to Shor's algorithm")
        return PQCResult("unknown", oid, oid, "OID not in classification database")

    @staticmethod
    def classify_name(name: str) -> PQCResult:
        lower = name.lower()
        # Check transitioning BEFORE safe — hybrid schemes contain safe algorithm
        # names (e.g. "RSA-Kyber-Hybrid" contains "kyber") but should classify
        # as transitioning, not safe.
        for pat in _TRANSITIONING_PATTERNS:
            if pat in lower:
                return PQCResult("transitioning", name, None, f"Matches transitioning pattern '{pat}'")
        for pat in _SAFE_PATTERNS:
            if pat in lower:
                return PQCResult("safe", name, None, f"Matches PQC-safe pattern '{pat}'")
        for pat in _VULNERABLE_PATTERNS:
            if pat in lower:
                return PQCResult("vulnerable", name, None, f"Matches vulnerable pattern '{pat}'")
        return PQCResult("unknown", name, None, "No pattern matched")

    @staticmethod
    def classify(oid: str | None, algorithm_name: str | None) -> PQCResult:
        if oid:
            r = PQCService.classify_oid(oid)
            if r.status != "unknown":
                return r
        if algorithm_name:
            return PQCService.classify_name(algorithm_name)
        return PQCResult("unknown", algorithm_name or oid or "", None, "No OID or name provided")

    @staticmethod
    def is_vulnerable(oid: str | None, algorithm_name: str | None) -> bool:
        return PQCService.classify(oid, algorithm_name).status == "vulnerable"
