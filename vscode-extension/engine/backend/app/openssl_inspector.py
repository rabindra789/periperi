"""OpenSSL-backed artifact inspection and binary cryptographic fingerprinting."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends.openssl.backend import backend as openssl_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from .detector import make_finding


BINARY_SUFFIXES = {
    ".exe", ".dll", ".so", ".dylib", ".a", ".lib", ".o", ".obj", ".class",
    ".jar", ".war", ".ear", ".wasm", ".bin", ".apk", ".ipa",
}

BINARY_SIGNATURES: list[tuple[str, str, bytes]] = [
    ("Library", "OpenSSL", rb"(?i)(?:OpenSSL|libcrypto|libssl|EVP_[A-Za-z0-9_]+)"),
    ("Library", "libsodium", rb"(?i)(?:libsodium|sodium_init|crypto_secretbox)"),
    ("Algorithm", "MD5", rb"(?i)(?:EVP_md5|MD5_(?:Init|Update|Final)|\bMD5\b)"),
    ("Algorithm", "SHA-1", rb"(?i)(?:EVP_sha1|SHA1_(?:Init|Update|Final)|\bSHA-?1\b)"),
    ("Algorithm", "SHA-256", rb"(?i)(?:EVP_sha256|SHA256_(?:Init|Update|Final)|\bSHA-?256\b)"),
    ("Algorithm", "AES-256-GCM", rb"(?i)(?:EVP_aes_256_gcm|AES-?256-?GCM)"),
    ("Algorithm", "AES-ECB", rb"(?i)(?:EVP_aes_(?:128|192|256)_ecb|AES-?(?:128|192|256)?-?ECB)"),
    ("Algorithm", "RSA", rb"(?i)(?:EVP_PKEY_RSA|RSA_(?:new|sign|verify)|\bRSA\b)"),
    ("Algorithm", "ECDSA", rb"(?i)(?:ECDSA_(?:sign|verify)|\bECDSA\b)"),
    ("Algorithm", "ECDH", rb"(?i)(?:ECDH_compute_key|\bECDH\b)"),
]


def openssl_details() -> dict[str, str]:
    return {
        "provider": "Python cryptography OpenSSL backend",
        "version": openssl_backend.openssl_version_text(),
    }


def _finding(category: str, name: str, relative_path: str, evidence: str, options: Any) -> dict[str, Any]:
    return make_finding(
        category=category,
        name=name,
        path=relative_path,
        line=0,
        evidence=evidence,
        sensitivity=options.sensitivity,
        migration_complexity=options.migration_complexity,
        threat_timeline=options.threat_timeline,
    )


def _key_name(key: Any) -> str | None:
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return f"RSA-{key.key_size}"
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return f"ECC {key.curve.name}"
    if isinstance(key, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        return f"DSA-{key.key_size}"
    return None


def _certificate_findings(cert: x509.Certificate, relative_path: str, options: Any) -> list[dict[str, Any]]:
    signature = getattr(cert.signature_hash_algorithm, "name", "unknown")
    expires = cert.not_valid_after_utc
    subject = cert.subject.rfc4514_string() or "unnamed subject"
    findings = [_finding(
        "Certificate",
        "X.509 certificate",
        relative_path,
        f"OpenSSL parsed certificate: subject={subject[:80]}, expires={expires.date()}, signature={signature}",
        options,
    )]
    key_name = _key_name(cert.public_key())
    if key_name:
        findings.append(_finding("Algorithm", key_name, relative_path, "OpenSSL parsed certificate public key", options))
    if signature.lower() in {"md5", "sha1"}:
        findings.append(_finding("Algorithm", signature.upper().replace("SHA1", "SHA-1"), relative_path, "OpenSSL parsed certificate signature", options))
    return findings


def inspect_crypto_artifact(path: Path, relative_path: str, data: bytes, options: Any) -> list[dict[str, Any]]:
    """Parse certificates and keys with the OpenSSL backend without exposing key material."""
    findings: list[dict[str, Any]] = []
    suffix = path.suffix.lower()

    certificate = None
    try:
        certificate = x509.load_pem_x509_certificate(data) if b"-----BEGIN CERTIFICATE-----" in data else x509.load_der_x509_certificate(data)
    except (ValueError, TypeError):
        pass
    if certificate is not None:
        return _certificate_findings(certificate, relative_path, options)

    if suffix in {".p12", ".pfx"}:
        try:
            key, certificate, extra = pkcs12.load_key_and_certificates(data, None)
            findings.append(_finding("Key", "PKCS#12 key store", relative_path, "OpenSSL parsed PKCS#12 container; key material redacted", options))
            if key_name := _key_name(key):
                findings.append(_finding("Algorithm", key_name, relative_path, "OpenSSL parsed PKCS#12 private key", options))
            if certificate:
                findings.extend(_certificate_findings(certificate, relative_path, options))
            for extra_certificate in extra:
                findings.extend(_certificate_findings(extra_certificate, relative_path, options))
            return findings
        except (ValueError, TypeError):
            return [_finding("Key", "Encrypted or unreadable PKCS#12 key store", relative_path, "OpenSSL could not inspect the container without a password", options)]

    loaders = (
        serialization.load_pem_private_key,
        serialization.load_der_private_key,
    )
    for loader in loaders:
        try:
            key = loader(data, password=None)
            findings.append(_finding("Key", "Private key detected", relative_path, "[key material redacted; validated by OpenSSL]", options))
            if key_name := _key_name(key):
                findings.append(_finding("Algorithm", key_name, relative_path, "OpenSSL parsed private-key parameters", options))
            return findings
        except (ValueError, TypeError):
            continue

    public_loaders = (serialization.load_pem_public_key, serialization.load_der_public_key)
    for loader in public_loaders:
        try:
            key = loader(data)
            findings.append(_finding("Key", "Public key detected", relative_path, "OpenSSL parsed public-key structure", options))
            if key_name := _key_name(key):
                findings.append(_finding("Algorithm", key_name, relative_path, "OpenSSL parsed public-key parameters", options))
            return findings
        except (ValueError, TypeError):
            continue
    return findings


def inspect_binary(relative_path: str, data: bytes, options: Any) -> list[dict[str, Any]]:
    """Find crypto-linked symbols and embedded names without executing the binary."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for category, name, expression in BINARY_SIGNATURES:
        match = re.search(expression, data)
        if match and (category, name) not in seen:
            token = match.group(0).decode("ascii", errors="replace")[:80]
            findings.append(_finding(category, name, relative_path, f"Binary symbol/string: {token}", options))
            seen.add((category, name))
    return findings
