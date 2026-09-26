"""OpenSSL-backed artifact inspection and binary cryptographic fingerprinting."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends.openssl.backend import backend as openssl_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa, x25519, x448
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtensionOID

from .detector import make_finding


BINARY_SUFFIXES = {
    ".exe", ".dll", ".so", ".dylib", ".a", ".lib", ".o", ".obj", ".class",
    ".jar", ".war", ".ear", ".wasm", ".bin", ".apk", ".ipa",
}

#: A certificate inside this window is reported as expiring rather than expired.
EXPIRY_WARNING = timedelta(days=30)

#: RSA public exponents below this are trivially breakable, per SP 800-56B.
MINIMUM_RSA_EXPONENT = 65537

#: OpenSSH public keys are the only non-PEM text keys the inspector decodes.
SSH_PUBLIC_KEY_PREFIXES = (b"ssh-", b"ecdsa-sha2-", b"sk-ssh-", b"sk-ecdsa-sha2-")


def _looks_like_ssh_public_key(data: bytes) -> bool:
    return data.lstrip().startswith(SSH_PUBLIC_KEY_PREFIXES)

BINARY_SIGNATURES: list[tuple[str, str, bytes]] = [
    ("Library", "OpenSSL", rb"(?i)(?:OpenSSL|libcrypto|libssl|EVP_[A-Za-z0-9_]+)"),
    ("Library", "libsodium", rb"(?i)(?:libsodium|sodium_init|crypto_secretbox)"),
    ("Algorithm", "MD5", rb"(?i)(?:EVP_md5|MD5_(?:Init|Update|Final)|\bMD5\b)"),
    ("Algorithm", "SHA-1", rb"(?i)(?:EVP_sha1|SHA1_(?:Init|Update|Final)|\bSHA-?1\b)"),
    ("Algorithm", "SHA-256", rb"(?i)(?:EVP_sha256|SHA256_(?:Init|Update|Final)|\bSHA-?256\b)"),
    ("Algorithm", "SHA-384", rb"(?i)(?:EVP_sha384|SHA384_(?:Init|Update|Final)|\bSHA-?384\b)"),
    ("Algorithm", "SHA-512", rb"(?i)(?:EVP_sha512|SHA512_(?:Init|Update|Final)|\bSHA-?512\b)"),
    ("Algorithm", "AES-GCM-SIV", rb"(?i)(?:EVP_aes_[0-9]{3}_gcm_siv|AES-?[0-9]{0,3}-?GCM[-_]?SIV)"),
    ("Algorithm", "AES-256-GCM", rb"(?i)(?:EVP_aes_256_gcm|AES-?256-?GCM)"),
    ("Algorithm", "AES-192-GCM", rb"(?i)(?:EVP_aes_192_gcm|AES-?192-?GCM)"),
    ("Algorithm", "AES-128-GCM", rb"(?i)(?:EVP_aes_128_gcm|AES-?128-?GCM)"),
    ("Algorithm", "AES-GCM", rb"(?i)(?:EVP_aes_(?:128|192)_gcm|AES-?GCM)"),
    ("Algorithm", "AES-CCM", rb"(?i)(?:EVP_aes_[0-9]{3}_ccm|AES-?CCM|EVP_PKEY_AEAD)"),
    ("Algorithm", "AES-CBC", rb"(?i)(?:EVP_aes_(?:128|192|256)_cbc|AES-?CBC|MODE_CBC)"),
    ("Algorithm", "AES-CTR", rb"(?i)(?:EVP_aes_(?:128|192|256)_ctr|AES-?CTR|MODE_CTR)"),
    ("Algorithm", "AES-ECB", rb"(?i)(?:EVP_aes_(?:128|192|256)_ecb|AES-?(?:128|192|256)?-?ECB)"),
    ("Algorithm", "ChaCha20", rb"(?i)(?:EVP_chacha20|ChaCha20(?:Poly1305)?)"),
    ("Algorithm", "RSA-PSS", rb"(?i)(?:RSA[_-]?PSS|EVP_PKEY_RSA_PSS|RSA_PKCS1_PSS_PADDING)"),
    ("Algorithm", "RSA-OAEP", rb"(?i)(?:RSA[_-]?OAEP|RSA_PKCS1_OAEP_PADDING|EVP_PKEY_CTX_set_rsa_oaep_md)"),
    ("Algorithm", "RSA", rb"(?i)(?:EVP_PKEY_RSA(?![_-]?(?:PSS|OAEP))|RSA_(?:new|sign|verify)|\bRSA\b)"),
    ("Algorithm", "ECDSA", rb"(?i)(?:ECDSA_(?:sign|verify)|\bECDSA\b)"),
    ("Algorithm", "ECDH", rb"(?i)(?:ECDH_compute_key|\bECDH\b)"),
    ("Algorithm", "Ed25519", rb"(?i)(?:\bEd25519\b|ED25519_|EVP_PKEY_ED25519)"),
    ("Algorithm", "Ed448", rb"(?i)(?:\bEd448\b|ED448_|EVP_PKEY_ED448)"),
    ("Algorithm", "EdDSA", rb"(?i)\bEdDSA\b"),
    ("Algorithm", "Curve25519", rb"(?i)\bCurve25519\b"),
    ("Algorithm", "Curve448", rb"(?i)\bCurve448\b"),
    ("Algorithm", "X25519", rb"(?i)(?:\bX25519\b|X25519_|EVP_PKEY_X25519)"),
    ("Algorithm", "X448", rb"(?i)(?:\bX448\b|X448_|EVP_PKEY_X448)"),
    ("Protocol", "TLS 1.0", rb"(?i)(?<![A-Za-z0-9])TLS[ _-]*v?1[._-]0(?![A-Za-z0-9])"),
    ("Protocol", "TLS 1.1", rb"(?i)(?<![A-Za-z0-9])TLS[ _-]*v?1[._-]1(?![A-Za-z0-9])"),
    ("Protocol", "TLS 1.2", rb"(?i)(?<![A-Za-z0-9])TLS[ _-]*v?1[._-]2(?![A-Za-z0-9])"),
    ("Protocol", "TLS 1.3", rb"(?i)(?<![A-Za-z0-9])TLS[ _-]*v?1[._-]3(?![A-Za-z0-9])"),
    ("Protocol", "TLS", rb"(?:SSL_CTX_set_tlsext|SSLContext)"),
    ("Protocol", "SSH", rb"(?i)(?:libssh2|OpenSSH|SSH_AUTH_SOCK)"),
    ("Protocol", "IPsec", rb"(?i)(?:libipsec|strongSwan|\bIKEv2\b)"),
    ("Algorithm", "ML-KEM", rb"(?i)(?:EVP_PKEY_ML[-_]?KEM|ML[-_]?KEM|KYBER)"),
    ("Algorithm", "ML-DSA", rb"(?i)(?:EVP_PKEY_ML[-_]?DSA|ML[-_]?DSA|DILITHIUM)"),
    ("Algorithm", "SLH-DSA", rb"(?i)(?:EVP_PKEY_SLH[-_]?DSA|SLH[-_]?DSA|SPHINCS)"),
    ("Key Derivation", "Argon2", rb"(?i)(?:argon2[-_]?(?:id|i|d)|PhonyWallet|libsodium)"),
    ("Key Derivation", "scrypt", rb"(?i)(?:\bscrypt\b|Scrypt_)"),
    ("Key Derivation", "PBKDF2", rb"(?i)(?:PKCS5_PBKDF2|PBKDF2_|\bpbkdf2\b)"),
]


def openssl_details() -> dict[str, Any]:
    import sys

    return {
        "provider": "Python cryptography OpenSSL backend",
        "version": openssl_backend.openssl_version_text(),
        "available": True,
        "python": ".".join(str(part) for part in sys.version_info[:3]),
    }


def _finding(
    category: str,
    name: str,
    relative_path: str,
    evidence: str,
    options: Any,
    *,
    confidence: float = 0.9,
    metadata: dict[str, Any] | None = None,
    version: str | None = None,
) -> dict[str, Any]:
    return make_finding(
        category=category,
        name=name,
        path=relative_path,
        line=0,
        evidence=evidence,
        sensitivity=options.sensitivity,
        migration_complexity=options.migration_complexity,
        threat_timeline=options.threat_timeline,
        confidence=confidence,
        metadata=metadata,
        version=version,
    )


def _safe_key_metadata(key: Any) -> dict[str, Any]:
    metadata: dict[str, Any] = {"key_type": key.__class__.__name__}
    if hasattr(key, "key_size"):
        metadata["key_size_bits"] = key.key_size
    if hasattr(key, "curve") and hasattr(key.curve, "name"):
        metadata["curve"] = key.curve.name
    public_numbers = getattr(key, "public_numbers", None)
    if callable(public_numbers) and isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        exponent = public_numbers().e
        metadata["public_exponent"] = exponent
        if exponent < MINIMUM_RSA_EXPONENT:
            metadata["untrusted_exponent"] = True
    metadata["material_exposed"] = False
    return metadata


def _spki_fingerprint(key: Any) -> str | None:
    """Return the SHA-256 SubjectPublicKeyInfo digest used for pinning and inventory."""
    try:
        spki = key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except (AttributeError, TypeError, ValueError):
        return None
    import hashlib

    return hashlib.sha256(spki).hexdigest()


def _key_name(key: Any) -> str | None:
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return f"RSA-{key.key_size}"
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return f"ECC {key.curve.name}"
    if isinstance(key, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        return f"DSA-{key.key_size}"
    if isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return "Ed25519"
    if isinstance(key, (ed448.Ed448PublicKey, ed448.Ed448PrivateKey)):
        return "Ed448"
    if isinstance(key, (x25519.X25519PublicKey, x25519.X25519PrivateKey)):
        return "X25519"
    if isinstance(key, (x448.X448PublicKey, x448.X448PrivateKey)):
        return "X448"
    return None


def _extension(cert: x509.Certificate, oid: Any) -> Any | None:
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None
    except ValueError:
        return None


def _lifecycle_metadata(cert: x509.Certificate, now: datetime) -> dict[str, Any]:
    """Describe the certificate's current validity window and trust shape."""
    expires = cert.not_valid_after_utc
    valid_from = cert.not_valid_before_utc
    subject = cert.subject.rfc4514_string() or "unnamed subject"
    issuer = cert.issuer.rfc4514_string() or "unnamed issuer"
    basic_constraints = _extension(cert, ExtensionOID.BASIC_CONSTRAINTS)
    key_usage = _extension(cert, ExtensionOID.KEY_USAGE)
    is_ca = bool(basic_constraints is not None and basic_constraints.ca)
    metadata: dict[str, Any] = {
        "subject": subject,
        "issuer": issuer,
        "expires_at": expires.isoformat(),
        "not_valid_before": valid_from.isoformat(),
        "self_signed": subject == issuer,
        "ca": is_ca,
        "expired": expires < now,
        "not_yet_valid": valid_from > now,
    }
    if now <= expires <= now + EXPIRY_WARNING:
        metadata["expiring_soon"] = True
        metadata["days_until_expiry"] = (expires - now).days
    if key_usage is not None:
        metadata["key_usage"] = {
            "digital_signature": bool(key_usage.digital_signature),
            "key_encipherment": bool(key_usage.key_encipherment),
            "key_agreement": bool(key_usage.key_agreement),
            "key_cert_sign": bool(key_usage.key_cert_sign),
        }
    san = _extension(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if san is not None:
        names = [str(name) for name in san.get_values_for_type(x509.DNSName)][:8]
        if names:
            metadata["subject_alt_names"] = names
    return metadata


def _certificate_findings(
    cert: x509.Certificate,
    relative_path: str,
    options: Any,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    now = now or datetime.now(timezone.utc)
    signature = getattr(cert.signature_hash_algorithm, "name", "unknown")
    metadata = _lifecycle_metadata(cert, now)
    expires = cert.not_valid_after_utc
    subject = str(metadata["subject"])
    issuer = str(metadata["issuer"])
    public_key = cert.public_key()
    metadata["signature_algorithm"] = signature
    metadata["public_key"] = _safe_key_metadata(public_key)
    fingerprint = _spki_fingerprint(public_key)
    if fingerprint:
        metadata["spki_sha256"] = fingerprint

    findings = [_finding(
        "Certificate",
        "X.509 certificate",
        relative_path,
        f"OpenSSL parsed certificate: subject={subject[:80]}, issuer={issuer[:80]}, expires={expires.date()}, signature={signature}",
        options,
        confidence=1.0,
        metadata=metadata,
    )]
    if key_name := _key_name(public_key):
        findings.append(_finding(
            "Algorithm", key_name, relative_path, "OpenSSL parsed certificate public key", options,
            confidence=1.0, metadata=_safe_key_metadata(public_key),
        ))
    if signature.lower() in {"md5", "sha1"}:
        findings.append(_finding(
            "Algorithm", signature.upper().replace("SHA1", "SHA-1"), relative_path,
            "OpenSSL parsed certificate signature", options, confidence=1.0,
            metadata={"source": "x509_signature"},
        ))
    findings.extend(_key_parameter_findings(public_key, relative_path, options))
    if metadata.get("expired"):
        findings.append(_finding(
            "Certificate",
            "Expired certificate",
            relative_path,
            f"Certificate expired on {expires.date()}",
            options,
            confidence=1.0,
            metadata={"source": "x509_validity", **metadata},
        ))
    elif metadata.get("expiring_soon"):
        findings.append(_finding(
            "Certificate",
            "Certificate expiring soon",
            relative_path,
            f"Certificate expires in {metadata['days_until_expiry']} days on {expires.date()}",
            options,
            confidence=1.0,
            metadata={"source": "x509_validity", **metadata},
        ))
    return findings


def inspect_crypto_artifact(path: Path, relative_path: str, data: bytes, options: Any) -> list[dict[str, Any]]:
    """Parse certificates and keys with the OpenSSL backend without exposing key material."""
    findings: list[dict[str, Any]] = []
    suffix = path.suffix.lower()

    certificate = None
    try:
        certificate = x509.load_pem_x509_certificate(data) if b"-----BEGIN CERTIFICATE-----" in data else x509.load_der_x509_certificate(data)
    except Exception:
        pass
    if certificate is not None:
        return _certificate_findings(certificate, relative_path, options)

    if suffix in {".p12", ".pfx"}:
        try:
            key, certificate, extra = pkcs12.load_key_and_certificates(data, None)
            findings.append(_finding(
                "Key", "PKCS#12 key store", relative_path,
                "OpenSSL parsed PKCS#12 container; key material redacted", options,
                confidence=1.0,
                metadata={
                    "container": "PKCS#12",
                    "private_material": "redacted",
                    "certificate_count": int(certificate is not None) + len(extra),
                },
            ))
            if key_name := _key_name(key):
                findings.append(_finding(
                    "Algorithm", key_name, relative_path, "OpenSSL parsed PKCS#12 private key", options,
                    confidence=1.0, metadata=_safe_key_metadata(key),
                ))
            if key:
                findings.extend(_key_parameter_findings(key, relative_path, options))
            if certificate:
                findings.extend(_certificate_findings(certificate, relative_path, options))
            for extra_certificate in extra:
                findings.extend(_certificate_findings(extra_certificate, relative_path, options))
            return findings
        except Exception:
            return [_finding(
                "Key", "Encrypted or unreadable PKCS#12 key store", relative_path,
                "OpenSSL could not inspect the container without a password", options,
                confidence=0.95, metadata={"container": "PKCS#12", "private_material": "not_inspected"},
            )]

    loaders = (
        serialization.load_pem_private_key,
        serialization.load_der_private_key,
    )
    for loader in loaders:
        try:
            key = loader(data, password=None)
            key_metadata = _safe_key_metadata(key)
            key_metadata["private_material"] = "redacted"
            if fingerprint := _spki_fingerprint(key.public_key()):
                key_metadata["spki_sha256"] = fingerprint
            findings.append(_finding(
                "Key", "Private key detected", relative_path,
                "[key material redacted; validated by OpenSSL]", options,
                confidence=1.0, metadata=key_metadata,
            ))
            if key_name := _key_name(key):
                findings.append(_finding(
                    "Algorithm", key_name, relative_path, "OpenSSL parsed private-key parameters", options,
                    confidence=1.0, metadata=_safe_key_metadata(key),
                ))
            findings.extend(_key_parameter_findings(key, relative_path, options))
            return findings
        except Exception:
            continue

    public_loaders = [serialization.load_pem_public_key, serialization.load_der_public_key]
    if _looks_like_ssh_public_key(data):
        public_loaders.insert(0, serialization.load_ssh_public_key)
    for loader in public_loaders:
        try:
            key = loader(data)
            key_metadata = _safe_key_metadata(key)
            if loader is serialization.load_ssh_public_key:
                key_metadata["container"] = "OpenSSH"
            if fingerprint := _spki_fingerprint(key):
                key_metadata["spki_sha256"] = fingerprint
            findings.append(_finding(
                "Key", "Public key detected", relative_path,
                "OpenSSL parsed public-key structure", options, confidence=1.0,
                metadata=key_metadata,
            ))
            if key_name := _key_name(key):
                findings.append(_finding(
                    "Algorithm", key_name, relative_path, "OpenSSL parsed public-key parameters", options,
                    confidence=1.0, metadata=_safe_key_metadata(key),
                ))
            findings.extend(_key_parameter_findings(key, relative_path, options))
            return findings
        except Exception:
            continue
    return findings


def _key_parameter_findings(key: Any, relative_path: str, options: Any) -> list[dict[str, Any]]:
    """Report structural weaknesses that are only visible after parsing the key."""
    findings: list[dict[str, Any]] = []
    metadata = _safe_key_metadata(key)
    if metadata.get("untrusted_exponent"):
        findings.append(_finding(
            "Algorithm", "RSA weak public exponent", relative_path,
            f"RSA public exponent is {metadata['public_exponent']}, below the recommended {MINIMUM_RSA_EXPONENT}",
            options, confidence=1.0, metadata=metadata,
        ))
    curve = str(metadata.get("curve", ""))
    if curve and re.search(r"(?i)^(?:sec(?:t)?p?192|sec(?:t)?p?224|sect\d{3}|brainpoolP256)", curve):
        findings.append(_finding(
            "Algorithm", f"Weak elliptic curve {curve}", relative_path,
            f"Elliptic curve {curve} is below the recommended 128-bit strength floor",
            options, confidence=1.0, metadata={**metadata, "weak_curve": True},
        ))
    return findings


def inspect_binary(relative_path: str, data: bytes, options: Any) -> list[dict[str, Any]]:
    """Find crypto-linked symbols and embedded names without executing the binary."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    algorithms_on_line: set[str] = set()
    algorithm_spans: dict[str, list[tuple[int, int]]] = {}

    def overlaps(match: re.Match[bytes], other: str) -> bool:
        return any(match.start() < end and start < match.end() for start, end in algorithm_spans.get(other, []))

    for category, name, expression in BINARY_SIGNATURES:
        for match in re.finditer(expression, data):
            token = match.group(0).decode("ascii", errors="replace")[:80]
            if category == "Algorithm":
                if name in {"AES-128-GCM", "AES-192-GCM", "AES-256-GCM"} and overlaps(match, "AES-GCM-SIV"):
                    continue
                if name == "AES-GCM" and any(overlaps(match, other) for other in {"AES-256-GCM", "AES-192-GCM", "AES-128-GCM", "AES-GCM-SIV"}):
                    continue
                if name == "AES" and any(item.startswith("AES-") for item in algorithms_on_line):
                    continue
                if name == "RSA" and any(item.startswith("RSA-") for item in algorithms_on_line):
                    continue
                if name == "EdDSA" and any(item in {"Ed25519", "Ed448"} for item in algorithms_on_line):
                    continue
            if category == "Protocol" and name == "TLS" and any(
                existing_name.startswith("TLS 1.") for existing_category, existing_name in seen
                if existing_category == "Protocol"
            ):
                continue
            finding_name = name
            metadata = {"source": "binary_fingerprint", "matched_token": token}
            if category == "Protocol" and finding_name.startswith("TLS 1."):
                metadata["protocol_version"] = token
            if (category, finding_name) in seen:
                continue
            findings.append(_finding(
                category, finding_name, relative_path, f"Binary symbol/string: {token}", options,
                confidence=0.9, metadata=metadata,
            ))
            seen.add((category, finding_name))
            if category == "Algorithm":
                algorithms_on_line.add(finding_name)
                algorithm_spans.setdefault(finding_name, []).append(match.span())
    return findings
