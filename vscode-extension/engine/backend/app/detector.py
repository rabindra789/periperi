"""Pattern-based cryptographic discovery with secret-safe evidence handling."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .recommendations import recommendation
from .risk import classical_risk, quantum_risk


PATTERNS: list[tuple[str, str, str]] = [
    ("Algorithm", "AES-256-GCM", r"(?i)AES[-_ ]?256[-_ ]?GCM|EVP_aes_256_gcm"),
    ("Algorithm", "AES-GCM", r"(?i)AES[-_ ]?GCM|AESGCM|AES\.new\([^\n]*MODE_GCM|EVP_aes_(?:128|192)_gcm"),
    ("Algorithm", "AES-ECB", r"(?i)AES[-_ ]?ECB|MODE_ECB|EVP_aes_(?:128|192|256)_ecb"),
    ("Algorithm", "AES", r"(?i)\bAES(?:[-_ ]?(?:128|192|256))?\b"),
    ("Algorithm", "RSA-1024", r"(?i)RSA[^\n]{0,40}(?:1024|key_size\s*=\s*1024)"),
    ("Algorithm", "RSA-2048", r"(?i)RSA[^\n]{0,40}(?:2048|key_size\s*=\s*2048)"),
    ("Algorithm", "RSA", r"(?i)\bRSA\b|generate_private_key\s*\(|EVP_PKEY_RSA|RSA_(?:new|sign|verify)"),
    ("Algorithm", "ECDSA", r"(?i)\bECDSA\b|ECDSA_(?:sign|verify)"),
    ("Algorithm", "ECDH", r"(?i)\bECDH\b|ECDH_compute_key"),
    ("Algorithm", "ECC", r"(?i)\bECC\b|EllipticCurve"),
    ("Algorithm", "Diffie-Hellman", r"(?i)Diffie[- ]Hellman|\bDHParameters\b"),
    ("Algorithm", "DSA", r"(?i)\bDSA\b"),
    ("Algorithm", "SHA-1", r"(?i)\bSHA[-_ ]?1\b|sha1\s*\(|EVP_sha1|SHA1_(?:Init|Update|Final)"),
    ("Algorithm", "SHA-256", r"(?i)\bSHA[-_ ]?256\b|sha256\s*\(|EVP_sha256|SHA256_(?:Init|Update|Final)"),
    ("Algorithm", "SHA-384", r"(?i)\bSHA[-_ ]?384\b|sha384\s*\("),
    ("Algorithm", "SHA-512", r"(?i)\bSHA[-_ ]?512\b|sha512\s*\("),
    ("Algorithm", "MD5", r"(?i)\bMD5\b|md5\s*\(|EVP_md5|MD5_(?:Init|Update|Final)"),
    ("Algorithm", "ChaCha20", r"(?i)\bChaCha20(?:Poly1305)?\b"),
    ("Library", "OpenSSL", r"(?i)\bOpenSSL\b|<openssl/|\blib(?:crypto|ssl)(?:\.so|\.dll|\.dylib)?\b|\bEVP_[A-Za-z0-9_]+"),
    ("Library", "PyCryptodome", r"(?i)(?:from|import)\s+Crypto(?:\.|\b)|PyCryptodome"),
    ("Library", "Python cryptography", r"(?i)(?:from|import)\s+cryptography(?:\.|\b)"),
    ("Library", "libsodium", r"(?i)\blibsodium\b|\bsodium_(?:init|crypto)"),
    ("Library", "Bouncy Castle", r"(?i)Bouncy\s*Castle|org\.bouncycastle"),
    ("Library", "Web Crypto API", r"(?i)crypto\.subtle|SubtleCrypto"),
    ("Library", "Node crypto", r"(?i)(?:require\(['\"]crypto['\"]\)|from\s+['\"](?:node:)?crypto['\"])"),
    ("HSM", "PKCS#11 / HSM", r"(?i)PKCS\s*#?11|hardware security module|\bHSM\b|pkcs11"),
]

CERTIFICATE_SUFFIXES = {".pem", ".crt", ".cer", ".der", ".p7b", ".p12", ".pfx"}
KEY_SUFFIXES = {".key", ".jks", ".keystore"}
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", re.I)
PUBLIC_KEY_RE = re.compile(r"-----BEGIN (?:RSA )?PUBLIC KEY-----", re.I)


def _safe_evidence(line: str, matched: str, is_secret: bool = False) -> str:
    if is_secret:
        return "[key material redacted]"
    compact = " ".join(line.strip().split())
    if len(compact) > 150:
        compact = compact[:147] + "..."
    # Avoid returning credential-looking assignments even when a crypto term is nearby.
    if re.search(r"(?i)(secret|password|token|private[_-]?key)\s*[:=]", compact):
        return f"Pattern matched: {matched} (surrounding value redacted)"
    return compact or f"Pattern matched: {matched}"


def _make_finding(
    *, category: str, name: str, path: str, line: int, evidence: str,
    sensitivity: str, migration_complexity: str, threat_timeline: int,
) -> dict[str, Any]:
    risk, why = classical_risk(name, category)
    q = quantum_risk(name if category == "Algorithm" else None, sensitivity, migration_complexity, threat_timeline)
    return {
        "type": category.lower(),
        "category": category,
        "name": name,
        "algorithm": name if category == "Algorithm" else None,
        "file": path.replace("\\", "/"),
        "line": line,
        "evidence": evidence,
        "risk": risk,
        "reason": why,
        "quantum_risk": q["level"],
        "quantum": q,
        "recommendation": recommendation(name, category, risk),
    }


def make_finding(**kwargs: Any) -> dict[str, Any]:
    """Public finding factory shared by source, binary and OpenSSL inspectors."""
    return _make_finding(**kwargs)


def detect_file(
    path: Path,
    relative_path: str,
    text: str,
    sensitivity: str,
    migration_complexity: str,
    threat_timeline: int,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()

    suffix = path.suffix.lower()
    is_certificate = suffix in CERTIFICATE_SUFFIXES and (
        suffix != ".pem" or "-----BEGIN CERTIFICATE-----" in text
    )
    if is_certificate:
        findings.append(_make_finding(
            category="Certificate", name="Certificate file", path=relative_path, line=1,
            evidence=f"Certificate artefact: {path.name}", sensitivity=sensitivity,
            migration_complexity=migration_complexity, threat_timeline=threat_timeline,
        ))
    if suffix in KEY_SUFFIXES:
        findings.append(_make_finding(
            category="Key", name="Cryptographic key file", path=relative_path, line=1,
            evidence="[key file contents not displayed]", sensitivity=sensitivity,
            migration_complexity=migration_complexity, threat_timeline=threat_timeline,
        ))

    lines = text.splitlines()
    for number, line in enumerate(lines, start=1):
        algorithms_on_line: set[str] = set()
        if PRIVATE_KEY_RE.search(line):
            key = ("Key", "Private key detected", number)
            if key not in seen:
                findings.append(_make_finding(
                    category="Key", name="Private key detected", path=relative_path, line=number,
                    evidence=_safe_evidence(line, "private-key header", True), sensitivity=sensitivity,
                    migration_complexity=migration_complexity, threat_timeline=threat_timeline,
                ))
                seen.add(key)
        elif PUBLIC_KEY_RE.search(line):
            key = ("Key", "Public key detected", number)
            if key not in seen:
                findings.append(_make_finding(
                    category="Key", name="Public key detected", path=relative_path, line=number,
                    evidence="Public-key PEM header", sensitivity=sensitivity,
                    migration_complexity=migration_complexity, threat_timeline=threat_timeline,
                ))
                seen.add(key)

        for category, name, expression in PATTERNS:
            match = re.search(expression, line)
            key = (category, name, number)
            if category == "Algorithm" and match:
                # Prefer the most specific match on a line over a generic family label.
                if name == "AES-GCM" and "AES-256-GCM" in algorithms_on_line:
                    continue
                if name == "AES" and any(item.startswith("AES-") for item in algorithms_on_line):
                    continue
                if name == "RSA" and any(item.startswith("RSA-") for item in algorithms_on_line):
                    continue
            if match and key not in seen:
                findings.append(_make_finding(
                    category=category, name=name, path=relative_path, line=number,
                    evidence=_safe_evidence(line, match.group(0)), sensitivity=sensitivity,
                    migration_complexity=migration_complexity, threat_timeline=threat_timeline,
                ))
                seen.add(key)
                if category == "Algorithm":
                    algorithms_on_line.add(name)

    return findings
