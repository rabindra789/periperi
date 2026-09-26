"""Pattern-based cryptographic discovery with secret-safe evidence handling."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .recommendations import recommendation, structured_recommendation
from .risk import classical_risk, lifecycle_detail, quantum_risk, references_for


PATTERNS: list[tuple[str, str, str]] = [
    ("Algorithm", "AES-GCM-SIV", r"(?i)AES[-_ ]?(?:[0-9]{3}[-_ ]?)?GCM[-_ ]?SIV|EVP_aes_[0-9]{3}_gcm_siv"),
    ("Algorithm", "AES-256-GCM", r"(?i)AES[-_ ]?256[-_ ]?GCM|EVP_aes_256_gcm"),
    ("Algorithm", "AES-192-GCM", r"(?i)AES[-_ ]?192[-_ ]?GCM|EVP_aes_192_gcm"),
    ("Algorithm", "AES-128-GCM", r"(?i)AES[-_ ]?128[-_ ]?GCM|EVP_aes_128_gcm"),
    ("Algorithm", "AES-GCM", r"(?i)AES[-_ ]?GCM|AESGCM|AES\.new\([^\n]*MODE_GCM|EVP_aes_(?:128|192)_gcm"),
    ("Algorithm", "AES-CCM", r"(?i)AES[-_ ]?CCM|EVP_aes_(?:128|192|256)_ccm"),
    ("Algorithm", "AES-CBC", r"(?i)AES[-_ ]?CBC|MODE_CBC|EVP_aes_(?:128|192|256)_cbc"),
    ("Algorithm", "AES-CTR", r"(?i)AES[-_ ]?CTR|MODE_CTR|EVP_aes_(?:128|192|256)_ctr"),
    ("Algorithm", "AES-ECB", r"(?i)AES[-_ ]?ECB|MODE_ECB|EVP_aes_(?:128|192|256)_ecb"),
    ("Algorithm", "AES", r"(?i)\bAES(?:[-_ ]?(?:128|192|256))?\b"),
    ("Algorithm", "RSA-1024", r"(?i)RSA[^\n]{0,40}(?:1024|key_size\s*=\s*1024)"),
    ("Algorithm", "RSA-2048", r"(?i)RSA[^\n]{0,40}(?:2048|key_size\s*=\s*2048)"),
    ("Algorithm", "RSA-PSS", r"(?i)\bRSA[-_ ]?PSS\b|EVP_PKEY_RSA_PSS|RSA_PKCS1_PSS_PADDING|(?:padding\.)?PSS\s*\([^)\n]*(?:MGF1|maskGenFunction)"),
    ("Algorithm", "RSA-OAEP", r"(?i)\bRSA[-_ ]?OAEP\b|OAEP\(|padding\s*=\s*padding\.OAEP"),
    ("Algorithm", "RSA", r"(?i)\bRSA\b|generate_private_key\s*\(|EVP_PKEY_RSA|RSA_(?:new|sign|verify)"),
    ("Algorithm", "ECDSA", r"(?i)\bECDSA\b|ECDSA_(?:sign|verify)"),
    ("Algorithm", "ECDH", r"(?i)\bECDH\b|ECDH_compute_key"),
    ("Algorithm", "ECC", r"(?i)\bECC\b|EllipticCurve"),
    ("Algorithm", "Diffie-Hellman", r"(?i)Diffie[- ]Hellman|\bDHParameters\b"),
    ("Algorithm", "DSA", r"(?i)\bDSA\b"),
    ("Algorithm", "Ed25519", r"(?i)\bEd25519\b|EVP_PKEY_ED25519"),
    ("Algorithm", "Ed448", r"(?i)\bEd448\b|EVP_PKEY_ED448"),
    ("Algorithm", "EdDSA", r"(?i)\bEdDSA\b"),
    ("Algorithm", "Curve25519", r"(?i)\bCurve25519\b"),
    ("Algorithm", "Curve448", r"(?i)\bCurve448\b"),
    ("Algorithm", "X25519", r"(?i)\bX25519\b|EVP_PKEY_X25519"),
    ("Algorithm", "X448", r"(?i)\bX448\b|EVP_PKEY_X448"),
    ("Algorithm", "SHA-1", r"(?i)\bSHA[-_ ]?1\b|sha1\s*\(|EVP_sha1|SHA1_(?:Init|Update|Final)"),
    ("Algorithm", "SHA-256", r"(?i)\bSHA[-_ ]?256\b|sha256\s*\(|EVP_sha256|SHA256_(?:Init|Update|Final)"),
    ("Algorithm", "SHA-384", r"(?i)\bSHA[-_ ]?384\b|sha384\s*\("),
    ("Algorithm", "SHA-512", r"(?i)\bSHA[-_ ]?512\b|sha512\s*\("),
    ("Algorithm", "MD5", r"(?i)\bMD5\b|md5\s*\(|EVP_md5|MD5_(?:Init|Update|Final)"),
    ("Algorithm", "ChaCha20", r"(?i)\bChaCha20(?:Poly1305)?\b"),
    ("Algorithm", "ML-KEM", r"(?i)\bML[-_ ]?KEM\b|\bKEM[-_ ]?ML\b|\bKyber(?:512|768|1024)?\b|ML[-_ ]?KEM|FIPS\s*203"),
    ("Algorithm", "ML-DSA", r"(?i)\bML[-_ ]?DSA\b|\bDilithium(?:2|3|5)?\b|FIPS\s*204"),
    ("Algorithm", "SLH-DSA", r"(?i)\bSLH[-_ ]?DSA\b|\bSPHINCS\+?\b|\bSPHINCS\b|FIPS\s*205"),
    ("Algorithm", "AES-KW", r"(?i)AES[-_ ]?(?:KEY[-_ ]?WRAP|KW)|\bKWP\b|\bAES[-_ ]?KWP\b"),
    ("Algorithm", "HMAC", r"(?i)\bHMAC\b|hmac\.new\s*\(|HMAC_(?:Init|Update|Final)"),
    ("Algorithm", "SHA-512/256", r"(?i)\bSHA[-_ ]?512[/_-]?256\b"),
    ("Algorithm", "BLAKE2", r"(?i)\bBLAKE2[bBs]?\b"),
    ("Library", "OpenSSL", r"(?i)\bOpenSSL\b|<openssl/|\blib(?:crypto|ssl)(?:\.so|\.dll|\.dylib)?\b|\bEVP_[A-Za-z0-9_]+"),
    ("Library", "PyCryptodome", r"(?i)(?:from|import)\s+Crypto(?:\.|\b)|PyCryptodome"),
    ("Library", "Python cryptography", r"(?i)(?:from|import)\s+cryptography(?:\.|\b)"),
    ("Library", "libsodium", r"(?i)\blibsodium\b|\bsodium_(?:init|crypto)"),
    ("Library", "Bouncy Castle", r"(?i)Bouncy\s*Castle|org\.bouncycastle"),
    ("Library", "Web Crypto API", r"(?i)crypto\.subtle|SubtleCrypto"),
    ("Library", "Node crypto", r"(?i)(?:require\(['\"]crypto['\"]\)|from\s+['\"](?:node:)?crypto['\"])"),
    ("Library", "Google Tink", r"(?i)\bcom\.google\.crypto\.tink\b|\bTink\b"),
    ("Library", "AWS Encryption SDK", r"(?i)aws[-_]encryption[-_]sdk|\bAWSEncryptionClient\b"),
    ("Key Derivation", "Argon2", r"(?i)\bArgon2(?:id|d|i)?\b|argon2i?\."),
    ("Key Derivation", "scrypt", r"(?i)\bscrypt\b|scrypt\s*\("),
    ("Key Derivation", "bcrypt", r"(?i)\bbcrypt\b"),
    ("Key Derivation", "PBKDF2", r"(?i)\bPBKDF2\b|PBKDF2(?:WithHMAC|HMAC_SHA|HMAC)?\s*\(|pbkdf2_hmac\s*\("),
    ("Key Derivation", "PBKDF2 low iteration count", r"(?i)PBKDF2[A-Za-z_]*\s*\([^)\n]{0,240}?(?:iterations?|rounds?)\s*[=:]\s*(?:[1-9][0-9]{0,3}|[1-9][0-9]000)\b"),
    ("Key Derivation", "HKDF", r"(?i)\bHKDF\b|HKDFExpand|hkdf\s*\("),
    ("Randomness", "Insecure random source", r"(?i)\bMath\s*\.\s*random\s*\(|\brandom\s*\.\s*random\s*\(|\brand\s*\(\s*\)|\bmt_rand\s*\(|\bsrand\s*\(|\bnew\s+Random\s*\(|\bnextInt\s*\(|\brandInt\s*\("),
    ("Token", "JOSE algorithm", r"(?i)\b(?:alg|algorithm)\s*[=:]\s*[\"']?(?:none|RS256|RS384|RS512|PS256|PS384|PS512|ES256|ES384|ES512|EdDSA|HS256|HS384|HS512)\b|\bjose\b|\bJWKS?\b|\bjwt\b|\bjwk\b"),
    ("Protocol", "Cipher suite", r"(?i)\b(?:TLS|SSL)_[A-Z0-9_]*(?:WITH|GCM|CCM|CHACHA)[A-Z0-9_]*\b|\b(?:ECDHE|DHE)-[A-Z0-9]{2,}(?:-[A-Z0-9]+)+\b|\b(?:AES|RC4|DES|3DES|NULL|EXPORT)(?:128|192|256)?-(?:GCM|CBC\d*|CCM|OCB|CTR|CFB|OFB|SHA|RC4|MD5)(?:-[A-Z0-9]+)+\b"),
    ("Protocol", "Certificate pinning", r"(?i)\bcertificate[_ -]?pinning\b|\bpin[_ -]?sha(?:256)?\b|\bHPKP\b|\bPublicKeyPin\b|\bnetwork_security_config\b|\bTrustManager\b|\bCertificatePinner\b"),
    ("Protocol", "TLS 1.0", r"(?i)(?<![A-Za-z0-9])TLS[ _-]*v?1[._-]0(?![A-Za-z0-9])"),
    ("Protocol", "TLS 1.1", r"(?i)(?<![A-Za-z0-9])TLS[ _-]*v?1[._-]1(?![A-Za-z0-9])"),
    ("Protocol", "TLS 1.2", r"(?i)(?<![A-Za-z0-9])TLS[ _-]*v?1[._-]2(?![A-Za-z0-9])"),
    ("Protocol", "TLS 1.3", r"(?i)(?<![A-Za-z0-9])TLS[ _-]*v?1[._-]3(?![A-Za-z0-9])"),
    ("Protocol", "TLS", r"(?<![A-Za-z0-9])(?:SSLContext|ssl\.TLS)(?![A-Za-z0-9])|(?<![A-Za-z0-9])TLS(?:_[A-Z][A-Z0-9_]+)(?![A-Za-z0-9])|(?<![A-Za-z0-9])tls(?:_[a-z][a-z0-9_]+)(?![A-Za-z0-9])"),
    ("Protocol", "SSH", r"(?i)\bssh(?:2|(?:[_-][A-Z][A-Z0-9_]*)+)?\b|\bopenssh\b|paramiko|ssh2"),
    ("Protocol", "IPsec", r"(?i)\bIPsec\b|\bIKEv?[12]?\b|strongSwan|libipsec|\besp[-_](?:aes|gcm|sha)"),
    ("HSM", "AWS CloudHSM", r"(?i)\bAWS\s+CloudHSM\b|cloudhsm"),
    ("HSM", "Azure Managed HSM", r"(?i)\bAzure\s+Managed\s+HSM\b|AzureManagedHSM"),
    ("HSM", "Google Cloud HSM", r"(?i)\bGoogle\s+Cloud\s+HSM\b|GoogleCloudHsm"),
    ("HSM", "Thales Ignite HSM", r"(?i)\bThales\s+Ignite\b|Ignite\s+HSM"),
    ("HSM", "Luna HSM", r"(?i)\bLuna\s+HSM\b|SafeNet\s+Luna"),
    ("HSM", "nShield HSM", r"(?i)\bnShield\b|entrust\s+nShield"),
    ("HSM", "Utimaco HSM", r"(?i)\bUtimaco\b"),
    ("Key Management", "AWS KMS", r"(?i)\bAWS\s+KMS\b|aws_kms"),
    ("Key Management", "Azure Key Vault", r"(?i)\bAzure\s+Key\s+Vault\b|azure[_-]?key[_-]?vault"),
    ("Key Management", "Google Cloud KMS", r"(?i)\bGoogle\s+Cloud\s+KMS\b|google[_-]?cloud[_-]?kms"),
    ("HSM", "PKCS#11 / HSM", r"(?i)PKCS\s*#?11|hardware security module|\bHSM\b|pkcs11"),
]

PATTERN_CONFIDENCE: dict[str, float] = {
    "Algorithm": 0.9,
    "Library": 0.95,
    "Protocol": 0.82,
    "HSM": 0.88,
    "Key Management": 0.88,
    "Key Derivation": 0.85,
    "Randomness": 0.6,
    "Token": 0.75,
}

CERTIFICATE_SUFFIXES = {".pem", ".crt", ".cer", ".der", ".p7b", ".p12", ".pfx"}
KEY_SUFFIXES = {".key", ".jks", ".keystore"}
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", re.I)
PUBLIC_KEY_RE = re.compile(r"-----BEGIN (?:RSA )?PUBLIC KEY-----", re.I)
INACTIVE_AFTER_RE = re.compile(
    r"(?i)\b(?:has\s+been|have\s+been|was|were|is|are|will\s+be|remains?|stays?)?\s*"
    r"(?:disable(?:d)?|not\s+(?:enabled|used|in\s+use|configured|supported|available)|"
    r"never\s+(?:enabled|used|configured|supported)|(?:not\s+)?(?:planned|future|added|roadmapped))\b"
)
INACTIVE_BEFORE_RE = re.compile(
    r"(?i)\b(?:do\s+not|does\s+not|did\s+not|never|no)\s+"
    r"(?:use|using|enable|enabled|configure|configured|support|supports)\s*$"
)
INACTIVE_PREFIX_RE = re.compile(r"(?i)\b(?:disabled?|unsupported|not\s+supported)\s*$")
CREDENTIAL_URI_RE = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^/\s@]*@")
ASSET_CONTEXT_RE = re.compile(r"(?i)\b(?:icon|logo|illustration)\b[^\n]{0,32}\b(?:HSM|PKCS\s*#?11)\b")
TLS_VERSION_RE = re.compile(r"(?i)TLS[ _-]*v?1[._-][0-3]")
KEY_MARKER_RE = re.compile(r"-----BEGIN [^-]*(?:PRIVATE|PUBLIC) KEY-----")
KEY_BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{48,}={0,2}(?![A-Za-z0-9+/=])")


def _safe_evidence(line: str, matched: str, is_secret: bool = False) -> str:
    if is_secret or KEY_MARKER_RE.search(line) or KEY_BLOB_RE.search(line):
        return "[key material redacted]"
    compact = CREDENTIAL_URI_RE.sub(r"\1[redacted]@", " ".join(line.strip().split()))
    if len(compact) > 150:
        compact = compact[:147] + "..."
    if re.search(r"(?i)(secret|password|token|api[_-]?key|private[_-]?key|client[_-]?secret|authorization|credential)\s*[:=]", compact):
        return f"Pattern matched: {matched} (surrounding value redacted)"
    return compact or f"Pattern matched: {matched}"


def _confidence_level(confidence: float) -> str:
    if confidence >= 0.9:
        return "high"
    if confidence >= 0.7:
        return "medium"
    return "low"


def _pattern_confidence(category: str, name: str) -> float:
    confidence = PATTERN_CONFIDENCE.get(category, 0.8)
    if category == "Algorithm" and name in {"AES", "RSA", "ECC", "PKCS#11 / HSM"}:
        confidence = 0.78
    if name in {"PKCS#11 / HSM", "TLS", "SSH", "IPsec"}:
        confidence = 0.8
    if name in {"Cipher suite", "Certificate pinning"}:
        confidence = 0.7
    return confidence


def _make_finding(
    *, category: str, name: str, path: str, line: int, evidence: str,
    sensitivity: str, migration_complexity: str, threat_timeline: int,
    confidence: float = 0.8, metadata: dict[str, Any] | None = None,
    version: str | None = None,
) -> dict[str, Any]:
    detail = lifecycle_detail(metadata)
    risk, why = classical_risk(name, category, detail)
    q = quantum_risk(name if category == "Algorithm" else None, sensitivity, migration_complexity, threat_timeline)
    confidence = round(min(1.0, max(0.0, float(confidence))), 2)
    return {
        "type": category.lower(),
        "category": category,
        "name": name,
        "algorithm": name if category == "Algorithm" else None,
        "version": version,
        "file": path.replace("\\", "/"),
        "line": line,
        "evidence": evidence,
        "confidence": confidence,
        "confidence_level": _confidence_level(confidence),
        "metadata": dict(metadata or {}),
        "risk": risk,
        "reason": why,
        "quantum_risk": q["level"],
        "quantum": q,
        "mosca": dict(q),
        "references": references_for(name, category, detail),
        "recommendation": recommendation(name, category, risk, detail),
        "recommendation_details": structured_recommendation(name, category, risk, detail),
    }


def make_finding(**kwargs: Any) -> dict[str, Any]:
    """Public finding factory shared by source, binary and OpenSSL inspectors."""
    return _make_finding(**kwargs)


def _inactive_inventory_statement(category: str, line: str, match_start: int) -> bool:
    if category not in {"Protocol", "HSM", "Key Management"}:
        return False
    stripped = line.lstrip()
    if stripped.startswith(("#", "//", "/*", "<!--", "*")):
        return True
    if category in {"HSM", "Key Management"} and ASSET_CONTEXT_RE.search(line):
        return True
    delimiters = {line.rfind(separator, 0, match_start) for separator in (";", ",", "\n")}
    clause_start = max(delimiters, default=-1) + 1
    boundary_positions = [line.find(separator, match_start) for separator in (";", ",", "\n")]
    clause_end = min((position for position in boundary_positions if position >= 0), default=len(line))
    clause = line[clause_start:clause_end]
    before = clause[:max(0, match_start - clause_start)]
    after = clause[max(0, match_start - clause_start):]
    return bool(
        INACTIVE_AFTER_RE.search(after)
        or INACTIVE_BEFORE_RE.search(before)
        or INACTIVE_PREFIX_RE.search(before)
    )


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
            confidence=0.95, metadata={"source": "filename_and_pem_header"},
        ))
    if suffix in KEY_SUFFIXES:
        findings.append(_make_finding(
            category="Key", name="Cryptographic key file", path=relative_path, line=1,
            evidence="[key file contents not displayed]", sensitivity=sensitivity,
            migration_complexity=migration_complexity, threat_timeline=threat_timeline,
            confidence=0.9, metadata={"source": "key_file_suffix"},
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
                    confidence=1.0, metadata={"private_material": "redacted", "source": "pem_header"},
                ))
                seen.add(key)
        elif PUBLIC_KEY_RE.search(line):
            key = ("Key", "Public key detected", number)
            if key not in seen:
                findings.append(_make_finding(
                    category="Key", name="Public key detected", path=relative_path, line=number,
                    evidence="Public-key PEM header", sensitivity=sensitivity,
                    migration_complexity=migration_complexity, threat_timeline=threat_timeline,
                    confidence=1.0, metadata={"source": "pem_header"},
                ))
                seen.add(key)

        siv_spans = [
            siv_match.span()
            for siv_category, siv_name, siv_expression in PATTERNS
            if siv_category == "Algorithm" and siv_name == "AES-GCM-SIV"
            for siv_match in re.finditer(siv_expression, line)
        ]
        for category, name, expression in PATTERNS:
            for match in re.finditer(expression, line):
                if category in {"HSM", "Key Management"} and re.search(
                    r"\.(?:avif|bmp|gif|ico|jpe?g|png|svg|webp)\b", line, re.IGNORECASE
                ):
                    continue
                if name == "TLS" and TLS_VERSION_RE.search(match.group(0)):
                    continue
                if name == "PKCS#11 / HSM" and any(
                    other_match
                    and not _inactive_inventory_statement("HSM", line, other_match.start())
                    for other_category, other_name, other_expression in PATTERNS
                    if other_category == "HSM" and other_name != name
                    for other_match in re.finditer(other_expression, line)
                ):
                    continue
                if category == "Algorithm":
                    if name in {"AES-128-GCM", "AES-192-GCM", "AES-256-GCM"} and any(
                        match.start() < end and start < match.end() for start, end in siv_spans
                    ):
                        continue
                    if name == "AES-GCM" and any(
                        item in {"AES-256-GCM", "AES-192-GCM", "AES-128-GCM", "AES-GCM-SIV"}
                        for item in algorithms_on_line
                    ):
                        continue
                    if name == "AES" and any(item.startswith("AES-") for item in algorithms_on_line):
                        continue
                    if name == "RSA" and any(item.startswith("RSA-") for item in algorithms_on_line):
                        continue
                    if name == "EdDSA" and any(item in {"Ed25519", "Ed448"} for item in algorithms_on_line):
                        continue
                    if name == "DSA" and any(item in {"ML-DSA", "SLH-DSA"} for item in algorithms_on_line):
                        continue
                    if name == "SHA-512" and "SHA-512/256" in algorithms_on_line:
                        continue
                key = (category, name, number)
                if _inactive_inventory_statement(category, line, match.start()) or key in seen:
                    continue
                findings.append(_make_finding(
                    category=category, name=name, path=relative_path, line=number,
                    evidence=_safe_evidence(line, match.group(0)), sensitivity=sensitivity,
                    migration_complexity=migration_complexity, threat_timeline=threat_timeline,
                    confidence=_pattern_confidence(category, name),
                    metadata={"source": "source_pattern", "matched_token": match.group(0)[:80]},
                ))
                seen.add(key)
                if category == "Algorithm":
                    algorithms_on_line.add(name)
                break

    return findings
