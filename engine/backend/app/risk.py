"""Transparent prototype risk, certificate-lifecycle and quantum-readiness rules.

Every rating comes from an ordered, readable rule cascade so a finding can be
argued with instead of trusted. The classical side answers "is this weak or
expiring today"; the quantum side applies Mosca's ``X + Y > Z`` inequality to
the configured data-lifetime, migration-time and threat-timeline assumptions.

Nothing here is a cryptographic audit. The output is a defensible first pass
with the reasoning and the references attached.
"""

from __future__ import annotations

from typing import Any


DATA_LIFETIME_YEARS = {
    "ephemeral": 1,
    "internal": 5,
    "pii": 10,
    "financial": 12,
    "high_sensitivity": 20,
}

MIGRATION_YEARS = {
    "small_project": 1,
    "standard_application": 3,
    "legacy_application": 5,
    "complex_system": 7,
}

VULNERABLE_FAMILIES = (
    "DIFFIE-HELLMAN",
    "ECDSA",
    "ECDH",
    "ED25519",
    "ED448",
    "EDDSA",
    "CURVE25519",
    "CURVE448",
    "X25519",
    "X448",
    "RSA",
    "ECC",
    "DSA",
    "DH",
)

QUANTUM_VULNERABLE = set(VULNERABLE_FAMILIES)

#: Post-quantum families that are already migration targets rather than debt.
POST_QUANTUM_FAMILIES = (
    "ML-KEM",
    "MLKEM",
    "KYBER",
    "ML-DSA",
    "MLDSA",
    "DILITHIUM",
    "SLH-DSA",
    "SLHDSA",
    "SPHINCS",
    "FALCON",
    "HQC",
)

#: Migration target for each quantum-vulnerable family.
PQC_MIGRATION_TARGETS = {
    "RSA": "ML-KEM (FIPS 203) for key transport, ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for signatures",
    "ECDSA": "ML-DSA (FIPS 204) or SLH-DSA (FIPS 205), deployed as a hybrid ECDSA+PQC signature during migration",
    "ECDH": "ML-KEM (FIPS 203), deployed as a hybrid X25519+ML-KEM key agreement during migration",
    "ECC": "ML-KEM (FIPS 203) for key establishment and ML-DSA (FIPS 204) for signatures",
    "ED25519": "ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for signatures, ML-KEM (FIPS 203) for key agreement",
    "ED448": "ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for signatures, ML-KEM (FIPS 203) for key agreement",
    "EDDSA": "ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for signatures, ML-KEM (FIPS 203) for key agreement",
    "CURVE25519": "ML-KEM (FIPS 203), deployed as a hybrid X25519+ML-KEM key agreement during migration",
    "X25519": "ML-KEM (FIPS 203), deployed as a hybrid X25519+ML-KEM key agreement during migration",
    "CURVE448": "ML-KEM (FIPS 203) for key agreement",
    "X448": "ML-KEM (FIPS 203) for key agreement",
    "DIFFIE-HELLMAN": "ML-KEM (FIPS 203) for key agreement",
    "DSA": "ML-DSA (FIPS 204)",
    "DH": "ML-KEM (FIPS 203) for key agreement",
}

#: Classical ratings ordered from most to least severe.
RISK_ORDER = ("critical", "high", "medium", "low", "info")

#: Primitives that are deprecated or below modern security expectations.
WEAK_PRIMITIVES = ("MD5", "SHA-1", "SHA1", "RSA-1024", "DES", "3DES", "RC4", "RC2", "BLOWFISH")

#: Usable, but only with a deliberate reason.
REVIEW_PRIMITIVES = (
    "ECB",
    "RSA-2048",
    "DSA",
    "DH",
    "TLS 1.0",
    "TLSV1.0",
    "TLS 1.1",
    "TLSV1.1",
    "PKCS1",
    "SECP256R1",
)

#: Elliptic curves that no longer meet the recommended strength floor.
WEAK_CURVES = ("SECP192", "SECP224", "SECT163", "SECT233", "SECT283", "SECT409", "SECT571", "BRAINPOOLP256")

#: Metadata keys that change how a finding is rated rather than only describing it.
LIFECYCLE_KEYS = (
    "expired",
    "not_yet_valid",
    "expiring_soon",
    "self_signed",
    "ca",
    "key_usage",
    "untrusted_exponent",
    "weak_curve",
)

#: Short references surfaced with each finding and exported in the CBOM.
REFERENCES = {
    "MD5": "NIST SP 800-131A Rev. 2 - MD5 is not approved for digital signature generation",
    "SHA-1": "NIST SP 800-131A Rev. 2 and CISA guidance on SHA-1 collision weaknesses",
    "SHA1": "NIST SP 800-131A Rev. 2 and CISA guidance on SHA-1 collision weaknesses",
    "RSA-1024": "NIST SP 800-57 Part 1 Rev. 5 - 1024-bit RSA is below the 112-bit security floor",
    "RSA-2048": "NIST SP 800-57 Part 1 Rev. 5 - 2048-bit RSA provides about 112 bits of strength",
    "RSA-3072": "NIST SP 800-57 Part 1 Rev. 5 - 3072-bit RSA provides about 128 bits of strength",
    "RSA-4096": "NIST SP 800-57 Part 1 Rev. 5 - 4096-bit RSA provides about 152 bits of strength",
    "DSA": "NIST SP 800-131A Rev. 2 - DSA and DH are legacy public-key algorithms",
    "DH": "NIST SP 800-131A Rev. 2 - DSA and DH are legacy public-key algorithms",
    "ECDSA": "FIPS 186-5 - approved ECDSA curves and signature parameters",
    "ECDH": "NIST SP 800-56A Rev. 3 - key-establishment guidelines",
    "ECC": "NIST SP 800-56A Rev. 3 - key-establishment guidelines",
    "ED25519": "FIPS 186-5 - EdDSA is approved, but remains quantum-vulnerable",
    "ED448": "FIPS 186-5 - EdDSA is approved, but remains quantum-vulnerable",
    "X25519": "SP 800-56A Rev. 3 - X25519 is approved, but remains quantum-vulnerable",
    "AES-ECB": "NIST SP 800-38A - ECB leaks plaintext structure; use an AEAD mode from SP 800-38D",
    "AES-GCM": "NIST SP 800-38D - GCM nonce reuse is catastrophic and the IV space is capped at 2^32 per key",
    "AES-256-GCM": "NIST SP 800-38D - GCM nonce reuse is catastrophic and the IV space is capped at 2^32 per key",
    "AES-GCM-SIV": "RFC 8452 - AES-GCM-SIV is nonce-misuse resistant, which relaxes IV handling",
    "AES-CBC": "NIST SP 800-38A - CBC requires a separate integrity mechanism and constant-time padding checks",
    "AES-CTR": "NIST SP 800-38A - CTR is a stream mode and must be combined with an authenticator",
    "AES-CCM": "SP 800-38C - CCM is approved for constrained devices with short messages",
    "CHACHA20": "RFC 8439 - ChaCha20-Poly1305 AEAD construction",
    "ML-KEM": "FIPS 203 - ML-KEM is the post-quantum key-encapsulation standard",
    "ML-DSA": "FIPS 204 - ML-DSA is the post-quantum signature standard",
    "SLH-DSA": "FIPS 205 - SLH-DSA is the post-quantum signature standard based on SPHINCS+",
    "TLS 1.0": "RFC 8996 - TLS 1.0 and 1.1 are deprecated",
    "TLS 1.1": "RFC 8996 - TLS 1.0 and 1.1 are deprecated",
    "TLS 1.2": "RFC 8446 - TLS 1.2 remains acceptable when cipher suites and options are constrained",
    "TLS 1.3": "RFC 8446 - TLS 1.3 removes legacy algorithms and reduces downgrade risk",
    "SSL2": "RFC 8996 - SSL 2.0 and 3.0 are prohibited",
    "SSL3": "RFC 8996 - SSL 2.0 and 3.0 are prohibited",
    "SSH": "RFC 8308 - SSH transport hardening recommendations",
    "IPSEC": "RFC 8247 - algorithm implementation requirements for IPsec",
    "PKCS1": "RFC 8017 - PKCS#1 v1.5 padding is the root of Bleichenbacher-style attacks; prefer OAEP and PSS",
    "PKCS8": "RFC 5958 - PKCS#8 private key information encoding",
    "PBKDF2": "NIST SP 800-132 - password-based KDFs need a tuned iteration count",
    "ARGON2": "RFC 9106 - Argon2 is the preferred memory-hard password KDF",
    "SCRYPT": "RFC 7914 - scrypt is a memory-hard password KDF",
    "HKDF": "RFC 5869 - HKDF for extracting and expanding key material",
    "RANDOM": "NIST SP 800-90A/B - use a CSPRNG; a general-purpose RNG is not a cryptographic source",
    "HSM": "NIST SP 800-57 Part 1 Rev. 5 - HSM key management and algorithm support",
}

#: Quantum-readiness references, keyed by the vulnerable family.
QUANTUM_REFERENCES = {
    "RSA": "NIST IR 8547 - transition to post-quantum cryptography, and CNSA 2.0 timelines",
    "ECC": "NIST IR 8547 - transition to post-quantum cryptography, and CNSA 2.0 timelines",
    "ECDSA": "NIST IR 8547 - transition to post-quantum cryptography, and CNSA 2.0 timelines",
    "ECDH": "NIST IR 8547 - transition to post-quantum cryptography, and CNSA 2.0 timelines",
    "DSA": "NIST IR 8547 - transition to post-quantum cryptography, and CNSA 2.0 timelines",
    "DH": "NIST IR 8547 - transition to post-quantum cryptography, and CNSA 2.0 timelines",
    "DIFFIE-HELLMAN": "NIST IR 8547 - transition to post-quantum cryptography, and CNSA 2.0 timelines",
    "ED25519": "NIST IR 8547 - Ed25519 is broken by Shor's algorithm; migrate to ML-DSA or SLH-DSA",
    "ED448": "NIST IR 8547 - Ed448 is broken by Shor's algorithm; migrate to ML-DSA or SLH-DSA",
    "EDDSA": "NIST IR 8547 - EdDSA is broken by Shor's algorithm; migrate to ML-DSA or SLH-DSA",
    "CURVE25519": "NIST IR 8547 - Curve25519 is broken by Shor's algorithm; migrate to ML-KEM",
    "X25519": "NIST IR 8547 - X25519 is broken by Shor's algorithm; migrate to ML-KEM",
    "CURVE448": "NIST IR 8547 - Curve448 is broken by Shor's algorithm; migrate to ML-KEM",
    "X448": "NIST IR 8547 - X448 is broken by Shor's algorithm; migrate to ML-KEM",
}

#: The quantum reason used when an algorithm is already post-quantum.
POST_QUANTUM_REASON = (
    "This is a post-quantum algorithm, so no harvest-now-decrypt-later exposure is calculated. "
    "Confirm the implementation is FIPS 203/204/205 conformant and correctly parameterised."
)


def quantum_family(algorithm: str | None) -> str | None:
    """Return the quantum-vulnerable family an algorithm name belongs to."""
    normalized = (algorithm or "").upper()
    return next((item for item in VULNERABLE_FAMILIES if item in normalized), None)


def post_quantum_family(algorithm: str | None) -> str | None:
    """Return the post-quantum family an algorithm name belongs to, if any."""
    normalized = (algorithm or "").upper().replace("_", "-")
    return next((item for item in POST_QUANTUM_FAMILIES if item in normalized), None)


def lifecycle_detail(metadata: dict[str, Any] | None) -> dict[str, Any]:
    """Extract the metadata keys that influence how a finding is rated."""
    metadata = metadata or {}
    return {key: metadata[key] for key in LIFECYCLE_KEYS if key in metadata}


def classical_risk(
    name: str,
    category: str,
    detail: dict[str, Any] | None = None,
) -> tuple[str, str]:
    """Return a deliberately conservative, explainable classical risk rating."""
    upper = (name or "").upper()
    detail = detail or {}

    if category == "Key" and "PRIVATE" in upper:
        return "critical", "Private-key material appears to be stored with the project."
    if detail.get("expired"):
        return "critical", "The certificate has expired, so every relying party will reject it."
    if detail.get("untrusted_exponent"):
        return "high", "The RSA public exponent is unacceptably small, which makes the key trivially breakable."
    if any(token in upper for token in WEAK_PRIMITIVES):
        return "high", "The detected primitive is deprecated or below modern security expectations."
    if category == "Certificate":
        if detail.get("not_yet_valid"):
            return "medium", "The certificate is not valid yet; confirm the intended activation date."
        if detail.get("expiring_soon"):
            return "medium", "The certificate expires soon and renewal should already be scheduled."
        if detail.get("self_signed") and detail.get("ca"):
            return "info", "A self-signed issuing CA is expected in private PKI; verify it is distributed and rotated."
        return "medium", "The certificate should be checked for expiry, trust and key strength."
    if category == "Randomness" or "NON-CRYPT" in upper or "INSECURE" in upper:
        return "high", "A non-cryptographic random source is used where unpredictable output is required."
    if category == "Key Derivation":
        if "PBKDF2" in upper and "ITERATION" in upper:
            return "high", "The configured PBKDF2 iteration count is far below current guidance, so offline password cracking stays cheap."
        return "medium", "Password-based key derivation must use a reviewed KDF with a tuned cost parameter."
    if category == "Protocol" and any(token in upper for token in ("TLS 1.0", "TLSV1.0", "TLS 1.1", "TLSV1.1")):
        return "high", "TLS 1.0 and TLS 1.1 are deprecated and should not be enabled."
    if any(token in upper for token in WEAK_CURVES) or detail.get("weak_curve"):
        return "medium", "The elliptic curve is below the recommended 128-bit strength floor."
    if any(token in upper for token in REVIEW_PRIMITIVES):
        return "medium", "The configuration is usable in some contexts but needs security review."
    if category in {"HSM", "Library", "Key Management", "Dependency"}:
        return "info", "Inventory signal detected; configuration determines the actual risk."
    if category == "Protocol":
        if "TLS 1.2" in upper or "TLSV1.2" in upper:
            return "medium", "TLS 1.2 requires validation of cipher suites, protocol options and client compatibility."
        return "low", "Protocol inventory signal detected; validate the negotiated version and configuration."
    return "low", "No immediate classical weakness is identified by the prototype rule set."


def references_for(name: str, category: str, detail: dict[str, Any] | None = None) -> list[str]:
    """Return the short standards references that apply to a finding."""
    upper = (name or "").upper()
    detail = detail or {}
    references: list[str] = []

    def add(reference: str) -> None:
        if reference and reference not in references:
            references.append(reference)

    for token, reference in REFERENCES.items():
        if token in upper or token == (category or "").upper():
            add(reference)
    if category == "Key" and "PRIVATE" in upper:
        add("OWASP Secrets Management Cheat Sheet - never store private keys inside a project")
    if detail.get("expired"):
        add("RFC 5280 - an expired certificate fails validation at every relying party")
    if detail.get("self_signed"):
        add("CA/Browser Forum Baseline Requirements - self-signed certificates are not publicly trusted")
    if detail.get("ca") and not detail.get("expired"):
        add("CA/Browser Forum Baseline Requirements - issuing CA key strength and rotation")
    if detail.get("key_usage"):
        add("RFC 5280 - key usage and extended key usage constrain what a certificate may be used for")
    if detail.get("untrusted_exponent"):
        add("NIST SP 800-56B Rev. 2 - RSA exponents smaller than 65537 are not acceptable")
    return references


def mosca_risk(
    algorithm: str | None,
    sensitivity: str = "pii",
    migration_complexity: str = "standard_application",
    threat_timeline: int = 15,
) -> dict[str, Any]:
    """Return an explicit Mosca inequality calculation and explanation."""
    if post_quantum_family(algorithm):
        return {
            "level": "not_applicable",
            "reason": POST_QUANTUM_REASON,
            "family": post_quantum_family(algorithm),
            "post_quantum": True,
            "x": None,
            "y": None,
            "z": threat_timeline,
            "margin": None,
            "migration_target": None,
            "references": [REFERENCES["ML-KEM"]],
        }

    family = quantum_family(algorithm)
    if not family:
        return {
            "level": "not_applicable",
            "reason": (
                "Mosca model: X is the data-lifetime requirement, Y is migration time and Z is the "
                f"quantum threat timeline ({threat_timeline} years). X, Y and margin are not calculated "
                "because this finding is not mapped to a quantum-vulnerable public-key family."
            ),
            "family": None,
            "post_quantum": False,
            "x": None,
            "y": None,
            "z": threat_timeline,
            "margin": None,
            "migration_target": None,
            "references": [],
        }

    x = DATA_LIFETIME_YEARS.get(sensitivity, DATA_LIFETIME_YEARS["pii"])
    y = MIGRATION_YEARS.get(migration_complexity, MIGRATION_YEARS["standard_application"])
    margin = threat_timeline - (x + y)
    if margin < 0:
        level = "critical"
    elif margin <= 3:
        level = "high"
    elif margin <= 7:
        level = "medium"
    else:
        level = "low"

    target = PQC_MIGRATION_TARGETS.get(family)
    return {
        "level": level,
        "reason": (
            f"{family} is vulnerable to sufficiently capable quantum attacks. Mosca model: "
            f"X={x} years of data lifetime, Y={y} years for migration, Z={threat_timeline} years "
            f"to the threat, and margin=Z-(X+Y)={margin} years."
            + (f" Migration target: {target}." if target else "")
        ),
        "family": family,
        "post_quantum": False,
        "x": x,
        "y": y,
        "z": threat_timeline,
        "margin": margin,
        "migration_target": target,
        "references": [QUANTUM_REFERENCES[family]] if family in QUANTUM_REFERENCES else [],
    }


def quantum_risk(
    algorithm: str | None,
    sensitivity: str = "pii",
    migration_complexity: str = "standard_application",
    threat_timeline: int = 15,
) -> dict[str, Any]:
    """Apply Mosca's X + Y > Z inequality using explicit prototype assumptions."""
    return mosca_risk(algorithm, sensitivity, migration_complexity, threat_timeline)


def risk_rank(risk: str) -> int:
    """Sort key for the classical levels, most severe first."""
    return RISK_ORDER.index(risk) if risk in RISK_ORDER else len(RISK_ORDER)


def summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate findings into the counters reported by the bridge and CBOM."""
    classical: dict[str, int] = {level: 0 for level in RISK_ORDER}
    quantum: dict[str, int] = {}
    categories: dict[str, int] = {}
    confidences: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    files: set[str] = set()
    for finding in findings:
        risk = str(finding.get("risk", "info"))
        classical[risk] = classical.get(risk, 0) + 1
        level = str(finding.get("quantum_risk", "not_applicable"))
        quantum[level] = quantum.get(level, 0) + 1
        category = str(finding.get("category", "Unknown"))
        categories[category] = categories.get(category, 0) + 1
        level_confidence = str(finding.get("confidence_level", ""))
        if level_confidence in confidences:
            confidences[level_confidence] += 1
        path = str(finding.get("file", ""))
        if path:
            files.add(path)
    return {
        "findings": len(findings),
        "files_with_findings": len(files),
        "risk_distribution": {level: count for level, count in classical.items() if count},
        "quantum_distribution": dict(sorted(quantum.items())),
        "category_distribution": dict(sorted(categories.items())),
        "confidence_distribution": {level: count for level, count in confidences.items() if count},
        "urgent": classical.get("critical", 0) + classical.get("high", 0),
    }
