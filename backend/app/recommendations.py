"""Concise remediation guidance for detected cryptographic artefacts.

Two shapes are produced for every finding: a one-sentence ``recommendation``
for the Problems panel and the report, and a ``recommendation_details`` object
that classifies the migration so a CBOM consumer can group and schedule work.
Neither claims to change code automatically.
"""

from __future__ import annotations

from typing import Any

from .risk import post_quantum_family, quantum_family


def _migration_target(name: str) -> str | None:
    family = quantum_family(name)
    if not family:
        return None
    from .risk import PQC_MIGRATION_TARGETS

    return PQC_MIGRATION_TARGETS.get(family)


def recommendation(name: str, category: str, risk: str, detail: dict[str, Any] | None = None) -> str:
    upper = (name or "").upper()
    detail = detail or {}

    if category == "Key" and "PRIVATE" in upper:
        return "Remove the key from the project, rotate it, and use a managed secret or key store."
    if detail.get("expired"):
        return "Replace or renew this certificate now; relying parties will reject it while it is expired."
    if detail.get("not_yet_valid"):
        return "Confirm the intended activation date and that the certificate is not deployed early."
    if detail.get("expiring_soon"):
        return "Schedule renewal now and confirm the replacement certificate is issued before expiry."
    if detail.get("untrusted_exponent"):
        return "Replace this RSA key with a generated key that uses the standard public exponent 65537."
    if detail.get("weak_curve"):
        return "Move to an approved curve such as P-256, Curve25519 or ML-KEM for key agreement."
    if post_quantum_family(name):
        return "Keep this post-quantum algorithm, and confirm the implementation matches FIPS 203/204/205."
    if "MD5" in upper or "SHA-1" in upper or "SHA1" in upper:
        return "Replace it with SHA-256 or stronger for security-sensitive integrity use."
    if "RSA-1024" in upper:
        return "Replace RSA-1024 immediately and plan a post-quantum or hybrid migration path."
    if "ECB" in upper:
        return "Use an authenticated encryption mode such as AES-GCM with safe nonce handling."
    if category == "Randomness" or "NON-CRYPT" in upper or "INSECURE" in upper:
        return "Replace this generator with a cryptographically secure source such as secrets, SecureRandom or os.urandom."
    if category == "Key Derivation":
        if "PBKDF2" in upper and "ITERATION" in upper:
            return "Raise the PBKDF2 iteration count to current guidance, or move password hashing to Argon2id or scrypt."
        return "Use Argon2id, scrypt or PBKDF2 with a tuned cost parameter instead of a single-pass hash."
    if category == "Token":
        return "Pin the accepted JOSE algorithms, reject alg=none, and prefer PS256 or EdDSA over RS256."
    if category == "Protocol" and any(token in upper for token in ("TLS 1.0", "TLSV1.0", "TLS 1.1", "TLSV1.1")):
        return "Disable TLS 1.0 and 1.1 and require TLS 1.2 or 1.3 on both client and server."
    if category == "Certificate":
        return "Validate expiry, trust chain, signature algorithm and public-key strength."
    if category == "HSM":
        return "Confirm supported algorithms, firmware status and post-quantum migration capabilities."
    if category in {"Library", "Dependency"}:
        return "Track the dependency version and confirm that security updates are maintained."
    if category == "Key Management":
        return "Review key-service algorithms, rotation controls and post-quantum roadmap support."
    if quantum_family(name):
        target = _migration_target(name)
        if target:
            return f"Plan a post-quantum migration for this public-key family; the target is {target}."
        return "Review retention needs and plan a post-quantum or hybrid migration for this public-key family."
    if risk in {"critical", "high"}:
        return "Prioritize review and replace the weak configuration with a modern approved alternative."
    return "Retain in the CBOM and review when cryptographic policy or threat assumptions change."


def structured_recommendation(
    name: str,
    category: str,
    risk: str,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Describe a manual migration action without changing source code."""
    upper = (name or "").upper()
    detail = detail or {}
    target = _migration_target(name)

    if category == "Key" and "PRIVATE" in upper:
        migration_type = "credential_rotation"
        complexity = "high"
        performance = {"level": "low", "description": "Rotation can be coordinated without changing cryptographic throughput."}
    elif detail.get("expired") or detail.get("expiring_soon"):
        migration_type = "certificate_rotation"
        complexity = "low"
        performance = {"level": "low", "description": "Certificate replacement normally has negligible application overhead."}
    elif detail.get("untrusted_exponent") or detail.get("weak_curve"):
        migration_type = "key_regeneration"
        complexity = "medium"
        performance = {"level": "low", "description": "Regenerating a key is cheap, but dependent key stores and pins need updating."}
    elif any(item in upper for item in ("MD5", "SHA-1", "SHA1", "ECB")):
        migration_type = "primitive_or_mode_replacement"
        complexity = "medium"
        performance = {"level": "low", "description": "Modern equivalents are generally comparable in throughput and memory use."}
    elif category == "Randomness" or "NON-CRYPT" in upper or "INSECURE" in upper:
        migration_type = "random_source_replacement"
        complexity = "low"
        performance = {"level": "low", "description": "A CSPRNG is slightly slower than a general-purpose generator and still negligible per use."}
    elif category == "Key Derivation":
        migration_type = "kdf_tuning"
        complexity = "medium"
        performance = {"level": "medium", "description": "Memory-hard parameters cost more CPU and memory per derivation; benchmark login and unlock paths."}
    elif category == "Token":
        migration_type = "token_algorithm_policy"
        complexity = "medium"
        performance = {"level": "low", "description": "Algorithm pinning is a configuration change with no measurable runtime cost."}
    elif quantum_family(name):
        migration_type = "post_quantum_migration"
        complexity = "high"
        performance = {
            "level": "medium",
            "description": "Larger keys and signatures increase handshake latency, certificate size and memory; benchmark before rollout.",
        }
    elif category == "Certificate":
        migration_type = "certificate_review"
        complexity = "low"
        performance = {"level": "low", "description": "Certificate replacement normally has negligible application overhead."}
    elif category == "HSM":
        migration_type = "platform_capability_review"
        complexity = "high"
        performance = {"level": "low", "description": "Validate firmware and provider support before scheduling any migration."}
    elif category == "Key Management":
        migration_type = "key_service_capability_review"
        complexity = "high"
        performance = {"level": "low", "description": "Validate managed-service support and migration constraints before rollout."}
    elif category in {"Library", "Dependency"}:
        migration_type = "dependency_upgrade"
        complexity = "low"
        performance = {"level": "low", "description": "Review release notes and run compatibility and performance tests."}
    elif category == "Protocol":
        migration_type = "protocol_configuration_review"
        complexity = "medium"
        performance = {"level": "low", "description": "Validate clients, interoperability and handshake performance during rollout."}
    elif risk in {"critical", "high"}:
        migration_type = "manual_remediation"
        complexity = "medium"
        performance = {"level": "low", "description": "Validate the selected replacement with project-specific benchmarks."}
    else:
        migration_type = "inventory_retention"
        complexity = "low"
        performance = {"level": "low", "description": "No immediate runtime change is proposed by this inventory action."}

    return {
        "action": recommendation(name, category, risk, detail),
        "migration_type": migration_type,
        "complexity": complexity,
        "performance_impact": performance,
        "automatic_migration": False,
        "post_quantum_target": target,
    }
