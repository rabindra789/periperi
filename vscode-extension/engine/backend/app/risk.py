"""Transparent prototype risk and quantum-readiness rules."""

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

QUANTUM_VULNERABLE = {"RSA", "ECC", "ECDSA", "ECDH", "DSA", "DH"}


def classical_risk(name: str, category: str) -> tuple[str, str]:
    """Return a deliberately conservative, explainable classical risk rating."""
    upper = name.upper()
    if category == "Key" and "PRIVATE" in upper:
        return "critical", "Private-key material appears to be stored with the project."
    if any(token in upper for token in ("MD5", "SHA-1", "SHA1", "RSA-1024", "DES", "RC4")):
        return "high", "The detected primitive is deprecated or below modern security expectations."
    if category == "Certificate":
        return "medium", "The certificate should be checked for expiry, trust and key strength."
    if any(token in upper for token in ("ECB", "RSA-2048", "DSA", "DH")):
        return "medium", "The configuration is usable in some contexts but needs security review."
    if category in {"HSM", "Library"}:
        return "info", "Inventory signal detected; configuration determines the actual risk."
    return "low", "No immediate classical weakness is identified by the prototype rule set."


def quantum_risk(
    algorithm: str | None,
    sensitivity: str = "pii",
    migration_complexity: str = "standard_application",
    threat_timeline: int = 15,
) -> dict[str, Any]:
    """Apply Mosca's X + Y > Z inequality using explicit prototype assumptions."""
    normalized = (algorithm or "").upper()
    family = next((item for item in QUANTUM_VULNERABLE if item in normalized), None)
    if not family:
        return {
            "level": "not_applicable",
            "reason": "Mosca timeline scoring is reserved for quantum-vulnerable public-key algorithms.",
            "x": None,
            "y": None,
            "z": threat_timeline,
            "margin": None,
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

    return {
        "level": level,
        "reason": (
            f"{family} is vulnerable to sufficiently capable quantum attacks. "
            f"The prototype margin is {margin} years under the selected assumptions."
        ),
        "x": x,
        "y": y,
        "z": threat_timeline,
        "margin": margin,
    }

