"""Concise remediation guidance for detected cryptographic artefacts."""

from __future__ import annotations


def recommendation(name: str, category: str, risk: str) -> str:
    upper = name.upper()
    if category == "Key" and "PRIVATE" in upper:
        return "Remove the key from the project, rotate it, and use a managed secret or key store."
    if "MD5" in upper or "SHA-1" in upper or "SHA1" in upper:
        return "Replace it with SHA-256 or stronger for security-sensitive integrity use."
    if "RSA-1024" in upper:
        return "Replace RSA-1024 immediately and plan a post-quantum or hybrid migration path."
    if "RSA" in upper:
        return "Inventory dependent protocols and plan a post-quantum or hybrid key-establishment migration."
    if any(item in upper for item in ("ECDSA", "ECDH", "ECC")):
        return "Review retention needs and plan a post-quantum or hybrid migration for long-lived data."
    if "DSA" in upper or upper == "DH":
        return "Replace legacy public-key usage and include it in the post-quantum migration plan."
    if "ECB" in upper:
        return "Use an authenticated encryption mode such as AES-GCM with safe nonce handling."
    if category == "Certificate":
        return "Validate expiry, trust chain, signature algorithm and public-key strength."
    if category == "HSM":
        return "Confirm supported algorithms, firmware status and post-quantum migration capabilities."
    if category == "Library":
        return "Track the library version and confirm that security updates are maintained."
    if risk in {"critical", "high"}:
        return "Prioritize review and replace the weak configuration with a modern approved alternative."
    return "Retain in the CBOM and review when cryptographic policy or threat assumptions change."

