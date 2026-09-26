"""Syft and Trivy adapters for container-image cryptographic inventory."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .detector import make_finding


CRYPTO_PACKAGES = {
    "openssl": "OpenSSL",
    "libssl": "OpenSSL",
    "libcrypto": "OpenSSL",
    "libsodium": "libsodium",
    "bouncycastle": "Bouncy Castle",
    "bcprov": "Bouncy Castle",
    "cryptography": "Python cryptography",
    "pycryptodome": "PyCryptodome",
}


def _executable(name: str) -> str | None:
    located = shutil.which(name)
    if located:
        return located
    local = os.environ.get("LOCALAPPDATA")
    if local:
        link = Path(local) / "Microsoft" / "WinGet" / "Links" / f"{name}.exe"
        if link.exists():
            return str(link)
    return None


def _version(executable: str | None) -> str | None:
    if not executable:
        return None
    try:
        completed = subprocess.run(
            [executable, "version"], capture_output=True, text=True, timeout=10, check=False,
        )
        text = (completed.stdout or completed.stderr).strip().splitlines()
        return text[0][:120] if text else "available"
    except (OSError, subprocess.TimeoutExpired):
        return None


def container_tool_details() -> dict[str, dict[str, Any]]:
    details: dict[str, dict[str, Any]] = {}
    for name in ("syft", "trivy"):
        executable = _executable(name)
        version = _version(executable)
        details[name] = {"available": bool(executable and version), "version": version}
    return details


def _crypto_library(package_name: str) -> str | None:
    lowered = package_name.lower()
    return next((label for token, label in CRYPTO_PACKAGES.items() if token in lowered), None)


def _finding(name: str, path: str, evidence: str, options: Any) -> dict[str, Any]:
    return make_finding(
        category="Library", name=name, path=path, line=0, evidence=evidence,
        sensitivity=options.sensitivity,
        migration_complexity=options.migration_complexity,
        threat_timeline=options.threat_timeline,
    )


def findings_from_syft(payload: dict[str, Any], options: Any) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for artifact in payload.get("artifacts", []):
        package_name = str(artifact.get("name", ""))
        library = _crypto_library(package_name)
        version = str(artifact.get("version", "unknown"))
        if library and (library, version) not in seen:
            findings.append(_finding(
                library, "container-image",
                f"Syft package inventory: {package_name} {version}", options,
            ))
            seen.add((library, version))
    return findings


def findings_from_trivy(payload: dict[str, Any], options: Any) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    risk_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    for result in payload.get("Results", []):
        for vulnerability in result.get("Vulnerabilities") or []:
            package_name = str(vulnerability.get("PkgName", ""))
            library = _crypto_library(package_name)
            identifier = str(vulnerability.get("VulnerabilityID", "unknown"))
            if not library or identifier in seen:
                continue
            finding = _finding(
                f"{library} package vulnerability", "container-image",
                f"Trivy: {identifier} in {package_name} {vulnerability.get('InstalledVersion', 'unknown')}", options,
            )
            severity = str(vulnerability.get("Severity", "UNKNOWN")).upper()
            finding["risk"] = risk_map.get(severity, "info")
            finding["reason"] = f"Trivy reports a {severity.lower()} vulnerability in a cryptographic package."
            finding["recommendation"] = "Upgrade the affected package to the fixed version reported by Trivy and rebuild the image."
            findings.append(finding)
            seen.add(identifier)
    return findings


def scan_container_with_tools(archive: Path, options: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run installed Syft and Trivy CLIs and return normalized ECDAT findings."""
    findings: list[dict[str, Any]] = []
    status: dict[str, Any] = container_tool_details()

    syft = _executable("syft")
    if syft:
        try:
            completed = subprocess.run(
                [syft, f"docker-archive:{archive}", "-o", "json", "-q"],
                capture_output=True, text=True, timeout=180, check=False,
            )
            if completed.returncode == 0:
                findings.extend(findings_from_syft(json.loads(completed.stdout), options))
                status["syft"]["scan"] = "completed"
            else:
                status["syft"]["scan"] = "failed"
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            status["syft"]["scan"] = "failed"

    trivy = _executable("trivy")
    if trivy:
        try:
            completed = subprocess.run(
                [trivy, "image", "--input", str(archive), "--format", "json", "--quiet", "--scanners", "vuln"],
                capture_output=True, text=True, timeout=300, check=False,
            )
            if completed.returncode == 0:
                findings.extend(findings_from_trivy(json.loads(completed.stdout), options))
                status["trivy"]["scan"] = "completed"
            else:
                status["trivy"]["scan"] = "failed"
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            status["trivy"]["scan"] = "failed"
    return findings, status
