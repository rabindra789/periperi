"""JSON stdin bridge used by the local VS Code extension.

The extension writes exactly one JSON request to stdin and reads exactly one
JSON object from stdout, so progress and diagnostics go to stderr. Failures are
reported as ``{"error": ...}`` with a non-zero exit code rather than as a
traceback, because the caller parses stdout as JSON.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from .. import SCHEMA_VERSION, __version__
from .dependencies import is_cryptographic_dependency, is_manifest, parse_manifest
from .detector import detect_file, make_finding
from .risk import summary as summarize

#: Request fields understood by the bridge, in addition to ``mode``.
REQUEST_FIELDS = (
    "mode",
    "path",
    "text",
    "sensitivity",
    "migration_complexity",
    "threat_timeline",
)

#: Modes handled without importing the heavier scanning modules.
LOCAL_MODES = {"text", "capabilities", "version"}


def _write_progress(event: dict[str, Any]) -> None:
    sys.stderr.write(f"ECDAT_PROGRESS {json.dumps(event, separators=(',', ':'))}\n")
    sys.stderr.flush()


def _engines() -> dict[str, Any]:
    """Report the analysis engines available to this interpreter."""
    from .container_tools import container_tool_details

    engines: dict[str, Any] = {}
    try:
        from .openssl_inspector import openssl_details

        engines["openssl"] = openssl_details()
    except Exception as exc:  # pragma: no cover - depends on the local interpreter
        engines["openssl"] = {"available": False, "error": str(exc)}
    engines.update(container_tool_details())
    return engines


def _analysis() -> dict[str, Any]:
    return {
        "engine_version": __version__,
        "schema": SCHEMA_VERSION,
        "python": ".".join(str(part) for part in sys.version_info[:3]),
    }


def _read_request() -> dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        raise ValueError("The request was empty; expected a JSON object on stdin.")
    try:
        request = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"The request was not valid JSON: {exc}") from exc
    if not isinstance(request, dict):
        raise ValueError("The request must be a JSON object.")
    return request


def _manifest_dependencies(relative_path: str, text: str) -> list[dict[str, Any]]:
    """Inventory a manifest buffer.

    ``parse_manifest`` reads from disk, so an unsaved or modified buffer is
    staged in a temporary file first. Nothing is ever written into the user's
    workspace, and the finding path stays the editor path.
    """
    manifest_path = Path(relative_path)
    if not is_manifest(manifest_path):
        return []
    try:
        if manifest_path.is_file() and manifest_path.read_text(encoding="utf-8") == text:
            return parse_manifest(manifest_path)
    except (OSError, UnicodeError):
        pass
    with tempfile.TemporaryDirectory(prefix="ecdat-manifest-") as staging:
        staged = Path(staging) / manifest_path.name
        try:
            staged.write_text(text, encoding="utf-8")
        except (OSError, UnicodeError):
            return []
        return parse_manifest(staged)


def _text_findings(
    relative_path: str,
    text: str,
    sensitivity: str,
    migration_complexity: str,
    threat_timeline: int,
) -> list[dict[str, Any]]:
    manifest_path = Path(relative_path)
    findings = detect_file(
        manifest_path,
        relative_path,
        text,
        sensitivity,
        migration_complexity,
        threat_timeline,
    )
    for dependency in _manifest_dependencies(relative_path, text):
        crypto_relevant = is_cryptographic_dependency(dependency["name"], dependency["ecosystem"])
        version = dependency["version"]
        findings.append(make_finding(
            category="Library" if crypto_relevant else "Dependency",
            name=dependency["name"],
            path=relative_path,
            line=0,
            evidence=f"Manifest dependency: {dependency['name']} {version or 'unspecified'}",
            sensitivity=sensitivity,
            migration_complexity=migration_complexity,
            threat_timeline=threat_timeline,
            confidence=0.99,
            version=version,
            metadata={
                "source": "manifest",
                "manifest": relative_path,
                "ecosystem": dependency["ecosystem"],
                "scope": dependency["scope"],
                "crypto_relevant": crypto_relevant,
            },
        ))
    for index, finding in enumerate(findings, start=1):
        finding["id"] = f"VSC-{index:04d}"
    return findings


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if "--version" in argv or "-V" in argv:
            json.dump(_analysis(), sys.stdout)
            return 0
        if "--capabilities" in argv:
            json.dump({"analysis": _analysis(), "engines": _engines(), "modes": sorted(LOCAL_MODES | {"workspace", "artifact"})}, sys.stdout)
            return 0

        request = _read_request()
        mode = str(request.get("mode") or "text")
        sensitivity = str(request.get("sensitivity") or "pii")
        migration_complexity = str(request.get("migration_complexity") or "standard_application")
        threat_timeline = int(request.get("threat_timeline") or 15)

        if mode in {"workspace", "artifact"}:
            from .scanner import ScanOptions, scan_project, scan_upload

            target_value = str(request.get("path") or "").strip()
            if not target_value:
                raise ValueError("A workspace or artifact path is required.")
            target = Path(target_value).resolve()
            options = ScanOptions(sensitivity, migration_complexity, threat_timeline)
            if mode == "workspace":
                result = scan_project(target, options, _write_progress)
                result["input_type"] = "workspace"
            else:
                if not target.is_file():
                    raise ValueError("The selected artifact does not exist.")
                result = scan_upload(
                    target.read_bytes(),
                    target.name,
                    options,
                    _write_progress,
                )
            findings = result["findings"]
            json.dump({
                "findings": findings,
                "engines": result.get("engines", {}),
                "input_type": result.get("input_type", mode),
                "files_scanned": result.get("files_scanned", 0),
                "files_skipped": result.get("files_skipped", 0),
                "analysis": _analysis(),
                "summary": summarize(findings),
            }, sys.stdout)
            return 0

        if mode == "capabilities":
            json.dump({
                "analysis": _analysis(),
                "engines": _engines(),
                "modes": sorted(LOCAL_MODES | {"workspace", "artifact"}),
                "request_fields": list(REQUEST_FIELDS),
            }, sys.stdout)
            return 0

        if mode == "version":
            json.dump(_analysis(), sys.stdout)
            return 0

        if mode != "text":
            raise ValueError(f"Unknown mode {mode!r}. Expected one of: capabilities, text, version, workspace, artifact.")

        relative_path = str(request.get("path") or "untitled.txt")
        text = str(request.get("text") or "")
        findings = _text_findings(relative_path, text, sensitivity, migration_complexity, threat_timeline)
        json.dump({
            "findings": findings,
            "engines": _engines(),
            "input_type": "source-file",
            "analysis": _analysis(),
            "summary": summarize(findings),
        }, sys.stdout)
        return 0
    except Exception as exc:
        json.dump({"error": f"ECDAT scan failed: {exc}"}, sys.stdout)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
