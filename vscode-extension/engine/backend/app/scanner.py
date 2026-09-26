"""Safe project traversal and ZIP extraction for ECDAT scans."""

from __future__ import annotations

import shutil
import tarfile
import tempfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .container_tools import container_tool_details, scan_container_with_tools
from .dependencies import is_cryptographic_dependency, is_manifest, parse_manifest
from .detector import CERTIFICATE_SUFFIXES, KEY_SUFFIXES, detect_file, make_finding
from .openssl_inspector import (
    BINARY_SUFFIXES,
    inspect_binary,
    inspect_crypto_artifact,
    openssl_details,
)

TEXT_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".c", ".cpp", ".h", ".hpp",
    ".go", ".rs", ".php", ".rb", ".cs", ".kt", ".swift", ".yaml", ".yml",
    ".json", ".xml", ".conf", ".config", ".ini", ".env", ".txt", ".md", ".toml",
    ".properties", ".gradle", ".lock", ".sh", ".ps1", ".dockerfile",
}
SPECIAL_FILENAMES = {"dockerfile", "makefile", "requirements.txt", "package-lock.json", "go.mod"}
SKIP_DIRS = {".git", ".gradle", ".cache", "node_modules", "venv", ".venv", "__pycache__", "target", "dist", "build", ".idea", ".vscode"}
MAX_FILE_SIZE = 2 * 1024 * 1024
MAX_BINARY_SIZE = 25 * 1024 * 1024
MAX_UPLOAD_SIZE = 100 * 1024 * 1024
MAX_EXTRACTED_SIZE = 250 * 1024 * 1024
MAX_FILES = 25_000
MAX_TOTAL_DEPENDENCIES = 5_000
MAX_TOTAL_FINDINGS = 100_000


class ScanError(ValueError):
    pass


ProgressCallback = Callable[[dict[str, Any]], None]


def _select_progress(
    progress: ProgressCallback | None,
    progress_callback: ProgressCallback | None,
) -> ProgressCallback | None:
    return progress_callback if progress_callback is not None else progress


def _emit_progress(
    progress_callback: ProgressCallback | None,
    phase: str,
    count: int,
    total: int,
    message: str,
) -> None:
    if progress_callback is not None:
        progress_callback({
            "phase": phase,
            "count": count,
            "total": total,
            "message": message,
        })


@dataclass
class ScanOptions:
    sensitivity: str = "pii"
    migration_complexity: str = "standard_application"
    threat_timeline: int = 15


def _is_supported(path: Path) -> bool:
    return (
        path.suffix.lower() in TEXT_SUFFIXES
        or path.suffix.lower() in CERTIFICATE_SUFFIXES
        or path.suffix.lower() in KEY_SUFFIXES
        or path.suffix.lower() in BINARY_SUFFIXES
        or path.name.lower() in SPECIAL_FILENAMES
        or is_manifest(path)
    )


def _project_entry_count(root: Path) -> int:
    total = 0
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if path.is_symlink() or (
            path.is_file() and not any(part in SKIP_DIRS for part in relative.parts)
        ):
            total += 1
            if total > MAX_FILES:
                return total
    return total


def _dependency_findings(
    path: Path,
    relative_path: str,
    options: ScanOptions,
    remaining: int,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for dependency in parse_manifest(path)[:remaining]:
        version = dependency["version"] or "unspecified"
        crypto_relevant = is_cryptographic_dependency(dependency["name"], dependency["ecosystem"])

        findings.append(make_finding(
            category="Library" if crypto_relevant else "Dependency",
            name=dependency["name"],
            path=relative_path,
            line=0,
            evidence=f"Manifest dependency: {dependency['name']} {version}",
            sensitivity=options.sensitivity,
            migration_complexity=options.migration_complexity,
            threat_timeline=options.threat_timeline,
            confidence=0.99,
            version=dependency["version"],
            metadata={
                "source": "manifest",
                "manifest": relative_path,
                "ecosystem": dependency["ecosystem"],
                "scope": dependency["scope"],
                "crypto_relevant": crypto_relevant,
            },
        ))
    return findings


def scan_project(
    root: Path,
    options: ScanOptions,
    progress_callback: ProgressCallback | None = None,
    *,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    if not root.exists() or not root.is_dir():
        raise ScanError("The selected project directory does not exist.")

    callback = _select_progress(progress, progress_callback)
    if callback is None:
        paths = root.rglob("*")
        total = 0
    else:
        total = _project_entry_count(root)
        paths = root.rglob("*")
        _emit_progress(callback, "discovering", 0, total, "Discovering project files")

    files_scanned = 0
    files_skipped = 0
    findings: list[dict[str, Any]] = []
    dependency_findings = 0
    for path in paths:
        relative = path.relative_to(root)
        if files_scanned + files_skipped >= MAX_FILES:
            raise ScanError(f"Project exceeds the {MAX_FILES:,}-file scan limit.")
        if path.is_symlink():
            files_skipped += 1
            _emit_progress(callback, "scanning", files_scanned + files_skipped, total, "Scanning project files")
            continue
        if not path.is_file() or any(part in SKIP_DIRS for part in relative.parts):
            continue
        if not _is_supported(path):
            files_skipped += 1
            _emit_progress(callback, "scanning", files_scanned + files_skipped, total, "Scanning project files")
            continue
        is_binary = path.suffix.lower() in BINARY_SUFFIXES
        size_limit = MAX_BINARY_SIZE if is_binary else MAX_FILE_SIZE
        if path.stat().st_size > size_limit:
            files_skipped += 1
            _emit_progress(callback, "scanning", files_scanned + files_skipped, total, "Scanning project files")
            continue
        try:
            data = path.read_bytes()
        except OSError:
            files_skipped += 1
            _emit_progress(callback, "scanning", files_scanned + files_skipped, total, "Scanning project files")
            continue
        relative = str(path.relative_to(root))
        artifact_findings = inspect_crypto_artifact(path, relative, data, options)
        findings.extend(artifact_findings)
        if is_binary or b"\x00" in data[:8192]:
            findings.extend(inspect_binary(relative, data, options))
        elif not artifact_findings:
            text = data.decode("utf-8", errors="ignore")
            findings.extend(detect_file(
                path, relative, text, options.sensitivity,
                options.migration_complexity, options.threat_timeline,
            ))
        if is_manifest(path) and dependency_findings < MAX_TOTAL_DEPENDENCIES:
            manifest_findings = _dependency_findings(
                path, relative, options, MAX_TOTAL_DEPENDENCIES - dependency_findings,
            )
            dependency_findings += len(manifest_findings)
            findings.extend(manifest_findings)
        if len(findings) > MAX_TOTAL_FINDINGS:
            raise ScanError(f"Project exceeds the {MAX_TOTAL_FINDINGS:,}-finding safety limit.")
        files_scanned += 1
        _emit_progress(callback, "scanning", files_scanned + files_skipped, total, "Scanning project files")

    for index, finding in enumerate(findings, start=1):
        finding["id"] = f"F-{index:04d}"

    result = {
        "project_name": root.name,
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "findings": findings,
        "dependency_findings": dependency_findings,
        "dependency_limit_reached": dependency_findings >= MAX_TOTAL_DEPENDENCIES,
        "assumptions": {
            "sensitivity": options.sensitivity,
            "migration_complexity": options.migration_complexity,
            "threat_timeline": options.threat_timeline,
        },
        "engines": {"openssl": openssl_details(), **container_tool_details()},
    }
    _emit_progress(callback, "complete", files_scanned + files_skipped, total, "Project scan complete")
    return result


def _validate_archive(info: zipfile.ZipInfo, destination: Path) -> None:
    member = Path(info.filename.replace("\\", "/"))
    if member.is_absolute() or ".." in member.parts:
        raise ScanError("ZIP contains an unsafe path.")
    resolved = (destination / member).resolve()
    if destination.resolve() not in resolved.parents and resolved != destination.resolve():
        raise ScanError("ZIP contains an unsafe path.")


def _safe_extract_tar(bundle: tarfile.TarFile, destination: Path) -> None:
    members = bundle.getmembers()
    if len(members) > MAX_FILES:
        raise ScanError(f"Archive exceeds the {MAX_FILES:,}-file limit.")
    if sum(member.size for member in members if member.isfile()) > MAX_EXTRACTED_SIZE:
        raise ScanError("Archive expands beyond the 250 MB safety limit.")
    destination_resolved = destination.resolve()
    for member in members:
        relative = Path(member.name.replace("\\", "/"))
        target = (destination / relative).resolve()
        if relative.is_absolute() or ".." in relative.parts or (
            destination_resolved not in target.parents and target != destination_resolved
        ):
            raise ScanError("Archive contains an unsafe path.")
        if member.issym() or member.islnk():
            continue
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
        elif member.isfile():
            target.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            if source is not None:
                with source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)


def _expand_container_layers(root: Path) -> int:
    layers = [path for path in root.rglob("*.tar") if path.is_file()][:100]
    expanded = 0
    for index, layer in enumerate(layers, start=1):
        destination = root / "ecdat_layers" / f"layer-{index:03d}"
        try:
            with tarfile.open(layer, "r:*") as bundle:
                _safe_extract_tar(bundle, destination)
            expanded += 1
        except (tarfile.TarError, OSError, ScanError):
            continue
    return expanded


def scan_zip(
    upload: bytes,
    filename: str,
    options: ScanOptions,
    progress_callback: ProgressCallback | None = None,
    *,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    callback = _select_progress(progress, progress_callback)
    if len(upload) > MAX_UPLOAD_SIZE:
        raise ScanError("ZIP upload exceeds the 100 MB limit.")
    temp_dir = Path(tempfile.mkdtemp(prefix="ecdat-"))
    archive = temp_dir / "project.zip"
    extracted = temp_dir / "project"
    try:
        archive.write_bytes(upload)
        try:
            with zipfile.ZipFile(archive) as bundle:
                infos = bundle.infolist()
                if len(infos) > MAX_FILES:
                    raise ScanError(f"ZIP exceeds the {MAX_FILES:,}-file limit.")
                if sum(item.file_size for item in infos) > MAX_EXTRACTED_SIZE:
                    raise ScanError("ZIP expands beyond the 250 MB safety limit.")
                total = len(infos)
                _emit_progress(callback, "extracting", 0, total, "Preparing archive")
                for index, info in enumerate(infos, start=1):
                    _validate_archive(info, extracted)
                    _emit_progress(callback, "extracting", index, total, "Validating archive contents")
                bundle.extractall(extracted)
                _emit_progress(callback, "extracting", total, total, "Extracting archive contents")
        except zipfile.BadZipFile as exc:
            raise ScanError("The uploaded file is not a valid ZIP archive.") from exc

        if callback is None:
            result = scan_project(extracted, options)
        else:
            result = scan_project(extracted, options, callback)
        result["project_name"] = Path(filename).stem or "uploaded-project"
        result["input_type"] = "repository-archive"
        return result
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def scan_upload(
    upload: bytes,
    filename: str,
    options: ScanOptions,
    progress_callback: ProgressCallback | None = None,
    *,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Scan repository archives, container-image archives, binaries, certificates or keys."""
    callback = _select_progress(progress, progress_callback)
    if len(upload) > MAX_UPLOAD_SIZE:
        raise ScanError("Upload exceeds the 100 MB limit.")
    lower_name = filename.lower()
    _emit_progress(callback, "preparing", 0, 1, "Preparing artifact for scanning")
    if lower_name.endswith(".zip"):
        if callback is None:
            return scan_zip(upload, filename, options)
        return scan_zip(upload, filename, options, callback)

    temp_dir = Path(tempfile.mkdtemp(prefix="ecdat-upload-"))
    extracted = temp_dir / "content"
    source = temp_dir / Path(filename).name
    try:
        source.write_bytes(upload)
        if lower_name.endswith((".tar", ".tar.gz", ".tgz")):
            extracted.mkdir(parents=True, exist_ok=True)
            try:
                with tarfile.open(source, "r:*") as bundle:
                    members = bundle.getmembers()
                    _emit_progress(callback, "extracting", 0, len(members), "Preparing archive")
                    names = {Path(member.name).name for member in members}
                    _safe_extract_tar(bundle, extracted)
                    _emit_progress(callback, "extracting", len(members), len(members), "Extracting archive contents")
            except tarfile.TarError as exc:
                raise ScanError("The uploaded file is not a valid TAR archive.") from exc
            container_markers = {"manifest.json", "index.json", "oci-layout"}
            is_container = bool(names & container_markers)
            layer_count = _expand_container_layers(extracted) if is_container else 0
            if callback is None:
                result = scan_project(extracted, options)
            else:
                result = scan_project(extracted, options, callback)
            result["input_type"] = "container-image" if is_container else "repository-archive"
            result["container_layers_scanned"] = layer_count
            if is_container:
                _emit_progress(callback, "container-tools", 0, 1, "Running container analysis tools")
                tool_findings, tool_status = scan_container_with_tools(source, options)
                container_name = Path(filename).name or "container-image"
                for tool_finding in tool_findings:
                    metadata = tool_finding.get("metadata")
                    if isinstance(metadata, dict):
                        metadata["container"] = container_name
                result["findings"].extend(tool_findings)
                result["engines"].update(tool_status)
                for index, finding in enumerate(result["findings"], start=1):
                    finding["id"] = f"F-{index:04d}"
                _emit_progress(callback, "complete", 1, 1, "Container analysis complete")
        else:
            extracted.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, extracted / source.name)
            if callback is None:
                result = scan_project(extracted, options)
            else:
                result = scan_project(extracted, options, callback)
            result["input_type"] = "binary-or-cryptographic-artifact"
        result["project_name"] = Path(filename).name or "uploaded-artifact"
        return result
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
