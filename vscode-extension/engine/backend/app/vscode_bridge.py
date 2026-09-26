"""JSON stdin bridge used by the local VS Code extension."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .detector import detect_file


def main() -> None:
    try:
        request = json.load(sys.stdin)
        mode = str(request.get("mode") or "text")
        sensitivity = str(request.get("sensitivity") or "pii")
        migration_complexity = str(request.get("migration_complexity") or "standard_application")
        threat_timeline = int(request.get("threat_timeline") or 15)

        if mode in {"workspace", "artifact"}:
            from .scanner import ScanOptions, scan_project, scan_upload

            target = Path(str(request.get("path") or "")).resolve()
            options = ScanOptions(sensitivity, migration_complexity, threat_timeline)
            if mode == "workspace":
                result = scan_project(target, options)
                result["input_type"] = "workspace"
            else:
                if not target.is_file():
                    raise ValueError("The selected artifact does not exist.")
                result = scan_upload(target.read_bytes(), target.name, options)
            json.dump({
                "findings": result["findings"],
                "engines": result.get("engines", {}),
                "input_type": result.get("input_type", mode),
                "files_scanned": result.get("files_scanned", 0),
                "files_skipped": result.get("files_skipped", 0),
            }, sys.stdout)
            return

        relative_path = str(request.get("path") or "untitled.txt")
        text = str(request.get("text") or "")
        findings = detect_file(
            Path(relative_path),
            relative_path,
            text,
            sensitivity,
            migration_complexity,
            threat_timeline,
        )
        for index, finding in enumerate(findings, start=1):
            finding["id"] = f"VSC-{index:04d}"
        json.dump({"findings": findings, "input_type": "source-file"}, sys.stdout)
    except Exception as exc:
        json.dump({"error": f"ECDAT scan failed: {exc}"}, sys.stdout)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
