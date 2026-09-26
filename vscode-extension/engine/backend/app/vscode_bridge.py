"""JSON stdin bridge used by the local VS Code extension."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .detector import detect_file


def main() -> None:
    try:
        request = json.load(sys.stdin)
        relative_path = str(request.get("path") or "untitled.txt")
        text = str(request.get("text") or "")
        findings = detect_file(
            Path(relative_path),
            relative_path,
            text,
            str(request.get("sensitivity") or "pii"),
            str(request.get("migration_complexity") or "standard_application"),
            int(request.get("threat_timeline") or 15),
        )
        for index, finding in enumerate(findings, start=1):
            finding["id"] = f"VSC-{index:04d}"
        json.dump({"findings": findings}, sys.stdout)
    except Exception as exc:
        json.dump({"error": f"ECDAT scan failed: {exc}"}, sys.stdout)
        raise SystemExit(1)


if __name__ == "__main__":
    main()

