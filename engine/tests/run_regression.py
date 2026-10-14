"""Deterministic false-positive regression baseline for the Periperi engine.

The corpus is generated into a temporary project directory and scanned through
``backend.app.vscode_bridge`` exactly as the VS Code extension does. Static
fixtures are embedded here so no PEM-looking file or key material is committed;
the "real" key and certificate for the validated cases are generated at run time
in a temporary directory and never written into the repository.

Fixtures fall into three groups:

* ``benign``     - must NOT produce a critical/high finding (guards against FPs).
* ``vulnerable`` - must produce the listed finding at or above the given risk.
* ``deferred``   - reported only; known false positives that need a larger fix.

Run from the repository root::

    python engine/tests/run_regression.py
"""

from __future__ import annotations

import datetime
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ENGINE = REPO / "engine"
RUNTIME = ENGINE / "runtime"
RISK_ORDER = ("critical", "high", "medium", "low", "info", "not_applicable")
BLOCKING_RISKS = {"critical", "high"}

LONE_HEADER = "-----BEGIN RSA PRIVATE KEY-----"
CERT_HEADER = "-----BEGIN CERTIFICATE-----"

BENIGN = {
    "docs/pem_header_only.md": (
        "# Key handling\n\n"
        "Never commit a key that starts with the line below:\n\n"
        "```\n"
        f"{LONE_HEADER}\n"
        "```\n"
    ),
    "src/string_header.py": (
        "PLACEHOLDER = \"" + LONE_HEADER + "\\n(MIIexamplebody)\"\n"
        "def describe():\n"
        "    return 'a private key starts with a PEM header'\n"
    ),
    "config/fake_with_end.pem": (
        f"{LONE_HEADER}\n"
        "notbase64notbase64notbase64\n"
        "-----END RSA PRIVATE KEY-----\n"
    ),
    "src/strong_tls.py": (
        "import ssl\n"
        "ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n"
        "ctx.minimum_version = ssl.TLSVersion.TLSv1_2\n"
    ),
}

VULNERABLE = {
    "src/md5_usage.py": ("digest = hashlib.md5(password).hexdigest()\n", "MD5", "high"),
    "src/sha1_usage.py": ("signature = hashlib.sha1(payload).hexdigest()\n", "SHA-1", "high"),
    "config/weak_tls.py": ('minimum_version = "TLS 1.0"\n', "TLS 1.0", "high"),
}

#: Reported but not gated - these are the deferred false positives.
DEFERRED = {
    "src/legacy_comment.py": "# We removed MD5 and DSA support in 2024; do not re-enable them.\n",
    "docs/negative_context.md": "The design decided not to use ECC or ECDH anywhere in the stack.\n",
}

GENERATED_PRIVATE_KEY = "keys/generated_private.pem"
GENERATED_PUBLIC_KEY = "keys/generated_public.pem"
GENERATED_CERT = "keys/generated_certificate.pem"


def _runtime_dir() -> Path | None:
    machine = platform.machine().lower()
    system = platform.system().lower()
    if system == "windows":
        candidate = "win32-x64"
    elif system == "darwin":
        candidate = "darwin-arm64" if ("arm" in machine or "aarch" in machine) else "darwin-x64"
    else:
        candidate = "linux-arm64" if ("arm" in machine or "aarch" in machine) else "linux-x64"
    path = RUNTIME / candidate
    return path if path.is_dir() else None


def _import_cryptography():
    runtime = _runtime_dir()
    if runtime is not None and str(runtime) not in sys.path:
        sys.path.insert(0, str(runtime))
    import cryptography  # noqa: F401

    return cryptography


def _generate_key_material(destination: Path) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "generated_private.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    (destination / "generated_public.pem").write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "periperi-regression")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    (destination / "generated_certificate.pem").write_bytes(
        cert_pem := certificate.public_bytes(serialization.Encoding.PEM)
    )
    assert CERT_HEADER.encode() in cert_pem


def _write_fixtures(root: Path) -> None:
    for relative, text in {**BENIGN, **{k: v[0] for k, v in VULNERABLE.items()}, **DEFERRED}.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")


def _boot() -> str:
    paths = [str(ENGINE)]
    runtime = _runtime_dir()
    if runtime is not None:
        paths.append(str(runtime))
    return (
        "import sys; sys.path[:0]=%r; "
        "from backend.app.vscode_bridge import main; raise SystemExit(main())" % (paths,)
    )


def _run(request: dict) -> dict:
    proc = subprocess.run(
        [sys.executable, "-c", _boot()],
        input=json.dumps(request),
        capture_output=True,
        text=True,
    )
    if not proc.stdout.strip():
        raise RuntimeError(f"engine produced no output (stderr: {proc.stderr.strip()[:400]})")
    return json.loads(proc.stdout)


def _risk_at_least(risk: str, floor: str) -> bool:
    return RISK_ORDER.index(risk) <= RISK_ORDER.index(floor)


def main() -> int:
    try:
        _import_cryptography()
        have_crypto = True
    except Exception as exc:  # pragma: no cover - depends on the prepared runtime
        have_crypto = False
        print(f"[warn] cryptography unavailable ({exc}); generated key cases will be skipped")

    with tempfile.TemporaryDirectory(prefix="ecdat-regression-") as staging:
        project = Path(staging)
        _write_fixtures(project)
        if have_crypto:
            _generate_key_material(project / "keys")

        result = _run({"mode": "workspace", "path": str(project), "max_files": 500})
        if "error" in result:
            print(f"[fail] engine error: {result['error']}")
            return 1

        by_file: dict[str, list[dict]] = {}
        for finding in result["findings"]:
            by_file.setdefault(finding["file"], []).append(finding)

        print(f"engine {result['analysis']['engine_version']} schema {result['analysis']['schema']} "
              f"files={result['files_scanned']} findings={len(result['findings'])}\n")

        failures = 0

        print("BENIGN (no critical/high allowed)")
        for relative in BENIGN:
            findings = by_file.get(relative, [])
            blocking = [f for f in findings if f["risk"] in BLOCKING_RISKS]
            status = "PASS" if not blocking else "FAIL"
            if blocking:
                failures += 1
            detail = ", ".join(f"{f['name']}:{f['risk']}" for f in findings) or "-"
            print(f"  [{status}] {relative} -> {detail}")

        print("\nVULNERABLE (required findings)")
        expected_total = 0
        expected_found = 0
        for relative, (_, name, floor) in VULNERABLE.items():
            expected_total += 1
            findings = by_file.get(relative, [])
            match = [f for f in findings if f["name"] == name and _risk_at_least(f["risk"], floor)]
            ok = bool(match)
            expected_found += int(ok)
            if not ok:
                failures += 1
            detail = ", ".join(f"{f['name']}:{f['risk']}" for f in findings) or "-"
            print(f"  [{'PASS' if ok else 'FAIL'}] {relative} need {name}>={floor} -> {detail}")

        if have_crypto:
            generated = {
                GENERATED_PRIVATE_KEY: ("Private key detected", "critical"),
                GENERATED_CERT: ("X.509 certificate", "info"),
            }
            for relative, (name, floor) in generated.items():
                findings = by_file.get(relative, [])
                if relative == GENERATED_PUBLIC_KEY:
                    continue
                match = [f for f in findings if f["name"] == name and _risk_at_least(f["risk"], floor)]
                expected_total += 1
                expected_found += int(bool(match))
                blocking = [f for f in findings if f["risk"] in BLOCKING_RISKS]
                if relative == GENERATED_PUBLIC_KEY and blocking:
                    failures += 1
                print(f"  [{'PASS' if match else 'SKIP'}] {relative} need {name}>={floor}")

            public_findings = by_file.get(GENERATED_PUBLIC_KEY, [])
            public_blocking = [f for f in public_findings if f["risk"] in BLOCKING_RISKS]
            if public_blocking:
                failures += 1
            print(f"  [{'PASS' if not public_blocking else 'FAIL'}] {GENERATED_PUBLIC_KEY} "
                  f"(no critical/high) -> "
                  + (", ".join(f"{f['name']}:{f['risk']}" for f in public_findings) or "-"))

        benign_fp = [
            (relative, f["name"], f["risk"])
            for relative in BENIGN
            for f in by_file.get(relative, [])
            if f["risk"] in BLOCKING_RISKS
        ]
        print("\nDEFERRED (reported only, known false positives)")
        for relative in DEFERRED:
            findings = by_file.get(relative, [])
            detail = ", ".join(f"{f['name']}:{f['risk']}" for f in findings) or "-"
            print(f"  [info] {relative} -> {detail}")

        tp = expected_found
        fp = len(benign_fp)
        recall = tp / expected_total if expected_total else 0.0
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        print("\nSYNTHETIC CORPUS (not a real-world accuracy claim)")
        print(f"  expected={expected_total} found={tp} benign_high_or_critical={fp}")
        print(f"  recall={recall:.2f} precision={precision:.2f}")
        print(f"\nresult: {'PASS' if failures == 0 else f'FAIL ({failures} fixture(s))'}")
        return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
