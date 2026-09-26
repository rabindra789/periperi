# ECDAT VS Code Extension

[![Release](https://img.shields.io/github/v/release/rabindra789/periperi?display_name=tag)](https://github.com/rabindra789/periperi/releases)

Periperi runs the ECDAT cryptographic discovery engine **locally** and surfaces the results inside VS Code as diagnostics, a report panel and a JSON CBOM export. Source text is handed only to a local Python child process — nothing is sent to an external service, and no project code or scanned binary is ever executed.

- **Version:** 0.2.0
- **Requires:** VS Code 1.90+ and a local Python 3 interpreter
- **Licence:** unlicensed / internal prototype — see [Prototype limits](#prototype-limits)

## What's new in 0.2.0

- New `Periperi: Scan Binary, Certificate, Key or Container` command with a file picker for archives, binaries, certificates, keys and container images.
- New OpenSSL-backed inspector: X.509, PEM/DER keys and PKCS#12 stores are now *parsed* rather than pattern-matched, so key size, curve, subject, expiry and signature algorithm are reported from the real structure.
- Binary fingerprinting for `.exe`, `.dll`, `.so`, `.dylib`, `.jar`, `.wasm`, `.apk` and friends, using embedded crypto symbols.
- Optional Syft and Trivy integration for container-image archives, with availability and version shown in the report.
- Workspace scanning now reports engine details, scanned/skipped file counts and progress.
- The three quantum-risk assumptions are configurable settings instead of constants.

## Features

- Scan the active file from the Command Palette or the editor context menu
- Scan supported files automatically on save (`ecdat.scanOnSave`, on by default)
- Show findings on the correct line and in the Problems panel, with classical **and** quantum risk in the diagnostic code
- Scan the whole workspace with progress feedback, including binaries, certificates and keys
- Scan a repository archive, container image, binary, certificate or key selected from disk
- Open a local cryptographic report beside the editor
- Export the current findings as a JSON CBOM
- Detect OpenSSL, PyCryptodome, Python `cryptography`, Node `crypto`, Web Crypto, libsodium, Bouncy Castle and PKCS#11/HSM usage in source, including the C `EVP_*` and `SHA*_Init`/`SHA*_Update`/`SHA*_Final` APIs
- Report the OpenSSL version in use, plus Syft/Trivy availability, in the report header

## How it works

```
VS Code UI  ──commands──▶  out/extension.js  ──JSON on stdin──▶  python -m backend.app.vscode_bridge
      ▲                            │                                        │
      └────── diagnostics, ────────┘                          detector · openssl_inspector
            report panel, CBOM                                  container_tools · risk · recommendations
```

The extension writes one JSON request to the child's stdin and reads one JSON response from stdout. Everything else is local process I/O. See [Engine layout](#engine-layout) for the module map.

## Development setup

Python 3 must be available locally. **No Periperi server is required.**

Scanning is split by depth:

| Mode | Commands | Needs |
| --- | --- | --- |
| Source | Scan Current File, scan-on-save | Python standard library only |
| Full | Scan Workspace, Scan Binary/Certificate/Key/Container | Python [`cryptography`](https://cryptography.io/) |
| Container images | Scan Binary, Certificate, Key or Container on an OCI/Docker archive | Syft and Trivy on `PATH` (optional) |

Install the full-scanning dependency from the repository root:

```powershell
python -m pip install -r requirements.txt
```

Syft and Trivy are separate command-line tools, not Python packages. Install them and put them on `PATH` to enable those checks; a scan without them still succeeds and simply reports the tools as unavailable. On Windows the engine also looks in `%LOCALAPPDATA%\Microsoft\WinGet\Links`.

If the extension cannot find the bundled engine, set `ecdat.engineRoot` to the directory that contains `engine/backend/app/vscode_bridge.py`.

> On some Windows Python installations a `python*._pth` file forces isolated mode, which removes the working directory from `sys.path`. The engine then fails with `ModuleNotFoundError: No module named 'backend'`, and `pip` itself is unavailable. Remove that file, or point `ecdat.pythonPath` at an interpreter that does not have one.

## Install

Periperi is distributed as a `.vsix` from [GitHub Releases](https://github.com/rabindra789/periperi/releases):

1. Download `periperi-0.2.0.vsix`.
2. In VS Code run **Extensions: Install from VSIX...** and pick the file.
3. Reload the window if prompted.

## Build from source

```powershell
cd vscode-extension
npm install
npm run package
```

This produces `periperi-0.2.0.vsix`.

## Commands

| Command | ID | What it does |
| --- | --- | --- |
| Periperi: Scan Current File | `ecdat.scanCurrentFile` | Scans the active editor buffer and reports findings inline |
| Periperi: Scan Workspace | `ecdat.scanWorkspace` | Full scan of the first workspace folder, with progress |
| Periperi: Scan Binary, Certificate, Key or Container | `ecdat.scanArtifact` | Full scan of a file chosen from disk |
| Periperi: Show Cryptographic Report | `ecdat.showReport` | Opens/refreshes the report panel |
| Periperi: Export CBOM | `ecdat.exportCbom` | Writes the current findings to a JSON CBOM |
| Periperi: Clear Findings | `ecdat.clearDiagnostics` | Drops all findings, diagnostics and engine state |

Command IDs and the `ecdat.*` settings namespace are unchanged from 0.1.0, so existing settings and keybindings keep working.

To build an installable package that includes the local Python scanner and all supported runtime variants:

| Setting | Default | Purpose |
| --- | --- | --- |
| `ecdat.scanOnSave` | `true` | Scan supported files when they are saved |
| `ecdat.pythonPath` | `python` | Python executable used to run the local engine |
| `ecdat.engineRoot` | *(empty)* | Engine root, when the extension folder is outside the repository |
| `ecdat.dataSensitivity` | `pii` | Data-lifetime assumption (X) for the quantum-risk model |
| `ecdat.migrationComplexity` | `standard_application` | Migration-time assumption (Y) for the quantum-risk model |
| `ecdat.threatTimeline` | `15` | Assumed quantum threat timeline in years (Z) |
| `ecdat.maxWorkspaceFiles` | `2000` | Declared file cap for a manual workspace scan |

`ecdat.dataSensitivity` accepts `ephemeral`, `internal`, `pii`, `financial`, `high_sensitivity`. `ecdat.migrationComplexity` accepts `small_project`, `standard_application`, `legacy_application`, `complex_system`.

> `ecdat.maxWorkspaceFiles` is declared for forward compatibility but is not yet read by the shipped bundle; the engine currently applies its own hard limits (see [Limits](#limits-and-privacy)).

## What gets detected

**Algorithms** — AES, AES-GCM, AES-256-GCM, AES-ECB, RSA, RSA-1024, RSA-2048, ECDSA, ECDH, ECC, Diffie-Hellman, DSA, SHA-1, SHA-256, SHA-384, SHA-512, MD5, ChaCha20.

**Libraries** — OpenSSL (including `libcrypto`/`libssl` linkage and `EVP_*`), PyCryptodome, Python `cryptography`, libsodium, Bouncy Castle, Web Crypto API, Node `crypto`.

**Key material** — PEM private/public key headers (`.key`, `.jks`, `.keystore`), and any key actually parsed by OpenSSL, reported without exposing the material.

**Artifacts** — `.pem`, `.crt`, `.cer`, `.der`, `.p7b`, `.p12`, `.pfx` certificates and key stores; `.exe`, `.dll`, `.so`, `.dylib`, `.a`, `.lib`, `.o`, `.obj`, `.class`, `.jar`, `.war`, `.ear`, `.wasm`, `.bin`, `.apk`, `.ipa` binaries.

**Containers** — OCI/Docker tar archives, where layers are expanded and the cryptographic package inventory is read via Syft, with Trivy vulnerabilities mapped onto crypto packages.

The most specific match on a line wins: a line containing `AES-256-GCM` reports `AES-256-GCM`, not `AES-GCM` and not `AES`.

## How risk is scored

Every finding carries a classical rating and a quantum-readiness rating.

**Classical** is a deliberately conservative, explainable rule cascade:

| Level | Trigger |
| --- | --- |
| `critical` | Private-key material stored with the project |
| `high` | MD5, SHA-1, RSA-1024, DES, RC4 |
| `medium` | Certificates; ECB, RSA-2048, DSA, DH |
| `info` | Library or HSM inventory signals |
| `low` | Everything else |

**Quantum** applies Mosca's inequality to the configurable assumptions:

```
margin = Z - (X + Y)      X = data lifetime, Y = migration time, Z = threat timeline
margin < 0 -> critical     margin <= 3 -> high     margin <= 7 -> medium     otherwise low
```

Only quantum-vulnerable public-key algorithms (RSA, ECC, ECDSA, ECDH, DSA, DH) are scored; every other finding reports `not_applicable`. The report shows the resulting `x`, `y`, `z` and `margin` so the rating can be argued with rather than trusted blindly.

## CBOM export

**Periperi: Export CBOM** writes a single JSON document:

| Field | Contents |
| --- | --- |
| `specification` | `ECDAT CBOM Prototype 1.0` |
| `generated_at` | ISO-8601 timestamp |
| `workspace`, `input_type` | Scan origin (`source-file`, `workspace`, `repository-archive`, `container-image`, `binary-or-cryptographic-artifact`) |
| `engines` | OpenSSL version and Syft/Trivy availability |
| `files_with_findings`, `findings_count`, `risk_distribution` | Summary counters |
| `findings[]` | `id`, `category`, `name`, `file`, `line`, `evidence`, `risk`, `reason`, `quantum_risk`, `quantum{x,y,z,margin}`, `recommendation` |
| `disclaimer` | Rule-based prototype warning |

`evidence` never contains key material: key findings report `[key material redacted]`, and any line that looks like `secret`/`password`/`token`/`private_key` assignment has its value stripped.

## Engine layout

```
engine/backend/app/
├── vscode_bridge.py       JSON stdin/stdout entrypoint; one request in, one response out
├── scanner.py            Safe project traversal, ZIP/TAR extraction, safety limits
├── detector.py           Source-text pattern detection (standard library only)
├── openssl_inspector.py  X.509 / PEM / DER / PKCS#12 parsing, binary fingerprinting
├── container_tools.py    Syft and Trivy adapters
├── risk.py               Classical rules and Mosca quantum scoring
└── recommendations.py    Remediation text per finding
```

## Limits and privacy

- **Save-time and current-file scanning** uses the lightweight source detector and covers supported text files up to **2 MB**.
- **Full scanning** uses the complete engine: 2 MB per text file, 25 MB per binary, 100 MB per upload, 250 MB of expanded archive contents, and 25,000 files per scan.
- Skipped by default: `.git`, `node_modules`, `venv`, `.venv`, `__pycache__`, `target`, `dist`, `build`, `.idea`, `.vscode`, `.gradle`, `.cache`.
- Archive extraction rejects absolute and `..` member paths, and skips symlinks and hard links.
- Periperi never executes project code, scanned binaries or container layers, and never makes network requests.

Install the generated `.vsix` through **Extensions: Install from VSIX**. No ECDAT server or package installation is required. Syft and Trivy remain optional external tools for container checks.

## Commands

The TypeScript sources are not present in this repository, so `npm run compile`, `npm run watch`, `npm run check` and `npm run prepare-engine` do not run. The compiled `out/extension.js` is committed and `npm run package` builds the `.vsix` directly from it. Because the bundle cannot be recompiled, its status bar, notifications, report panel and CBOM output are still labelled "ECDAT"; only the manifest, the Command Palette titles and the package filename use the Periperi name. Restoring the TypeScript sources would let the remaining strings be renamed at source.

## Prototype limits

Detection is pattern- and rule-based and **can produce false positives**. Nothing here is a substitute for review: validate every finding before making a security decision, and do not treat the quantum rating as an audit result. Syft and Trivy results depend entirely on those tools' own vulnerability databases.

## Contributing

Issues and pull requests are welcome at [github.com/rabindra789/periperi](https://github.com/rabindra789/periperi). Please include the Periperi version, the VS Code version, your Python version and the exact command you ran.

## Licence

Unlicensed prototype. No licence file is published yet, so no grant of rights is made; add one before distributing the code.
