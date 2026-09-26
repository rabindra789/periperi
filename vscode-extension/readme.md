# Periperi

Periperi runs the ECDAT cryptographic detector locally and shows findings directly in VS Code. Source text is passed only to the local Python process and is not sent to an external service.

## Features

- Scan the active file from the Command Palette or editor context menu
- Scan supported files automatically when they are saved
- Show risk findings on the correct line and in the Problems panel
- Scan the complete workspace with progress feedback
- Select a repository archive, binary, certificate, key or container-image archive for a full local scan
- Run the complete OpenSSL-backed engine across source, binaries, certificates and keys
- Show OpenSSL, Syft and Trivy engine details in the report
- Open a local cryptographic report inside VS Code
- Export the current findings as a JSON CBOM
- Detect OpenSSL, PyCryptodome, Python cryptography, Node Crypto, Web Crypto, libsodium, Bouncy Castle and PKCS#11/HSM source usage, including the C `EVP_*` and `SHA*_Init`/`SHA*_Update`/`SHA*_Final` APIs

## Requirements

Python 3 must be available locally. No Periperi server is required.

Scanning is split by depth:

- **Source scanning** (scan on save, Scan Current File) uses the source detector, which is Python standard library only and needs no extra packages.
- **Full scanning** (Scan Workspace, Scan Binary/Certificate/Key/Container) parses certificates, keys and binaries with [Python `cryptography`](https://cryptography.io/). Install it from the repository root:

```powershell
python -m pip install -r requirements.txt
```

Container-image analysis additionally shells out to **Syft** and **Trivy**, which are separate command-line tools rather than Python packages. Install them and put them on `PATH` to enable those checks; the scan still runs without them and simply reports the tools as unavailable.

If the extension cannot find the bundled engine, set `ecdat.engineRoot` to the directory that contains `engine/backend/app/vscode_bridge.py`.

> On some Windows Python installations a `python*._pth` file forces isolated mode, which removes the working directory from `sys.path`. The engine then fails to import with `ModuleNotFoundError: No module named 'backend'`, and `pip` itself is unavailable. Remove that file, or point `ecdat.pythonPath` at an interpreter that does not have one.

## Build

```powershell
cd vscode-extension
npm install
npm run package
```

This produces `periperi-0.2.0.vsix`. Install it through **Extensions: Install from VSIX...**

## Commands

- `Periperi: Scan Current File`
- `Periperi: Scan Workspace`
- `Periperi: Scan Binary, Certificate, Key or Container`
- `Periperi: Show Cryptographic Report`
- `Periperi: Export CBOM`
- `Periperi: Clear Findings`

The command IDs and the `ecdat.*` settings namespace are unchanged, so existing settings and keybindings keep working.

## Settings

| Setting | Default | Purpose |
| --- | --- | --- |
| `ecdat.scanOnSave` | `true` | Scan supported files when they are saved |
| `ecdat.pythonPath` | `python` | Python executable used to run the local engine |
| `ecdat.engineRoot` | *(empty)* | Engine root, when the extension folder is outside the repository |
| `ecdat.dataSensitivity` | `pii` | Data-lifetime assumption for the quantum-risk model |
| `ecdat.migrationComplexity` | `standard_application` | Migration-time assumption for the quantum-risk model |
| `ecdat.threatTimeline` | `15` | Assumed quantum threat timeline in years |
| `ecdat.maxWorkspaceFiles` | `2000` | File cap for a manual workspace scan |

## Development

Open the repository in VS Code, select the `vscode-extension` folder, and press `F5` to start an Extension Development Host. Open a source file and run **Periperi: Scan Current File**.

The TypeScript sources are not present in this repository, so `npm run compile`, `npm run watch`, `npm run check` and `npm run prepare-engine` do not run. The compiled `out/extension.js` is committed and `npm run package` builds the `.vsix` directly from it. Because the bundle cannot be recompiled, its status bar, notifications, report panel and CBOM output are still labelled "ECDAT"; only the manifest, the Command Palette titles and the package filename use the Periperi name. Restoring the TypeScript sources would let the remaining strings be renamed at source.

## Prototype limits

Detection is pattern-based and can produce false positives. Validate findings before making security decisions. Save-time scanning uses the lightweight source detector and covers supported text files up to 2 MB. Full scanning uses the complete local engine with OpenSSL-backed artifact parsing, binary fingerprints and Syft/Trivy container analysis. Periperi never executes project code or scanned binaries.

Key material is redacted from reported evidence. The quantum-risk rating applies Mosca's `X + Y > Z` inequality and is limited to quantum-vulnerable public-key algorithms; other findings report `not_applicable`.
