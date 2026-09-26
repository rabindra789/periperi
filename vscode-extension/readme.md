# ECDAT VS Code Extension

This extension runs the ECDAT cryptographic detector locally and shows findings directly in VS Code. Source text is passed only to the local Python process and is not sent to an external service.

## Features

- Scan the active file from the Command Palette or editor context menu
- Scan supported files automatically when they are saved
- Show risk findings on the correct line and in the Problems panel
- Scan the complete workspace with determinate progress feedback and phase updates
- Run the complete OpenSSL-backed engine across source, binaries, certificates and keys in the workspace
- Select repository archives, binaries, certificates, keys or container-image archives for a full local scan
- Show OpenSSL, Syft and Trivy engine details in the report
- Open a local cryptographic report inside VS Code
- Preview the generated CBOM in the report and export the complete JSON CBOM
- Detect OpenSSL, PyCryptodome, Python cryptography, Node Crypto, Web Crypto, libsodium, Bouncy Castle and PKCS#11/HSM source usage

## Development setup

From the repository root, install the backend requirements for local backend development:

```powershell
python -m pip install -r requirements.txt
```

To build the universal VSIX, install `uv` and Node.js, then build the extension:

```powershell
cd vscode-extension
npm install
npm run package
```

Open the repository in VS Code, select the `vscode-extension` folder, and press `F5` to start an Extension Development Host. Open a source file and run **ECDAT: Scan Current File**.

The extension uses bundled platform runtimes for Windows x64, Linux x64/ARM64 (glibc and musl), and macOS Intel/Apple Silicon. It supports CPython 3.10–3.14. Python itself must be installed and available through `ecdat.pythonPath`; users do not need to install ECDAT Python packages. The packaging step uses `uv` to fetch the native wheels and can be overridden with `ECDAT_UV_PATH`.

To build an installable package that includes the local Python scanner and all supported runtime variants:

```powershell
npm run package
```

Install the generated `.vsix` through **Extensions: Install from VSIX**. No ECDAT server or package installation is required. Syft and Trivy remain optional external tools for container checks.

## Commands

- `ECDAT: Scan Current File`
- `ECDAT: Scan Workspace`
- `ECDAT: Scan Binary, Certificate, Key or Container`
- `ECDAT: Show Cryptographic Report`
- `ECDAT: Export CBOM`
- `ECDAT: Clear Findings`

## Prototype limits

Save-time scanning uses the lightweight source detector. Manual workspace and artifact commands use the complete local engine with OpenSSL-backed artifact parsing, binary fingerprints, progress events, and Syft/Trivy container analysis. The packaged runtime includes the required cryptography dependencies for supported platforms. Syft and Trivy must be installed for their container checks. Validate findings before making security decisions. ECDAT never executes project code or scanned binaries.
