# ECDAT VS Code Extension

This extension runs the ECDAT cryptographic detector locally and shows findings directly in VS Code. Source text is passed only to the local Python process and is not sent to an external service.

## Features

- Scan the active file from the Command Palette or editor context menu
- Scan supported files automatically when they are saved
- Show risk findings on the correct line and in the Problems panel
- Scan the complete workspace with progress feedback
- Open a local cryptographic report inside VS Code
- Export the current findings as a JSON CBOM

## Development setup

From the repository root, install the backend requirements first:

```powershell
python -m pip install -r requirements.txt
```

Then build the extension:

```powershell
cd vscode-extension
npm install
npm run compile
```

Open the repository in VS Code, select the `vscode-extension` folder, and press `F5` to start an Extension Development Host. Open a source file and run **ECDAT: Scan Current File**.

The extension assumes its folder is directly inside the ECDAT repository during development. If it is copied elsewhere without packaging, set `ecdat.engineRoot` to the repository root and `ecdat.pythonPath` to a Python executable with the backend requirements installed.

To build an installable package that includes the local Python scanner:

```powershell
npm run package
```

Install the generated `.vsix` through **Extensions: Install from VSIX**. Python must be available locally, but no ECDAT server is required.

## Commands

- `ECDAT: Scan Current File`
- `ECDAT: Scan Workspace`
- `ECDAT: Show Cryptographic Report`
- `ECDAT: Export CBOM`
- `ECDAT: Clear Findings`

## Prototype limits

Detection is pattern-based and can produce false positives. Validate findings before making security decisions. Save-time scanning covers supported text files up to 2 MB and never executes project code.