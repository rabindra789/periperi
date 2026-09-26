# Periperi

Periperi runs the ECDAT cryptographic detector locally and shows findings directly in VS Code. Source text is passed only to the local Python process and is not sent to an external service.

## Features

- Scan the active file from the Command Palette or editor context menu
- Scan supported files automatically when they are saved
- Show risk findings on the correct line and in the Problems panel
- Scan the complete workspace with progress feedback
- Open a local cryptographic report inside VS Code
- Export the current findings as a JSON CBOM

## Requirements

Python 3 must be available locally. The detector is Python standard library only, so there are no third-party packages to install and no `requirements.txt`. No Periperi server is required.

If the extension cannot find the bundled engine, set `ecdat.engineRoot` to the directory that contains `engine/backend/app/vscode_bridge.py`.

> On some Windows Python installations a `python*._pth` file forces isolated mode, which removes the working directory from `sys.path` and makes the engine fail to import with `ModuleNotFoundError: No module named 'backend'`. Remove that file, or point `ecdat.pythonPath` at an interpreter that does not have one.

## Build

```powershell
cd vscode-extension
npm install
npm run package
```

This produces `periperi-0.1.0.vsix`. Install it through **Extensions: Install from VSIX...**

## Commands

- `Periperi: Scan Current File`
- `Periperi: Scan Workspace`
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

The TypeScript sources are not present in this repository, so `npm run compile`, `npm run watch`, `npm run check` and `npm run prepare-engine` do not run. The compiled `out/extension.js` is committed and `npm run package` builds the `.vsix` directly from it. Because the bundle cannot be recompiled, its status bar, notifications and report panel are still labelled "ECDAT"; only the manifest, the Command Palette titles and the package filename use the Periperi name.

## Prototype limits

Detection is pattern-based and can produce false positives. Validate findings before making security decisions. Save-time scanning covers supported text files up to 2 MB and never executes project code. Key material is redacted from reported evidence.

The quantum-risk rating applies Mosca's `X + Y > Z` inequality and is limited to quantum-vulnerable public-key algorithms; other findings report `not_applicable`.
