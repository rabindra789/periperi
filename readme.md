# Periperi

Periperi is a local-only cryptographic discovery and post-quantum risk assessment toolkit for VS Code, built on the **ECDAT** rule engine. It finds cryptographic algorithms, libraries, key material, certificates and container packages in your workspace, explains the classical and quantum risk of each finding, and exports the result as a CBOM.

Everything runs on your machine. The extension spawns a local Python process, passes it source text over stdin, and renders the JSON response in the editor. There is no backend service, no telemetry and no network call — and no project code or scanned binary is ever executed.

```
┌─────────────────────────────┐        JSON on stdin        ┌──────────────────────────────┐
│  VS Code extension          │  ─────────────────────────▶ │  python -m                    │
│  out/extension.js           │        JSON on stdout       │  backend.app.vscode_bridge    │
│  commands, diagnostics,     │  ◀───────────────────────── │  detector, openssl_inspector, │
│  report panel, CBOM export  │                             │  container_tools, risk        │
└─────────────────────────────┘                             └──────────────────────────────┘
```

## Repository layout

```
periperi/
├── requirements.txt              Python dependency for full scanning (cryptography>=42)
└── vscode-extension/             The VS Code extension
    ├── package.json              Manifest: commands, menus, ecdat.* settings
    ├── readme.md                 User-facing documentation (also the marketplace page)
    ├── .vscodeignore             What is excluded from the packaged .vsix
    ├── .vscode/                  F5 launch config and the npm: compile task
    ├── out/extension.js          Committed compiled bundle (TypeScript sources are absent)
    └── engine/backend/app/       The ECDAT Python engine
        ├── vscode_bridge.py      JSON stdin/stdout entrypoint
        ├── scanner.py            Safe traversal, archive extraction, size limits
        ├── detector.py           Source-text pattern detection (standard library only)
        ├── openssl_inspector.py  X.509 / PEM / DER / PKCS#12 parsing, binary fingerprinting
        ├── container_tools.py    Syft and Trivy adapters
        ├── risk.py               Classical rules and Mosca X + Y > Z quantum scoring
        └── recommendations.py    Remediation text per finding
```

## Quick start

```powershell
git clone https://github.com/rabindra789/periperi.git
cd periperi
python -m pip install -r requirements.txt        # optional: only needed for full scanning
cd vscode-extension
npm install
npm run package                                   # -> periperi-0.2.0.vsix
```

Install the result through **Extensions: Install from VSIX...** in VS Code, then run **Periperi: Scan Current File**. Downloads for released versions are on the [releases page](https://github.com/rabindra789/periperi/releases).

Full usage, settings, detection coverage and the risk model are documented in [`vscode-extension/readme.md`](vscode-extension/readme.md).

## Using the engine directly

The engine is a plain Python package and can be driven without VS Code:

```powershell
cd vscode-extension\engine
'{"mode":"text","path":"demo.py","text":"import hashlib`nhashlib.md5(b""x"")"}' |
    python -m backend.app.vscode_bridge
```

Request fields: `mode` (`text` | `workspace` | `artifact`), `path`, `text`, `sensitivity`, `migration_complexity`, `threat_timeline`. The response is a single JSON object on stdout; failures are returned as `{"error": "..."}` with exit code 1.

## Releases

- Versions follow the manifest in `vscode-extension/package.json`; the packaged filename and the git tag share the number (`v0.2.0` → `periperi-0.2.0.vsix`).
- `npm run package` builds the `.vsix` from the committed `out/extension.js`, and the release notes are the long-form entry in [`CHANGELOG.md`](CHANGELOG.md).
- Because the TypeScript sources are not in this repository, the bundle cannot currently be recompiled — see the [Development section](vscode-extension/readme.md#development) for what that means for contributors.

## Contributing

Issues and pull requests are welcome. Please state the Periperi version, your VS Code, Python, Syft and Trivy versions, and the exact command you ran. Because the bundle is committed compiled output, changes to extension behaviour currently have to be made by rebuilding and committing `out/extension.js` alongside `package.json`.

## Licence

Unlicensed prototype. No licence file has been published, so no grant of rights is made. Add one before redistributing.
