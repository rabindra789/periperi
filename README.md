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
periperi/                         The VS Code extension (repository root)
├── package.json                  Manifest: commands, menus, ecdat.* settings
├── README.md                     User-facing documentation (also the marketplace page)
├── CHANGELOG.md                  Release notes
├── .vscodeignore                 What is excluded from the packaged .vsix
├── tsconfig.json                 TypeScript build config
├── src/extension.ts              Extension source (activation, commands, report, CBOM)
├── out/extension.js              Compiled bundle loaded by VS Code
└── engine/                       Bundled engine
    ├── backend/app/              Python engine
    │   ├── vscode_bridge.py      JSON stdin/stdout entrypoint
    │   ├── scanner.py            Safe traversal, archive extraction, size limits
    │   ├── detector.py           Source-text pattern detection (standard library only)
    │   ├── openssl_inspector.py  X.509 / PEM / DER / PKCS#12 parsing, binary fingerprinting
    │   ├── container_tools.py    Syft and Trivy adapters
    │   ├── risk.py               Classical rules and Mosca X + Y > Z quantum scoring
    │   └── recommendations.py    Remediation text per finding
    └── runtime/                  Per-platform Python runtime (generated, git-ignored)
```

## Quick start

```powershell
git clone https://github.com/rabindra789/periperi.git
cd periperi
npm install
npm run check                # typecheck src/extension.ts
npm run compile              # src/ -> out/extension.js
npm run prepare-engine       # optional: bundle cryptography for each platform (requires uv)
npm run package              # -> periperi-0.3.3.vsix
```

`npm run prepare-engine` needs [`uv`](https://docs.astral.sh/uv/) on `PATH` (or `ECDAT_UV_PATH`) and a network connection; it rebuilds `engine/runtime/` from the committed `engine/backend` sources. It is only required to ship the self-contained runtime — the engine also falls back to a system Python that has the `cryptography` package installed.

Install the result through **Extensions: Install from VSIX...** in VS Code, then run **Periperi: Scan Current File**. Downloads for released versions are on the [releases page](https://github.com/rabindra789/periperi/releases).

Full usage is available from the `Periperi:` commands in the command palette, and settings are under `periperi.*` (for example `periperi.maxWorkspaceFiles`).

## Using the engine directly

The engine is a plain Python package and can be driven without VS Code:

```powershell
cd engine
'{"mode":"text","path":"demo.py","text":"import hashlib`nhashlib.md5(b""x"")"}' |
    python -m backend.app.vscode_bridge
```

Request fields: `mode` (`text` | `workspace` | `artifact`), `path`, `text`, `max_files`, `sensitivity`, `migration_complexity`, `threat_timeline`. The response is a single JSON object on stdout; failures are returned as `{"error": "..."}` with exit code 1.

## Releases

- Versions follow the manifest in `package.json`; the packaged filename and the git tag share the number (`v0.3.3` → `periperi-0.3.3.vsix`).
- `npm run package` builds the `.vsix` from the committed `out/extension.js`, and the release notes are the long-form entry in [`CHANGELOG.md`](CHANGELOG.md).
- Run `npm run prepare-engine` before packaging to include the self-contained Python runtime in the `.vsix`.

## Contributing

Issues and pull requests are welcome. Please state the Periperi version, your VS Code, Python, Syft and Trivy versions, and the exact command you ran. Extension behaviour is written in `src/extension.ts`; run `npm run compile` and commit the regenerated `out/extension.js` alongside `package.json`.

## Licence

Unlicensed prototype. No licence file has been published, so no grant of rights is made. Add one before redistributing.
