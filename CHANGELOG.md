# Changelog

All notable changes to Periperi are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses semantic versioning.

## [0.2.0] — 2026-09-26

Extension ID: `thesixbugs.periperi` · Asset: `periperi-0.2.0.vsix`

### Added

- New **Periperi: Scan Binary, Certificate, Key or Container** command (`ecdat.scanArtifact`) with a file picker covering `zip`, `tar`, `gz`, `tgz`, `exe`, `dll`, `so`, `dylib`, `jar`, `war`, `apk`, `pem`, `crt`, `cer`, `der`, `key`, `p12` and `pfx`.
- New `openssl_inspector` module: X.509 certificates, PEM/DER public and private keys and PKCS#12 stores are parsed with the `cryptography` OpenSSL backend, so key size, curve, subject, expiry and signature algorithm come from the real structure. Password-less parsing only; encrypted stores are reported as unreadable rather than guessed at.
- Binary fingerprinting for `.exe`, `.dll`, `.so`, `.dylib`, `.a`, `.lib`, `.o`, `.obj`, `.class`, `.jar`, `.war`, `.ear`, `.wasm`, `.bin`, `.apk` and `.ipa`, matching embedded crypto symbols without executing the file.
- Container-image analysis: OCI/Docker archives are detected, their layers expanded, and the cryptographic package inventory read through Syft, with Trivy vulnerabilities mapped onto crypto packages and severity reflected in the finding risk.
- `container_tools` module reporting Syft and Trivy availability and versions in the report header, including a Windows `WinGet\Links` lookup.
- Archive safety hardening: absolute and `..` member paths rejected, symlinks and hard links skipped, and explicit caps on upload size, expanded size, file count and layer count.
- Report header now shows engine details and the input type; workspace scans report scanned and skipped file counts.
- Detector pattern refinements, including `AES-256-GCM`, `RSA-1024`/`RSA-2048` key-size variants, PKCS#11/HSM and Web Crypto detection, and stronger de-duplication so the most specific match on a line wins.
- `requirements.txt` documenting the single optional dependency and the external container tooling.
- `.vscode/launch.json` and `.vscode/tasks.json` for F5 extension-development-host runs.
- This changelog and a repository-level README.

### Changed

- Risk assumptions are now settings-driven: `ecdat.dataSensitivity`, `ecdat.migrationComplexity` and `ecdat.threatTimeline` feed the Mosca `X + Y > Z` calculation, and each finding carries the resulting `x`, `y`, `z` and `margin`.
- Finding objects are normalised across all inspectors through a single `make_finding` factory, so source, binary, OpenSSL and container findings share one shape for the CBOM export.
- The manifest, Command Palette titles, readme and package filename use the Periperi name; command IDs and the `ecdat.*` settings namespace are unchanged from 0.1.0.
- Evidence handling redacts key material and any `secret`/`password`/`token`/`private_key` assignment value, and truncates long lines.

### Known limitations

- The TypeScript sources and `tsconfig.json` are still absent, so `npm run compile`, `watch`, `check` and `prepare-engine` do not run; the committed `out/extension.js` is packaged as-is and its status bar, notifications, report and CBOM output remain labelled "ECDAT".
- `out/extension.js` ends with a `//# sourceMappingURL=extension.js.map` reference, but that map is not shipped, so stack traces will not map back to original TypeScript positions.
- `ecdat.maxWorkspaceFiles` is declared but not yet read by the bundle; the engine applies its own limits (25,000 files, 2 MB per text file, 25 MB per binary, 100 MB per upload, 250 MB expanded).
- Detection is pattern- and rule-based and can produce false positives. Syft and Trivy output depends on those tools' own vulnerability databases.
- No licence file is published, so the package remains unlicensed.

## [0.1.0] — 2026-09-26

Extension ID: `thesixbugs.periperi` · Asset: `periperi-0.1.0.vsix`

### Added

- First public release: local cryptographic discovery, risk diagnostics and CBOM export for VS Code.
- **Periperi: Scan Current File**, with the command also available in the editor context menu, and scan-on-save via `ecdat.scanOnSave`.
- **Periperi: Scan Workspace** with progress feedback, **Periperi: Show Cryptographic Report** rendered in a webview panel, **Periperi: Export CBOM** and **Periperi: Clear Findings**.
- Findings on the correct line and in the Problems panel, each rated with a classical risk level and a Mosca quantum-readiness level.
- A standard-library-only Python source detector covering common algorithms, libraries and PEM key headers, with key material redacted from evidence.
- JSON stdin/stdout bridge between the extension and the engine.

[0.2.0]: https://github.com/rabindra789/periperi/releases/tag/v0.2.0
[0.1.0]: https://github.com/rabindra789/periperi/releases/tag/v0.1.0
