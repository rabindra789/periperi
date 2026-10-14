# Review of commit `0a011f5` (Periperi 0.3.3)

Reviewed on branch `master` at `0a011f5` (`fix: 0.3.3 correctness fixes for engine
bundling, CBOM schema and scan limits`), working tree clean. This records what the
commit actually does, not what its message claims.

## Verification table

| Claim | Evidence | Verified | Risk / issue |
|---|---|---|---|
| `prepare-engine.mjs` builds `engine/runtime` from committed `engine/backend` instead of a nonexistent `../backend` | `scripts/prepare-engine.mjs:7-8` (`engineRoot = extensionRoot/engine`), `:95-101` validates the 8 backend files, `:102` removes only `engine/runtime` | Yes | Deletes `engine/runtime` **before** calling `uv`; if `uv` is missing the previous runtime is lost. It is a generated, git-ignored artifact, so this is acceptable but not free. |
| Extension and engine versions unified at `0.3.3` | `package.json:6`, `engine/backend/__init__.py:9` | Yes | — |
| CBOM schema is `1.1` | `engine/backend/__init__.py:12` (`SCHEMA_VERSION`), `src/extension.ts:51` (`FALLBACK_SCHEMA`) | Yes | Two sources of truth; the extension prefers the engine's `analysis.schema` and only falls back to the literal. |
| Extension reads spec/version from engine analysis | `src/extension.ts:120,159,213` set `lastAnalysis`; `:456-462` build the CBOM from it; `:562` render the engine version | Yes | `lastAnalysis` is only refreshed on a scan; export before any scan uses the fallback schema and `null` engine. |
| `ecdat.maxWorkspaceFiles` reaches the bridge as `max_files` | `src/extension.ts:159-160`; `vscode_bridge.py:169-171`; `REQUEST_FIELDS` at `:23-31` | Yes | Only the **workspace** command sends it; artifact scans rely on the engine default. |
| `scanner.scan_project` enforces the effective limit | `scanner.py:159` `file_limit = min(max(int(options.max_files),1),MAX_FILES)`, `:162` raises `ScanError` | Yes | Enforced while iterating `rglob`, not against a pre-count, so the raise depends on directory order; a large tree can be partially traversed first. |
| Effective limit appears in scan assumptions | `scanner.py:222` `"max_files": options.max_files` | Partial | Echoes the **requested** value, not the clamped `file_limit`. `max_files=999999` reports `999999` while the real cap is `25000`. |
| Broken runtime stub removed | No `engine/runtime/**` entries in `git show --stat 0a011f5`; `0a011f5^` (`9a48659`) tracked no `engine/` at all | Not as stated | The stub was never committed in `HEAD~`; it was removed from the working tree only. `.gitignore` now prevents it being added. The commit message overstates this. |
| `engine/runtime/` is Git-ignored | `.gitignore:260` (added in the commit) | Yes | Verified: after a full `npm run prepare-engine`, `git status` stays clean. |
| `package-lock.json` committed for `npm ci` | `0a011f5` adds `package-lock.json` (1872 lines); `.gitignore` dropped the old `package-lock.*` rule | Yes | `npm ci` succeeds (see build status). |
| `vscode:prepublish` compiles the extension | `package.json:79` `"vscode:prepublish": "npm run compile"` | Yes | `vsce package` triggers it; confirmed during packaging. |
| GitHub Actions builds the project | `.github/workflows/build.yml` | Yes | Runs `npm ci`, `npm run check`, `npm run compile` on Node 20. No `permissions:` block (defaults are sufficient). It compiles but does not fail on a stale committed bundle. |
| README reflects the flattened layout | `README.md` rewritten in the commit | Yes | Corrected in this review only after import-path verification. |

## Extra checks requested

- **Broken import paths:** none found. `vscode_bridge.py` imports resolve; `prepare-engine.mjs`
  validates every backend file before use.
- **JSON request/response fields:** consistent. Every bridge response (text, workspace,
  artifact, `--capabilities`, `--version`) carries `analysis`; `max_files` is additive and
  validated (`isinstance(int) and not bool and > 0`).
- **Version / schema drift:** unified at `0.3.3` / `1.1`. No remaining literal `1.0`.
- **Runtime script deleting required files before failing:** it validates the sources first
  and only deletes the generated runtime. See the note above for the residual risk.
- **Generated artifacts committed:** `out/extension.js` and `out/extension.js.map` are
  committed build output (pre-existing convention). Verified that `npm run compile`
  reproduces them byte-for-byte (`git status` stays clean afterwards).
- **Clean-checkout build:** verified with `npm ci` (see `docs/RELEASE_CLEANUP.md`).
- **Commands / output compatibility:** extension command IDs and the `ecdat.*` namespace are
  unchanged. The added `analysis` field is ignored by older consumers.
