# Release artifact cleanup and packaging behaviour

Scope: the large VSIX files tracked in Git, and what `npm run package` actually
produces. No history rewrite was performed.

## Tracked VSIX inventory (at `0a011f5`)

| File | Size | Git tag | GitHub Release asset |
|---|---|---|---|
| `periperi-0.1.0.vsix` | 0.01 MB | `v0.1.0` | yes (`periperi-0.1.0.vsix`) |
| `periperi-0.2.0.vsix` | 0.03 MB | `v0.2.0` | yes (`periperi-0.2.0.vsix`) |
| `periperi-0.3.0.vsix` | 0.05 MB | `v0.3.0` | yes (`periperi-0.3.0.vsix`) |
| `periperi-0.3.1.vsix` | 38.76 MB | none | **no** |
| `periperi-0.3.2.vsix` | 38.76 MB | none | **no** |

Total tracked: ~77.6 MB, of which `0.3.1` + `0.3.2` are ~77.5 MB.

Provenance of the three backed-up files was verified by hash, not just by size:

```
gh release download v0.3.0 --repo rabindra789/periperi --pattern periperi-0.3.0.vsix
Get-FileHash -Algorithm SHA256 periperi-0.3.0.vsix   # committed
```

`0.1.0`, `0.2.0` and `0.3.0` matched their Release assets exactly (SHA-256).

## What was changed

`git rm --cached` staged the deletion of the three **backed-up** artifacts
(`periperi-0.1.0/0.2.0/0.3.0.vsix`). `--cached` keeps the local copies on disk.
This is staged only — **not committed**.

`.gitignore` already contains `*vsix` (line 258), which covers future build
output such as `periperi-0.3.3.vsix`. No additional ignore rule was needed.

## Preservation blocker

`periperi-0.3.1.vsix` and `periperi-0.3.2.vsix` have **no GitHub Release** (the
releases API returns assets only for `v0.1.0`, `v0.2.0`, `v0.3.0`, and no tag
exists for `0.3.1`/`0.3.2`). They are the only published copies, so they were
left tracked rather than deleted.

Recommended safe procedure before removing them:

1. Create releases `v0.3.1` and `v0.3.2` and upload the two VSIX files as assets
   (verify SHA-256 against the tracked files).
2. Then `git rm --cached periperi-0.3.1.vsix periperi-0.3.2.vsix` and commit.

Note: deleting a tracked file is a normal commit. It stops the file appearing in
future checkouts but does **not** remove its bytes from existing history; the
objects remain reachable from older commits. Shrinking the repository requires a
history rewrite, which is out of scope here.

## Packaging behaviour (verified)

`npm run package` (`vsce package --out periperi-0.3.3.vsix`) exited 0 and produced
`periperi-0.3.3.vsix` (1286 files, 38.76 MB). Inspected contents:

- Included: `out/extension.js`, `engine/backend/app` (9 files), the seven
  `engine/runtime/<platform>` trees, `images/`, `scripts/prepare-engine.mjs`.
- Excluded by `.vscodeignore`: `**/*.ts`, `**/*.map`, `node_modules/**`,
  `.github/**`, `package-lock.json`, `**/*.vsix`, `**/__pycache__/**`.
- No old VSIX, TypeScript source, source map, lockfile or `__pycache__` entry was
  found in the package.
- The output VSIX is ignored by `.gitignore` (`*vsix`), so packaging does not
  dirty the tree.

Full command results are in the review summary for this task.
