# False-positive regression baseline

Deterministic corpus and results for the ECDAT/PY detector, measured through
`backend.app.vscode_bridge` exactly as the extension drives it.

Runner: `engine/tests/run_regression.py` (run from the repository root with
`python engine/tests/run_regression.py`).

The corpus is **generated into a temporary project directory** at run time. Static
fixtures are embedded in the runner so no PEM-looking file is committed; the real
key, public key and certificate used for the validated cases are generated into a
temporary directory and never written into the repository. This is a synthetic
corpus — the precision/recall figures below are **not** a real-world accuracy claim.

## Fixtures and intended results

| Fixture | Group | Intended result | Rationale |
|---|---|---|---|
| `docs/pem_header_only.md` | benign | no critical/high | A lone `-----BEGIN RSA PRIVATE KEY-----` inside a code fence is documentation, not key material. |
| `src/string_header.py` | benign | no critical/high | The header is inside a string literal; nothing is validated as a key. |
| `config/fake_with_end.pem` | benign | no critical/high | Header + `-----END-----` with a garbage body does not parse as a key. |
| `src/strong_tls.py` | benign | no critical/high | `PROTOCOL_TLS_CLIENT` + `TLSv1_2` is an acceptable configuration. |
| `keys/generated_public.pem` | benign | no critical/high | A public key is inventory, not a secret. |
| `src/md5_usage.py` | vulnerable | `MD5 >= high` | Real `hashlib.md5(...)` call. |
| `src/sha1_usage.py` | vulnerable | `SHA-1 >= high` | Real `hashlib.sha1(...)` call. |
| `config/weak_tls.py` | vulnerable | `TLS 1.0 >= high` | Deprecated protocol explicitly configured. |
| `keys/generated_private.pem` | vulnerable | `Private key detected >= critical` | A real, parseable private key on disk. |
| `keys/generated_certificate.pem` | vulnerable | `X.509 certificate >= info` | Real self-signed certificate. |
| `src/legacy_comment.py` | deferred | (reported only) | `# We removed MD5 and DSA support ...` — a negative comment, currently reported. |
| `docs/negative_context.md` | deferred | (reported only) | `decided not to use ECC or ECDH` — negated mention, currently reported. |

## Before and after the fix

Command: `python engine/tests/run_regression.py`.

| Metric | Before (`0a011f5`) | After (this change) |
|---|---|---|
| findings in corpus | 22 | 18 |
| benign fixtures with a critical/high finding | 3 | 0 |
| recall (required findings) | 1.00 | 1.00 |
| precision (synthetic) | 0.62 | 1.00 |
| runner exit code | 1 (FAIL) | 0 (PASS) |

### Root cause of the fixed false positives

`engine/backend/app/detector.py` matched `PRIVATE_KEY_RE`
(`-----BEGIN ... PRIVATE KEY-----`) directly on any line and emitted
`Key / "Private key detected"` at `confidence=1.0`, which
`risk.classical_risk` scored `critical` purely because the name contained
`PRIVATE`. A header string in a comment, doc or string literal was therefore
reported as a critical leaked private key even though nothing was validated. The
real, parsed-key path (`openssl_inspector.inspect_crypto_artifact`) already
distinguished these — but only the workspace/artifact scans use it; the
extension's per-file scan (`mode: text`) does not.

### The fix

1. `detector._private_key_is_validated(text)` lazily loads the OpenSSL backend
   and attempts `load_pem_private_key`; failure (or no backend) returns `False`.
2. `detect_file` now marks an unparseable header with `metadata.unvalidated_key`
   and `confidence=0.5` instead of `1.0`.
3. `risk.classical_risk` returns `medium` ("confirm whether real key material is
   present") for `unvalidated_key`, and keeps `critical` for validated keys.
   `recommendations` mirrors the same split (`key_material_triage` vs
   `credential_rotation`).
4. Lines that are PEM boundaries (`-----BEGIN/END ...-----`) no longer run the
   algorithm pattern scan, removing redundant `RSA` noise on key header/footer
   lines.

A real, parseable key still scores `critical` (verified by
`keys/generated_private.pem`). No detection rule was disabled.

## Deferred false positives (documented, not fixed)

These need a context/scope model larger than a targeted fix and are intentionally
left in place:

- **Negated statements** (`legacy_comment.py`, `negative_context.md`):
  `_inactive_inventory_statement` only suppresses `Protocol`/`HSM`/`Key
  Management` categories, so an algorithm named in a "we do not use X" comment is
  still reported (here `MD5:high`, `DSA:medium`, `ECDH:medium`). A reliable fix
  needs sentence-level negation handling.
- **Duplicate protocol signals:** a line such as
  `ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)` reports both `TLS 1.2:medium` and
  `TLS:low`. The binary inspector already collapses this; the text detector does
  not.
- **Documentation/test files are treated the same as source.** Path-based
  down-weighting (docs/tests/vendor) is a policy decision, deliberately not
  guessed at here.

## Limitations

- The corpus is small and synthetic; the numbers above demonstrate regression
  behaviour, not production accuracy.
- Recall is only measured on the handful of labeled positive fixtures listed.
- The generated key/certificate cases are skipped (with a printed warning) when
  `engine/runtime/<platform>` is not prepared, so run `npm run prepare-engine`
  first for full coverage.
