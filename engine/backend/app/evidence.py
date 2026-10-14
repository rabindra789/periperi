"""Evidence and validation model for Periperi findings.

The engine keeps five ideas deliberately separate so a regex match is never
silently promoted to a vulnerability:

* **evidence type** - *how* a finding was discovered (structured parse, manifest,
  binary fingerprint or a plain text pattern);
* **usage context** - *where* the match sits (active code, comment, string,
  documentation or configuration);
* **file role** - *what kind of file* it is (first-party source, test, docs,
  configuration, manifest, vendored dependency, bundled runtime, generated
  output or an artifact);
* **validation state** - the strongest conclusion the evidence supports;
* **severity / risk** - the classical rating, which is only allowed to stay high
  when the evidence and context justify it.

Here is the per-finding field set this module produces (all additive to the
existing schema, so older consumers keep working):

``rule_id``            stable rule identifier, e.g. ``ALGORITHM-MD5``.
``evidence_type``      ``structured_artifact`` | ``manifest_entry`` |
                       ``container_tool`` | ``binary_fingerprint`` | ``text_pattern``.
``usage_context``      ``code`` | ``comment`` | ``string`` | ``documentation`` |
                       ``configuration`` | ``unknown``.
``file_role``          one of the roles below.
``validation_state``   ``candidate`` | ``observed`` | ``validated`` |
                       ``contextually_risky`` | ``confirmed`` | ``unresolved``.
``confidence_reason``  short human explanation of the evidence interpretation.
``component_identity`` stable component id where the evidence supports it.
``provenance``         human-readable origin of the evidence.
``group_id``           deterministic dedup key; ``related_findings`` links the
                       other ids that share it.

The central safety rule: a **text pattern match in a comment, string, doc,
vendored/bundled dependency or generated file is inventory (``info``)**, never a
high/critical vulnerability. Structured parses and active first-party usage keep
the classical rating. Nothing is ever labelled ``confirmed`` by this prototype.
"""

from __future__ import annotations

import re
from typing import Any


# --- file roles -----------------------------------------------------------

ROLE_FIRST_PARTY = "first_party_source"
ROLE_TEST = "test"
ROLE_DOC = "documentation"
ROLE_CONFIG = "configuration"
ROLE_MANIFEST = "dependency_manifest"
ROLE_VENDOR = "vendored_dependency"
ROLE_RUNTIME = "bundled_runtime"
ROLE_GENERATED = "generated"
ROLE_ARTIFACT = "artifact"
ROLE_DETECTION_RULE = "detection_rule"
ROLE_UNKNOWN = "unknown"

FILE_ROLES = (
    ROLE_FIRST_PARTY, ROLE_TEST, ROLE_DOC, ROLE_CONFIG, ROLE_MANIFEST,
    ROLE_VENDOR, ROLE_RUNTIME, ROLE_GENERATED, ROLE_ARTIFACT, ROLE_DETECTION_RULE, ROLE_UNKNOWN,
)

# --- evidence types -------------------------------------------------------

EV_STRUCTURED = "structured_artifact"
EV_MANIFEST = "manifest_entry"
EV_CONTAINER = "container_tool"
EV_BINARY = "binary_fingerprint"
EV_TEXT = "text_pattern"

EVIDENCE_TYPES = (EV_STRUCTURED, EV_MANIFEST, EV_CONTAINER, EV_BINARY, EV_TEXT)

# --- usage contexts -------------------------------------------------------

CTX_CODE = "code"
CTX_COMMENT = "comment"
CTX_STRING = "string"
CTX_DOC = "documentation"
CTX_CONFIG = "configuration"
CTX_UNKNOWN = "unknown"

USAGE_CONTEXTS = (CTX_CODE, CTX_COMMENT, CTX_STRING, CTX_DOC, CTX_CONFIG, CTX_UNKNOWN)

# --- validation states ----------------------------------------------------

ST_CANDIDATE = "candidate"
ST_OBSERVED = "observed"
ST_VALIDATED = "validated"
ST_CONTEXTUAL = "contextually_risky"
ST_CONFIRMED = "confirmed"
ST_UNRESOLVED = "unresolved"

VALIDATION_STATES = (
    ST_CANDIDATE, ST_OBSERVED, ST_VALIDATED, ST_CONTEXTUAL, ST_CONFIRMED, ST_UNRESOLVED,
)

INVENTORY_RISK = "info"

# --- path / suffix classification -----------------------------------------

DOC_SUFFIXES = {".md", ".markdown", ".rst", ".adoc", ".txt"}
CONFIG_SUFFIXES = {
    ".yaml", ".yml", ".json", ".xml", ".conf", ".config", ".ini", ".env",
    ".toml", ".properties", ".gradle", ".cfg", ".cnf", ".plist",
}
CERT_SUFFIXES = {".pem", ".crt", ".cer", ".der", ".p7b", ".p12", ".pfx"}
KEY_SUFFIXES = {".key", ".jks", ".keystore"}
BINARY_SUFFIXES = {
    ".exe", ".dll", ".so", ".dylib", ".a", ".lib", ".o", ".obj", ".class",
    ".jar", ".war", ".ear", ".wasm", ".bin", ".apk", ".ipa",
}
MANIFEST_NAMES = {
    "pyproject.toml", "cargo.toml", "go.mod", "package.json", "requirements.txt",
}
DOC_NAMES = {"readme", "license", "licence", "changelog", "authors", "notice", "contributing"}

GENERATED_SEGMENTS = {"dist", "build", "out", "gen", "generated", "coverage", "obj", "bin", "target", ".next"}
VENDOR_SEGMENTS = {
    "node_modules", "vendor", "third_party", "third-party", "deps", "site-packages",
    "extern", "external", ".venv", "venv", "bower_components", "jspm_packages",
}
TEST_SEGMENTS = {"test", "tests", "spec", "specs", "__tests__", "testdata", "fixtures", "e2e", "testing"}
TEST_NAME_RE = re.compile(r"(?i)(?:^test[_-]|[_-]test\.|\.test\.|\.spec\.|^spec[_-])")


def _split_path(relative_path: str) -> tuple[str, list[str]]:
    normalized = (relative_path or "").replace("\\", "/").strip("/")
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    base = parts[-1] if parts else ""
    return base, parts


def suffix_of(name: str) -> str:
    lowered = name.lower()
    return "." + lowered.rsplit(".", 1)[1] if "." in lowered else ""


DETECTION_RULE_BASES = {
    "detector", "openssl_inspector", "evidence", "risk", "recommendations",
    "dependencies", "container_tools", "scanner", "vscode_bridge",
}

DETECTION_RULE_DIRS = {"engine", "backend", "app"}

def classify_file(relative_path: str) -> str:
    """Best-effort, path-based file-role classification.

    Paths are the only signal available for a file we have not opened, so this
    is a heuristic. It is deliberately conservative: anything that is not a
    recognised documentation/test/vendor/runtime/generated/manifest/artifact
    path is treated as first-party source (i.e. kept at full severity).
    """
    base, parts = _split_path(relative_path)
    lowered_parts = [part.lower() for part in parts]
    lower_base = base.lower()
    suffix = suffix_of(base)

    if lower_base in MANIFEST_NAMES or (
        lower_base.startswith("requirements") and suffix == ".txt"
    ):
        return ROLE_MANIFEST
    if any(segment in TEST_SEGMENTS for segment in lowered_parts[:-1]) or TEST_NAME_RE.search(base):
        return ROLE_TEST
    if "engine" in lowered_parts and "runtime" in lowered_parts:
        return ROLE_RUNTIME
    if any(segment in VENDOR_SEGMENTS for segment in lowered_parts):
        return ROLE_VENDOR
    if any(segment in GENERATED_SEGMENTS for segment in lowered_parts[:-1]):
        return ROLE_GENERATED
    if lower_base.split(".")[0] in DETECTION_RULE_BASES and all(
        segment in DETECTION_RULE_DIRS for segment in lowered_parts if segment not in (lower_base,)
    ):
        return ROLE_DETECTION_RULE
    if suffix in DOC_SUFFIXES or lower_base in DOC_NAMES or lower_base.split(".")[0] in DOC_NAMES:
        return ROLE_DOC
    if suffix in CERT_SUFFIXES or suffix in KEY_SUFFIXES or suffix in BINARY_SUFFIXES:
        return ROLE_ARTIFACT
    if suffix in CONFIG_SUFFIXES or lower_base == "dockerfile" or lower_base.startswith("dockerfile."):
        return ROLE_CONFIG
    if not suffix:
        return ROLE_UNKNOWN
    return ROLE_FIRST_PARTY


def default_context(file_role: str) -> str:
    if file_role == ROLE_DOC:
        return "documentation"
    if file_role in {ROLE_CONFIG, ROLE_MANIFEST}:
        return "configuration"
    if file_role in {ROLE_ARTIFACT, ROLE_UNKNOWN, ROLE_DETECTION_RULE}:
        return "unknown"
    return "code"


# --- usage-context classification -----------------------------------------

COMMENT_MARKERS: dict[str, tuple[str, ...]] = {
    ".py": ("#",), ".rb": ("#",), ".sh": ("#",), ".ps1": ("#",), ".yaml": ("#",),
    ".yml": ("#",), ".conf": ("#",), ".config": ("#",), ".ini": ("#", ";"),
    ".env": ("#",), ".toml": ("#",), ".properties": ("#",), ".cfg": ("#",),
    ".js": ("//",), ".jsx": ("//",), ".ts": ("//",), ".tsx": ("//",), ".java": ("//",),
    ".c": ("//",), ".cpp": ("//",), ".h": ("//",), ".hpp": ("//",), ".go": ("//",),
    ".rs": ("//",), ".php": ("//", "#"), ".cs": ("//",), ".kt": ("//",),
    ".swift": ("//",), ".gradle": ("//",),
}
DEFAULT_COMMENT_MARKERS = ("//", "#")
BLOCK_COMMENT_MARKERS = ("/*", "<!--", "(*", "{/*")


def _line_state(line: str, suffix: str) -> tuple[list[tuple[int, int]], int | None]:
    """Return (string spans, line-comment start) for a single source line."""
    markers = COMMENT_MARKERS.get(suffix, DEFAULT_COMMENT_MARKERS)
    spans: list[tuple[int, int]] = []
    quote: str | None = None
    quote_start = 0
    escaped = False
    index = 0
    length = len(line)
    while index < length:
        char = line[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                # Check for triple quote
                if index + 2 < length and line[index + 1] == quote and line[index + 2] == quote:
                    index += 3
                else:
                    index += 1
                spans.append((quote_start, index - 1))
                quote = None
                continue
            index += 1
            continue
        if char in "'\"`":
            # Check for triple quote start
            if index + 2 < length and line[index + 1] == char and line[index + 2] == char:
                quote = char * 3
                quote_start = index
                index += 3
            else:
                quote = char
                quote_start = index
                index += 1
            continue
        if any(line.startswith(marker, index) for marker in markers):
            if quote is not None:
                spans.append((quote_start, length))
            return spans, index
        index += 1
    if quote is not None:
        spans.append((quote_start, length))
    return spans, None


_DOCSTRING_STATE: dict[str, bool] = {}

def reset_docstring_state(file_path: str, suffix: str) -> None:
    """Reset docstring tracking state for a new file."""
    key = f"{file_path}:{suffix}"
    _DOCSTRING_STATE.pop(key, None)

def classify_usage(line: str, start: int | None, suffix: str, file_role: str, file_path: str = "") -> str:
    """Classify where on ``line`` the match at ``start`` sits."""
    if file_role == ROLE_DOC:
        return "documentation"
    
    key = f"{file_path}:{suffix}" if file_path else f"{file_role}:{suffix}"
    in_docstring = _DOCSTRING_STATE.get(key, False)
    spans, comment_start = _line_state(line, suffix)
    
    # Update docstring state
    triple_quotes = sum(1 for _, end in spans if end - _ >= 2 and line[_] == line[_+1] == line[_+2] and line[_] in "'\"`")
    if triple_quotes % 2 == 1:
        in_docstring = not in_docstring
        _DOCSTRING_STATE[key] = in_docstring
    
    if start is not None:
        if in_docstring:
            return "string"
        if any(begin < start < end for begin, end in spans):
            return "string"
        if comment_start is not None and start >= comment_start:
            return "comment"
        for marker in BLOCK_COMMENT_MARKERS:
            marker_at = line.find(marker)
            if 0 <= marker_at < (start or 0):
                close_at = line.find("*/", marker_at + len(marker))
                if close_at == -1 or close_at > (start or 0):
                    return "comment"
    elif spans or comment_start is not None or in_docstring:
        return "comment" if not in_docstring else "string"
    
    # Configuration files: plain string mentions may still be inventory if not active code,
    # but for explicit config patterns we want to avoid downgrading
    if file_role in {ROLE_CONFIG, ROLE_MANIFEST} or suffix in CONFIG_SUFFIXES:
        return "configuration"
    return "code"


# --- severity + validation-state resolution -------------------------------

def severity_for(base_risk: str, evidence_type: str, usage_context: str, file_role: str) -> tuple[str, str]:
    """Return (risk, reason-suffix) after applying the evidence model.

    Structured parses and manifests keep the classical rating. Binary matches
    are unresolved fingerprints. Text patterns: for active first-party code or
    configuration with clear weakness (e.g. TLS 1.0/1.1, MD5, SHA-1, RSA-1024)
    we keep the base rating. Documentation, tests, vendor/runtime/generated,
    comments/strings and other weak contexts are downgraded to inventory.
    """
    # Detection rule files: only downgrade textual mentions (strings/comments), not active code
    if file_role == ROLE_DETECTION_RULE and usage_context in {"string", "comment", "documentation"}:
        return "info", "Match is inside a detection rule definition; recorded as inventory, not a vulnerability."
    if evidence_type in {EV_STRUCTURED, EV_MANIFEST, EV_CONTAINER}:
        return base_risk, ""
    if evidence_type == EV_BINARY:
        return "low", "Binary symbol/string fingerprint only; runtime usage is unresolved and is recorded as inventory."
    # Preserve true positives in active first-party source
    if file_role == ROLE_FIRST_PARTY and usage_context == "code" and base_risk in {"critical", "high"}:
        return base_risk, ""
    # Configuration files can have insecure settings
    if (file_role in {ROLE_CONFIG, ROLE_MANIFEST}) and base_risk in {"critical", "high"}:
        return base_risk, ""
    if usage_context == "configuration" and base_risk in {"critical", "high"}:
        return base_risk, ""
    # But not string literals that are just mentions in third-party code
    if usage_context in {"comment"}:
        return "info", "Match is inside a comment; recorded as inventory."
    if usage_context == "string" and file_role != ROLE_FIRST_PARTY:
        return "info", "Match is inside a string literal; recorded as inventory."
    if usage_context == "string" and file_role == ROLE_FIRST_PARTY:
        # String context in first-party source may be an assignment value,
        # not a mere mention; keep the base rating.
        return base_risk, ""
    if usage_context == "documentation" or file_role == ROLE_DOC:
        return "info", "Textual mention in documentation; recorded as inventory, not a vulnerability."
    if file_role == ROLE_RUNTIME:
        return "info", "Match is inside the bundled runtime (third-party code); recorded as inventory."
    if file_role == ROLE_VENDOR:
        return "info", "Match is inside a vendored dependency; recorded as inventory, not first-party source."
    if file_role == ROLE_GENERATED:
        return "info", "Match is inside generated output; recorded as inventory."
    if file_role == ROLE_TEST:
        return "info", "Match is inside test code/fixtures; recorded as inventory for this prototype."
    if usage_context in {"comment", "string"}:
        return "info", "Match is inside a comment or string literal; recorded as inventory."
    return base_risk, ""


def resolve_state(evidence_type: str, risk: str, usage_context: str) -> str:
    if evidence_type == EV_STRUCTURED:
        return "validated"
    if evidence_type in {EV_MANIFEST, EV_CONTAINER}:
        return "observed"
    if evidence_type == EV_BINARY:
        return "unresolved"
    if risk in {"critical", "high"} and usage_context in {"code", "configuration"}:
        return "contextually_risky"
    return "candidate"


def confidence_reason(evidence_type: str, usage_context: str, file_role: str, validated: bool) -> str:
    if evidence_type == EV_STRUCTURED:
        return "Parsed by the OpenSSL backend; the structure is present in the artifact." if validated else "Structured artifact field."
    if evidence_type == EV_MANIFEST:
        return "Declared in a dependency manifest; identity is observed, not a vulnerability conclusion."
    if evidence_type == EV_CONTAINER:
        return "Reported by a container analysis tool; treat scanner output as unverified until reproduced."
    if evidence_type == EV_BINARY:
        return "Matched as a binary symbol/string; presence does not establish active use."
    if usage_context in {"comment", "string"}:
        return "The token sits inside a comment or string literal, so it is a mention rather than usage."
    if file_role == ROLE_DOC:
        return "The token appears in documentation text."
    if file_role in {ROLE_VENDOR, ROLE_RUNTIME}:
        return "The token appears in vendored/bundled third-party code."
    if usage_context == "configuration":
        return "The token appears in a configuration file and may describe an enabled setting."
    return "The token appears in active first-party source and matches a known crypto API or primitive name."


def make_rule_id(category: str, name: str) -> str:
    token = re.sub(r"[^A-Za-z0-9]+", "-", name or "").strip("-").upper()
    return f"{(category or 'unknown').upper()}-{token}"


def make_group_id(rule: str, file: str, component_identity: str | None) -> str:
    return f"{rule}|{file}|{component_identity or ''}"


def provenance_for(evidence_type: str) -> str:
    return {
        EV_STRUCTURED: "openssl-parse",
        EV_MANIFEST: "manifest-parse",
        EV_CONTAINER: "container-tool",
        EV_BINARY: "binary-fingerprint",
        EV_TEXT: "text-pattern",
    }.get(evidence_type, "text-pattern")


def annotate_related(findings: list[dict[str, Any]]) -> None:
    """Populate ``group_id`` (if missing) and ``related_findings`` in place."""
    groups: dict[str, list[str]] = {}
    for finding in findings:
        if not finding.get("group_id"):
            finding["group_id"] = make_group_id(
                str(finding.get("rule_id") or finding.get("name") or ""),
                str(finding.get("file") or ""),
                finding.get("component_identity"),
            )
        groups.setdefault(str(finding["group_id"]), []).append(str(finding.get("id")))
    for finding in findings:
        members = groups.get(str(finding.get("group_id")), [])
        finding["related_findings"] = [item for item in members if item != finding.get("id")]


def summarize_evidence(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts used by both the engine summary and the CBOM report."""
    validation: dict[str, int] = {}
    file_roles: dict[str, int] = {}
    usage: dict[str, int] = {}
    groups: set[str] = set()
    for finding in findings:
        state = str(finding.get("validation_state") or "candidate")
        validation[state] = validation.get(state, 0) + 1
        role = str(finding.get("file_role") or ROLE_UNKNOWN)
        file_roles[role] = file_roles.get(role, 0) + 1
        context = str(finding.get("usage_context") or "unknown")
        usage[context] = usage.get(context, 0) + 1
        groups.add(str(finding.get("group_id") or finding.get("id")))
    return {
        "occurrences": len(findings),
        "unique_issues": len(groups),
        "validation_states": validation,
        "file_roles": file_roles,
        "usage_contexts": usage,
    }
