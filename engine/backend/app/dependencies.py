from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:
    import tomli as tomllib


__all__ = ["parse_manifest", "is_manifest", "is_cryptographic_dependency"]


_REQUIREMENT_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_EXTRAS_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_REQUIREMENT_SPECIFIER = re.compile(r"[A-Za-z0-9 ._*+!<>=/,~^-]+")
_REQUIREMENT_CONSTRAINT = re.compile(
    r"(?:===|==|!=|~=|>=|<=|>|<|\^|~)[ \t]*[A-Za-z0-9][A-Za-z0-9*+._!-]*",
)
_MARKER_TEXT = re.compile(r"[A-Za-z0-9_.,()\s<>=!~'\"\\/-]+")
_CARGO_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
_CARGO_VERSION = re.compile(r"[A-Za-z0-9 ._*+^~<>=!-]+")
_GO_MODULE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~!+@/-]*")
_GO_VERSION = re.compile(r"v[0-9][A-Za-z0-9.+-]*")
_NPM_NAME = re.compile(r"(?:@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+")
_PRIVATE_MATERIAL = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----", re.IGNORECASE)
_PRIVATE_BLOCK = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)(?:password|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret|authorization|credential)\s*[:=]",
)
_CREDENTIAL_URL = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@")
_CREDENTIAL_QUERY = re.compile(
    r"(?i)(?:[?&](?:access[_-]?token|api[_-]?key|auth|password|secret|token)=)[^&#\s]+"
)
_BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_SOURCE_REFERENCE = re.compile(
    r"(?i)^(?:file:|git(?:\+[a-z0-9.-]+)?:|https?://|ssh://|[^/\s]+@[^:\s]+:)"
)
_MAX_NAME_LENGTH = 256
_MAX_VERSION_LENGTH = 2048
_MAX_MARKER_LENGTH = 4096
MAX_DEPENDENCIES_PER_MANIFEST = 500
_CRYPTO_DEPENDENCY_TOKENS = {
    "aead", "aes", "aes-gcm", "argon2", "bcrypt", "bcryptjs", "bcfips",
    "bcprov", "blake2", "blake3", "blowfish", "botan", "botan2", "botan3",
    "bouncycastle", "chacha20", "chacha20poly1305", "cryptography",
    "cryptography-ffi", "curve25519", "curve448", "digest", "ed25519", "hmac",
    "jose", "jwcrypto", "k256", "libsodium", "md5", "nacl", "openssl", "p256",
    "passlib", "p384", "pycrypto", "pycryptodome", "pycryptodomex", "pynacl",
    "pysodium", "python-jose", "rsa", "rustls", "scrypt", "secp256k1",
    "securesystemslib", "sha1", "sha2", "sha3", "sigstore", "sodium",
    "tweetnacl", "x448", "x25519",
}
_CRYPTO_NAME_MARKERS = (
    "bouncycastle", "cryptography", "crypto-js", "libsodium", "pycrypto",
    "secp256k1", "tweetnacl",
)


def _is_private(value: str) -> bool:
    return bool(
        _PRIVATE_MATERIAL.search(value)
        or _CREDENTIAL_ASSIGNMENT.search(value)
        or _CREDENTIAL_URL.search(value)
        or _CREDENTIAL_QUERY.search(value)
        or _BEARER_TOKEN.search(value)
    )


def is_cryptographic_dependency(name: str, ecosystem: str | None = None) -> bool:
    normalized = name.casefold().strip()
    tokens = {token for token in re.split(r"[^a-z0-9]+", normalized) if token}
    if tokens & _CRYPTO_DEPENDENCY_TOKENS:
        return True
    if normalized in {"crypto", "ring"}:
        return normalized == "crypto" or (ecosystem or "").casefold() in {"cargo", "rust"}
    if normalized.startswith(("@noble/", "@stablelib/")):
        return True
    if normalized.endswith("/x/crypto"):
        return True
    return any(marker in normalized for marker in _CRYPTO_NAME_MARKERS)


def _strip_private_content(text: str) -> str:
    text = _PRIVATE_BLOCK.sub("", text)
    kept: list[str] = []
    private_tail = False
    for line in text.splitlines(keepends=True):
        if _PRIVATE_MATERIAL.search(line):
            private_tail = True
            continue
        if private_tail:
            continue
        kept.append(line)
    return "".join(kept)


def _safe_version(value: Any, *, allow_empty: bool = False) -> tuple[bool, str | None]:
    if value is None:
        return True, None
    if not isinstance(value, str):
        return False, None
    text = value.strip()
    if not text:
        return allow_empty, None
    if len(text) > _MAX_VERSION_LENGTH or any(ord(char) < 32 for char in text):
        return False, None
    if _is_private(text) or _SOURCE_REFERENCE.match(text):
        return True, None
    return True, text


def _safe_requirement_name(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    name = value.strip()
    if not name or len(name) > _MAX_NAME_LENGTH or _is_private(name):
        return None
    if not _REQUIREMENT_NAME.fullmatch(name):
        return None
    return name


def _safe_cargo_name(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    name = value.strip()
    if not name or len(name) > _MAX_NAME_LENGTH or _is_private(name):
        return None
    if not _CARGO_NAME.fullmatch(name):
        return None
    return name


def _safe_go_module(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    name = value.strip()
    if not name or len(name) > _MAX_NAME_LENGTH or _is_private(name):
        return None
    if not _GO_MODULE.fullmatch(name) or ".." in name or name.startswith("/"):
        return None
    return name


def _safe_npm_name(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    name = value.strip()
    if not name or len(name) > _MAX_NAME_LENGTH or _is_private(name):
        return None
    if not _NPM_NAME.fullmatch(name):
        return None
    return name


def _item(
    name: str,
    version: str | None,
    scope: str,
    ecosystem: str,
    manifest: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "version": version,
        "scope": scope,
        "ecosystem": ecosystem,
        "manifest": manifest,
    }


def _add_item(
    items: list[dict[str, Any]],
    seen: set[tuple[str, str | None, str, str, str]],
    name: str,
    version: str | None,
    scope: str,
    ecosystem: str,
    manifest: str,
) -> None:
    if len(items) >= MAX_DEPENDENCIES_PER_MANIFEST:
        return
    key = (name, version, scope, ecosystem, manifest)
    if key in seen:
        return
    seen.add(key)
    items.append(_item(name, version, scope, ecosystem, manifest))


def _mapping(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _strip_requirement_comment(value: str) -> str:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(value):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
        elif char == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip()
    return value.rstrip()


def _split_marker(value: str) -> tuple[str, str | None]:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(value):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == ";":
            return value[:index].rstrip(), value[index + 1:].strip()
    return value.rstrip(), None


def _valid_marker(marker: str) -> bool:
    if not marker or len(marker) > _MAX_MARKER_LENGTH or _is_private(marker):
        return False
    if not _MARKER_TEXT.fullmatch(marker):
        return False
    if _unbalanced_quotes(marker) or not _balanced_parentheses(marker):
        return False
    if not re.search(r"(?:==|!=|<=|>=|<|>|~|\bin\b)", marker):
        return False
    return True


def _unbalanced_quotes(value: str) -> bool:
    quote: str | None = None
    escaped = False
    for char in value:
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in "'\"":
            quote = char
    return quote is not None


def _valid_requirement_specifier(value: str) -> bool:
    if not value or len(value) > _MAX_VERSION_LENGTH or _is_private(value):
        return False
    if not _REQUIREMENT_SPECIFIER.fullmatch(value):
        return False
    constraints = value.split(",")
    return all(bool(_REQUIREMENT_CONSTRAINT.fullmatch(item.strip())) for item in constraints)


def _strip_requirement_options(value: str) -> str:
    parts = value.split()
    kept: list[str] = []
    skip_next = False
    for part in parts:
        if skip_next:
            skip_next = False
            continue
        if part == "--hash":
            skip_next = True
            continue
        if part.startswith("--hash="):
            continue
        kept.append(part)
    return " ".join(kept)


def _parse_editable(value: str) -> tuple[str, str | None] | None:
    parts = value.split(maxsplit=1)
    target = parts[1].strip() if len(parts) == 2 else ""
    if not target or "\x00" in target or _is_private(target):
        return None
    fragment = target.split("#", 1)[1] if "#" in target else ""
    for part in fragment.split("&"):
        if part.startswith("egg="):
            name = _safe_requirement_name(part[4:])
            if name is not None:
                return name, None
    return None


def _parse_requirement(value: Any) -> tuple[str, str | None] | None:
    if not isinstance(value, str):
        return None
    text = _strip_requirement_comment(value.strip())
    if not text or any(ord(char) < 32 for char in text):
        return None
    if text.startswith("-e") or text.startswith("--editable"):
        return _parse_editable(text)
    if text.startswith("-"):
        return None
    text = _strip_requirement_options(text)
    text, marker = _split_marker(text)
    if marker is not None and not _valid_marker(marker):
        return None
    match = _REQUIREMENT_NAME.match(text)
    if match is None:
        return None
    name = _safe_requirement_name(match.group(0))
    if name is None:
        return None
    rest = text[match.end():].lstrip()
    if rest.startswith("["):
        close = rest.find("]")
        if close < 0:
            return None
        extras = rest[1:close]
        if not extras or any(not _EXTRAS_NAME.fullmatch(item.strip()) for item in extras.split(",")):
            return None
        rest = rest[close + 1:].lstrip()
    if rest.startswith("@"):
        return name, None
    if rest.startswith("("):
        if not rest.endswith(")") or not _balanced_parentheses(rest):
            return None
        version = rest[1:-1].strip()
    else:
        version = rest.strip()
    if version and not _valid_requirement_specifier(version):
        return None
    if not version:
        return name, None
    safe, cleaned = _safe_version(version)
    return (name, cleaned) if safe else None


def _balanced_parentheses(value: str) -> bool:
    depth = 0
    for char in value:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def _logical_requirement_lines(text: str) -> list[str]:
    lines: list[str] = []
    buffer = ""
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r\n")
        if buffer:
            buffer = f"{buffer} {line.strip()}"
        else:
            buffer = line.strip()
        if buffer.endswith("\\"):
            buffer = buffer[:-1].rstrip()
            continue
        lines.append(buffer)
        buffer = ""
    if buffer:
        lines.append(buffer)
    return lines


def _parse_requirements(path: Path) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return []
    text = _strip_private_content(text)
    if "\x00" in text:
        return []
    if text.startswith("\ufeff"):
        text = text[1:]
    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None, str, str, str]] = set()
    for line in _logical_requirement_lines(text):
        if not line or line.startswith("#"):
            continue
        parsed = _parse_requirement(line)
        if parsed is not None:
            name, version = parsed
            _add_item(items, seen, name, version, "runtime", "python", path.name)
    return items


def _load_toml(path: Path) -> dict[str, Any] | None:
    if tomllib is None:
        return None
    try:
        with path.open("rb") as stream:
            data = tomllib.load(stream)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _add_requirement_list(
    values: Any,
    scope: str,
    items: list[dict[str, Any]],
    seen: set[tuple[str, str | None, str, str, str]],
    manifest: str,
) -> None:
    if not isinstance(values, list):
        return
    for value in values:
        parsed = _parse_requirement(value)
        if parsed is None:
            continue
        name, version = parsed
        _add_item(items, seen, name, version, scope, "python", manifest)


def _poetry_declarations(
    name: str,
    value: Any,
    default_scope: str,
    items: list[dict[str, Any]],
    seen: set[tuple[str, str | None, str, str, str]],
    manifest: str,
) -> None:
    safe_name = _safe_requirement_name(name)
    if safe_name is None or safe_name.casefold() == "python":
        return
    values = value if isinstance(value, list) else [value]
    for declaration in values:
        scope = default_scope
        if isinstance(declaration, dict):
            if declaration.get("optional") is True:
                scope = "optional"
            if "version" in declaration:
                if declaration["version"] is None:
                    continue
                valid, version = _safe_version(declaration["version"])
                if not valid:
                    continue
            elif any(
                key in declaration
                for key in ("git", "path", "url", "branch", "tag", "rev", "workspace", "registry")
            ):
                version = None
            else:
                continue
        elif isinstance(declaration, str):
            valid, version = _safe_version(declaration)
            if not valid:
                continue
        else:
            continue
        _add_item(items, seen, safe_name, version, scope, "python", manifest)


def _parse_poetry_table(
    values: Any,
    scope: str,
    items: list[dict[str, Any]],
    seen: set[tuple[str, str | None, str, str, str]],
    manifest: str,
) -> None:
    table = _mapping(values)
    if table is None:
        return
    for name, value in table.items():
        _poetry_declarations(name, value, scope, items, seen, manifest)


def _parse_pyproject(data: dict[str, Any], path: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None, str, str, str]] = set()
    manifest = path.name
    build_system = _mapping(data.get("build-system"))
    if build_system is not None:
        _add_requirement_list(build_system.get("requires"), "build", items, seen, manifest)
    project = _mapping(data.get("project"))
    if project is not None:
        _add_requirement_list(project.get("dependencies"), "runtime", items, seen, manifest)
        optional = _mapping(project.get("optional-dependencies"))
        if optional is not None:
            for group_values in optional.values():
                _add_requirement_list(group_values, "optional", items, seen, manifest)
        groups = _mapping(data.get("dependency-groups"))
        if groups is not None:
            for group_values in groups.values():
                _add_requirement_list(group_values, "dev", items, seen, manifest)
    tool = _mapping(data.get("tool"))
    poetry = _mapping(tool.get("poetry")) if tool is not None else None
    if poetry is not None:
        _parse_poetry_table(poetry.get("dependencies"), "runtime", items, seen, manifest)
        _parse_poetry_table(poetry.get("dev-dependencies"), "dev", items, seen, manifest)
        groups = _mapping(poetry.get("group"))
        if groups is not None:
            for group_data in groups.values():
                group_table = _mapping(group_data)
                if group_table is not None:
                    _parse_poetry_table(group_table.get("dependencies"), "dev", items, seen, manifest)
    return items


def _valid_cargo_version(value: Any) -> tuple[bool, str | None]:
    valid, version = _safe_version(value)
    if not valid or version is None or not _CARGO_VERSION.fullmatch(version):
        return False, None
    if not any(char.isdigit() for char in version) and not any(
        char in "*^~<>=!" for char in version
    ):
        return False, None
    return True, version


def _cargo_version(value: Any) -> tuple[bool, str | None] | None:
    if isinstance(value, str):
        return _valid_cargo_version(value)
    if not isinstance(value, dict):
        return None
    if "version" in value:
        if value["version"] is None:
            return False, None
        raw = value["version"]
        if isinstance(raw, list):
            return False, None
        return _valid_cargo_version(raw)
    if any(key in value for key in ("git", "path", "registry", "workspace")):
        return True, None
    return None


def _parse_cargo_table(
    values: Any,
    scope: str,
    items: list[dict[str, Any]],
    seen: set[tuple[str, str | None, str, str, str]],
    manifest: str,
) -> None:
    table = _mapping(values)
    if table is None:
        return
    for name, value in table.items():
        safe_name = _safe_cargo_name(name)
        if safe_name is None:
            continue
        result = _cargo_version(value)
        if result is None:
            continue
        valid, version = result
        if not valid:
            continue
        _add_item(items, seen, safe_name, version, scope, "rust", manifest)


def _parse_cargo(data: dict[str, Any], path: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None, str, str, str]] = set()
    manifest = path.name
    _parse_cargo_table(data.get("dependencies"), "runtime", items, seen, manifest)
    _parse_cargo_table(data.get("dev-dependencies"), "dev", items, seen, manifest)
    _parse_cargo_table(data.get("build-dependencies"), "build", items, seen, manifest)
    workspace = _mapping(data.get("workspace"))
    if workspace is not None:
        _parse_cargo_table(workspace.get("dependencies"), "workspace", items, seen, manifest)
        _parse_cargo_table(workspace.get("dev-dependencies"), "dev", items, seen, manifest)
        _parse_cargo_table(workspace.get("build-dependencies"), "build", items, seen, manifest)
    targets = _mapping(data.get("target"))
    if targets is not None:
        for target in targets.values():
            target_table = _mapping(target)
            if target_table is None:
                continue
            _parse_cargo_table(target_table.get("dependencies"), "runtime", items, seen, manifest)
            _parse_cargo_table(target_table.get("dev-dependencies"), "dev", items, seen, manifest)
            _parse_cargo_table(target_table.get("build-dependencies"), "build", items, seen, manifest)
    return items


def _strip_go_comment(value: str) -> tuple[str, str]:
    if "//" not in value:
        return value, ""
    content, comment = value.split("//", 1)
    return content, comment


def _parse_go_require_line(value: str, comment: str) -> tuple[str, str, str] | None:
    parts = value.split()
    if len(parts) != 2:
        return None
    name = _safe_go_module(parts[0])
    valid, version = _safe_version(parts[1])
    if name is None or not valid or version is None or not _GO_VERSION.fullmatch(version):
        return None
    scope = "indirect" if re.search(r"\bindirect\b", comment, re.IGNORECASE) else "runtime"
    return name, version, scope


def _parse_go_mod(text: str, path: Path) -> list[dict[str, Any]]:
    if text.startswith("\ufeff"):
        text = text[1:]
    text = _strip_private_content(text)
    if "\x00" in text:
        return []
    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None, str, str, str]] = set()
    in_require = False
    for raw_line in text.splitlines():
        content, comment = _strip_go_comment(raw_line)
        line = content.strip()
        if in_require:
            if not line:
                continue
            if line == ")":
                in_require = False
                continue
            parsed = _parse_go_require_line(line, comment)
            if parsed is not None:
                name, version, scope = parsed
                _add_item(items, seen, name, version, scope, "go", path.name)
            continue
        if re.fullmatch(r"require\s*\(\s*", line):
            in_require = True
            continue
        if not re.match(r"^require(?:\s|$)", line):
            continue
        parsed = _parse_go_require_line(line[7:].strip(), comment)
        if parsed is not None:
            name, version, scope = parsed
            _add_item(items, seen, name, version, scope, "go", path.name)
    if in_require:
        return []
    return items


def _parse_package_json(data: dict[str, Any], path: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None, str, str, str]] = set()
    fields = (
        ("dependencies", "runtime"),
        ("devDependencies", "dev"),
        ("peerDependencies", "peer"),
        ("optionalDependencies", "optional"),
    )
    for field, scope in fields:
        values = _mapping(data.get(field))
        if values is None:
            continue
        for name, raw_version in values.items():
            safe_name = _safe_npm_name(name)
            valid, version = _safe_version(raw_version, allow_empty=True)
            if safe_name is None or not valid:
                continue
            _add_item(items, seen, safe_name, version, scope, "npm", path.name)
    return items


def _is_requirements_path(path: Path) -> bool:
    name = path.name.lower()
    if name in {"requirements", "constraints"}:
        return True
    if path.suffix.lower() not in {".txt", ".in", ".pip"}:
        return False
    stem = path.stem.lower()
    if "requirements" in stem or "constraints" in stem:
        return True
    if path.parent.name.lower() not in {"requirements", "constraints"}:
        return False
    return bool(re.fullmatch(
        r"(?:base|common|default|main|dev|development|test|tests|prod|production|local|all)(?:[-_.].*)?",
        stem,
    ))


def is_manifest(path: Path) -> bool:
    try:
        path = Path(path)
    except Exception:
        return False
    name = path.name.lower()
    if name in {"pyproject.toml", "cargo.toml", "go.mod", "package.json"}:
        return True
    return _is_requirements_path(path)


def parse_manifest(path: Path) -> list[dict]:
    try:
        path = Path(path)
        name = path.name.lower()
        if name == "pyproject.toml":
            data = _load_toml(path)
            return [] if data is None else _parse_pyproject(data, path)
        if name == "cargo.toml":
            data = _load_toml(path)
            return [] if data is None else _parse_cargo(data, path)
        if name == "go.mod":
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                return []
            return _parse_go_mod(text, path)
        if name == "package.json":
            try:
                text = path.read_text(encoding="utf-8")
                if text.startswith("\ufeff"):
                    text = text[1:]
                data = json.loads(text)
            except (OSError, UnicodeError, TypeError, ValueError, RecursionError):
                return []
            return _parse_package_json(data, path) if isinstance(data, dict) else []
        if _is_requirements_path(path):
            return _parse_requirements(path)
        return []
    except Exception:
        return []
