"""Safe INI, Dotenv, and Properties configuration parser, validator, and formatter for Jarvis."""

from __future__ import annotations

import configparser
import os
import re
from pathlib import Path
from typing import Any

try:
    import operator_tools as ops
except ImportError:
    ops = None

MAX_CONFIG_BYTES = 512 * 1024  # 512 KB limit

SENSITIVE_FILENAME_PATTERNS = {
    ".ssh",
    ".gnupg",
    ".password-store",
    "secrets.json",
    ".git-credentials",
    ".aws",
    ".docker",
    ".kube",
}


def _is_sensitive_file(target: Path) -> bool:
    """Check if the resolved path points to a sensitive file or directory."""
    if ops is not None:
        try:
            return bool(ops.is_credential_target(target) or ops.is_sensitive_target(target))
        except Exception:
            pass

    resolved = target.resolve()
    parts = {part.casefold() for part in resolved.parts}
    if parts.intersection(SENSITIVE_FILENAME_PATTERNS):
        return True
    if resolved.name.startswith(".env") and not resolved.name.endswith(".example"):
        # Guard real .env files from being read by untrusted queries
        # (unless test/example)
        if any(p in parts for p in (".ssh", ".gnupg", ".jarvis-tools", "etc")):
            return True
    return False


def _parse_ini(text: str) -> dict[str, dict[str, str]]:
    """Parse INI configuration with interpolation strictly disabled."""
    parser = configparser.ConfigParser(interpolation=None)
    # Check if content has section headers. If not, add a [DEFAULT] header
    lines = text.splitlines()
    has_section = any(line.strip().startswith("[") and line.strip().endswith("]") for line in lines if line.strip())

    if not has_section:
        text = f"[DEFAULT]\n{text}"

    parser.read_string(text)
    result: dict[str, dict[str, str]] = {}

    # Extract DEFAULT section if not empty
    if parser.defaults():
        result["DEFAULT"] = dict(parser.defaults())

    for section in parser.sections():
        result[section] = dict(parser.items(section, raw=True))

    return result


def _parse_dotenv(text: str) -> dict[str, str]:
    """Pure lexical parser for .env files without shell sourcing or eval."""
    result: dict[str, str] = {}
    lines = text.splitlines()

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Strip optional leading 'export '
        if stripped.startswith("export ") and len(stripped) > 7:
            stripped = stripped[7:].lstrip()

        if "=" not in stripped:
            continue

        key_part, val_part = stripped.split("=", 1)
        key = key_part.strip()
        if not key:
            continue

        val = val_part.strip()

        # Quoted values
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            quote_char = val[0]
            val = val[1:-1]
            if quote_char == '"':
                val = (
                    val.replace(r"\n", "\n")
                    .replace(r"\r", "\r")
                    .replace(r"\t", "\t")
                    .replace(r'\"', '"')
                    .replace(r"\\", "\\")
                )
        else:
            # Unquoted: strip trailing inline comments
            # Inline comment must be preceded by whitespace: foo=bar # comment
            comment_match = re.search(r"\s+#", val)
            if comment_match:
                val = val[: comment_match.start()].rstrip()

        result[key] = val

    return result


def _parse_properties(text: str) -> dict[str, str]:
    """Parse Java .properties format with continuation lines and escape handling."""
    result: dict[str, str] = {}
    raw_lines = text.splitlines()
    merged_lines: list[str] = []
    buffer = ""

    for line in raw_lines:
        r_line = line.rstrip("\r\n")
        num_bs = len(r_line) - len(r_line.rstrip("\\"))
        if num_bs % 2 == 1:
            buffer += r_line[:-1]
        else:
            buffer += r_line
            merged_lines.append(buffer)
            buffer = ""
    if buffer:
        merged_lines.append(buffer)

    for line in merged_lines:
        stripped = line.lstrip()
        if not stripped or stripped.startswith(("#", "!")):
            continue

        key_chars: list[str] = []
        i = 0
        n = len(stripped)
        while i < n:
            c = stripped[i]
            if c == "\\":
                if i + 1 < n:
                    key_chars.append(stripped[i + 1])
                    i += 2
                    continue
                else:
                    key_chars.append(c)
                    i += 1
                    continue
            if c in ("=", ":") or c.isspace():
                break
            key_chars.append(c)
            i += 1

        key = "".join(key_chars).strip()
        # Skip separator delimiter and leading whitespace of value
        sep_seen = False
        while i < n:
            if stripped[i] in ("=", ":") and not sep_seen:
                sep_seen = True
                i += 1
            elif stripped[i].isspace():
                i += 1
            else:
                break
        val = stripped[i:] if i < n else ""

        # Unescape standard Java properties escapes
        val = (
            val.replace(r"\n", "\n")
            .replace(r"\t", "\t")
            .replace(r"\r", "\r")
            .replace(r"\\", "\\")
        )
        val = re.sub(
            r"\\u([0-9a-fA-F]{4})",
            lambda m: chr(int(m.group(1), 16)),
            val,
        )
        if key:
            result[key] = val

    return result


def _format_config(parsed: dict[str, Any], fmt: str) -> str:
    """Format structured dictionary into INI, Dotenv, or Properties string."""
    if fmt == "ini":
        out: list[str] = []
        # Check if nested sections or flat dict
        is_nested = any(isinstance(v, dict) for v in parsed.values())
        if not is_nested:
            out.append("[DEFAULT]")
            for k, v in parsed.items():
                out.append(f"{k} = {v}")
        else:
            for sec, vals in parsed.items():
                out.append(f"[{sec}]")
                if isinstance(vals, dict):
                    for k, v in vals.items():
                        out.append(f"{k} = {v}")
                out.append("")
        return "\n".join(out).strip() + "\n"

    if fmt == "dotenv":
        out = []
        flat = {}
        for k, v in parsed.items():
            if isinstance(v, dict):
                flat.update(v)
            else:
                flat[k] = v
        for k, v in flat.items():
            s_val = str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            out.append(f'{k}="{s_val}"')
        return "\n".join(out) + "\n"

    if fmt == "properties":
        out = []
        flat = {}
        for k, v in parsed.items():
            if isinstance(v, dict):
                flat.update(v)
            else:
                flat[k] = v
        for k, v in flat.items():
            s_val = str(v).replace("\\", "\\\\").replace("\n", "\\n")
            out.append(f"{k}={s_val}")
        return "\n".join(out) + "\n"

    raise ValueError(f"Unsupported format for format action: {fmt!r}")


def _safe_resolve_path(raw_path: Any) -> Path:
    """Validate and canonicalize path against allowed roots and sensitive targets."""
    if not isinstance(raw_path, str):
        raise ValueError("Field 'path' must be a string")
    if not raw_path.strip():
        raise ValueError("Field 'path' must be a non-empty string")
    if len(raw_path) > 4096:
        raise ValueError("File path exceeds maximum length")

    expanded = Path(raw_path).expanduser()
    if any(part in ("..", "") for part in expanded.parts):
        raise PermissionError(f"Directory traversal sequences not allowed: {raw_path}")

    try:
        resolved = Path(os.path.realpath(str(expanded)))
    except (OSError, ValueError):
        resolved = expanded.resolve()

    if ops is not None:
        if not ops._inside(resolved):
            raise PermissionError(f"Path outside allowed roots: {raw_path}")
        if ops.is_sensitive_target(resolved) or ops.is_credential_target(resolved) or _is_sensitive_file(resolved):
            raise PermissionError(f"Refusing to access protected credential target: {raw_path}")
    else:
        home = Path.home().resolve()
        tmp = Path("/tmp").resolve()
        allowed = (
            resolved == home or resolved.is_relative_to(home) or
            resolved == tmp or resolved.is_relative_to(tmp)
        )
        if not allowed:
            raise PermissionError(f"Path outside allowed directories: {raw_path}")
        if _is_sensitive_file(resolved):
            raise PermissionError(f"Refusing to access protected credential target: {raw_path}")

    if not resolved.is_file():
        raise FileNotFoundError(f"Configuration file not found: {raw_path}")

    if resolved.stat().st_size > MAX_CONFIG_BYTES:
        raise ValueError(f"File exceeds maximum size ({MAX_CONFIG_BYTES} bytes)")

    return resolved


def _load_config_text(arguments: dict[str, Any]) -> str:
    text = arguments.get("text")
    path_str = arguments.get("path")

    if text is not None:
        if not isinstance(text, str):
            raise ValueError("Field 'text' must be a string")
        if len(text.encode("utf-8", errors="ignore")) > MAX_CONFIG_BYTES:
            raise ValueError(f"Configuration text exceeds maximum size ({MAX_CONFIG_BYTES} bytes)")
        return text

    if path_str is not None:
        resolved = _safe_resolve_path(path_str)
        return resolved.read_text(encoding="utf-8", errors="replace")

    raise ValueError("Either 'text' or 'path' must be provided")


def _config_parser_impl(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    action = arguments.get("action")
    if not action:
        return {"ok": False, "success": False, "data": None, "result": None, "error": "Missing required field 'action'"}

    fmt = str(arguments.get("format") or "ini").lower()
    if fmt not in ("ini", "dotenv", "properties"):
        return {"ok": False, "success": False, "data": None, "result": None, "error": f"Unsupported format: {fmt!r}"}

    text = _load_config_text(arguments)

    # Parse config according to format
    if fmt == "ini":
        parsed = _parse_ini(text)
    elif fmt == "dotenv":
        parsed = _parse_dotenv(text)
    elif fmt == "properties":
        parsed = _parse_properties(text)
    else:
        parsed = {}

    if action == "parse":
        entry_count = sum(len(v) for v in parsed.values()) if fmt == "ini" else len(parsed)
        data = {
            "format": fmt,
            "config": parsed,
            "entry_count": entry_count,
        }
        return {"ok": True, "success": True, "data": data, "result": data, "error": None}

    if action == "get_value":
        key = arguments.get("key")
        if not key:
            return {"ok": False, "success": False, "data": None, "result": None, "error": "Missing required field 'key'"}

        section = arguments.get("section")
        found = False
        value = None
        found_section = None

        if fmt == "ini":
            if section:
                sec_dict = parsed.get(section, {})
                if key in sec_dict:
                    found = True
                    value = sec_dict[key]
                    found_section = section
                elif key.lower() in sec_dict:
                    found = True
                    value = sec_dict[key.lower()]
                    found_section = section
            else:
                # Search all sections
                for s_name, s_data in parsed.items():
                    if key in s_data:
                        found = True
                        value = s_data[key]
                        found_section = s_name
                        break
                    if key.lower() in s_data:
                        found = True
                        value = s_data[key.lower()]
                        found_section = s_name
                        break
        else:
            if key in parsed:
                found = True
                value = parsed[key]

        data = {
            "key": key,
            "value": value,
            "found": found,
            "section": found_section,
        }
        return {"ok": True, "success": True, "data": data, "result": data, "error": None}

    if action == "format":
        formatted_str = _format_config(parsed, fmt)
        data = {
            "formatted": formatted_str,
            "format": fmt,
        }
        return {"ok": True, "success": True, "data": data, "result": data, "error": None}

    if action == "validate":
        required_keys = arguments.get("required_keys") or []
        missing: list[str] = []
        found_keys: list[str] = []

        if fmt == "ini":
            all_keys: set[str] = set()
            for s_name, s_dict in parsed.items():
                for k in s_dict:
                    all_keys.add(k)
                    all_keys.add(f"{s_name}.{k}")
            found_keys = sorted(list(all_keys))
            for req in required_keys:
                if req not in all_keys and req.lower() not in all_keys:
                    missing.append(req)
        else:
            found_keys = sorted(list(parsed.keys()))
            for req in required_keys:
                if req not in parsed:
                    missing.append(req)

        is_valid = len(missing) == 0
        data = {
            "valid": is_valid,
            "errors": [f"Missing required key: {k}" for k in missing],
            "missing_keys": missing,
            "found_keys_count": len(found_keys),
        }
        return {"ok": True, "success": True, "data": data, "result": data, "error": None}

    return {"ok": False, "success": False, "data": None, "result": None, "error": f"Unsupported action: {action!r}"}


def config_parser(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute safe configuration parsing, querying, formatting, and validation."""
    try:
        return _config_parser_impl(arguments, context)
    except Exception as err:
        return {
            "ok": False,
            "success": False,
            "data": None,
            "result": None,
            "error": f"Config parsing error: {type(err).__name__}: {err}",
        }


TOOL = {
    "name": "config_parser",
    "description": (
        "Safe INI, Dotenv (.env), and Java Properties configuration parser, validator, and formatter. "
        "Operates with interpolation=None to neutralize recursion bombs and uses pure lexical parsing for .env files."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["parse", "get_value", "format", "validate"],
                "description": "Configuration operation to perform.",
            },
            "format": {
                "type": "string",
                "enum": ["ini", "dotenv", "properties"],
                "description": "Configuration syntax format (default: ini).",
            },
            "text": {
                "type": "string",
                "description": "Configuration text content.",
            },
            "path": {
                "type": "string",
                "description": "Path to local configuration file.",
            },
            "section": {
                "type": "string",
                "description": "INI section name.",
            },
            "key": {
                "type": "string",
                "description": "Key name for get_value.",
            },
            "required_keys": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of key names required when action='validate'.",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": config_parser,
    "approval": False,
}
