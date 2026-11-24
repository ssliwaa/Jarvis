"""Configuration validation and structural linting operator module for Jarvis.

Provides validation of JSON, INI/CFG, and .env files against syntax specifications,
custom schemas, type definitions, and structural hygiene standards using EXCLUSIVELY
the Python standard library. Zero external dependencies.
"""

from __future__ import annotations

import configparser
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

# =============================================================================
# Security Perimeter & Configuration Boundaries
# =============================================================================

HOME = Path.home().resolve()
ALLOWED_ROOTS: tuple[Path, ...] = (
    HOME,
    Path("/tmp").resolve(),
    Path("/mnt").resolve(),
    Path("/media").resolve(),
)

MAX_CONFIG_BYTES: int = 5 * 1024 * 1024       # 5 MB
MAX_RECURSION_DEPTH: int = 50
MAX_REGEX_STRING_LEN: int = 4096
MAX_REGEX_PATTERN_LEN: int = 500
REGEX_TIMEOUT_SECONDS: float = 0.5
MAX_DIAGNOSTICS_RETURNED: int = 200

# Sensitive directories and credential files that must never be read
SENSITIVE_NAMES: frozenset[str] = frozenset({
    ".ssh",
    ".gnupg",
    ".password-store",
    ".aws",
    ".docker",
    ".kube",
    ".git-credentials",
    "secrets.json",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".gitconfig",
})

VALID_ACTIONS: frozenset[str] = frozenset({
    "validate_json",
    "validate_ini",
    "validate_dotenv",
    "lint_config",
})

KNOWN_ARGUMENTS: frozenset[str] = frozenset({
    "action",
    "content",
    "text",
    "path",
    "schema",
    "format",
    "required_sections",
    "required_options",
    "forbidden_sections",
    "forbidden_options",
    "check_interpolation",
    "interpolation",
    "required_variables",
    "template_path",
    "template_content",
    "strict_naming",
    "allow_duplicate_keys",
    "indent_size",
    "max_line_length",
    "strict",
    "max_depth",
})

# ReDoS static inspection: detects nested quantifiers like (a+)+, (a*)*, ([a-z]+)*
NESTED_QUANTIFIER_RE = re.compile(r"\([^()]*([*+]|\{\d+,?\d*\})[^()]*\)([*+]|\{\d+,?\d*\})")
DOTENV_VAR_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
PLACEHOLDER_VAL_RE = re.compile(r"(?i)\b(changeme|todo|replace_me|your_.*_here|xxx+)\b")


# =============================================================================
# Exceptions
# =============================================================================

class ConfigValidatorError(Exception):
    """Base exception for config_validator module."""


class PathSecurityError(ConfigValidatorError):
    """Raised when path resolution violates ALLOWED_ROOTS or traversal rules."""


class SensitivePathError(ConfigValidatorError):
    """Raised when accessing sensitive credential files or directories."""


class ConfigSizeError(ConfigValidatorError):
    """Raised when config input exceeds size limits."""


class ReDoSSecurityError(ConfigValidatorError):
    """Raised when regex pattern or execution presents a ReDoS risk."""


# =============================================================================
# Envelope Helpers
# =============================================================================

def _envelope_success(data: dict[str, Any]) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator success envelope."""
    return {
        "ok": True,
        "success": True,
        "data": data,
        "result": data,
        "error": None,
    }


def _envelope_error(err: str | Exception) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator error envelope."""
    if isinstance(err, Exception):
        msg = f"{type(err).__name__}: {err}"
    else:
        msg = str(err)
    return {
        "ok": False,
        "success": False,
        "data": None,
        "result": None,
        "error": msg,
    }


# =============================================================================
# Path Confinement & Input Loader Helpers
# =============================================================================

def _is_inside_allowed_roots(path: Path) -> bool:
    """Verify that path resides strictly inside ALLOWED_ROOTS."""
    try:
        resolved = Path(os.path.realpath(str(path)))
        for root in ALLOWED_ROOTS:
            try:
                root_res = Path(os.path.realpath(str(root)))
                if resolved == root_res or resolved.is_relative_to(root_res):
                    return True
            except (OSError, RuntimeError, ValueError):
                continue
        return False
    except (OSError, RuntimeError, ValueError):
        return False


def _is_sensitive_path(path: Path) -> bool:
    """Check if any path component touches sensitive credential directories or files."""
    parts = [p.casefold() for p in path.parts]
    for part in parts:
        if part in SENSITIVE_NAMES:
            return True
        if part == ".jarvis-tools":
            return True
    return False


def _validate_and_resolve_path(path_str: str) -> Path:
    """Resolve and confine a file path, ensuring security invariants."""
    if not isinstance(path_str, str) or not path_str.strip():
        raise ValueError("File path must be a non-empty string.")
    if "\0" in path_str:
        raise PathSecurityError("Null bytes are prohibited in file paths.")

    parts = Path(path_str).parts
    if ".." in parts:
        resolved_test = Path(os.path.realpath(os.path.expanduser(path_str)))
        if not _is_inside_allowed_roots(resolved_test):
            raise PathSecurityError(f"Path traversal escape detected: '{path_str}'")

    resolved = Path(os.path.realpath(os.path.expanduser(path_str)))

    if not _is_inside_allowed_roots(resolved):
        raise PathSecurityError(f"Path '{path_str}' resolves outside ALLOWED_ROOTS.")

    if _is_sensitive_path(resolved):
        raise SensitivePathError(f"Access to sensitive path '{resolved}' is restricted.")

    if not resolved.exists():
        raise FileNotFoundError(f"Configuration file not found: '{path_str}'")

    if not resolved.is_file():
        raise ValueError(f"Path '{path_str}' is not a regular file.")

    st = resolved.stat()
    if st.st_size > MAX_CONFIG_BYTES:
        raise ConfigSizeError(
            f"File size ({st.st_size} bytes) exceeds maximum allowed size ({MAX_CONFIG_BYTES} bytes)."
        )

    return resolved


def _load_input(arguments: dict[str, Any]) -> tuple[str, str | None]:
    """Retrieve content string from either 'content'/'text' or 'path'."""
    content = arguments.get("content")
    if content is None:
        content = arguments.get("text")
    path_str = arguments.get("path")

    if content is not None:
        if not isinstance(content, str):
            raise ValueError("'content' must be a string.")
        content_bytes = content.encode("utf-8")
        if len(content_bytes) > MAX_CONFIG_BYTES:
            raise ConfigSizeError(
                f"Content size ({len(content_bytes)} bytes) exceeds maximum limit ({MAX_CONFIG_BYTES} bytes)."
            )
        return content, str(path_str) if path_str else None

    if path_str is not None:
        resolved = _validate_and_resolve_path(path_str)
        try:
            text = resolved.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = resolved.read_text(encoding="latin-1")
        return text, str(resolved)

    raise ValueError("Either 'content' (inline text) or 'path' (file path) must be provided.")


# =============================================================================
# ReDoS Defense Engine
# =============================================================================

def _check_regex_safety(pattern: str) -> None:
    """Statically verify regex pattern safety against ReDoS."""
    if not isinstance(pattern, str):
        raise ValueError("Pattern must be a string.")
    if len(pattern) > MAX_REGEX_PATTERN_LEN:
        raise ReDoSSecurityError(
            f"Regex pattern length ({len(pattern)}) exceeds maximum allowed ({MAX_REGEX_PATTERN_LEN})."
        )
    nested = NESTED_QUANTIFIER_RE.search(pattern)
    if nested:
        raise ReDoSSecurityError(
            f"Dangerous nested quantifier detected in regex pattern: {nested.group(0)!r}"
        )


_REGEX_WORKER_SOURCE = (
    "import json, re, sys\n"
    "req = json.loads(sys.stdin.read())\n"
    "try:\n"
    "    matched = bool(re.compile(req['pattern']).search(req['text']))\n"
    "    sys.stdout.write(json.dumps({'match': matched}))\n"
    "except Exception as err:\n"
    "    sys.stdout.write(json.dumps({'error': '%s: %s' % (type(err).__name__, err)}))\n"
)


def _safe_regex_match(pattern: str, text: str, timeout: float = REGEX_TIMEOUT_SECONDS) -> bool:
    """Execute regex search with static complexity checks, length bounds, and timeout.

    The search itself runs in a short-lived subprocess with a hard
    wall-clock kill. A worker thread cannot enforce the timeout: the
    C-level regex engine holds the GIL for the entire match, so the
    timeout check in this thread would only run after the (possibly
    catastrophic) match finished anyway.
    """
    _check_regex_safety(pattern)
    if len(text) > MAX_REGEX_STRING_LEN:
        raise ReDoSSecurityError(
            f"Target text length ({len(text)}) exceeds maximum evaluation limit ({MAX_REGEX_STRING_LEN})."
        )

    # Compilation is linear (never backtracks), so malformed patterns
    # fail cheaply here in the parent.
    re.compile(pattern)

    try:
        completed = subprocess.run(
            [sys.executable, "-c", _REGEX_WORKER_SOURCE],
            input=json.dumps({"pattern": pattern, "text": text}),
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise ReDoSSecurityError(
            f"Regex execution timed out after {timeout}s (suspected catastrophic backtracking/ReDoS)."
        ) from None
    if completed.returncode != 0:
        raise ReDoSSecurityError(
            f"Regex worker failed (exit {completed.returncode}): "
            f"{(completed.stderr or '').strip()[:200]}"
        )
    try:
        answer = json.loads(completed.stdout or "")
    except ValueError:
        raise ReDoSSecurityError(
            f"Regex worker returned malformed output: {(completed.stdout or '').strip()[:200]}"
        ) from None
    if "error" in answer:
        raise ReDoSSecurityError(f"Regex execution error: {str(answer['error'])[:200]}")
    return bool(answer.get("match"))


# =============================================================================
# Action 1: validate_json Implementation
# =============================================================================

def _validate_json_schema(
    data: Any,
    schema: dict[str, Any],
    diagnostics: list[dict[str, Any]],
    current_depth: int = 0,
    current_path: str = "$",
    max_depth: int = MAX_RECURSION_DEPTH,
) -> None:
    """Recursively validate parsed JSON data against custom schema rules."""
    if current_depth > max_depth:
        diagnostics.append({
            "field": current_path,
            "line": None,
            "column": None,
            "message": f"Maximum nesting depth ({max_depth}) exceeded during schema evaluation.",
            "severity": "ERROR",
        })
        return

    # 1. Type validation
    if "type" in schema:
        expected_types = schema["type"]
        if isinstance(expected_types, str):
            expected_types = [expected_types]

        matched = False
        for exp in expected_types:
            if exp == "string" and isinstance(data, str):
                matched = True
            elif exp == "integer" and isinstance(data, int) and not isinstance(data, bool):
                matched = True
            elif exp == "number" and isinstance(data, (int, float)) and not isinstance(data, bool):
                matched = True
            elif exp == "boolean" and isinstance(data, bool):
                matched = True
            elif exp == "array" and isinstance(data, list):
                matched = True
            elif exp == "object" and isinstance(data, dict):
                matched = True
            elif exp == "null" and data is None:
                matched = True

        if not matched:
            diagnostics.append({
                "field": current_path,
                "line": None,
                "column": None,
                "message": f"Expected type {schema['type']!r}, got {type(data).__name__}.",
                "severity": "ERROR",
            })
            return  # Stop deeper validation if type mismatches

    # 2. Enum validation
    if "enum" in schema:
        if data not in schema["enum"]:
            diagnostics.append({
                "field": current_path,
                "line": None,
                "column": None,
                "message": f"Value {data!r} is not in permitted enum list {schema['enum']!r}.",
                "severity": "ERROR",
            })

    # 3. Object-specific constraints
    if isinstance(data, dict):
        # Required keys
        if "required" in schema and isinstance(schema["required"], list):
            for req in schema["required"]:
                if req not in data:
                    diagnostics.append({
                        "field": f"{current_path}.{req}",
                        "line": None,
                        "column": None,
                        "message": f"Missing required property: '{req}'.",
                        "severity": "ERROR",
                    })

        # Forbidden keys
        forbidden = schema.get("forbidden") or schema.get("forbidden_keys")
        if forbidden and isinstance(forbidden, list):
            for forb in forbidden:
                if forb in data:
                    diagnostics.append({
                        "field": f"{current_path}.{forb}",
                        "line": None,
                        "column": None,
                        "message": f"Forbidden property present: '{forb}'.",
                        "severity": "ERROR",
                    })

        # additionalProperties: False
        if schema.get("additionalProperties") is False:
            allowed_keys = set(schema.get("properties", {}).keys()) | set(schema.get("required", []))
            for k in data.keys():
                if k not in allowed_keys:
                    diagnostics.append({
                        "field": f"{current_path}.{k}",
                        "line": None,
                        "column": None,
                        "message": f"Property '{k}' is not allowed by additionalProperties: False.",
                        "severity": "ERROR",
                    })

        # minProperties / maxProperties
        if "minProperties" in schema and len(data) < schema["minProperties"]:
            diagnostics.append({
                "field": current_path,
                "line": None,
                "column": None,
                "message": f"Object has {len(data)} properties, minimum required is {schema['minProperties']}.",
                "severity": "ERROR",
            })
        if "maxProperties" in schema and len(data) > schema["maxProperties"]:
            diagnostics.append({
                "field": current_path,
                "line": None,
                "column": None,
                "message": f"Object has {len(data)} properties, maximum allowed is {schema['maxProperties']}.",
                "severity": "ERROR",
            })

        # Recurse into properties
        if "properties" in schema and isinstance(schema["properties"], dict):
            for prop_name, prop_schema in schema["properties"].items():
                if prop_name in data:
                    _validate_json_schema(
                        data[prop_name],
                        prop_schema,
                        diagnostics,
                        current_depth + 1,
                        f"{current_path}.{prop_name}",
                        max_depth,
                    )

    # 4. Array-specific constraints
    elif isinstance(data, list):
        if "minItems" in schema and len(data) < schema["minItems"]:
            diagnostics.append({
                "field": current_path,
                "line": None,
                "column": None,
                "message": f"Array has {len(data)} items, minimum required is {schema['minItems']}.",
                "severity": "ERROR",
            })
        if "maxItems" in schema and len(data) > schema["maxItems"]:
            diagnostics.append({
                "field": current_path,
                "line": None,
                "column": None,
                "message": f"Array has {len(data)} items, maximum allowed is {schema['maxItems']}.",
                "severity": "ERROR",
            })
        if schema.get("uniqueItems") is True:
            seen_items = set()
            for idx, item in enumerate(data):
                try:
                    serialized = json.dumps(item, sort_keys=True)
                except Exception:
                    serialized = str(item)
                if serialized in seen_items:
                    diagnostics.append({
                        "field": f"{current_path}[{idx}]",
                        "line": None,
                        "column": None,
                        "message": f"Duplicate item detected in array under uniqueItems: {item!r}.",
                        "severity": "ERROR",
                    })
                seen_items.add(serialized)

        if "items" in schema and isinstance(schema["items"], dict):
            for idx, item in enumerate(data):
                _validate_json_schema(
                    item,
                    schema["items"],
                    diagnostics,
                    current_depth + 1,
                    f"{current_path}[{idx}]",
                    max_depth,
                )

    # 5. String-specific constraints
    elif isinstance(data, str):
        if "minLength" in schema and len(data) < schema["minLength"]:
            diagnostics.append({
                "field": current_path,
                "line": None,
                "column": None,
                "message": f"String length ({len(data)}) is less than minLength ({schema['minLength']}).",
                "severity": "ERROR",
            })
        if "maxLength" in schema and len(data) > schema["maxLength"]:
            diagnostics.append({
                "field": current_path,
                "line": None,
                "column": None,
                "message": f"String length ({len(data)}) exceeds maxLength ({schema['maxLength']}).",
                "severity": "ERROR",
            })
        if "pattern" in schema:
            pat = schema["pattern"]
            matched = _safe_regex_match(pat, data)
            if not matched:
                diagnostics.append({
                    "field": current_path,
                    "line": None,
                    "column": None,
                    "message": f"String {data!r} does not match required pattern {pat!r}.",
                    "severity": "ERROR",
                })

    # 6. Number-specific constraints
    elif isinstance(data, (int, float)) and not isinstance(data, bool):
        if "minimum" in schema and data < schema["minimum"]:
            diagnostics.append({
                "field": current_path,
                "line": None,
                "column": None,
                "message": f"Value {data} is less than minimum {schema['minimum']}.",
                "severity": "ERROR",
            })
        if "maximum" in schema and data > schema["maximum"]:
            diagnostics.append({
                "field": current_path,
                "line": None,
                "column": None,
                "message": f"Value {data} exceeds maximum {schema['maximum']}.",
                "severity": "ERROR",
            })
        if "exclusiveMinimum" in schema and data <= schema["exclusiveMinimum"]:
            diagnostics.append({
                "field": current_path,
                "line": None,
                "column": None,
                "message": f"Value {data} must be strictly greater than exclusiveMinimum {schema['exclusiveMinimum']}.",
                "severity": "ERROR",
            })
        if "exclusiveMaximum" in schema and data >= schema["exclusiveMaximum"]:
            diagnostics.append({
                "field": current_path,
                "line": None,
                "column": None,
                "message": f"Value {data} must be strictly less than exclusiveMaximum {schema['exclusiveMaximum']}.",
                "severity": "ERROR",
            })


def _do_validate_json(arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute JSON syntax parsing, duplicate key detection, and schema validation."""
    text, path = _load_input(arguments)
    schema = arguments.get("schema")
    allow_duplicates = bool(arguments.get("allow_duplicate_keys", False))
    max_depth = int(arguments.get("max_depth", MAX_RECURSION_DEPTH))

    duplicate_keys: list[str] = []

    def _pair_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        seen = set()
        res = {}
        for k, v in pairs:
            if k in seen:
                duplicate_keys.append(k)
            seen.add(k)
            res[k] = v
        return res

    def _parse_constant(c: str) -> None:
        raise ValueError(f"Disallowed RFC 8259 constant: {c}")

    diagnostics: list[dict[str, Any]] = []
    parsed_data: Any = None
    syntax_valid = False

    try:
        parsed_data = json.loads(text, object_pairs_hook=_pair_hook, parse_constant=_parse_constant)
        syntax_valid = True
    except (json.JSONDecodeError, ValueError) as err:
        lineno = getattr(err, "lineno", None)
        colno = getattr(err, "colno", None)
        pos = getattr(err, "pos", None)
        pos_msg = f" (at char {pos})" if pos is not None else ""
        diagnostics.append({
            "field": "<syntax>",
            "line": lineno,
            "column": colno,
            "message": f"JSON syntax error: {err}{pos_msg}.",
            "severity": "ERROR",
        })

    # Check duplicate keys
    if duplicate_keys:
        for dup in duplicate_keys:
            severity = "ERROR" if not allow_duplicates else "WARNING"
            diagnostics.append({
                "field": dup,
                "line": None,
                "column": None,
                "message": f"Duplicate key detected in JSON object: {dup!r}.",
                "severity": severity,
            })

    # Schema validation
    if syntax_valid and schema is not None:
        if not isinstance(schema, dict):
            raise ValueError("'schema' must be a dictionary.")
        _validate_json_schema(parsed_data, schema, diagnostics, current_depth=0, max_depth=max_depth)

    errors = [d["message"] for d in diagnostics if d["severity"] == "ERROR"]
    warnings = [d["message"] for d in diagnostics if d["severity"] == "WARNING"]
    is_valid = len(errors) == 0

    count_keys = len(parsed_data) if isinstance(parsed_data, (dict, list)) else (1 if parsed_data is not None else 0)

    data = {
        "valid": is_valid,
        "format": "json",
        "errors": errors[:MAX_DIAGNOSTICS_RETURNED],
        "warnings": warnings[:MAX_DIAGNOSTICS_RETURNED],
        "errors_count": len(errors),
        "warnings_count": len(warnings),
        "diagnostics": diagnostics[:MAX_DIAGNOSTICS_RETURNED],
        "summary": (
            "JSON validation passed cleanly."
            if is_valid
            else f"JSON validation failed with {len(errors)} error(s) and {len(warnings)} warning(s)."
        ),
        "details": {
            "path": path,
            "syntax_valid": syntax_valid,
            "schema_applied": schema is not None,
            "duplicate_keys": duplicate_keys,
            "keys_count": count_keys,
        },
    }
    return _envelope_success(data)


# =============================================================================
# Action 2: validate_ini Implementation
# =============================================================================

def _do_validate_ini(arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute INI/CFG syntax parsing, section/option checks, and interpolation audit."""
    text, path = _load_input(arguments)
    required_sections = arguments.get("required_sections") or []
    required_options = arguments.get("required_options") or {}
    forbidden_sections = arguments.get("forbidden_sections") or []
    forbidden_options = arguments.get("forbidden_options") or {}
    check_interp = bool(arguments.get("check_interpolation", True))
    interp_mode = str(arguments.get("interpolation", "basic")).lower()
    allow_duplicates = bool(arguments.get("allow_duplicate_keys", False))

    if interp_mode == "extended":
        interp = configparser.ExtendedInterpolation()
    elif interp_mode == "none":
        interp = None
    else:
        interp = configparser.BasicInterpolation()

    parser = configparser.ConfigParser(strict=not allow_duplicates, interpolation=interp)
    diagnostics: list[dict[str, Any]] = []
    syntax_valid = False

    try:
        parser.read_string(text)
        syntax_valid = True
    except configparser.DuplicateSectionError as err:
        diagnostics.append({
            "field": err.section,
            "line": err.lineno,
            "column": None,
            "message": f"Duplicate section header detected: [{err.section}].",
            "severity": "ERROR",
        })
    except configparser.DuplicateOptionError as err:
        diagnostics.append({
            "field": f"{err.section}.{err.option}",
            "line": err.lineno,
            "column": None,
            "message": f"Duplicate option '{err.option}' detected in section [{err.section}].",
            "severity": "ERROR",
        })
    except configparser.MissingSectionHeaderError as err:
        diagnostics.append({
            "field": "<syntax>",
            "line": err.lineno,
            "column": None,
            "message": f"Missing section header: {err.message}.",
            "severity": "ERROR",
        })
    except configparser.ParsingError as err:
        for lineno, line in err.errors:
            diagnostics.append({
                "field": "<syntax>",
                "line": lineno,
                "column": None,
                "message": f"INI parsing error on line {lineno}: {line!r}.",
                "severity": "ERROR",
            })
    except configparser.Error as err:
        diagnostics.append({
            "field": "<syntax>",
            "line": None,
            "column": None,
            "message": f"INI syntax error: {err}.",
            "severity": "ERROR",
        })

    if syntax_valid:
        present_sections = set(parser.sections())

        # Check required sections
        for sec in required_sections:
            if sec not in present_sections:
                diagnostics.append({
                    "field": sec,
                    "line": None,
                    "column": None,
                    "message": f"Missing required section: [{sec}].",
                    "severity": "ERROR",
                })

        # Check forbidden sections
        for sec in forbidden_sections:
            if sec in present_sections:
                diagnostics.append({
                    "field": sec,
                    "line": None,
                    "column": None,
                    "message": f"Forbidden section present: [{sec}].",
                    "severity": "ERROR",
                })

        # Check required options
        req_opts_norm: dict[str, list[str]] = {}
        if isinstance(required_options, dict):
            for sec, opts in required_options.items():
                req_opts_norm[sec] = opts if isinstance(opts, list) else [str(opts)]
        elif isinstance(required_options, list):
            for item in required_options:
                if "." in str(item):
                    s, o = str(item).split(".", 1)
                    req_opts_norm.setdefault(s, []).append(o)

        for sec, opts in req_opts_norm.items():
            if sec not in present_sections:
                continue
            for opt in opts:
                if not parser.has_option(sec, opt):
                    diagnostics.append({
                        "field": f"{sec}.{opt}",
                        "line": None,
                        "column": None,
                        "message": f"Missing required option '{opt}' in section [{sec}].",
                        "severity": "ERROR",
                    })

        # Check forbidden options
        forb_opts_norm: dict[str, list[str]] = {}
        if isinstance(forbidden_options, dict):
            for sec, opts in forbidden_options.items():
                forb_opts_norm[sec] = opts if isinstance(opts, list) else [str(opts)]
        elif isinstance(forbidden_options, list):
            for item in forbidden_options:
                if "." in str(item):
                    s, o = str(item).split(".", 1)
                    forb_opts_norm.setdefault(s, []).append(o)

        for sec, opts in forb_opts_norm.items():
            if sec in present_sections:
                for opt in opts:
                    if parser.has_option(sec, opt):
                        diagnostics.append({
                            "field": f"{sec}.{opt}",
                            "line": None,
                            "column": None,
                            "message": f"Forbidden option '{opt}' present in section [{sec}].",
                            "severity": "ERROR",
                        })

        # Check interpolation
        if check_interp and interp is not None:
            for sec in parser.sections():
                for opt in parser.options(sec):
                    try:
                        parser.get(sec, opt)
                    except configparser.InterpolationMissingOptionError as err:
                        diagnostics.append({
                            "field": f"{sec}.{opt}",
                            "line": None,
                            "column": None,
                            "message": (
                                f"Interpolation error in [{sec}] '{opt}': "
                                f"missing referenced option '{err.reference}'."
                            ),
                            "severity": "ERROR",
                        })
                    except configparser.InterpolationSyntaxError as err:
                        diagnostics.append({
                            "field": f"{sec}.{opt}",
                            "line": None,
                            "column": None,
                            "message": f"Interpolation syntax error in [{sec}] '{opt}': {err}.",
                            "severity": "ERROR",
                        })
                    except configparser.InterpolationDepthError:
                        diagnostics.append({
                            "field": f"{sec}.{opt}",
                            "line": None,
                            "column": None,
                            "message": f"Circular interpolation recursion detected in [{sec}] '{opt}'.",
                            "severity": "ERROR",
                        })
                    except configparser.InterpolationError as err:
                        diagnostics.append({
                            "field": f"{sec}.{opt}",
                            "line": None,
                            "column": None,
                            "message": f"Interpolation error in [{sec}] '{opt}': {err}.",
                            "severity": "ERROR",
                        })

    errors = [d["message"] for d in diagnostics if d["severity"] == "ERROR"]
    warnings = [d["message"] for d in diagnostics if d["severity"] == "WARNING"]
    is_valid = len(errors) == 0

    total_options = sum(len(parser.options(s)) for s in parser.sections()) if syntax_valid else 0

    data = {
        "valid": is_valid,
        "format": "ini",
        "errors": errors[:MAX_DIAGNOSTICS_RETURNED],
        "warnings": warnings[:MAX_DIAGNOSTICS_RETURNED],
        "errors_count": len(errors),
        "warnings_count": len(warnings),
        "diagnostics": diagnostics[:MAX_DIAGNOSTICS_RETURNED],
        "summary": (
            "INI validation passed cleanly."
            if is_valid
            else f"INI validation failed with {len(errors)} error(s) and {len(warnings)} warning(s)."
        ),
        "details": {
            "path": path,
            "syntax_valid": syntax_valid,
            "sections": parser.sections() if syntax_valid else [],
            "sections_count": len(parser.sections()) if syntax_valid else 0,
            "options_count": total_options,
            "interpolation_checked": check_interp and interp is not None,
        },
    }
    return _envelope_success(data)


# =============================================================================
# Action 3: validate_dotenv Implementation
# =============================================================================

def _parse_dotenv_lexical(
    text: str,
    strict_naming: bool,
    allow_duplicates: bool,
    diagnostics: list[dict[str, Any]],
) -> dict[str, str]:
    """Pure lexical line scanner for .env syntax and duplicate detection."""
    lines = text.splitlines()
    parsed_vars: dict[str, str] = {}
    seen_vars: dict[str, list[int]] = {}

    in_multiline: Optional[str] = None
    multiline_var: str = ""
    multiline_start_line: int = 0
    multiline_buffer: list[str] = []

    for lineno, line in enumerate(lines, 1):
        # 1. Inside multiline quote
        if in_multiline is not None:
            multiline_buffer.append(line)
            # Check for unescaped closing quote
            pos = 0
            closed = False
            while pos < len(line):
                idx = line.find(in_multiline, pos)
                if idx == -1:
                    break
                # Check escape
                if in_multiline == '"' and idx > 0 and line[idx - 1] == "\\":
                    pos = idx + 1
                    continue
                closed = True
                break
            if closed:
                parsed_vars[multiline_var] = "\n".join(multiline_buffer)
                in_multiline = None
            continue

        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Optional export prefix
        if stripped.startswith("export ") and len(stripped) > 7:
            stripped = stripped[7:].lstrip()

        # Check assignment delimiter
        if "=" not in stripped:
            diagnostics.append({
                "field": "<syntax>",
                "line": lineno,
                "column": None,
                "message": (
                    f"Syntax error at line {lineno}: line is not a comment and contains no '=' "
                    f"assignment delimiter (unquoted multiline values are prohibited)."
                ),
                "severity": "ERROR",
            })
            continue

        key_part, val_part = stripped.split("=", 1)
        key = key_part.strip()
        val = val_part.lstrip()

        if not key:
            diagnostics.append({
                "field": "<syntax>",
                "line": lineno,
                "column": None,
                "message": f"Syntax error at line {lineno}: missing variable name before '='.",
                "severity": "ERROR",
            })
            continue

        # Variable naming compliance
        if strict_naming and not DOTENV_VAR_NAME_RE.fullmatch(key):
            diagnostics.append({
                "field": key,
                "line": lineno,
                "column": None,
                "message": (
                    f"Invalid variable name '{key}' at line {lineno}: "
                    f"variable names must comply with '^[A-Za-z_][A-Za-z0-9_]*$'."
                ),
                "severity": "ERROR",
            })

        # Duplicate variable detection
        if key in seen_vars:
            prev_line = seen_vars[key][0]
            severity = "ERROR" if not allow_duplicates else "WARNING"
            diagnostics.append({
                "field": key,
                "line": lineno,
                "column": None,
                "message": f"Duplicate variable '{key}' declared at line {lineno} (previously declared at line {prev_line}).",
                "severity": severity,
            })
        seen_vars.setdefault(key, []).append(lineno)

        # Value and quote parsing
        if val.startswith("'"):
            if len(val) >= 2 and val.endswith("'"):
                parsed_vars[key] = val[1:-1]
            elif val.count("'") >= 2 and val[1:].find("'") != -1:
                end_idx = val[1:].find("'") + 1
                parsed_vars[key] = val[1:end_idx]
            else:
                in_multiline = "'"
                multiline_var = key
                multiline_start_line = lineno
                multiline_buffer = [val[1:]]
        elif val.startswith('"'):
            pos = 1
            closed_idx = -1
            while pos < len(val):
                idx = val.find('"', pos)
                if idx == -1:
                    break
                if val[idx - 1] == "\\":
                    pos = idx + 1
                    continue
                closed_idx = idx
                break
            if closed_idx != -1:
                parsed_vars[key] = val[1:closed_idx]
            else:
                in_multiline = '"'
                multiline_var = key
                multiline_start_line = lineno
                multiline_buffer = [val[1:]]
        else:
            comment_idx = val.find(" #")
            if comment_idx != -1:
                val = val[:comment_idx].rstrip()
            parsed_vars[key] = val

    if in_multiline is not None:
        diagnostics.append({
            "field": multiline_var,
            "line": multiline_start_line,
            "column": None,
            "message": f"Unclosed quote {in_multiline} starting at line {multiline_start_line} for variable '{multiline_var}'.",
            "severity": "ERROR",
        })

    return parsed_vars


def _do_validate_dotenv(arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute .env syntax validation, naming compliance, and template comparison."""
    text, path = _load_input(arguments)
    strict_naming = bool(arguments.get("strict_naming", True))
    allow_duplicates = bool(arguments.get("allow_duplicate_keys", False))
    required_vars = arguments.get("required_variables") or []
    tmpl_content = arguments.get("template_content")
    tmpl_path = arguments.get("template_path")

    diagnostics: list[dict[str, Any]] = []

    parsed_vars = _parse_dotenv_lexical(text, strict_naming, allow_duplicates, diagnostics)
    syntax_valid = not any(d["severity"] == "ERROR" and d["field"] == "<syntax>" for d in diagnostics)

    # Check required variables
    for req in required_vars:
        if req not in parsed_vars:
            diagnostics.append({
                "field": req,
                "line": None,
                "column": None,
                "message": f"Missing required environment variable: '{req}'.",
                "severity": "ERROR",
            })

    # Template comparison (e.g. against .env.example)
    missing_template_keys: list[str] = []
    placeholder_warnings: list[str] = []
    template_checked = False

    template_text = None
    if tmpl_content is not None:
        template_text = str(tmpl_content)
    elif tmpl_path is not None:
        resolved_tmpl = _validate_and_resolve_path(tmpl_path)
        template_text = resolved_tmpl.read_text(encoding="utf-8")

    if template_text is not None:
        template_checked = True
        tmpl_diag: list[dict[str, Any]] = []
        tmpl_vars = _parse_dotenv_lexical(template_text, strict_naming=False, allow_duplicates=True, diagnostics=tmpl_diag)

        for tvar in tmpl_vars.keys():
            if tvar not in parsed_vars:
                missing_template_keys.append(tvar)
                diagnostics.append({
                    "field": tvar,
                    "line": None,
                    "column": None,
                    "message": f"Missing template variable '{tvar}' required by .env template.",
                    "severity": "ERROR",
                })

    # Check for placeholder values
    for var_name, var_val in parsed_vars.items():
        if PLACEHOLDER_VAL_RE.search(var_val):
            placeholder_warnings.append(var_name)
            diagnostics.append({
                "field": var_name,
                "line": None,
                "column": None,
                "message": f"Variable '{var_name}' appears to retain placeholder value: {var_val!r}.",
                "severity": "WARNING",
            })

    errors = [d["message"] for d in diagnostics if d["severity"] == "ERROR"]
    warnings = [d["message"] for d in diagnostics if d["severity"] == "WARNING"]
    is_valid = len(errors) == 0

    data = {
        "valid": is_valid,
        "format": "dotenv",
        "errors": errors[:MAX_DIAGNOSTICS_RETURNED],
        "warnings": warnings[:MAX_DIAGNOSTICS_RETURNED],
        "errors_count": len(errors),
        "warnings_count": len(warnings),
        "diagnostics": diagnostics[:MAX_DIAGNOSTICS_RETURNED],
        "summary": (
            "Dotenv validation passed cleanly."
            if is_valid
            else f"Dotenv validation failed with {len(errors)} error(s) and {len(warnings)} warning(s)."
        ),
        "details": {
            "path": path,
            "syntax_valid": syntax_valid,
            "variables_count": len(parsed_vars),
            "variables": sorted(list(parsed_vars.keys())),
            "template_checked": template_checked,
            "missing_template_variables": missing_template_keys,
            "placeholder_warnings": placeholder_warnings,
        },
    }
    return _envelope_success(data)


# =============================================================================
# Action 4: lint_config Implementation
# =============================================================================

def _detect_format(content: str, path: Optional[str], format_hint: str) -> str:
    """Infer configuration format from hint, extension, or content heuristics."""
    if format_hint and format_hint != "auto":
        return format_hint.lower()

    if path:
        lower_p = path.lower()
        if lower_p.endswith(".json"):
            return "json"
        if lower_p.endswith((".ini", ".cfg")):
            return "ini"
        if lower_p.endswith(".env") or ".env." in lower_p:
            return "dotenv"
        if lower_p.endswith((".yaml", ".yml")):
            return "yaml"

    stripped = content.strip()
    if stripped.startswith("{") or (stripped.startswith("[") and stripped.endswith("]")):
        return "json"
    if stripped.startswith("[") and "]" in stripped.splitlines()[0]:
        return "ini"
    if "=" in stripped and "\n" in stripped:
        first_line = stripped.splitlines()[0].strip()
        if "=" in first_line and not first_line.startswith(("{", "<", "[")):
            return "dotenv"

    return "auto"


def _do_lint_config(arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute structural configuration linting across JSON, INI, Dotenv, and YAML."""
    text, path = _load_input(arguments)
    format_hint = str(arguments.get("format", "auto")).lower()
    indent_size = int(arguments.get("indent_size", 2))
    max_line_length = int(arguments.get("max_line_length", 120))
    is_strict = bool(arguments.get("strict", False))

    fmt = _detect_format(text, path, format_hint)
    diagnostics: list[dict[str, Any]] = []

    lines = text.splitlines(keepends=True)
    warn_severity = "ERROR" if is_strict else "WARNING"

    # Rule 1: Missing EOF newline
    if text and not text.endswith("\n"):
        diagnostics.append({
            "field": "missing_eof_newline",
            "line": len(lines),
            "column": None,
            "message": f"File is missing a trailing newline at end of file (line {len(lines)}).",
            "severity": warn_severity,
        })

    for lineno, line in enumerate(lines, 1):
        eol_stripped = line.rstrip("\r\n")

        # Rule 2: Trailing whitespace
        if eol_stripped.endswith((" ", "\t")):
            diagnostics.append({
                "field": "trailing_whitespace",
                "line": lineno,
                "column": len(eol_stripped),
                "message": f"Line {lineno} contains trailing whitespace.",
                "severity": warn_severity,
            })

        # Rule 3: Max line length
        if max_line_length > 0 and len(eol_stripped) > max_line_length:
            diagnostics.append({
                "field": "max_line_length",
                "line": lineno,
                "column": max_line_length + 1,
                "message": f"Line {lineno} length ({len(eol_stripped)}) exceeds limit of {max_line_length}.",
                "severity": warn_severity,
            })

        # Rule 4: Control characters and null bytes
        for col, ch in enumerate(eol_stripped, 1):
            if ch == "\0":
                diagnostics.append({
                    "field": "control_characters",
                    "line": lineno,
                    "column": col,
                    "message": f"Null byte character (\\x00) detected at line {lineno}, column {col}.",
                    "severity": "ERROR",
                })
            elif ord(ch) < 32 and ch not in ("\t", "\r", "\n"):
                diagnostics.append({
                    "field": "control_characters",
                    "line": lineno,
                    "column": col,
                    "message": f"Non-printable control character (ASCII {ord(ch)}) at line {lineno}, column {col}.",
                    "severity": "ERROR",
                })
            elif ord(ch) == 127:
                diagnostics.append({
                    "field": "control_characters",
                    "line": lineno,
                    "column": col,
                    "message": f"DEL control character (ASCII 127) at line {lineno}, column {col}.",
                    "severity": "ERROR",
                })

        # Rule 5: Indentation consistency
        leading = eol_stripped[:len(eol_stripped) - len(eol_stripped.lstrip())]
        if "\t" in leading and " " in leading:
            diagnostics.append({
                "field": "inconsistent_indentation",
                "line": lineno,
                "column": 1,
                "message": f"Line {lineno} has mixed tabs and spaces in indentation.",
                "severity": "ERROR",
            })
        elif fmt in ("json", "yaml") and indent_size > 0 and leading.startswith(" ") and "\t" not in leading:
            if len(leading) % indent_size != 0:
                diagnostics.append({
                    "field": "inconsistent_indentation",
                    "line": lineno,
                    "column": 1,
                    "message": (
                        f"Line {lineno} indentation ({len(leading)} spaces) is not a multiple "
                        f"of indent_size ({indent_size})."
                    ),
                    "severity": warn_severity,
                })

    # Rule 6: Format-specific duplicate key and syntax verification
    syntax_valid = True
    if fmt == "json":
        dup_keys: list[str] = []
        def _hook(pairs):
            seen = set()
            d = {}
            for k, v in pairs:
                if k in seen:
                    dup_keys.append(k)
                seen.add(k)
                d[k] = v
            return d
        try:
            json.loads(text, object_pairs_hook=_hook)
        except json.JSONDecodeError as err:
            syntax_valid = False
            diagnostics.append({
                "field": "syntax_verification",
                "line": err.lineno,
                "column": err.colno,
                "message": f"JSON syntax error: {err.msg}.",
                "severity": "ERROR",
            })
        for dup in dup_keys:
            diagnostics.append({
                "field": "duplicate_keys",
                "line": None,
                "column": None,
                "message": f"Duplicate key detected in JSON: '{dup}'.",
                "severity": "ERROR",
            })
    elif fmt == "ini":
        parser = configparser.ConfigParser(strict=True)
        try:
            parser.read_string(text)
        except configparser.DuplicateSectionError as err:
            diagnostics.append({
                "field": "duplicate_keys",
                "line": err.lineno,
                "column": None,
                "message": f"Duplicate section [{err.section}] in INI.",
                "severity": "ERROR",
            })
        except configparser.DuplicateOptionError as err:
            diagnostics.append({
                "field": "duplicate_keys",
                "line": err.lineno,
                "column": None,
                "message": f"Duplicate option '{err.option}' in section [{err.section}].",
                "severity": "ERROR",
            })
        except configparser.Error as err:
            syntax_valid = False
            diagnostics.append({
                "field": "syntax_verification",
                "line": None,
                "column": None,
                "message": f"INI syntax error: {err}.",
                "severity": "ERROR",
            })
    elif fmt == "dotenv":
        dot_diag: list[dict[str, Any]] = []
        _parse_dotenv_lexical(text, strict_naming=False, allow_duplicates=False, diagnostics=dot_diag)
        for d in dot_diag:
            diagnostics.append({
                "field": "duplicate_keys" if "Duplicate variable" in d["message"] else "syntax_verification",
                "line": d["line"],
                "column": d["column"],
                "message": d["message"],
                "severity": d["severity"],
            })

    errors = [d["message"] for d in diagnostics if d["severity"] == "ERROR"]
    warnings = [d["message"] for d in diagnostics if d["severity"] == "WARNING"]
    is_valid = len(errors) == 0

    data = {
        "valid": is_valid,
        "format": fmt,
        "errors": errors[:MAX_DIAGNOSTICS_RETURNED],
        "warnings": warnings[:MAX_DIAGNOSTICS_RETURNED],
        "errors_count": len(errors),
        "warnings_count": len(warnings),
        "diagnostics": diagnostics[:MAX_DIAGNOSTICS_RETURNED],
        "summary": (
            f"Linting passed cleanly ({len(lines)} lines)."
            if is_valid
            else f"Linting found {len(errors)} error(s) and {len(warnings)} warning(s) across {len(lines)} lines."
        ),
        "details": {
            "path": path,
            "detected_format": fmt,
            "lines_count": len(lines),
            "syntax_valid": syntax_valid,
            "strict_mode": is_strict,
            "rules_checked": [
                "trailing_whitespace",
                "missing_eof_newline",
                "inconsistent_indentation",
                "control_characters",
                "duplicate_keys",
                "max_line_length",
                "syntax_verification",
            ],
        },
    }
    return _envelope_success(data)


# =============================================================================
# Main Dispatch Handler & TOOL Declaration
# =============================================================================

def config_validator(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute safe configuration validation and structural linting for Jarvis."""
    try:
        if not isinstance(arguments, dict):
            return _envelope_error(ValueError("Arguments must be a dictionary."))

        # Enforce additionalProperties: False at handler boundary
        unknown_args = set(arguments.keys()) - KNOWN_ARGUMENTS
        if unknown_args:
            return _envelope_error(
                ValueError(f"Unknown argument(s) rejected: {', '.join(sorted(unknown_args))}")
            )

        action = arguments.get("action")
        if not action or action not in VALID_ACTIONS:
            return _envelope_error(
                ValueError(f"Invalid or missing action '{action}'. Valid actions: {sorted(VALID_ACTIONS)}")
            )

        if action == "validate_json":
            return _do_validate_json(arguments)
        elif action == "validate_ini":
            return _do_validate_ini(arguments)
        elif action == "validate_dotenv":
            return _do_validate_dotenv(arguments)
        elif action == "lint_config":
            return _do_lint_config(arguments)
        else:
            return _envelope_error(ValueError(f"Unhandled action '{action}'"))
    except Exception as exc:
        return _envelope_error(exc)


TOOL = {
    "name": "config_validator",
    "description": (
        "Zero-dependency configuration validation and structural linting for Jarvis. "
        "Validates JSON, INI/CFG, and .env files against syntax specifications, custom schemas, "
        "type rules, value ranges, and structural hygiene standards. Pure standard library with "
        "strict path confinement to ALLOWED_ROOTS (HOME, /tmp, /mnt, /media) and ReDoS defenses."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "validate_json",
                    "validate_ini",
                    "validate_dotenv",
                    "lint_config",
                ],
                "description": "Configuration validation or linting action to perform.",
            },
            "content": {
                "type": "string",
                "description": "Inline configuration text content to validate or lint.",
            },
            "text": {
                "type": "string",
                "description": "Alias for 'content'. Inline configuration text content.",
            },
            "path": {
                "type": "string",
                "description": (
                    "Filesystem path to configuration file. Must resolve within ALLOWED_ROOTS "
                    "(HOME, /tmp, /mnt, /media) and be under 5 MB."
                ),
            },
            "schema": {
                "type": "object",
                "description": (
                    "Schema specification dictionary for 'validate_json'. Supports type validation "
                    "(string, integer, number, boolean, array, object, null), required keys, enum, "
                    "forbidden keys, additionalProperties, regex patterns, min/max values and lengths."
                ),
            },
            "format": {
                "type": "string",
                "enum": ["json", "ini", "dotenv", "yaml", "auto"],
                "default": "auto",
                "description": "Configuration format for 'lint_config' (default: 'auto').",
            },
            "required_sections": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of required section names for 'validate_ini'.",
            },
            "required_options": {
                "type": "object",
                "description": (
                    "Dictionary mapping section name to list of required option names for 'validate_ini', "
                    "or list of 'section.option' strings."
                ),
            },
            "forbidden_sections": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of disallowed section names for 'validate_ini'.",
            },
            "forbidden_options": {
                "type": "object",
                "description": "Dictionary mapping section name to list of disallowed option names for 'validate_ini'.",
            },
            "check_interpolation": {
                "type": "boolean",
                "default": True,
                "description": "Whether to check interpolation validity for 'validate_ini' (default: true).",
            },
            "interpolation": {
                "type": "string",
                "enum": ["basic", "extended", "none"],
                "default": "basic",
                "description": "Interpolation mode for 'validate_ini' (default: 'basic').",
            },
            "required_variables": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of required variable names for 'validate_dotenv'.",
            },
            "template_path": {
                "type": "string",
                "description": "Path to template file (e.g. .env.example) for 'validate_dotenv'.",
            },
            "template_content": {
                "type": "string",
                "description": "Inline template content (e.g. .env.example) for 'validate_dotenv'.",
            },
            "strict_naming": {
                "type": "boolean",
                "default": True,
                "description": "Whether to enforce strict variable naming ^[A-Za-z_][A-Za-z0-9_]*$ in 'validate_dotenv' (default: true).",
            },
            "allow_duplicate_keys": {
                "type": "boolean",
                "default": False,
                "description": "Whether to permit duplicate keys in JSON objects, INI sections/options, or dotenv variables (default: false).",
            },
            "indent_size": {
                "type": "integer",
                "minimum": 1,
                "maximum": 8,
                "default": 2,
                "description": "Expected indentation step in spaces for 'lint_config' (default: 2).",
            },
            "max_line_length": {
                "type": "integer",
                "minimum": 0,
                "maximum": 1000,
                "default": 120,
                "description": "Maximum line length limit for 'lint_config' (default: 120, 0 to disable).",
            },
            "strict": {
                "type": "boolean",
                "default": False,
                "description": "If true, treat warnings as validation errors in 'lint_config' (default: false).",
            },
            "max_depth": {
                "type": "integer",
                "minimum": 1,
                "maximum": 100,
                "default": 50,
                "description": "Maximum recursion depth for nested JSON schema validation (default: 50).",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": config_validator,
    "approval": False,
}
