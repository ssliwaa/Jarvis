"""Zero-dependency JSON Schema Validation, Self-Healing Repair & Regex FSM Structured Decoding Guard.

Synthesizes architectural patterns from:
- Instructor (#20): Schema-driven tool validation, compiler-style self-correction prompts, repair loop instructions.
- Outlines (#21): Regex-constrained structured generation, prefix conformance checking, token boundary validation.
- Guidance (#22): Structural constraint enforcement, deterministic key/type checks, operator schema auditing.

Exclusively uses the Python standard library. Zero external dependencies.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
from pathlib import Path
from typing import Any

try:
    from atomic_io import atomic_write_text
except ImportError:  # standalone copy: reach the repo root next to operator_modules/
    import sys
    _repo_root = str(Path(__file__).resolve().parents[1])
    if _repo_root not in sys.path:
        sys.path.insert(0, _repo_root)
    from atomic_io import atomic_write_text

# Security perimeter: Allowed root directories
HOME = Path.home().resolve()
ALLOWED_ROOTS: tuple[Path, ...] = (
    HOME,
    Path("/tmp").resolve(),
    Path("/mnt").resolve(),
    Path("/media").resolve(),
)

SENSITIVE_NAMES: frozenset[str] = frozenset({
    ".ssh",
    ".gnupg",
    ".password-store",
    ".hermes",
    ".aws",
    ".docker",
    ".kube",
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".xprofile",
    ".gitconfig",
    "config.json",
    "secrets.json",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
})

VALID_ACTIONS: frozenset[str] = frozenset({
    "validate_json",
    "repair_json",
    "enforce_regex",
    "generate_repair_prompt",
    "audit_schema",
})

KNOWN_ARGUMENTS: frozenset[str] = frozenset({
    "action",
    "json_text",
    "payload",
    "schema",
    "regex_pattern",
    "module_path",
    "export_path",
})


class SchemaGuardError(Exception):
    """Base exception for schema_guard."""


class PathSecurityError(SchemaGuardError):
    """Raised when module_path or export_path resolves outside ALLOWED_ROOTS."""


class SensitivePathError(SchemaGuardError):
    """Raised when access to sensitive paths is restricted."""


def _envelope_success(data: Any) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator success envelope."""
    return {"ok": True, "success": True, "data": data, "result": data, "error": None}


def _envelope_error(error: str | Exception) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator error envelope."""
    if isinstance(error, Exception):
        msg = f"{type(error).__name__}: {error}"
    else:
        msg = str(error)
    return {"ok": False, "success": False, "data": None, "result": None, "error": msg}


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
    """Check if any path component touches sensitive credential or configuration directories."""
    parts = [p.casefold() for p in path.parts]
    for part in parts:
        if part in SENSITIVE_NAMES:
            return True
        if part == ".env" or (part.startswith(".env.") and len(part) > 5):
            return True
    return False


def _validate_path(raw_path: Any) -> Path:
    """Validate and canonically resolve target path within ALLOWED_ROOTS."""
    if not isinstance(raw_path, (str, Path)):
        raise ValueError("File path must be a valid string or Path.")
    path_str = str(raw_path).strip()
    if not path_str:
        raise ValueError("File path cannot be empty.")
    if len(path_str) > 4096 or "\x00" in path_str:
        raise ValueError("Invalid path string: exceeds length limit or contains null bytes.")
    p = Path(path_str).expanduser()
    if not p.is_absolute():
        p = Path.cwd() / p

    try:
        resolved = Path(os.path.realpath(str(p)))
    except (OSError, ValueError) as err:
        raise ValueError(f"Path resolution error: {err}") from err

    if not _is_inside_allowed_roots(resolved):
        raise PathSecurityError(
            f"Target path '{p}' resolves to '{resolved}', which is outside "
            "allowed roots (HOME, /tmp, /mnt, /media)."
        )

    if _is_sensitive_path(resolved):
        raise SensitivePathError(f"Access to sensitive path '{resolved}' is restricted.")

    return resolved


def _validate_data_against_schema(
    data: Any, schema: dict[str, Any], path: str = "root"
) -> tuple[list[str], list[str], list[str], list[dict[str, Any]]]:
    """Pure-Python recursive schema validator enforcing types, required, and additionalProperties: False.

    Returns: (all_errors, missing_required, disallowed_keys, type_mismatches)
    """
    errors: list[str] = []
    missing_required: list[str] = []
    disallowed_keys: list[str] = []
    type_mismatches: list[dict[str, Any]] = []

    if not isinstance(schema, dict):
        return errors, missing_required, disallowed_keys, type_mismatches

    expected_type = schema.get("type")
    type_map = {
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "array": list,
        "object": dict,
        "null": type(None),
    }

    if expected_type and expected_type in type_map:
        expected_cls = type_map[expected_type]
        # In Python bool is a subclass of int (isinstance(True, int) is True).
        # We must explicitly distinguish integer from boolean.
        if expected_type == "integer" and isinstance(data, bool):
            err = f"At '{path}': expected integer, got boolean ({data})"
            errors.append(err)
            type_mismatches.append({"path": path, "expected": "integer", "got": "boolean", "value": data})
            return errors, missing_required, disallowed_keys, type_mismatches
        elif not isinstance(data, expected_cls):
            err = f"At '{path}': expected {expected_type}, got {type(data).__name__}"
            errors.append(err)
            type_mismatches.append({"path": path, "expected": expected_type, "got": type(data).__name__, "value": data})
            return errors, missing_required, disallowed_keys, type_mismatches

    # Numeric constraints
    if isinstance(data, (int, float)) and not isinstance(data, bool):
        if "minimum" in schema and data < schema["minimum"]:
            errors.append(f"At '{path}': {data} is less than minimum {schema['minimum']}")
        if "maximum" in schema and data > schema["maximum"]:
            errors.append(f"At '{path}': {data} is greater than maximum {schema['maximum']}")

    # String constraints
    if isinstance(data, str):
        if "minLength" in schema and len(data) < schema["minLength"]:
            errors.append(f"At '{path}': length {len(data)} is less than minLength {schema['minLength']}")
        if "maxLength" in schema and len(data) > schema["maxLength"]:
            errors.append(f"At '{path}': length {len(data)} exceeds maxLength {schema['maxLength']}")
        if "pattern" in schema:
            try:
                if not re.search(schema["pattern"], data):
                    errors.append(f"At '{path}': '{data}' does not match pattern r'{schema['pattern']}'")
            except re.error as re_err:
                errors.append(f"At '{path}': invalid schema regex pattern: {re_err}")
        if "enum" in schema and data not in schema["enum"]:
            errors.append(f"At '{path}': '{data}' is not in allowed enum {schema['enum']}")

    # Array constraints
    if isinstance(data, list) and expected_type == "array":
        item_schema = schema.get("items")
        if item_schema and isinstance(item_schema, dict):
            for i, elem in enumerate(data):
                sub_errs, sub_miss, sub_dis, sub_tm = _validate_data_against_schema(
                    elem, item_schema, f"{path}[{i}]"
                )
                errors.extend(sub_errs)
                missing_required.extend(sub_miss)
                disallowed_keys.extend(sub_dis)
                type_mismatches.extend(sub_tm)

    # Object constraints
    if isinstance(data, dict) and expected_type == "object":
        required = schema.get("required", [])
        for req in required:
            if req not in data:
                err = f"At '{path}': missing required property '{req}'"
                errors.append(err)
                missing_required.append(f"{path}.{req}" if path != "root" else req)

        properties = schema.get("properties", {})
        additional_allowed = schema.get("additionalProperties", True)

        for key, value in data.items():
            sub_path = f"{path}.{key}" if path != "root" else key
            if key in properties:
                sub_errs, sub_miss, sub_dis, sub_tm = _validate_data_against_schema(
                    value, properties[key], sub_path
                )
                errors.extend(sub_errs)
                missing_required.extend(sub_miss)
                disallowed_keys.extend(sub_dis)
                type_mismatches.extend(sub_tm)
            elif additional_allowed is False:
                err = f"At '{path}': disallowed additional property '{key}' (additionalProperties is False)"
                errors.append(err)
                disallowed_keys.append(sub_path)

    return errors, missing_required, disallowed_keys, type_mismatches


def _validate_json(args: dict[str, Any]) -> dict[str, Any]:
    """Validate JSON text or parsed payload against a JSON schema."""
    raw_text = args.get("json_text") or args.get("payload")
    schema = args.get("schema")

    if raw_text is None:
        raise SchemaGuardError("Missing required parameter 'json_text' or 'payload'.")

    parsed_data = None
    if isinstance(raw_text, (dict, list)):
        parsed_data = raw_text
    elif isinstance(raw_text, str):
        try:
            parsed_data = json.loads(raw_text)
        except json.JSONDecodeError as jde:
            return {
                "valid": False,
                "syntax_error": f"JSONDecodeError at line {jde.lineno}, col {jde.colno}: {jde.msg}",
                "errors": [f"JSON syntax error: {jde.msg} (pos {jde.pos})"],
                "parsed_data": None,
                "missing_required": [],
                "disallowed_extra_keys": [],
                "type_mismatches": [],
            }
    else:
        raise SchemaGuardError("Payload must be a JSON string, object, or array.")

    if not schema:
        # Syntax check only
        return {
            "valid": True,
            "syntax_error": None,
            "errors": [],
            "parsed_data": parsed_data,
            "missing_required": [],
            "disallowed_extra_keys": [],
            "type_mismatches": [],
        }

    errs, missing, disallowed, mismatches = _validate_data_against_schema(parsed_data, schema)
    return {
        "valid": len(errs) == 0,
        "syntax_error": None,
        "errors": errs,
        "parsed_data": parsed_data,
        "missing_required": missing,
        "disallowed_extra_keys": disallowed,
        "type_mismatches": mismatches,
    }


def _repair_json(args: dict[str, Any]) -> dict[str, Any]:
    """Heuristically repair common LLM syntax errors and strip schema-disallowed properties."""
    raw_text = args.get("json_text") or args.get("payload")
    schema = args.get("schema")

    if not isinstance(raw_text, str):
        if isinstance(raw_text, (dict, list)):
            data = raw_text
            raw_text = json.dumps(data)
        else:
            raise SchemaGuardError("Parameter 'json_text' must be a string.")

    applied_fixes = []
    text = raw_text.strip()

    # 1. Strip markdown fences ```json ... ``` or ``` ... ```
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*\n?", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\n?```\s*$", "", text)
        text = text.strip()
        applied_fixes.append("Stripped markdown code fences (```json ... ```)")

    # 2. Extract JSON object or array if surrounded by preamble/postamble
    if not (text.startswith("{") or text.startswith("[")):
        obj_match = re.search(r"(\{.*\}|\[.*\])", text, re.DOTALL)
        if obj_match:
            text = obj_match.group(1).strip()
            applied_fixes.append("Extracted embedded JSON object/array from conversational text")

    # 3. Strip trailing commas before closing braces/brackets
    cleaned = re.sub(r",\s*([}\]])", r"\1", text)
    if cleaned != text:
        text = cleaned
        applied_fixes.append("Removed trailing commas before closing braces/brackets")

    # 4. Replace single quotes around keys and string values with double quotes
    # Match 'key': or: 'value' (handling simple unquoted/escaped single quotes)
    sq_cleaned = re.sub(r"(?<=[\{\s,])\'([A-Za-z0-9_]+)\'\s*:", r'"\1":', text)
    sq_cleaned = re.sub(r":\s*\'([^\']*?)\'", r': "\1"', sq_cleaned)
    if sq_cleaned != text:
        text = sq_cleaned
        applied_fixes.append("Normalized single quotes to standard JSON double quotes")

    # Try parsing
    parsed = None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        # Secondary fallback: replace unquoted keys with quoted keys
        unquoted_key_fixed = re.sub(r"([{,]\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:", r'\1"\2":', text)
        try:
            parsed = json.loads(unquoted_key_fixed)
            text = unquoted_key_fixed
            applied_fixes.append("Quoted unquoted object keys")
        except json.JSONDecodeError as err:
            return {
                "repaired": False,
                "repaired_text": text,
                "parsed_data": None,
                "error": f"Failed to repair JSON syntax: {err}",
                "applied_fixes": applied_fixes,
                "repair_instruction": (
                    f"Invalid JSON syntax near character {err.pos}: {err.msg}. "
                    "Ensure all strings and keys use double quotes, trailing commas are removed, "
                    "and the output contains ONLY valid JSON without conversational preamble."
                ),
            }

    # If schema provided and parsed is a dict, apply structural repairs
    if schema and isinstance(parsed, dict):
        properties = schema.get("properties", {})
        additional_allowed = schema.get("additionalProperties", True)
        if additional_allowed is False:
            disallowed = [k for k in parsed.keys() if k not in properties]
            for dis in disallowed:
                del parsed[dis]
                applied_fixes.append(f"Pruned disallowed additional property '{dis}'")

        # Check missing required and optionally populate defaults if declared
        for req in schema.get("required", []):
            if req not in parsed:
                prop_spec = properties.get(req, {})
                if "default" in prop_spec:
                    parsed[req] = prop_spec["default"]
                    applied_fixes.append(f"Inserted declared default for required property '{req}'")

        text = json.dumps(parsed, indent=2)

    # Generate repair prompt feedback for LLM retry loop
    repair_instruction = ""
    if schema and parsed is not None:
        errs, missing, disallowed, mismatches = _validate_data_against_schema(parsed, schema)
        if errs:
            repair_instruction = (
                f"Your JSON output failed schema validation with errors: {errs}. "
                f"Missing required fields: {missing}. Disallowed keys: {disallowed}. "
                "Please output ONLY corrected JSON strictly adhering to schema."
            )
        else:
            repair_instruction = "JSON output is now valid and conforms to schema."

    return {
        "repaired": True,
        "repaired_text": text,
        "parsed_data": parsed,
        "applied_fixes": applied_fixes,
        "repair_instruction": repair_instruction,
    }


def _enforce_regex(args: dict[str, Any]) -> dict[str, Any]:
    """Test candidate text against a regular expression pattern and check prefix conformance."""
    candidate = str(args.get("payload") or args.get("json_text") or "")
    pattern_str = args.get("regex_pattern")
    if not pattern_str:
        raise SchemaGuardError("Missing required parameter 'regex_pattern'.")

    try:
        compiled = re.compile(pattern_str)
    except re.error as re_err:
        raise SchemaGuardError(f"Invalid regex_pattern '{pattern_str}': {re_err}")

    # Full match test
    full_match = bool(compiled.fullmatch(candidate))

    # Search match test
    search_match = bool(compiled.search(candidate))

    # Prefix conformance check (simulating FSM token generation validation)
    # A candidate is a valid prefix if extending it could potentially match the pattern.
    is_valid_prefix = False
    if full_match or not candidate:
        is_valid_prefix = True
    else:
        clean_p = pattern_str.lstrip("^").rstrip("$")
        relaxed_p = re.sub(r"\{(\d+)\}", r"{1,\1}", clean_p)
        for p_variant in (clean_p, relaxed_p):
            for end_idx in range(len(p_variant), 0, -1):
                sub_pattern = "^" + p_variant[:end_idx] + "$"
                try:
                    if re.fullmatch(sub_pattern, candidate):
                        is_valid_prefix = True
                        break
                except re.error:
                    continue
            if is_valid_prefix:
                break
        if not is_valid_prefix and search_match:
            is_valid_prefix = True

    return {
        "candidate": candidate,
        "pattern": pattern_str,
        "full_match": full_match,
        "search_match": search_match,
        "is_valid_prefix": is_valid_prefix,
        "matched_length": len(candidate) if full_match else (len(compiled.search(candidate).group(0)) if search_match else 0),
    }


def _generate_repair_prompt(args: dict[str, Any]) -> dict[str, Any]:
    """Generate deterministic, actionable error feedback instructing the model how to correct JSON."""
    raw_text = str(args.get("json_text") or args.get("payload") or "")
    schema = args.get("schema")

    if not schema or not isinstance(schema, dict):
        raise SchemaGuardError("Parameter 'schema' dictionary is required for generate_repair_prompt.")

    val_res = _validate_json({"json_text": raw_text, "schema": schema})

    if val_res["valid"]:
        prompt = "The provided JSON payload is already fully valid according to the target schema."
    elif val_res.get("syntax_error"):
        prompt = (
            f"Your output could not be parsed as JSON: {val_res['syntax_error']}. "
            "Please regenerate your response outputting ONLY a syntactically valid JSON object. "
            "Ensure all strings are enclosed in double quotes, keys are quoted, and no trailing commas exist."
        )
    else:
        instructions = []
        if val_res["missing_required"]:
            instructions.append(f"Supply the following missing required fields: {val_res['missing_required']}")
        if val_res["disallowed_extra_keys"]:
            instructions.append(f"Remove the following unrecognized extra keys: {val_res['disallowed_extra_keys']}")
        if val_res["type_mismatches"]:
            for tm in val_res["type_mismatches"]:
                instructions.append(f"Field '{tm['path']}' must be of type '{tm['expected']}', got '{tm['got']}'")

        instructions_str = "; ".join(instructions)
        prompt = (
            f"Your output violated the schema contract: {instructions_str}. "
            f"Target Schema properties: {list(schema.get('properties', {}).keys())}. "
            "Please output the corrected JSON object strictly satisfying all schema requirements."
        )

    return {
        "is_valid": val_res["valid"],
        "validation_errors": val_res.get("errors", []),
        "repair_prompt": prompt,
    }


def _audit_schema(args: dict[str, Any]) -> dict[str, Any]:
    """Audit an operator schema or operator module file for compliance with Jarvis standards."""
    target_schema = args.get("schema")
    module_path_raw = args.get("module_path")

    if module_path_raw:
        resolved_path = _validate_path(module_path_raw)
        if not resolved_path.is_file() or resolved_path.suffix != ".py":
            raise SchemaGuardError(f"Module path '{resolved_path}' is not an existing Python file.")

        # Dynamically inspect module for TOOL dict
        mod_name = f"audit_target_{abs(hash(str(resolved_path)))}"
        spec = importlib.util.spec_from_file_location(mod_name, resolved_path)
        if not spec or not spec.loader:
            raise SchemaGuardError(f"Cannot load module spec for {resolved_path}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        tool = getattr(mod, "TOOL", None)
        if not isinstance(tool, dict):
            raise SchemaGuardError(f"Module '{resolved_path.name}' does not export a TOOL dictionary.")
        target_schema = tool.get("input_schema")
        tool_name = tool.get("name")
        has_approval = "approval" in tool
        handler_callable = callable(tool.get("handler"))
    else:
        tool_name = None
        has_approval = True
        handler_callable = True

    if not isinstance(target_schema, dict):
        raise SchemaGuardError("Target schema must be a dictionary.")

    findings = []
    compliant = True

    # Standard 1: type == object
    if target_schema.get("type") != "object":
        findings.append("Schema 'type' must be 'object'.")
        compliant = False

    # Standard 2: additionalProperties must be explicitly False
    if target_schema.get("additionalProperties") is not False:
        findings.append("Schema 'additionalProperties' must be explicitly False.")
        compliant = False

    # Standard 3: action must be in properties and required
    props = target_schema.get("properties", {})
    required = target_schema.get("required", [])
    if "action" not in props:
        findings.append("Property 'action' must be defined in schema 'properties'.")
        compliant = False
    if "action" not in required:
        findings.append("Property 'action' must be listed in schema 'required'.")
        compliant = False

    # Standard 4: check types of properties
    valid_types = {"string", "integer", "number", "boolean", "array", "object", "null"}
    for p_name, p_spec in props.items():
        if isinstance(p_spec, dict):
            ptype = p_spec.get("type")
            if ptype and ptype not in valid_types:
                findings.append(f"Property '{p_name}' has unrecognized type '{ptype}'.")
                compliant = False
            if not p_spec.get("description"):
                findings.append(f"Property '{p_name}' is missing a 'description'.")

    return {
        "compliant": compliant,
        "tool_name": tool_name,
        "has_approval_gate": has_approval,
        "has_callable_handler": handler_callable,
        "findings_count": len(findings),
        "findings": findings,
        "schema_audited": target_schema,
    }


def schema_guard(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Main dispatch handler for schema_guard operator tool."""
    if not isinstance(arguments, dict):
        return _envelope_error("Arguments must be a JSON dictionary.")

    extra_keys = set(arguments.keys()) - KNOWN_ARGUMENTS
    if extra_keys:
        return _envelope_error(f"Disallowed additional arguments: {sorted(extra_keys)}")

    action = arguments.get("action")
    if not action or action not in VALID_ACTIONS:
        return _envelope_error(
            f"Invalid or missing action '{action}'. Valid actions: {sorted(VALID_ACTIONS)}"
        )

    try:
        if action == "validate_json":
            res = _validate_json(arguments)
        elif action == "repair_json":
            res = _repair_json(arguments)
        elif action == "enforce_regex":
            res = _enforce_regex(arguments)
        elif action == "generate_repair_prompt":
            res = _generate_repair_prompt(arguments)
        elif action == "audit_schema":
            res = _audit_schema(arguments)
        else:
            return _envelope_error(f"Unhandled action '{action}'.")

        export_path = arguments.get("export_path")
        if export_path:
            resolved = _validate_path(export_path)
            resolved.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(resolved, json.dumps(res, indent=2), dir_mode=None)
            res["exported_to"] = str(resolved)

        return _envelope_success(res)
    except SchemaGuardError as sge:
        return _envelope_error(sge)
    except (ValueError, TypeError) as err:
        return _envelope_error(err)
    except Exception as exc:
        return _envelope_error(exc)


TOOL = {
    "name": "schema_guard",
    "description": (
        "Zero-dependency JSON Schema validator, self-healing repair prompt generator, "
        "regular expression FSM prefix checker, and operator module schema auditor."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "validate_json",
                    "repair_json",
                    "enforce_regex",
                    "generate_repair_prompt",
                    "audit_schema",
                ],
                "description": "Validation or repair action to execute.",
            },
            "json_text": {
                "type": "string",
                "description": "Raw JSON string or candidate data to validate or repair.",
            },
            "payload": {
                "type": "string",
                "description": "Alias for json_text.",
            },
            "schema": {
                "type": "object",
                "description": "JSON Schema specification dictionary.",
            },
            "regex_pattern": {
                "type": "string",
                "description": "Regular expression pattern for enforce_regex.",
            },
            "module_path": {
                "type": "string",
                "description": "File path to Python operator module to audit for schema compliance.",
            },
            "export_path": {
                "type": "string",
                "description": "Optional file path within ALLOWED_ROOTS to export report JSON.",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": schema_guard,
    "approval": False,
}
