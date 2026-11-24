"""Zero-dependency JSON schema and envelope validator inspired by PydanticAI.

Strictly verifies dictionary structures against JSON schemas, checks type conformity,
validates required keys, enforces additionalProperties: False, validates standard 5-key envelopes,
and audits operator modules for system compliance. Exclusively uses the Python standard library.
"""

from __future__ import annotations

import importlib
import importlib.util
import re
import time
from pathlib import Path
from typing import Any

# Security perimeter: Allowed root directories
HOME = Path.home().resolve()
ALLOWED_ROOTS: tuple[Path, ...] = (
    HOME,
    Path("/tmp").resolve(),
    Path("/mnt").resolve(),
    Path("/media").resolve(),
)

VALID_ACTIONS: frozenset[str] = frozenset({
    "validate_envelope",
    "validate_schema",
    "audit_operator_module",
})

KNOWN_ARGUMENTS: frozenset[str] = frozenset({
    "action",
    "payload",
    "schema",
    "module_name",
    "enforce_5key_envelope",
})

MANDATORY_ENVELOPE_KEYS: frozenset[str] = frozenset({
    "ok",
    "success",
    "data",
    "result",
    "error",
})


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


def _validate_envelope_dict(payload: Any) -> tuple[bool, list[str]]:
    """Validate that payload strictly matches the standard 5-key Jarvis operator envelope."""
    errors: list[str] = []

    if not isinstance(payload, dict):
        return False, ["Payload must be a dictionary."]

    actual_keys = set(payload.keys())
    missing_keys = MANDATORY_ENVELOPE_KEYS - actual_keys
    if missing_keys:
        errors.append(f"Envelope missing required keys: {sorted(list(missing_keys))}")

    extra_keys = actual_keys - MANDATORY_ENVELOPE_KEYS
    if extra_keys:
        errors.append(f"Envelope contains unauthorized extra keys: {sorted(list(extra_keys))}")

    if "ok" in payload and not isinstance(payload["ok"], bool):
        errors.append(f"Field 'ok' must be boolean, got '{type(payload['ok']).__name__}'.")

    if "success" in payload and not isinstance(payload["success"], bool):
        errors.append(f"Field 'success' must be boolean, got '{type(payload['success']).__name__}'.")

    if "ok" in payload and "success" in payload and payload["ok"] != payload["success"]:
        errors.append(f"Fields 'ok' ({payload['ok']}) and 'success' ({payload['success']}) must be identical.")

    if payload.get("ok") is True:
        if payload.get("error") is not None:
            errors.append(f"Successful envelope must have error=None, got {payload.get('error')!r}.")
        if "data" in payload and "result" in payload and payload["data"] != payload["result"]:
            errors.append("Successful envelope must have data == result.")
    elif payload.get("ok") is False:
        err = payload.get("error")
        if not isinstance(err, str) or not err.strip():
            errors.append("Failed envelope must have a non-empty string in 'error'.")
        if payload.get("data") is not None or payload.get("result") is not None:
            errors.append("Failed envelope should have data=None and result=None.")

    return len(errors) == 0, errors


def _check_type(val: Any, expected_type: str) -> bool:
    """Check if value matches JSON schema type name."""
    if expected_type == "string":
        return isinstance(val, str)
    elif expected_type == "number":
        return isinstance(val, (int, float)) and not isinstance(val, bool)
    elif expected_type == "integer":
        return isinstance(val, int) and not isinstance(val, bool)
    elif expected_type == "boolean":
        return isinstance(val, bool)
    elif expected_type == "array":
        return isinstance(val, list)
    elif expected_type == "object":
        return isinstance(val, dict)
    elif expected_type == "null":
        return val is None
    return True


def _validate_json_schema(val: Any, schema: dict[str, Any], path: str = "root") -> tuple[bool, list[str], int]:
    """Recursively validate a value against a JSON schema specification."""
    errors: list[str] = []
    checks_count = 0

    if not isinstance(schema, dict):
        return True, [], 0

    # 1. Type check
    if "type" in schema:
        checks_count += 1
        t = schema["type"]
        if isinstance(t, str):
            if not _check_type(val, t):
                errors.append(f"TypeMismatch at '{path}': expected '{t}', got '{type(val).__name__}'")
                return False, errors, checks_count
        elif isinstance(t, list):
            if not any(_check_type(val, single_t) for single_t in t):
                errors.append(f"TypeMismatch at '{path}': expected one of {t}, got '{type(val).__name__}'")
                return False, errors, checks_count

    # 2. Enum check
    if "enum" in schema:
        checks_count += 1
        allowed_enum = schema["enum"]
        if val not in allowed_enum:
            errors.append(f"EnumViolation at '{path}': value {val!r} not in {allowed_enum}")

    # 3. String constraints
    if isinstance(val, str):
        if "minLength" in schema:
            checks_count += 1
            if len(val) < schema["minLength"]:
                errors.append(f"LengthViolation at '{path}': length {len(val)} < minLength {schema['minLength']}")
        if "maxLength" in schema:
            checks_count += 1
            if len(val) > schema["maxLength"]:
                errors.append(f"LengthViolation at '{path}': length {len(val)} > maxLength {schema['maxLength']}")
        if "pattern" in schema:
            checks_count += 1
            try:
                if not re.search(schema["pattern"], val):
                    errors.append(f"PatternViolation at '{path}': string does not match pattern '{schema['pattern']}'")
            except re.error as r_err:
                errors.append(f"SchemaError at '{path}': invalid regex pattern '{schema['pattern']}': {r_err}")

    # 4. Number constraints
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        if "minimum" in schema:
            checks_count += 1
            if val < schema["minimum"]:
                errors.append(f"RangeViolation at '{path}': value {val} < minimum {schema['minimum']}")
        if "maximum" in schema:
            checks_count += 1
            if val > schema["maximum"]:
                errors.append(f"RangeViolation at '{path}': value {val} > maximum {schema['maximum']}")

    # 5. Array constraints
    if isinstance(val, list):
        if "minItems" in schema:
            checks_count += 1
            if len(val) < schema["minItems"]:
                errors.append(f"ItemCountViolation at '{path}': count {len(val)} < minItems {schema['minItems']}")
        if "maxItems" in schema:
            checks_count += 1
            if len(val) > schema["maxItems"]:
                errors.append(f"ItemCountViolation at '{path}': count {len(val)} > maxItems {schema['maxItems']}")
        if "items" in schema and isinstance(schema["items"], dict):
            for idx, item in enumerate(val):
                _, item_errs, item_checks = _validate_json_schema(item, schema["items"], f"{path}[{idx}]")
                checks_count += item_checks
                errors.extend(item_errs)

    # 6. Object constraints
    if isinstance(val, dict):
        # Required properties
        if "required" in schema:
            checks_count += 1
            req_keys = schema["required"]
            for req in req_keys:
                if req not in val:
                    errors.append(f"RequiredFieldMissing at '{path}': field '{req}' is required.")

        properties = schema.get("properties", {})
        # Check additionalProperties
        if schema.get("additionalProperties") is False:
            checks_count += 1
            for k in val.keys():
                if k not in properties:
                    errors.append(f"AdditionalPropertyForbidden at '{path}': property '{k}' is not defined in schema.")

        # Validate defined properties
        for prop_name, prop_schema in properties.items():
            if prop_name in val:
                _, prop_errs, prop_checks = _validate_json_schema(val[prop_name], prop_schema, f"{path}.{prop_name}")
                checks_count += prop_checks
                errors.extend(prop_errs)

    return len(errors) == 0, errors, checks_count


def _audit_module(module_name: str) -> dict[str, Any]:
    """Audit an operator module for adherence to Jarvis operator architecture standards."""
    clean_name = module_name.strip()
    if clean_name.endswith(".py"):
        clean_name = clean_name[:-3]

    op_dir = Path(__file__).resolve().parent
    module_path = op_dir / f"{clean_name}.py"

    checks = {
        "module_file_exists": False,
        "module_imported": False,
        "has_tool_dict": False,
        "has_valid_name": False,
        "has_description": False,
        "has_additional_properties_false": False,
        "handler_callable": False,
        "error_envelope_compliant": False,
    }
    issues: list[str] = []

    if not module_path.is_file():
        issues.append(f"Module file not found: {module_path}")
        return {
            "module_name": clean_name,
            "compliant": False,
            "checks": checks,
            "issues": issues,
        }

    checks["module_file_exists"] = True

    try:
        mod_qual = f"jarvis_audit_{clean_name}_{time.time_ns()}"
        spec = importlib.util.spec_from_file_location(mod_qual, module_path)
        if not spec or not spec.loader:
            issues.append(f"Could not build import spec for {module_path}")
            return {"module_name": clean_name, "compliant": False, "checks": checks, "issues": issues}
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        checks["module_imported"] = True
    except Exception as exc:
        issues.append(f"Import failure: {type(exc).__name__}: {exc}")
        return {"module_name": clean_name, "compliant": False, "checks": checks, "issues": issues}

    tool = getattr(mod, "TOOL", None)
    if not isinstance(tool, dict):
        issues.append("Module does not export a 'TOOL' dictionary.")
        return {"module_name": clean_name, "compliant": False, "checks": checks, "issues": issues}
    checks["has_tool_dict"] = True

    tool_name = tool.get("name")
    if isinstance(tool_name, str) and re.fullmatch(r"^[a-zA-Z_][a-zA-Z0-9_]{0,63}$", tool_name):
        checks["has_valid_name"] = True
    else:
        issues.append(f"Invalid TOOL['name']: {tool_name!r}")

    desc = tool.get("description")
    if isinstance(desc, str) and desc.strip():
        checks["has_description"] = True
    else:
        issues.append("TOOL['description'] is missing or empty.")

    schema = tool.get("input_schema")
    if isinstance(schema, dict) and schema.get("type") == "object":
        if schema.get("additionalProperties") is False:
            checks["has_additional_properties_false"] = True
        else:
            issues.append("TOOL['input_schema'] must have 'additionalProperties: False'.")
    else:
        issues.append("TOOL['input_schema'] is not an object schema.")

    handler = tool.get("handler")
    if callable(handler):
        checks["handler_callable"] = True
    else:
        issues.append("TOOL['handler'] is not callable.")

    # Test error envelope behavior
    if callable(handler):
        try:
            # Pass invalid argument to trigger error envelope
            err_res = handler({"action": f"__audit_invalid_{time.time_ns()}__"})
            is_env_valid, env_errs = _validate_envelope_dict(err_res)
            if is_env_valid and err_res.get("ok") is False:
                checks["error_envelope_compliant"] = True
            else:
                issues.append(f"Handler did not return valid 5-key error envelope: {env_errs}")
        except Exception as exc:
            issues.append(f"Calling handler with invalid action raised unhandled exception: {exc}")

    compliant = all(checks.values())
    return {
        "module_name": clean_name,
        "compliant": compliant,
        "checks": checks,
        "issues": issues,
        "tool_metadata": {
            "name": tool.get("name"),
            "approval": bool(tool.get("approval", False)),
        },
    }


def contract_validator(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute contract validator actions."""
    if not isinstance(arguments, dict):
        return _envelope_error(ValueError("Arguments must be a dictionary."))

    for key in arguments:
        if key not in KNOWN_ARGUMENTS:
            return _envelope_error(ValueError(f"Unknown argument '{key}' or schema violation"))

    action = arguments.get("action")
    if not action or not isinstance(action, str):
        return _envelope_error(ValueError("Missing required parameter 'action'"))

    if action not in VALID_ACTIONS:
        return _envelope_error(ValueError(f"Invalid or unsupported action '{action}'"))

    try:
        if action == "validate_envelope":
            payload = arguments.get("payload")
            is_valid, errors = _validate_envelope_dict(payload)
            return _envelope_success({
                "valid": is_valid,
                "errors": errors,
                "checked_keys": sorted(list(payload.keys())) if isinstance(payload, dict) else [],
            })

        elif action == "validate_schema":
            payload = arguments.get("payload")
            schema = arguments.get("schema")
            if not isinstance(schema, dict):
                raise ValueError("Parameter 'schema' must be a dictionary.")

            is_valid, errors, checked_count = _validate_json_schema(payload, schema)

            # If enforce_5key_envelope requested
            if arguments.get("enforce_5key_envelope") and is_valid:
                env_valid, env_errors = _validate_envelope_dict(payload)
                if not env_valid:
                    is_valid = False
                    errors.extend(env_errors)

            return _envelope_success({
                "valid": is_valid,
                "errors": errors,
                "fields_validated": checked_count,
            })

        elif action == "audit_operator_module":
            module_name = arguments.get("module_name")
            if not module_name or not isinstance(module_name, str):
                raise ValueError("Parameter 'module_name' must be a non-empty string.")

            audit_result = _audit_module(module_name)
            return _envelope_success(audit_result)

        else:
            return _envelope_error(ValueError(f"Unhandled action '{action}'"))
    except Exception as exc:
        return _envelope_error(exc)


TOOL = {
    "name": "contract_validator",
    "description": (
        "Zero-dependency JSON schema validator, 5-key envelope guard, and operator module auditor "
        "inspired by PydanticAI. Verifies dictionary structures against schemas, checks type conformity, "
        "validates required keys, enforces additionalProperties: False, and audits operator compliance."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["validate_envelope", "validate_schema", "audit_operator_module"],
                "description": "Validation action to perform.",
            },
            "payload": {
                "description": "Data payload or envelope dictionary to validate.",
            },
            "schema": {
                "type": "object",
                "description": "JSON schema definition against which payload is validated.",
            },
            "module_name": {
                "type": "string",
                "description": "Name or filename of operator module to audit (e.g. 'op_state_graph').",
            },
            "enforce_5key_envelope": {
                "type": "boolean",
                "description": "Whether to also enforce standard 5-key envelope requirements.",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": contract_validator,
    "approval": False,
}
