"""Pure in-memory structured data transformation, query, and validation module for Jarvis."""

from __future__ import annotations

import csv
import io
import json
import re
from typing import Any

# Optional PyYAML support with clean fallback
try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

MAX_INPUT_BYTES = 5 * 1024 * 1024  # 5 MB


def _safe_query(data: Any, path: str) -> Any:
    """Evaluate path expression like 'foo.bar[0].baz' without eval."""
    tokens = re.findall(r"[^.\[\]]+|\[\d+\]|\[\*\]", path)
    current = data
    for token in tokens:
        if current is None:
            return None
        if token == "[*]":
            if isinstance(current, list):
                return current
            return None
        if token.startswith("[") and token.endswith("]"):
            try:
                idx = int(token[1:-1])
            except ValueError:
                return None
            if isinstance(current, list) and 0 <= idx < len(current):
                current = current[idx]
            else:
                return None
        elif isinstance(current, list) and token.isdigit():
            idx = int(token)
            if 0 <= idx < len(current):
                current = current[idx]
            else:
                return None
        else:
            if isinstance(current, dict) and token in current:
                current = current[token]
            else:
                return None
    return current


def _validate_schema(data: Any, schema: dict[str, Any]) -> tuple[bool, list[str]]:
    """Verify data compliance with basic JSON schema constraints."""
    errors: list[str] = []
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

    if expected_type in type_map:
        py_type = type_map[expected_type]
        # In Python bool is a subclass of int; prevent bool from matching int/number
        if expected_type in ("integer", "number") and isinstance(data, bool):
            errors.append(f"Expected {expected_type}, got boolean.")
        elif not isinstance(data, py_type):
            errors.append(f"Expected {expected_type}, got {type(data).__name__}.")

    if isinstance(data, dict):
        required = schema.get("required", [])
        if isinstance(required, (list, tuple, set)):
            for req in required:
                if isinstance(req, str):
                    if req not in data:
                        errors.append(f"Missing required property: {req!r}.")
                else:
                    errors.append(f"Schema 'required' items must be strings, got {type(req).__name__}.")
        else:
            errors.append("Schema 'required' property must be a list/iterable.")

        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for prop, prop_schema in properties.items():
                if prop in data and isinstance(prop_schema, dict):
                    sub_valid, sub_errors = _validate_schema(data[prop], prop_schema)
                    for err in sub_errors:
                        errors.append(f"{prop}.{err}")
        else:
            errors.append("Schema 'properties' must be a dictionary.")

    elif isinstance(data, list) and "items" in schema and isinstance(schema["items"], dict):
        for idx, item in enumerate(data[:100]):  # check up to first 100 items
            sub_valid, sub_errors = _validate_schema(item, schema["items"])
            for err in sub_errors:
                errors.append(f"[{idx}].{err}")

    return len(errors) == 0, errors


def _data_transform_impl(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute pure in-memory structured data transformations, path queries, and schema validation.

    Parameters in arguments:
        action (str): 'query', 'convert', 'validate', 'summarize', or 'filter'.
        data (str | dict | list): Input payload to transform.
        path (str, optional): Dot/bracket query path for action='query' (e.g. 'users[0].name').
        from_format (str, optional): Source format ('json', 'csv', 'tsv', 'ndjson', 'yaml').
        to_format (str, optional): Target format for conversion ('json', 'csv', 'ndjson', 'yaml').
        schema (dict, optional): Schema dictionary for action='validate'.
        filter_expr (dict, optional): Filter criteria {'field': str, 'op': str, 'value': Any} for action='filter'.
        limit (int, optional): Maximum items to return (default: 100, max: 1000).
    """
    args = arguments if isinstance(arguments, dict) else {}
    action = str(args.get("action") or "query").strip().lower()

    if "data" not in args or args["data"] is None:
        return {
            "ok": False,
            "success": False,
            "data": None,
            "result": None,
            "error": "Parameter 'data' is required.",
        }

    raw_data = args["data"]
    parsed_data = raw_data

    # Parse string input if needed
    if isinstance(raw_data, str):
        if len(raw_data.encode("utf-8")) > MAX_INPUT_BYTES:
            return {
                "ok": False,
                "success": False,
                "data": None,
                "result": None,
                "error": f"Input data exceeds maximum allowed size ({MAX_INPUT_BYTES} bytes).",
            }

        from_format = str(args.get("from_format") or "json").strip().lower()
        if from_format == "json":
            try:
                parsed_data = json.loads(raw_data)
            except Exception as err:
                return {
                    "ok": False,
                    "success": False,
                    "data": None,
                    "result": None,
                    "error": f"Invalid JSON string: {err}",
                }
        elif from_format in ("csv", "tsv"):
            delimiter = "\t" if from_format == "tsv" else ","
            try:
                reader = csv.DictReader(io.StringIO(raw_data), delimiter=delimiter)
                parsed_data = list(reader)
            except Exception as err:
                return {
                    "ok": False,
                    "success": False,
                    "data": None,
                    "result": None,
                    "error": f"Invalid CSV/TSV string: {err}",
                }
        elif from_format == "ndjson":
            try:
                parsed_data = [json.loads(line) for line in raw_data.splitlines() if line.strip()]
            except Exception as err:
                return {
                    "ok": False,
                    "success": False,
                    "data": None,
                    "result": None,
                    "error": f"Invalid NDJSON string: {err}",
                }
        elif from_format == "yaml":
            if yaml is None:
                return {
                    "ok": False,
                    "success": False,
                    "data": None,
                    "result": None,
                    "error": "YAML parsing requires 'pyyaml' package which is not installed. Use JSON or CSV format.",
                }
            try:
                parsed_data = yaml.safe_load(raw_data)
            except Exception as err:
                return {
                    "ok": False,
                    "success": False,
                    "data": None,
                    "result": None,
                    "error": f"Invalid YAML: {err}",
                }

    # Action 1: Query
    if action == "query":
        query_path = str(args.get("path") or "").strip()
        if not query_path:
            out = {"query": "", "result": parsed_data, "found": True}
            return {"ok": True, "success": True, "data": out, "result": out, "error": None}
        extracted = _safe_query(parsed_data, query_path)
        out = {"query": query_path, "result": extracted, "found": extracted is not None}
        return {"ok": True, "success": True, "data": out, "result": out, "error": None}

    # Action 2: Convert
    if action == "convert":
        to_format = str(args.get("to_format") or "json").strip().lower()
        if to_format == "json":
            out_str = json.dumps(parsed_data, indent=2, ensure_ascii=False)
            out = {"format": "json", "result": out_str}
            return {"ok": True, "success": True, "data": out, "result": out, "error": None}

        if to_format == "csv":
            if not isinstance(parsed_data, list) or (parsed_data and not isinstance(parsed_data[0], dict)):
                return {
                    "ok": False,
                    "success": False,
                    "data": None,
                    "result": None,
                    "error": "CSV conversion requires an array of objects/dicts.",
                }
            if any(not isinstance(row, dict) for row in parsed_data):
                return {
                    "ok": False,
                    "success": False,
                    "data": None,
                    "result": None,
                    "error": "CSV conversion requires all items in the array to be objects/dicts.",
                }
            if not parsed_data:
                out = {"format": "csv", "result": "", "row_count": 0}
                return {"ok": True, "success": True, "data": out, "result": out, "error": None}
            fieldnames = list(dict.fromkeys(k for row in parsed_data if isinstance(row, dict) for k in row.keys()))
            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(parsed_data)
            out = {"format": "csv", "result": buf.getvalue(), "row_count": len(parsed_data)}
            return {"ok": True, "success": True, "data": out, "result": out, "error": None}

        if to_format == "ndjson":
            if not isinstance(parsed_data, list):
                return {
                    "ok": False,
                    "success": False,
                    "data": None,
                    "result": None,
                    "error": "NDJSON conversion requires an array of items.",
                }
            lines = [json.dumps(item, ensure_ascii=False) for item in parsed_data]
            out = {"format": "ndjson", "result": "\n".join(lines), "row_count": len(lines)}
            return {"ok": True, "success": True, "data": out, "result": out, "error": None}

        if to_format == "yaml":
            if yaml is None:
                return {
                    "ok": False,
                    "success": False,
                    "data": None,
                    "result": None,
                    "error": "YAML conversion requires 'pyyaml' package which is not installed. Use JSON or CSV.",
                }
            out_str = yaml.safe_dump(parsed_data, sort_keys=False)
            out = {"format": "yaml", "result": out_str}
            return {"ok": True, "success": True, "data": out, "result": out, "error": None}

        return {
            "ok": False,
            "success": False,
            "data": None,
            "result": None,
            "error": f"Unsupported target format: {to_format!r}",
        }

    # Action 3: Validate
    if action == "validate":
        schema = args.get("schema")
        if not isinstance(schema, dict):
            return {
                "ok": False,
                "success": False,
                "data": None,
                "result": None,
                "error": "Parameter 'schema' must be a JSON schema dictionary.",
            }
        try:
            valid, errors = _validate_schema(parsed_data, schema)
        except Exception as err:
            return {
                "ok": True,
                "success": True,
                "data": {"valid": False, "error_count": 1, "errors": [f"Malformed schema: {err}"]},
                "result": {"valid": False, "error_count": 1, "errors": [f"Malformed schema: {err}"]},
                "error": None,
            }
        out = {"valid": valid, "error_count": len(errors), "errors": errors}
        return {"ok": True, "success": True, "data": out, "result": out, "error": None}

    # Action 4: Summarize
    if action == "summarize":
        if isinstance(parsed_data, list):
            count = len(parsed_data)
            sample_keys = list(parsed_data[0].keys()) if count > 0 and isinstance(parsed_data[0], dict) else []
            out = {"type": "array", "item_count": count, "keys": sample_keys}
            return {"ok": True, "success": True, "data": out, "result": out, "error": None}
        if isinstance(parsed_data, dict):
            out = {"type": "object", "key_count": len(parsed_data), "keys": list(parsed_data.keys())}
            return {"ok": True, "success": True, "data": out, "result": out, "error": None}
        out = {"type": type(parsed_data).__name__, "value": str(parsed_data)[:200]}
        return {"ok": True, "success": True, "data": out, "result": out, "error": None}

    # Action 5: Filter
    if action == "filter":
        if not isinstance(parsed_data, list):
            return {
                "ok": False,
                "success": False,
                "data": None,
                "result": None,
                "error": "Filter action requires a list of items.",
            }
        filter_expr = args.get("filter_expr")
        if not isinstance(filter_expr, dict):
            return {
                "ok": False,
                "success": False,
                "data": None,
                "result": None,
                "error": "Parameter 'filter_expr' must be a dictionary with 'field', 'op', and 'value'.",
            }
        field = filter_expr.get("field")
        op = str(filter_expr.get("op") or "==").strip()
        val = filter_expr.get("value")

        filtered = []
        for item in parsed_data:
            if not isinstance(item, dict):
                continue
            try:
                if field not in item:
                    continue
            except (TypeError, KeyError):
                continue
            item_val = item[field]
            match = False
            try:
                if op == "==" and item_val == val:
                    match = True
                elif op == "!=" and item_val != val:
                    match = True
                elif op == ">" and item_val > val:
                    match = True
                elif op == "<" and item_val < val:
                    match = True
                elif op == ">=" and item_val >= val:
                    match = True
                elif op == "<=" and item_val <= val:
                    match = True
                elif op == "in" and val is not None and item_val in val:
                    match = True
                elif op == "contains" and item_val is not None and val in item_val:
                    match = True
            except (TypeError, ValueError):
                match = False
            if match:
                filtered.append(item)

        try:
            limit = max(1, min(int(args.get("limit") or 100), 1000))
        except (TypeError, ValueError):
            limit = 100

        truncated = len(filtered) > limit
        out = {"matched_count": len(filtered), "truncated": truncated, "results": filtered[:limit]}
        return {"ok": True, "success": True, "data": out, "result": out, "error": None}

    return {
        "ok": False,
        "success": False,
        "data": None,
        "result": None,
        "error": f"Unsupported action: {action!r}",
    }


def data_transform(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute pure in-memory structured data transformations, path queries, and schema validation."""
    try:
        return _data_transform_impl(arguments, context)
    except Exception as err:
        return {
            "ok": False,
            "success": False,
            "data": None,
            "result": None,
            "error": f"Transformation error: {type(err).__name__}: {err}",
        }


TOOL = {
    "name": "data_transform",
    "description": (
        "Pure in-memory structured data transformation, query, conversion, and validation. "
        "Actions: 'query' (dot-notation paths), 'convert' (JSON, CSV, NDJSON, YAML), "
        "'validate' (JSON schema check), 'summarize' (dataset stats), 'filter' (predicate filter)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["query", "convert", "validate", "summarize", "filter"], "description": "Operation to perform."},
            "data": {"description": "Input data payload: raw string, dict, or list."},
            "path": {"type": "string", "description": "Query path (e.g. 'items[0].name')."},
            "from_format": {"type": "string", "enum": ["json", "csv", "tsv", "ndjson", "yaml"], "description": "Format of input string."},
            "to_format": {"type": "string", "enum": ["json", "csv", "ndjson", "yaml"], "description": "Target format for conversion."},
            "schema": {"type": "object", "description": "JSON schema object for validation."},
            "filter_expr": {"type": "object", "description": "Filter criteria {'field': str, 'op': '=='|'!='|'>'|'<'|'contains'|'in', 'value': Any}."},
            "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "description": "Max results to return."},
        },
        "required": ["data"],
        "additionalProperties": False,
    },
    "handler": data_transform,
    "approval": False,
}
