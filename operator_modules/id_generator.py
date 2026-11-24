"""Cryptographically secure identifier generator and UUID validator for Jarvis."""

from __future__ import annotations

import secrets
import uuid
from typing import Any

DEFAULT_NANOID_ALPHABET = "_-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

NAMESPACE_MAP = {
    "dns": uuid.NAMESPACE_DNS,
    "url": uuid.NAMESPACE_URL,
    "oid": uuid.NAMESPACE_OID,
    "x500": uuid.NAMESPACE_X500,
}


def _resolve_namespace(ns_input: str | None) -> uuid.UUID:
    if not ns_input:
        return uuid.NAMESPACE_DNS
    key = str(ns_input).strip().lower()
    if key in NAMESPACE_MAP:
        return NAMESPACE_MAP[key]
    # Attempt to parse as custom UUID string
    try:
        return uuid.UUID(ns_input.strip())
    except Exception as err:
        raise ValueError(f"Invalid UUID namespace: {ns_input!r} (must be 'dns', 'url', 'oid', 'x500', or valid UUID)") from err


def _generate_nanoid(length: int, alphabet: str) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _id_generator_impl(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    action = arguments.get("action")
    if not action:
        return {"ok": False, "success": False, "data": None, "result": None, "error": "Missing required field 'action'"}

    # Bounded limits
    count_raw = arguments.get("count")
    count = 1
    if count_raw is not None:
        try:
            count = max(1, min(int(count_raw), 1000))
        except (ValueError, TypeError):
            return {"ok": False, "success": False, "data": None, "result": None, "error": "Field 'count' must be an integer (1-1000)"}

    length_raw = arguments.get("length")
    length = 32
    if length_raw is not None:
        try:
            length = max(4, min(int(length_raw), 512))
        except (ValueError, TypeError):
            return {"ok": False, "success": False, "data": None, "result": None, "error": "Field 'length' must be an integer (4-512)"}

    alphabet = arguments.get("alphabet")
    if alphabet is None:
        alphabet = DEFAULT_NANOID_ALPHABET
    if not isinstance(alphabet, str) or len(set(alphabet)) < 2:
        return {
            "ok": False,
            "success": False,
            "data": None,
            "result": None,
            "error": "Field 'alphabet' must contain at least 2 unique characters",
        }
    if any(ord(c) < 32 or ord(c) == 127 for c in alphabet):
        return {
            "ok": False,
            "success": False,
            "data": None,
            "result": None,
            "error": "Field 'alphabet' cannot contain non-printable control characters",
        }

    if action == "uuid4":
        ids = [str(uuid.uuid4()) for _ in range(count)]
        data = {
            "id": ids[0],
            "ids": ids,
            "count": count,
            "type": "uuid4",
        }
        return {"ok": True, "success": True, "data": data, "result": data, "error": None}

    if action == "uuid5":
        name = arguments.get("name")
        if name is None:
            return {"ok": False, "success": False, "data": None, "result": None, "error": "Field 'name' is required for action 'uuid5'"}
        ns = _resolve_namespace(arguments.get("namespace"))
        val = str(uuid.uuid5(ns, str(name)))
        data = {
            "id": val,
            "ids": [val],
            "count": 1,
            "type": "uuid5",
            "name": str(name),
            "namespace": str(ns),
        }
        return {"ok": True, "success": True, "data": data, "result": data, "error": None}

    if action == "token_hex":
        nbytes = (length + 1) // 2
        ids = [secrets.token_hex(nbytes)[:length] for _ in range(count)]
        data = {
            "id": ids[0],
            "ids": ids,
            "count": count,
            "length": length,
            "type": "token_hex",
        }
        return {"ok": True, "success": True, "data": data, "result": data, "error": None}

    if action == "token_urlsafe":
        ids = [secrets.token_urlsafe(length)[:length] for _ in range(count)]
        data = {
            "id": ids[0],
            "ids": ids,
            "count": count,
            "length": length,
            "type": "token_urlsafe",
        }
        return {"ok": True, "success": True, "data": data, "result": data, "error": None}

    if action == "nanoid":
        ids = [_generate_nanoid(length, alphabet) for _ in range(count)]
        data = {
            "id": ids[0],
            "ids": ids,
            "count": count,
            "length": length,
            "alphabet_size": len(set(alphabet)),
            "type": "nanoid",
        }
        return {"ok": True, "success": True, "data": data, "result": data, "error": None}

    if action == "validate":
        value = arguments.get("value")
        if not value or not isinstance(value, str):
            return {"ok": False, "success": False, "data": None, "result": None, "error": "Field 'value' must be a non-empty string"}

        try:
            parsed = uuid.UUID(value.strip())
            data = {
                "valid": True,
                "version": parsed.version,
                "variant": parsed.variant,
                "hex": parsed.hex,
                "urn": parsed.urn,
                "value": str(parsed),
            }
            return {"ok": True, "success": True, "data": data, "result": data, "error": None}
        except ValueError as err:
            data = {
                "valid": False,
                "version": None,
                "variant": None,
                "hex": None,
                "urn": None,
                "error": str(err),
            }
            return {"ok": True, "success": True, "data": data, "result": data, "error": None}

    if action == "batch":
        # Generate batch of default uuid4 or token_hex if specified
        ids = [str(uuid.uuid4()) for _ in range(count)]
        data = {
            "id": ids[0],
            "ids": ids,
            "count": count,
            "type": "uuid4",
        }
        return {"ok": True, "success": True, "data": data, "result": data, "error": None}

    return {"ok": False, "success": False, "data": None, "result": None, "error": f"Unsupported action: {action!r}"}


def id_generator(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Generate cryptographically secure identifiers or validate UUIDs."""
    try:
        return _id_generator_impl(arguments, context)
    except Exception as err:
        return {
            "ok": False,
            "success": False,
            "data": None,
            "result": None,
            "error": f"ID generation error: {type(err).__name__}: {err}",
        }


TOOL = {
    "name": "id_generator",
    "description": (
        "Cryptographically secure identifier generator and UUID validator. "
        "Supports UUIDv4, UUIDv5 (deterministic namespace/name), random hex/urlsafe tokens, "
        "and custom-alphabet nanoids with batch generation up to 1000 items."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["uuid4", "uuid5", "token_hex", "token_urlsafe", "nanoid", "validate", "batch"],
                "description": "Identifier generation or validation operation.",
            },
            "count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 1000,
                "description": "Number of IDs to generate in batch mode (default: 1).",
            },
            "length": {
                "type": "integer",
                "minimum": 4,
                "maximum": 512,
                "description": "Token byte length or nanoid character length (default: 32).",
            },
            "alphabet": {
                "type": "string",
                "description": "Custom character set for nanoid generation.",
            },
            "namespace": {
                "type": "string",
                "description": "UUID namespace for uuid5 (dns, url, oid, x500, or raw UUID string).",
            },
            "name": {
                "type": "string",
                "description": "Name string for uuid5 generation.",
            },
            "value": {
                "type": "string",
                "description": "UUID string to validate when action='validate'.",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": id_generator,
    "approval": False,
}
