"""Multi-codec encoder, decoder, structural JWT inspector, and format detector for Jarvis."""

from __future__ import annotations

import base64
import binascii
import html
import json
import quopri
import re
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any

MAX_CODEC_BYTES = 1024 * 1024  # 1 MB ceiling to prevent memory bombs

SUPPORTED_FORMATS = {
    "base64",
    "base32",
    "hex",
    "url",
    "html",
    "ascii85",
    "unicode_escape",
    "quoted_printable",
}


def _b64url_decode(segment: str) -> bytes:
    """Safely decode a base64url segment with missing padding."""
    clean = segment.strip()
    rem = len(clean) % 4
    if rem > 0:
        clean += "=" * (4 - rem)
    return base64.urlsafe_b64decode(clean)


def _encode_data(data: str, fmt: str) -> dict[str, Any]:
    raw_utf8 = data.encode("utf-8")
    if fmt == "base64":
        encoded = base64.b64encode(raw_utf8).decode("ascii")
    elif fmt == "base32":
        encoded = base64.b32encode(raw_utf8).decode("ascii")
    elif fmt == "hex":
        encoded = binascii.hexlify(raw_utf8).decode("ascii")
    elif fmt == "url":
        encoded = urllib.parse.quote(data)
    elif fmt == "html":
        encoded = html.escape(data)
    elif fmt == "ascii85":
        encoded = base64.a85encode(raw_utf8).decode("ascii")
    elif fmt == "unicode_escape":
        encoded = data.encode("unicode_escape").decode("ascii")
    elif fmt == "quoted_printable":
        encoded = quopri.encodestring(raw_utf8).decode("ascii")
    else:
        raise ValueError(f"Unsupported format: {fmt!r}")

    return {
        "encoded": encoded,
        "format": fmt,
        "input_bytes": len(raw_utf8),
        "output_chars": len(encoded),
    }


def _decode_data(data: str, fmt: str) -> dict[str, Any]:
    raw_bytes: bytes | None = None
    decoded_text: str | None = None

    if fmt == "base64":
        clean = re.sub(r"\s+", "", data)
        rem = len(clean) % 4
        if rem > 0:
            clean += "=" * (4 - rem)
        raw_bytes = base64.b64decode(clean, validate=False)
    elif fmt == "base32":
        clean = re.sub(r"\s+", "", data).upper()
        rem = len(clean) % 8
        if rem > 0:
            clean += "=" * (8 - rem)
        raw_bytes = base64.b32decode(clean, casefold=True)
    elif fmt == "hex":
        clean = re.sub(r"[\s:]+", "", data)
        raw_bytes = binascii.unhexlify(clean)
    elif fmt == "url":
        decoded_text = urllib.parse.unquote(data)
    elif fmt == "html":
        decoded_text = html.unescape(data)
    elif fmt == "ascii85":
        clean = data.strip().encode("ascii")
        raw_bytes = base64.a85decode(clean)
    elif fmt == "unicode_escape":
        decoded_text = data.encode("utf-8").decode("unicode_escape")
    elif fmt == "quoted_printable":
        raw_bytes = quopri.decodestring(data.encode("ascii", errors="replace"))
    else:
        raise ValueError(f"Unsupported format: {fmt!r}")

    if raw_bytes is not None:
        try:
            decoded_text = raw_bytes.decode("utf-8")
            is_binary = False
            hex_fallback = None
        except UnicodeDecodeError:
            is_binary = True
            hex_fallback = binascii.hexlify(raw_bytes).decode("ascii")
            decoded_text = hex_fallback
        byte_length = len(raw_bytes)
    else:
        assert decoded_text is not None
        is_binary = False
        hex_fallback = None
        byte_length = len(decoded_text.encode("utf-8"))

    return {
        "decoded": decoded_text,
        "format": fmt,
        "binary": is_binary,
        "hex": hex_fallback,
        "byte_length": byte_length,
    }


def _inspect_jwt(token: str) -> dict[str, Any]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT structure: expected 3 dot-separated parts, found {len(parts)}")

    header_bytes = _b64url_decode(parts[0])
    payload_bytes = _b64url_decode(parts[1])
    signature_raw = parts[2]

    header = json.loads(header_bytes.decode("utf-8"))
    payload = json.loads(payload_bytes.decode("utf-8"))

    now = time.time()
    exp = payload.get("exp")
    iat = payload.get("iat")
    nbf = payload.get("nbf")

    expired = None
    exp_iso = None
    iat_iso = None
    nbf_iso = None

    if isinstance(exp, (int, float)):
        expired = now > exp
        try:
            exp_iso = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()
        except (ValueError, OverflowError, OSError):
            exp_iso = None

    if isinstance(iat, (int, float)):
        try:
            iat_iso = datetime.fromtimestamp(iat, tz=timezone.utc).isoformat()
        except (ValueError, OverflowError, OSError):
            iat_iso = None

    if isinstance(nbf, (int, float)):
        try:
            nbf_iso = datetime.fromtimestamp(nbf, tz=timezone.utc).isoformat()
        except (ValueError, OverflowError, OSError):
            nbf_iso = None

    return {
        "header": header,
        "payload": payload,
        "signature": signature_raw,
        "expired": expired,
        "exp_iso": exp_iso,
        "iat_iso": iat_iso,
        "nbf_iso": nbf_iso,
    }


def _detect_formats(data: str) -> dict[str, Any]:
    candidates: list[str] = []
    stripped = data.strip()

    # JWT check
    if re.fullmatch(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", stripped):
        try:
            p = stripped.split(".")
            h = json.loads(_b64url_decode(p[0]))
            py = json.loads(_b64url_decode(p[1]))
            if isinstance(h, dict) and isinstance(py, dict):
                candidates.append("jwt")
        except Exception:
            pass

    # Hex check
    hex_clean = re.sub(r"[\s:]+", "", stripped)
    if len(hex_clean) >= 2 and len(hex_clean) % 2 == 0 and re.fullmatch(r"^[0-9a-fA-F]+$", hex_clean):
        candidates.append("hex")

    # URL encoding check
    if re.search(r"%[0-9a-fA-F]{2}", data):
        candidates.append("url")

    # HTML entity check
    if re.search(r"&(?:[a-zA-Z]+|#\d+|#[xX][0-9a-fA-F]+);", data):
        candidates.append("html")

    # Quoted-printable check
    if re.search(r"=[0-9A-Fa-f]{2}|=\r?\n", data):
        candidates.append("quoted_printable")

    # Base64 check
    b64_clean = re.sub(r"\s+", "", stripped)
    if len(b64_clean) >= 4 and len(b64_clean) % 4 == 0 and re.fullmatch(r"^[A-Za-z0-9+/]+={0,2}$", b64_clean):
        try:
            base64.b64decode(b64_clean, validate=True)
            candidates.append("base64")
        except Exception:
            pass

    # Base32 check
    b32_clean = re.sub(r"\s+", "", stripped).upper()
    if len(b32_clean) >= 8 and len(b32_clean) % 8 == 0 and re.fullmatch(r"^[A-Z2-7]+=*$", b32_clean):
        try:
            base64.b32decode(b32_clean, casefold=True)
            candidates.append("base32")
        except Exception:
            pass

    # Unicode escape check
    if re.search(r"\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}", data):
        candidates.append("unicode_escape")

    primary = candidates[0] if candidates else "plain_text"
    return {"candidates": candidates, "primary": primary}


def _codec_tools_impl(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    action = arguments.get("action")
    if not action:
        return {"ok": False, "success": False, "data": None, "result": None, "error": "Missing required field 'action'"}

    data = arguments.get("data")
    if not isinstance(data, str):
        return {"ok": False, "success": False, "data": None, "result": None, "error": "Field 'data' must be a string"}

    if len(data.encode("utf-8", errors="ignore")) > MAX_CODEC_BYTES:
        return {
            "ok": False,
            "success": False,
            "data": None,
            "result": None,
            "error": f"Payload exceeds maximum allowed size ({MAX_CODEC_BYTES} bytes)",
        }

    fmt = arguments.get("format")
    if fmt is not None:
        fmt = str(fmt).lower()

    if action == "encode":
        if not fmt:
            return {"ok": False, "success": False, "data": None, "result": None, "error": "Missing format for action 'encode'"}
        if fmt not in SUPPORTED_FORMATS:
            return {"ok": False, "success": False, "data": None, "result": None, "error": f"Unsupported format: {fmt!r}"}
        res = _encode_data(data, fmt)
        return {"ok": True, "success": True, "data": res, "result": res, "error": None}

    if action == "decode":
        if not fmt:
            return {"ok": False, "success": False, "data": None, "result": None, "error": "Missing format for action 'decode'"}
        if fmt not in SUPPORTED_FORMATS:
            return {"ok": False, "success": False, "data": None, "result": None, "error": f"Unsupported format: {fmt!r}"}
        res = _decode_data(data, fmt)
        return {"ok": True, "success": True, "data": res, "result": res, "error": None}

    if action == "jwt_inspect":
        res = _inspect_jwt(data)
        return {"ok": True, "success": True, "data": res, "result": res, "error": None}

    if action == "detect":
        res = _detect_formats(data)
        return {"ok": True, "success": True, "data": res, "result": res, "error": None}

    return {"ok": False, "success": False, "data": None, "result": None, "error": f"Unsupported action: {action!r}"}


def codec_tools(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute multi-codec conversions, structural JWT token inspection, and format detection."""
    try:
        return _codec_tools_impl(arguments, context)
    except Exception as err:
        return {
            "ok": False,
            "success": False,
            "data": None,
            "result": None,
            "error": f"Codec error: {type(err).__name__}: {err}",
        }


TOOL = {
    "name": "codec_tools",
    "description": (
        "Pure in-memory multi-codec encoder, decoder, JWT inspector, and format detector. "
        "Supports base64, base32, hex, url, html, ascii85, unicode_escape, quoted_printable. "
        "Provides structural JWT inspection without eval and handles binary fallback safely."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["encode", "decode", "jwt_inspect", "detect"],
                "description": "Encoding operation to perform.",
            },
            "format": {
                "type": "string",
                "enum": [
                    "base64",
                    "base32",
                    "hex",
                    "url",
                    "html",
                    "ascii85",
                    "unicode_escape",
                    "quoted_printable",
                ],
                "description": "Encoding format for encode/decode.",
            },
            "data": {
                "type": "string",
                "description": "Data payload string to process.",
            },
        },
        "required": ["action", "data"],
        "additionalProperties": False,
    },
    "handler": codec_tools,
    "approval": False,
}
