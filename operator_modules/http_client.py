"""Safe, SSRF-guarded HTTP/REST client operator module for Jarvis."""

from __future__ import annotations

import ipaddress
import json
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

# Optional import of net_guard; fallback to local SSRF validator if standalone
try:
    import net_guard
except ImportError:
    _parent = str(Path(__file__).resolve().parents[1])
    if _parent not in sys.path:
        sys.path.insert(0, _parent)
    try:
        import net_guard
    except ImportError:
        net_guard = None  # type: ignore

# PROJECT.md contract: blocking network operations are capped at 10 seconds.
MAX_TIMEOUT = 10.0
DEFAULT_TIMEOUT = 10.0
MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB
DEFAULT_RESPONSE_BYTES = 1024 * 1024  # 1 MB

REDACTED_HEADERS = frozenset({
    "authorization", "proxy-authorization", "x-api-key", "api-key",
    "cookie", "set-cookie", "token", "x-auth-token"
})


def _is_url_allowed(url: str, allow_local: bool = False) -> tuple[bool, str]:
    """Validate URL against SSRF policy."""
    try:
        parsed = urllib.parse.urlsplit(url)
    except Exception as err:
        return False, f"Invalid URL structure: {err}"

    if parsed.scheme not in ("http", "https"):
        return False, f"Unsupported scheme {parsed.scheme!r}. Only http and https are allowed."

    host = (parsed.hostname or "").strip("[]").lower()
    if not host:
        return False, "URL must contain a valid hostname."

    if parsed.username is not None or parsed.password is not None:
        return False, "URL with embedded userinfo/credentials is not allowed."

    if allow_local:
        if host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost") or host.endswith(".local"):
            return True, ""

    if net_guard is not None:
        if not net_guard.is_public_url(url):
            return False, f"Refusing connection to non-public/private target {host!r} (SSRF protection)."
    else:
        # Fallback conservative SSRF validation for standalone use (net_guard
        # unavailable). Literal private/loopback addresses are refused, and a
        # DNS name is resolved: when ANY record points into a private range
        # the request is refused too, so a name like "internal.service" can
        # never race past the literal-prefix checks.
        if host in ("localhost", "127.0.0.1", "::1") and not allow_local:
            return False, f"Refusing connection to loopback target {host!r}."
        literal = None
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            pass
        if literal is not None:
            if (literal.is_private or literal.is_loopback or literal.is_link_local
                    or literal.is_reserved or literal.is_multicast or literal.is_unspecified):
                return False, f"Refusing connection to private subnet {host!r}."
        else:
            try:
                infos = socket.getaddrinfo(host, None)
            except OSError as err:
                return False, f"Could not resolve hostname {host!r} for SSRF validation: {err}"
            for info in infos:
                try:
                    addr = ipaddress.ip_address(info[4][0])
                except ValueError:
                    return False, f"Refusing non-IP address for {host!r}."
                if (addr.is_private or addr.is_loopback or addr.is_link_local
                        or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
                    return False, (f"Refusing connection to non-public target {host!r} "
                                   f"({addr}) (SSRF protection).")

    return True, ""


def _redact_headers(headers: dict[str, str] | Any) -> dict[str, str]:
    """Return a copy of headers with sensitive authorization values masked."""
    sanitized: dict[str, str] = {}
    if not headers:
        return sanitized
    for k, v in dict(headers).items():
        if str(k).lower() in REDACTED_HEADERS:
            sanitized[str(k)] = "[REDACTED]"
        else:
            sanitized[str(k)] = str(v)
    return sanitized


def http_client(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute safe, bounded HTTP/REST requests with SSRF filtering and header redaction.

    Parameters in arguments:
        url (str): Target URL (http or https).
        method (str, optional): HTTP method (default: 'GET').
        headers (dict, optional): Request headers.
        params (dict, optional): URL query parameters.
        json_body (dict | list, optional): Payload serialized as JSON (sets Content-Type: application/json).
        data (str, optional): Raw string request body.
        timeout (float, optional): Request timeout in seconds (default: 10, max: 30).
        allow_local (bool, optional): Allow loopback/local targets if True (default: False).
        max_bytes (int, optional): Maximum response bytes to read (default: 1048576, max: 5242880).

    Returns:
        dict: Standardized outcome dictionary {"ok": bool, "success": bool, "data": ..., "result": ..., "error": ...}
    """
    args = arguments if isinstance(arguments, dict) else {}
    raw_url = args.get("url")
    if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
        return {
            "ok": False,
            "success": False,
            "data": None,
            "result": None,
            "error": "Parameter 'url' is required and must be a non-empty string.",
        }

    raw_url = raw_url.strip()
    method = str(args.get("method") or "GET").strip().upper()
    allowed_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    if method not in allowed_methods:
        return {
            "ok": False,
            "success": False,
            "data": None,
            "result": None,
            "error": f"Method {method!r} not allowed. Supported: {sorted(allowed_methods)}",
        }

    allow_local = bool(args.get("allow_local", False))
    valid, reason = _is_url_allowed(raw_url, allow_local=allow_local)
    if not valid:
        return {
            "ok": False,
            "success": False,
            "data": None,
            "result": None,
            "error": reason,
        }

    # Query params handling
    params = args.get("params")
    target_url = raw_url
    if isinstance(params, dict) and params:
        query_string = urllib.parse.urlencode(params)
        sep = "&" if "?" in target_url else "?"
        target_url = f"{target_url}{sep}{query_string}"

    # Timeout & Max Bytes bounds
    try:
        timeout = max(1.0, min(float(args.get("timeout") or DEFAULT_TIMEOUT), MAX_TIMEOUT))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT

    try:
        max_bytes = max(1024, min(int(args.get("max_bytes") or DEFAULT_RESPONSE_BYTES), MAX_RESPONSE_BYTES))
    except (TypeError, ValueError):
        max_bytes = DEFAULT_RESPONSE_BYTES

    raw_headers = args.get("headers")
    if raw_headers is not None and not isinstance(raw_headers, dict):
        return {
            "ok": False,
            "success": False,
            "data": None,
            "result": None,
            "error": "Parameter 'headers' must be a dictionary of key-value pairs.",
        }
    headers = {str(k): str(v) for k, v in (raw_headers or {}).items()}
    body_bytes: bytes | None = None
    if "json_body" in args and args["json_body"] is not None:
        try:
            body_bytes = json.dumps(args["json_body"]).encode("utf-8")
            if not any(k.lower() == "content-type" for k in headers):
                headers["Content-Type"] = "application/json"
        except (TypeError, ValueError) as err:
            return {
                "ok": False,
                "success": False,
                "data": None,
                "result": None,
                "error": f"Invalid json_body payload: {err}",
            }
    elif "data" in args and args["data"] is not None:
        body_bytes = str(args["data"]).encode("utf-8")

    # Build opener with SSRF pinned handler when using net_guard and not allow_local
    opener = urllib.request.build_opener()
    if net_guard is not None and not allow_local:
        opener = urllib.request.build_opener(
            net_guard.PinnedHTTPHandler(allow_private=False),
            net_guard.PinnedHTTPSHandler(allow_private=False)
        )

    req = urllib.request.Request(target_url, data=body_bytes, headers=headers, method=method)
    start_time = time.monotonic()

    try:
        with opener.open(req, timeout=timeout) as resp:
            elapsed = round(time.monotonic() - start_time, 4)
            status_code = getattr(resp, "status", 200)
            reason = getattr(resp, "reason", "OK")
            resp_headers = dict(resp.headers.items()) if hasattr(resp, "headers") else {}
            content_type = resp.headers.get("Content-Type", "") if hasattr(resp, "headers") else ""

            # Stream read up to max_bytes + 1 to detect truncation
            raw_data = resp.read(max_bytes + 1)
            truncated = len(raw_data) > max_bytes
            body_slice = raw_data[:max_bytes]

            text_content = ""
            json_data = None
            try:
                text_content = body_slice.decode("utf-8", errors="replace")
                if "application/json" in content_type.lower() or text_content.strip().startswith(("{", "[")):
                    try:
                        json_data = json.loads(text_content)
                    except ValueError:
                        pass
            except Exception:
                text_content = "<binary data>"

            out = {
                "status_code": status_code,
                "status_text": reason,
                "url": target_url,
                "method": method,
                "timeout_used": timeout,
                "headers": _redact_headers(resp_headers),
                "content_type": content_type,
                "bytes_read": len(body_slice),
                "truncated": truncated,
                "elapsed_seconds": elapsed,
                "text": text_content,
                "json": json_data,
            }
            return {"ok": True, "success": True, "data": out, "result": out, "error": None}

    except urllib.error.HTTPError as err:
        try:
            elapsed = round(time.monotonic() - start_time, 4)
            err_body = err.read(max_bytes).decode("utf-8", errors="replace") if hasattr(err, "read") else ""
            err_json = None
            try:
                err_json = json.loads(err_body)
            except Exception:
                pass
            out = {
                "status_code": err.code,
                "status_text": err.reason,
                "url": target_url,
                "method": method,
                "headers": _redact_headers(dict(err.headers.items())) if hasattr(err, "headers") else {},
                "bytes_read": len(err_body),
                "truncated": False,
                "elapsed_seconds": elapsed,
                "text": err_body,
                "json": err_json,
            }
            return {"ok": True, "success": True, "data": out, "result": out, "error": None}
        finally:
            try:
                err.close()
            except Exception:
                pass

    except urllib.error.URLError as err:
        return {"ok": False, "success": False, "data": None, "result": None, "error": f"Network connection failed: {err.reason}"}
    except (socket.timeout, TimeoutError):
        return {"ok": False, "success": False, "data": None, "result": None, "error": f"Request timed out after {timeout} seconds."}
    except Exception as err:
        return {"ok": False, "success": False, "data": None, "result": None, "error": f"HTTP request failed: {type(err).__name__}: {err}"}


TOOL = {
    "name": "http_client",
    "description": (
        "Execute safe, bounded HTTP/REST requests (GET, POST, PUT, PATCH, DELETE, HEAD) "
        "with SSRF protection, timeout bounding, response size limits, and sensitive header redaction."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Target URL starting with http:// or https://."},
            "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"], "description": "HTTP method (default: 'GET')."},
            "headers": {"type": "object", "description": "Optional request headers dictionary."},
            "params": {"type": "object", "description": "Optional URL query parameters dictionary."},
            "json_body": {"description": "Optional request body serialized as JSON."},
            "data": {"type": "string", "description": "Optional raw string body."},
            "timeout": {"type": "number", "minimum": 1, "maximum": 10, "description": "Timeout in seconds (default: 10; capped at 10 per the network contract)."},
            "allow_local": {"type": "boolean", "description": "Allow connection to localhost/127.0.0.1 if true (default: false)."},
            "max_bytes": {"type": "integer", "minimum": 1024, "maximum": 5242880, "description": "Max response bytes to download (default: 1MB, max: 5MB)."},
        },
        "required": ["url"],
        "additionalProperties": False,
    },
    "handler": http_client,
    "approval": True,
}
