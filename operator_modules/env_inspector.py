"""Safe environment, CLI toolchain, and local port diagnostic inspector for Jarvis."""

from __future__ import annotations

import os
import platform
import re
import shutil
import socket
import sys
import time
from typing import Any

# Mandatory sensitive keys and values regex patterns
SENSITIVE_KEY_RE = re.compile(
    r"(?:key|token|secret|password|passwd|\bpass\b|\bpwd\b|(?:\b|_)(?:pass|pwd)(?:\b|_)|auth|cred|cert|priv|sign|api_?key|jwt|database_url|db_url|redis_url|webhook)",
    re.IGNORECASE,
)
SENSITIVE_VAL_RE = re.compile(
    r"(?:\bsk-(?:or-|ant-|proj-)?[A-Za-z0-9_-]{8,}|\bsk_(?:live|test)_[A-Za-z0-9_-]{16,}|"
    r"\bgh[pousr]_[A-Za-z0-9_]{20,}|\bAKIA[A-Z0-9]{16}\b|\bBearer\s+\S+|-----BEGIN|"
    r"://[^:@]*:[^@]+@|\b[0-9a-f]{32,}\b)",
    re.IGNORECASE,
)


def _is_sensitive_env(key: str, val: str) -> bool:
    """Detect whether an environment variable key or value contains sensitive credentials."""
    if SENSITIVE_KEY_RE.search(key):
        return True
    if SENSITIVE_VAL_RE.search(val):
        return True
    return False


def env_inspector(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Inspect environment variables with mandatory secret redaction, CLI tool availability, and local port listeners.

    Parameters in arguments:
        action (str): 'env', 'check_tools', 'which', 'check_port', or 'system_info' (default: 'env').
        names (list[str], optional): Variable names (for 'env') or tool names (for 'check_tools').
        prefix (str, optional): Key prefix filter for 'env' (e.g. 'JARVIS_' or 'PATH').
        port (int, optional): TCP port to probe for 'check_port' (1-65535).
        host (str, optional): Host for 'check_port' (strictly restricted to loopback '127.0.0.1' or '::1').
    """
    args = arguments if isinstance(arguments, dict) else {}
    action = str(args.get("action") or "env").strip().lower()

    # Action 1: Environment Variables
    if action == "env":
        names_filter = {str(n) for n in args.get("names") or [] if isinstance(n, (str, int, float, bool))} if isinstance(args.get("names"), list) else None
        prefix_filter = str(args.get("prefix") or "").strip().lower()

        filtered_vars: dict[str, str] = {}
        redacted_count = 0

        for key, val in sorted(os.environ.items()):
            if names_filter is not None and key not in names_filter:
                continue
            if prefix_filter and not key.lower().startswith(prefix_filter):
                continue

            if _is_sensitive_env(key, val):
                filtered_vars[key] = "[REDACTED]"
                redacted_count += 1
            else:
                # Truncate overly long values
                filtered_vars[key] = val[:500] if len(val) <= 500 else f"{val[:500]}... [truncated]"

        out = {
            "total_count": len(filtered_vars),
            "redacted_count": redacted_count,
            "variables": filtered_vars,
        }
        return {"ok": True, "success": True, "data": out, "result": out, "error": None}

    # Action 2: Check CLI Tools
    if action in ("check_tools", "which"):
        raw_tools = args.get("names")
        if not raw_tools or not isinstance(raw_tools, list):
            # Default common tools
            tools_to_check = ["git", "python3", "pytest", "node", "npm", "docker", "curl", "tesseract"]
        else:
            tools_to_check = [str(t).strip() for t in raw_tools if str(t).strip()]

        results: dict[str, dict[str, Any]] = {}
        for tool_name in tools_to_check:
            # Prevent injection / directory traversal in tool_name
            if "/" in tool_name or "\\" in tool_name:
                results[tool_name] = {"installed": False, "path": None, "error": "Invalid tool name format."}
                continue
            resolved = shutil.which(tool_name)
            results[tool_name] = {
                "installed": resolved is not None,
                "path": resolved,
            }

        out = {"tools": results, "checked_count": len(results)}
        return {"ok": True, "success": True, "data": out, "result": out, "error": None}

    # Action 3: Check Local Port
    if action == "check_port":
        raw_port = args.get("port")
        if raw_port is None:
            return {
                "ok": False,
                "success": False,
                "data": None,
                "result": None,
                "error": "Parameter 'port' is required for check_port.",
            }
        try:
            port = int(raw_port)
            if not (1 <= port <= 65535):
                raise ValueError
        except (ValueError, TypeError):
            return {
                "ok": False,
                "success": False,
                "data": None,
                "result": None,
                "error": "Parameter 'port' must be an integer between 1 and 65535.",
            }

        host = str(args.get("host") or "127.0.0.1").strip().lower()
        if host not in ("127.0.0.1", "localhost", "::1"):
            return {
                "ok": False,
                "success": False,
                "data": None,
                "result": None,
                "error": f"Refusing to probe remote host {host!r}. Only loopback targets ('127.0.0.1', '::1') are permitted.",
            }

        t_start = time.monotonic()
        listening = False
        try:
            sock_family = socket.AF_INET6 if host == "::1" else socket.AF_INET
            target_host = "127.0.0.1" if host == "localhost" else host
            with socket.socket(sock_family, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.0)
                res = sock.connect_ex((target_host, port))
                listening = (res == 0)
        except Exception:
            listening = False
        latency = round((time.monotonic() - t_start) * 1000, 2)

        out = {
            "host": host,
            "port": port,
            "listening": listening,
            "latency_ms": latency,
            "status": "open / listening" if listening else "closed / not responding",
        }
        return {"ok": True, "success": True, "data": out, "result": out, "error": None}

    # Action 4: System Information
    if action == "system_info":
        out = {
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python_version": sys.version.split()[0],
            "python_executable": sys.executable,
        }
        return {"ok": True, "success": True, "data": out, "result": out, "error": None}

    return {
        "ok": False,
        "success": False,
        "data": None,
        "result": None,
        "error": f"Unsupported action: {action!r}",
    }


TOOL = {
    "name": "env_inspector",
    "description": (
        "Inspect runtime environment variables with mandatory secret masking ('env'), "
        "verify CLI toolchain binary availability ('check_tools'), "
        "probe local loopback listening ports ('check_port'), or retrieve system details ('system_info')."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["env", "check_tools", "which", "check_port", "system_info"], "description": "Diagnostic action."},
            "names": {"type": "array", "items": {"type": "string"}, "description": "Variable names for 'env' or tool names for 'check_tools'."},
            "prefix": {"type": "string", "description": "Prefix filter for environment variable keys."},
            "port": {"type": "integer", "minimum": 1, "maximum": 65535, "description": "Port number to check for 'check_port'."},
            "host": {"type": "string", "description": "Host for check_port (loopback only: 127.0.0.1 or ::1)."},
        },
        "additionalProperties": False,
    },
    "handler": env_inspector,
    "approval": False,
}
