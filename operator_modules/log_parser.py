"""Pure standard library multi-format structured log parsing, format detection, aggregation, and stack trace extraction."""

from __future__ import annotations

import collections
import json
import os
import re
from pathlib import Path
from typing import Any

try:
    import operator_tools
except ImportError:
    operator_tools = None  # type: ignore

MAX_LOG_BYTES = 4 * 1024 * 1024  # 4 MB
MAX_RECORDS_LIMIT = 5000

LEVEL_RANKS: dict[str, int] = {
    "DEBUG": 10,
    "INFO": 20,
    "NOTICE": 25,
    "WARN": 30,
    "WARNING": 30,
    "ERROR": 40,
    "CRITICAL": 50,
    "FATAL": 50,
}

# Regexes for format matching
# Syslog RFC 3164: "Oct 11 22:14:15 host process[123]: message"
RE_SYSLOG_3164 = re.compile(
    r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([^\s:]+)\s+([^:\[\s]+)(?:\[(\d+)\])?:\s*(.*)$"
)
# Syslog RFC 5424: "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\"] BOMAn application event log entry..."
RE_SYSLOG_5424 = re.compile(
    r"^<(\d+)>(\d+)?\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)?\s*(.*)$"
)

# Nginx Combined: '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"'
RE_NGINX_COMBINED = re.compile(
    r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"'
)

# Apache Common: '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326'
RE_APACHE_COMMON = re.compile(
    r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)'
)

# Python standard loggers:
# 1. '2023-10-11 14:02:00,123 - my_logger - INFO - message'
RE_PY_DASH = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d+)?)\s*[-:]\s*([^\s-]+)\s*[-:]\s*([A-Za-z]+)\s*[-:]\s*(.*)$"
)
# 2. 'INFO:my_module:message'
RE_PY_COLON = re.compile(
    r"^([A-Z]+):([^:]+):(.*)$"
)
# 3. '2023-10-11 14:02:00 [INFO] [module]: message'
RE_PY_BRACKET = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d+)?)\s+\[([A-Za-z]+)\]\s*(?:\[([^\]]+)\]\s*)?[-:]?\s*(.*)$"
)

# Secret sanitization patterns
RE_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+={0,2}")
RE_SECRET_PARAM = re.compile(r"(?i)\b(password|secret|token|apikey|api_key|access_token|auth)=([^\s&\"'>]+)")
RE_BASIC_AUTH_URL = re.compile(r"https?://([^:]+):([^@]+)@")


def _sanitize_message(message: str) -> str:
    """Mask common sensitive credentials in log messages."""
    if not message:
        return ""
    text = RE_BEARER.sub("Bearer [REDACTED]", message)
    text = RE_SECRET_PARAM.sub(r"\1=[REDACTED]", text)
    text = RE_BASIC_AUTH_URL.sub(r"https://\1:[REDACTED]@", text)
    return text


def _safe_resolve_path(raw_path: str) -> Path:
    """Validate and canonicalize path against allowed roots and sensitive targets."""
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError("Path parameter must be a non-empty string.")
    if len(raw_path) > 4096:
        raise ValueError("File path exceeds maximum length.")

    expanded = Path(raw_path).expanduser()
    if any(part in ("..", "") for part in expanded.parts):
        raise PermissionError(f"Directory traversal sequences not allowed: {raw_path}")

    try:
        resolved = Path(os.path.realpath(str(expanded)))
    except (OSError, ValueError):
        resolved = expanded.resolve()

    if operator_tools is not None:
        if not operator_tools._inside(resolved):
            raise PermissionError(f"Path outside allowed roots: {resolved}")
        if operator_tools.is_sensitive(resolved) or operator_tools.is_credential_target(resolved):
            raise PermissionError(f"Access to sensitive or credential target is blocked: {resolved}")
    else:
        home = Path.home().resolve()
        tmp = Path("/tmp").resolve()
        allowed = (
            resolved == home or resolved.is_relative_to(home) or
            resolved == tmp or resolved.is_relative_to(tmp)
        )
        if not allowed:
            raise PermissionError(f"Path outside allowed directories: {resolved}")

    if not resolved.is_file():
        raise FileNotFoundError(f"File not found: {resolved}")

    size = resolved.stat().st_size
    if size > MAX_LOG_BYTES:
        raise ValueError(f"Log file exceeds maximum limit of {MAX_LOG_BYTES} bytes ({size} bytes).")

    return resolved


def _get_log_text(text_arg: Any, path_arg: Any) -> str:
    """Extract and validate log content from either text or file path."""
    if text_arg is not None:
        if not isinstance(text_arg, str):
            raise TypeError("Parameter 'text' must be a string.")
        encoded = text_arg.encode("utf-8")
        if len(encoded) > MAX_LOG_BYTES:
            raise ValueError(f"Log text exceeds maximum limit of {MAX_LOG_BYTES} bytes ({len(encoded)} bytes).")
        return text_arg

    if path_arg is not None:
        resolved = _safe_resolve_path(str(path_arg))
        return resolved.read_text(encoding="utf-8", errors="replace")

    raise ValueError("Either 'text' or 'path' must be provided.")


def _parse_json_line(line: str) -> dict[str, Any] | None:
    """Parse single JSON log line."""
    line = line.strip()
    if not line.startswith("{") or not line.endswith("}"):
        return None
    try:
        obj = json.loads(line)
        if not isinstance(obj, dict):
            return None
    except json.JSONDecodeError:
        return None

    # Identify fields
    timestamp = obj.get("timestamp") or obj.get("time") or obj.get("ts") or obj.get("datetime")
    level = obj.get("level") or obj.get("severity") or obj.get("lvl") or obj.get("log_level") or "INFO"
    message = obj.get("message") or obj.get("msg") or obj.get("text") or obj.get("log") or ""

    level_str = str(level).upper() if level else "INFO"
    return {
        "timestamp": str(timestamp) if timestamp is not None else None,
        "level": level_str,
        "message": _sanitize_message(str(message)),
        "data": obj,
        "raw": line,
    }


def _parse_syslog_line(line: str) -> dict[str, Any] | None:
    """Parse single Syslog line."""
    m_3164 = RE_SYSLOG_3164.match(line)
    if m_3164:
        ts, host, app, pid, msg = m_3164.groups()
        return {
            "timestamp": ts,
            "host": host,
            "program": app,
            "pid": int(pid) if pid else None,
            "level": "INFO",
            "message": _sanitize_message(msg),
            "raw": line,
        }

    m_5424 = RE_SYSLOG_5424.match(line)
    if m_5424:
        prival, ver, ts, host, app, procid, msgid, msg = m_5424.groups()
        level = "INFO"
        if prival and prival.isdigit():
            pri = int(prival)
            severity = pri % 8
            # 0=emerg, 1=alert, 2=crit, 3=err, 4=warn, 5=notice, 6=info, 7=debug
            sev_map = {0: "FATAL", 1: "CRITICAL", 2: "CRITICAL", 3: "ERROR", 4: "WARNING", 5: "INFO", 6: "INFO", 7: "DEBUG"}
            level = sev_map.get(severity, "INFO")
        return {
            "timestamp": ts if ts != "-" else None,
            "host": host if host != "-" else None,
            "program": app if app != "-" else None,
            "pid": int(procid) if procid and procid.isdigit() else None,
            "level": level,
            "message": _sanitize_message(msg),
            "raw": line,
        }

    return None


def _parse_nginx_combined_line(line: str) -> dict[str, Any] | None:
    """Parse Nginx Combined log line."""
    m = RE_NGINX_COMBINED.match(line)
    if not m:
        return None
    ip, ident, user, ts, req, status, size, ref, ua = m.groups()
    code = int(status)
    level = "ERROR" if code >= 500 else ("WARNING" if code >= 400 else "INFO")

    return {
        "timestamp": ts,
        "client_ip": ip,
        "user": user if user != "-" else None,
        "request": req,
        "status": code,
        "bytes": int(size) if size.isdigit() else 0,
        "referer": ref if ref != "-" else None,
        "user_agent": ua if ua != "-" else None,
        "level": level,
        "message": f'{req} -> {status}',
        "raw": line,
    }


def _parse_apache_common_line(line: str) -> dict[str, Any] | None:
    """Parse Apache Common log line."""
    m = RE_APACHE_COMMON.match(line)
    if not m:
        return None
    ip, ident, user, ts, req, status, size = m.groups()
    code = int(status)
    level = "ERROR" if code >= 500 else ("WARNING" if code >= 400 else "INFO")

    return {
        "timestamp": ts,
        "client_ip": ip,
        "user": user if user != "-" else None,
        "request": req,
        "status": code,
        "bytes": int(size) if size.isdigit() else 0,
        "level": level,
        "message": f'{req} -> {status}',
        "raw": line,
    }


def _parse_python_line(line: str) -> dict[str, Any] | None:
    """Parse standard Python log line."""
    m = RE_PY_DASH.match(line)
    if m:
        ts, logger, lvl, msg = m.groups()
        return {
            "timestamp": ts,
            "logger": logger,
            "level": lvl.upper(),
            "message": _sanitize_message(msg),
            "raw": line,
        }

    m = RE_PY_BRACKET.match(line)
    if m:
        ts, lvl, logger, msg = m.groups()
        return {
            "timestamp": ts,
            "logger": logger,
            "level": lvl.upper(),
            "message": _sanitize_message(msg),
            "raw": line,
        }

    m = RE_PY_COLON.match(line)
    if m:
        lvl, logger, msg = m.groups()
        if lvl.upper() in LEVEL_RANKS:
            return {
                "timestamp": None,
                "logger": logger,
                "level": lvl.upper(),
                "message": _sanitize_message(msg),
                "raw": line,
            }

    return None


PARSERS = {
    "json": _parse_json_line,
    "nginx_combined": _parse_nginx_combined_line,
    "apache_common": _parse_apache_common_line,
    "python": _parse_python_line,
    "syslog": _parse_syslog_line,
}


def _detect_format(lines: list[str]) -> tuple[str, float, dict[str, float]]:
    """Test candidate parsers against sample lines and return best match format."""
    sample = [line for line in lines[:50] if line.strip()]
    if not sample:
        return "syslog", 0.0, {}

    scores: dict[str, int] = collections.defaultdict(int)
    for line in sample:
        for fmt, parser_fn in PARSERS.items():
            if parser_fn(line) is not None:
                scores[fmt] += 1

    total = len(sample)
    normalized = {fmt: round(count / total, 2) for fmt, count in scores.items()}

    if not normalized:
        return "syslog", 0.0, {}

    best_fmt, best_score = max(normalized.items(), key=lambda item: item[1])
    return best_fmt, best_score, normalized


def _extract_traces_impl(text: str) -> list[dict[str, Any]]:
    """Extract Python stack traces from raw log text."""
    lines = text.splitlines()
    traces = []
    in_trace = False
    current_trace_lines: list[str] = []

    re_frame = re.compile(r'^\s*File "([^"]+)", line (\d+), in (.*)$')

    for line in lines:
        if "Traceback (most recent call last):" in line:
            if current_trace_lines:
                # Flush previous trace
                traces.append("\n".join(current_trace_lines))
                current_trace_lines = []
            in_trace = True
            current_trace_lines.append(line)
            continue

        if in_trace:
            current_trace_lines.append(line)
            # If line is not indented and looks like an exception (e.g. ValueError: msg), end trace
            if line and not line.startswith(" ") and not line.startswith("\t"):
                traces.append("\n".join(current_trace_lines))
                current_trace_lines = []
                in_trace = False

    if in_trace and current_trace_lines:
        traces.append("\n".join(current_trace_lines))

    results = []
    for raw_trace in traces:
        t_lines = raw_trace.splitlines()
        frames = []
        exc_type = "Exception"
        exc_msg = ""

        for tline in t_lines:
            fm = re_frame.match(tline)
            if fm:
                f_path, f_line, f_func = fm.groups()
                frames.append({
                    "file": f_path,
                    "line": int(f_line),
                    "function": f_func,
                })

        # Last line typically holds ExceptionName: message
        if t_lines:
            last = t_lines[-1].strip()
            if ":" in last:
                parts = last.split(":", 1)
                exc_type = parts[0].strip()
                exc_msg = parts[1].strip()
            else:
                exc_type = last

        results.append({
            "exception_type": exc_type,
            "message": exc_msg,
            "frames_count": len(frames),
            "frames": frames,
            "raw_trace": raw_trace,
        })

    return results


def log_parser(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Parse, detect format, aggregate, and extract stack traces from log lines."""
    del context
    try:
        args = arguments or {}
        action = str(args.get("action") or "").strip().lower()
        if not action:
            return {"ok": False, "success": False, "data": None, "result": None, "error": "Missing required 'action' parameter."}

        raw_text = _get_log_text(args.get("text"), args.get("path"))
        lines = raw_text.splitlines()

        if action == "detect_format":
            best_fmt, score, candidates = _detect_format(lines)
            payload = {
                "detected_format": best_fmt,
                "confidence": score,
                "candidates": candidates,
                "sample_lines_tested": min(len(lines), 50),
            }
            return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

        elif action == "extract_traces":
            traces = _extract_traces_impl(raw_text)
            payload = {
                "traces_count": len(traces),
                "traces": traces,
            }
            return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

        elif action in ("parse", "aggregate"):
            fmt_arg = str(args.get("format") or "auto").strip().lower()
            if fmt_arg == "auto":
                fmt_arg, _, _ = _detect_format(lines)

            parser_fn = PARSERS.get(fmt_arg)
            if not parser_fn:
                return {
                    "ok": False,
                    "success": False,
                    "data": None,
                    "result": None,
                    "error": f"Unsupported log format: {fmt_arg!r}. Supported formats: auto, json, syslog, nginx_combined, apache_common, python.",
                }

            min_level_str = args.get("min_level")
            min_rank = 0
            if min_level_str:
                min_rank = LEVEL_RANKS.get(str(min_level_str).upper(), 0)

            limit = max(1, min(int(args.get("limit") if args.get("limit") is not None else 1000), MAX_RECORDS_LIMIT))

            records = []
            unparsed = 0
            for line in lines:
                if not line.strip():
                    continue
                parsed_rec = parser_fn(line)
                if parsed_rec is None:
                    unparsed += 1
                    continue

                rec_level = parsed_rec.get("level", "INFO").upper()
                rec_rank = LEVEL_RANKS.get(rec_level, 20)
                if min_rank > 0 and rec_rank < min_rank:
                    continue

                records.append(parsed_rec)

            if action == "parse":
                truncated = len(records) > limit
                payload = {
                    "format": fmt_arg,
                    "total_lines": len(lines),
                    "parsed_count": len(records),
                    "unparsed_count": unparsed,
                    "truncated": truncated,
                    "records": records[:limit],
                }
                return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

            else:  # action == "aggregate"
                by_level: dict[str, int] = collections.defaultdict(int)
                status_codes: dict[str, int] = collections.defaultdict(int)
                msg_counts: dict[str, int] = collections.defaultdict(int)

                for r in records:
                    lvl = r.get("level", "INFO").upper()
                    by_level[lvl] += 1

                    if "status" in r and r["status"]:
                        status_codes[str(r["status"])] += 1

                    msg = r.get("message", "")
                    if msg:
                        # Normalize message (strip numbers)
                        summary = re.sub(r"\d+", "N", msg)[:80]
                        msg_counts[summary] += 1

                top_messages = [
                    {"message": msg, "count": count}
                    for msg, count in sorted(msg_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                ]

                error_count = sum(by_level.get(lvl, 0) for lvl in ["ERROR", "CRITICAL", "FATAL"])

                payload = {
                    "total_records": len(records),
                    "by_level": dict(by_level),
                    "status_codes": dict(status_codes),
                    "error_count": error_count,
                    "top_messages": top_messages,
                    "format": fmt_arg,
                }
                return {"ok": True, "success": True, "data": payload, "result": payload, "error": None}

        else:
            return {
                "ok": False,
                "success": False,
                "data": None,
                "result": None,
                "error": f"Unsupported action: {action!r}. Supported actions: parse, detect_format, aggregate, extract_traces.",
            }

    except Exception as err:
        return {
            "ok": False,
            "success": False,
            "data": None,
            "result": None,
            "error": f"{type(err).__name__}: {err}",
        }


TOOL = {
    "name": "log_parser",
    "description": (
        "Pure Python structured log parsing, automatic format detection (Syslog, Nginx/Apache CLF, "
        "JSON lines, Python logger), severity aggregation, secret sanitization, and Python stack trace extraction."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["parse", "detect_format", "aggregate", "extract_traces"],
                "description": "Operation to perform.",
            },
            "text": {"type": "string", "description": "Raw log text content."},
            "path": {"type": "string", "description": "Local path to log file."},
            "format": {
                "type": "string",
                "enum": ["auto", "json", "syslog", "nginx_combined", "apache_common", "python"],
                "description": "Log syntax parser (default: 'auto').",
            },
            "min_level": {
                "type": "string",
                "enum": ["DEBUG", "INFO", "WARN", "WARNING", "ERROR", "CRITICAL", "FATAL"],
                "description": "Filter records by minimum severity level.",
            },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 5000,
                "description": "Maximum records to return (1-5000, default: 1000).",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": log_parser,
    "approval": False,
}
