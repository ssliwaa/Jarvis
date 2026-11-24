"""Zero-dependency OpenTelemetry Flight Recorder and Observability Engine for Jarvis.

Synthesizes architectural patterns from:
- Langfuse (#14): Hierarchical trace-span trees, token consumption accounting, execution status.
- Phoenix by Arize (#15): OTel GenAI semantic conventions, latency percentiles, tree diagnostics.
- OpenLIT (#16): OTLP standard JSON export, zero-overhead SQLite WAL flight recorder, hardware telemetry.

Exclusively uses the Python standard library. Zero external dependencies.
"""

from __future__ import annotations

import json
import math
import os
import sqlite3
import time
import uuid
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
    "start_trace",
    "end_trace",
    "start_span",
    "end_span",
    "record_event",
    "query_traces",
    "export_otlp",
    "get_metrics",
})

KNOWN_ARGUMENTS: frozenset[str] = frozenset({
    "action",
    "trace_id",
    "span_id",
    "parent_span_id",
    "name",
    "span_type",
    "attributes",
    "tokens",
    "status",
    "event_name",
    "event_data",
    "db_path",
    "export_path",
    "limit",
})


class TracerError(Exception):
    """Base exception for otel_tracer."""


class PathSecurityError(TracerError):
    """Raised when db_path or export_path resolves outside ALLOWED_ROOTS."""


class SensitivePathError(TracerError):
    """Raised when path touches sensitive directories or files."""


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


def _validate_and_resolve_path(raw_path: Any, default_filename: str) -> Path:
    """Validate and canonically resolve path within ALLOWED_ROOTS."""
    if raw_path is None or raw_path == "":
        p = Path("/tmp") / default_filename
    elif isinstance(raw_path, (str, Path)):
        path_str = str(raw_path).strip()
        if not path_str:
            p = Path("/tmp") / default_filename
        else:
            if len(path_str) > 4096 or "\x00" in path_str:
                raise ValueError("Invalid path string: exceeds length limit or contains null bytes.")
            p = Path(path_str).expanduser()
            if not p.is_absolute():
                p = Path.cwd() / p
    else:
        raise ValueError("Parameter must be a valid path string.")

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

    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def _get_connection(db_path: Path) -> sqlite3.Connection:
    """Open SQLite connection and ensure trace schemas exist."""
    conn = sqlite3.connect(str(db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    with conn:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS traces (
                trace_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                start_time REAL NOT NULL,
                end_time REAL,
                duration_ms REAL,
                status TEXT NOT NULL,
                attributes_json TEXT
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS spans (
                span_id TEXT PRIMARY KEY,
                trace_id TEXT NOT NULL,
                parent_span_id TEXT,
                name TEXT NOT NULL,
                span_type TEXT NOT NULL,
                start_time REAL NOT NULL,
                end_time REAL,
                duration_ms REAL,
                prompt_tokens INTEGER DEFAULT 0,
                completion_tokens INTEGER DEFAULT 0,
                total_tokens INTEGER DEFAULT 0,
                status TEXT NOT NULL,
                attributes_json TEXT,
                FOREIGN KEY(trace_id) REFERENCES traces(trace_id)
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS span_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                span_id TEXT,
                trace_id TEXT,
                event_name TEXT NOT NULL,
                timestamp REAL NOT NULL,
                attributes_json TEXT
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_spans_trace ON spans(trace_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_spans_start ON spans(start_time);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_span ON span_events(span_id);")
    return conn


def _start_trace(args: dict[str, Any], conn: sqlite3.Connection) -> dict[str, Any]:
    """Initialize a new root execution trace."""
    trace_id = str(args.get("trace_id") or uuid.uuid4())
    name = str(args.get("name") or "agent_execution")
    attrs = args.get("attributes") or {}
    start_time = time.time()
    status = str(args.get("status") or "UNSET")

    with conn:
        conn.execute(
            """
            INSERT INTO traces (trace_id, name, start_time, status, attributes_json)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(trace_id) DO UPDATE SET
                name = excluded.name,
                attributes_json = excluded.attributes_json
            """,
            (trace_id, name, start_time, status, json.dumps(attrs)),
        )

    return {
        "trace_id": trace_id,
        "name": name,
        "start_time": start_time,
        "status": status,
        "attributes": attrs,
    }


def _end_trace(args: dict[str, Any], conn: sqlite3.Connection) -> dict[str, Any]:
    """Close an active trace and calculate total duration."""
    trace_id = args.get("trace_id")
    if not trace_id:
        raise TracerError("Missing required parameter 'trace_id' for end_trace.")

    status = str(args.get("status") or "OK")
    extra_attrs = args.get("attributes")
    end_time = time.time()

    cur = conn.cursor()
    row = cur.execute("SELECT * FROM traces WHERE trace_id = ?", (trace_id,)).fetchone()
    if not row:
        raise TracerError(f"Trace with ID '{trace_id}' not found.")

    start_time = float(row["start_time"])
    duration_ms = round((end_time - start_time) * 1000.0, 2)

    attrs = json.loads(row["attributes_json"] or "{}")
    if extra_attrs and isinstance(extra_attrs, dict):
        attrs.update(extra_attrs)

    with conn:
        conn.execute(
            """
            UPDATE traces
            SET end_time = ?, duration_ms = ?, status = ?, attributes_json = ?
            WHERE trace_id = ?
            """,
            (end_time, duration_ms, status, json.dumps(attrs), trace_id),
        )

    # Calculate aggregate tokens across child spans
    token_row = cur.execute(
        """
        SELECT SUM(prompt_tokens) as p, SUM(completion_tokens) as c, SUM(total_tokens) as t
        FROM spans WHERE trace_id = ?
        """,
        (trace_id,),
    ).fetchone()

    return {
        "trace_id": trace_id,
        "name": row["name"],
        "start_time": start_time,
        "end_time": end_time,
        "duration_ms": duration_ms,
        "status": status,
        "total_prompt_tokens": token_row["p"] or 0,
        "total_completion_tokens": token_row["c"] or 0,
        "total_tokens": token_row["t"] or 0,
        "attributes": attrs,
    }


def _start_span(args: dict[str, Any], conn: sqlite3.Connection) -> dict[str, Any]:
    """Open a child span inside a trace."""
    trace_id = args.get("trace_id")
    if not trace_id:
        raise TracerError("Missing required parameter 'trace_id' for start_span.")

    # 16-hex char span ID
    span_id = str(args.get("span_id") or uuid.uuid4().hex[:16])
    parent_span_id = args.get("parent_span_id")
    name = str(args.get("name") or "operation_span")
    span_type = str(args.get("span_type") or "tool_call")
    attrs = args.get("attributes") or {}
    status = str(args.get("status") or "UNSET")
    start_time = time.time()

    with conn:
        conn.execute(
            """
            INSERT INTO spans (
                span_id, trace_id, parent_span_id, name, span_type,
                start_time, status, attributes_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                span_id,
                trace_id,
                parent_span_id,
                name,
                span_type,
                start_time,
                status,
                json.dumps(attrs),
            ),
        )

    return {
        "span_id": span_id,
        "trace_id": trace_id,
        "parent_span_id": parent_span_id,
        "name": name,
        "span_type": span_type,
        "start_time": start_time,
        "status": status,
    }


def _end_span(args: dict[str, Any], conn: sqlite3.Connection) -> dict[str, Any]:
    """Close an active span and record token usage and status."""
    span_id = args.get("span_id")
    if not span_id:
        raise TracerError("Missing required parameter 'span_id' for end_span.")

    status = str(args.get("status") or "OK")
    tokens = args.get("tokens") or {}
    extra_attrs = args.get("attributes")
    end_time = time.time()

    cur = conn.cursor()
    row = cur.execute("SELECT * FROM spans WHERE span_id = ?", (span_id,)).fetchone()
    if not row:
        raise TracerError(f"Span with ID '{span_id}' not found.")

    start_time = float(row["start_time"])
    duration_ms = round((end_time - start_time) * 1000.0, 2)

    prompt_tok = int(tokens.get("prompt_tokens") or 0)
    compl_tok = int(tokens.get("completion_tokens") or 0)
    total_tok = int(tokens.get("total_tokens") or (prompt_tok + compl_tok))

    attrs = json.loads(row["attributes_json"] or "{}")
    if extra_attrs and isinstance(extra_attrs, dict):
        attrs.update(extra_attrs)

    with conn:
        conn.execute(
            """
            UPDATE spans
            SET end_time = ?, duration_ms = ?, prompt_tokens = ?, completion_tokens = ?,
                total_tokens = ?, status = ?, attributes_json = ?
            WHERE span_id = ?
            """,
            (
                end_time,
                duration_ms,
                prompt_tok,
                compl_tok,
                total_tok,
                status,
                json.dumps(attrs),
                span_id,
            ),
        )

    return {
        "span_id": span_id,
        "trace_id": row["trace_id"],
        "name": row["name"],
        "duration_ms": duration_ms,
        "prompt_tokens": prompt_tok,
        "completion_tokens": compl_tok,
        "total_tokens": total_tok,
        "status": status,
        "attributes": attrs,
    }


def _record_event(args: dict[str, Any], conn: sqlite3.Connection) -> dict[str, Any]:
    """Record an atomic milestone event or log entry inside a span."""
    span_id = args.get("span_id")
    trace_id = args.get("trace_id")
    event_name = str(args.get("event_name") or args.get("name") or "milestone")
    event_data = args.get("event_data") or args.get("attributes") or {}
    ts = time.time()

    with conn:
        cur = conn.execute(
            """
            INSERT INTO span_events (span_id, trace_id, event_name, timestamp, attributes_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (span_id, trace_id, event_name, ts, json.dumps(event_data)),
        )
        event_id = cur.lastrowid

    return {
        "event_id": event_id,
        "span_id": span_id,
        "trace_id": trace_id,
        "event_name": event_name,
        "timestamp": ts,
        "data": event_data,
    }


def _query_traces(args: dict[str, Any], conn: sqlite3.Connection) -> dict[str, Any]:
    """Retrieve trace trees (traces with nested child spans and events)."""
    target_trace_id = args.get("trace_id")
    filter_status = args.get("status")
    filter_name = args.get("name")
    limit = max(1, min(int(args.get("limit") or 50), 500))

    query_parts = ["SELECT * FROM traces"]
    conds = []
    params = []
    if target_trace_id:
        conds.append("trace_id = ?")
        params.append(target_trace_id)
    if filter_status:
        conds.append("status = ?")
        params.append(filter_status)
    if filter_name:
        conds.append("name LIKE ?")
        params.append(f"%{filter_name}%")

    if conds:
        query_parts.append("WHERE " + " AND ".join(conds))
    query_parts.append("ORDER BY start_time DESC LIMIT ?")
    params.append(limit)

    cur = conn.cursor()
    trace_rows = cur.execute(" ".join(query_parts), tuple(params)).fetchall()

    results = []
    for t in trace_rows:
        tid = t["trace_id"]
        # Fetch spans for this trace
        spans_cur = cur.execute(
            "SELECT * FROM spans WHERE trace_id = ? ORDER BY start_time ASC",
            (tid,),
        )
        spans = []
        for s in spans_cur.fetchall():
            sid = s["span_id"]
            # Fetch events for span
            ev_cur = cur.execute(
                "SELECT * FROM span_events WHERE span_id = ? ORDER BY timestamp ASC",
                (sid,),
            )
            events = [
                {
                    "event_name": ev["event_name"],
                    "timestamp": ev["timestamp"],
                    "data": json.loads(ev["attributes_json"] or "{}"),
                }
                for ev in ev_cur.fetchall()
            ]
            spans.append({
                "span_id": sid,
                "parent_span_id": s["parent_span_id"],
                "name": s["name"],
                "span_type": s["span_type"],
                "start_time": s["start_time"],
                "end_time": s["end_time"],
                "duration_ms": s["duration_ms"],
                "tokens": {
                    "prompt_tokens": s["prompt_tokens"],
                    "completion_tokens": s["completion_tokens"],
                    "total_tokens": s["total_tokens"],
                },
                "status": s["status"],
                "attributes": json.loads(s["attributes_json"] or "{}"),
                "events": events,
            })

        results.append({
            "trace_id": tid,
            "name": t["name"],
            "start_time": t["start_time"],
            "end_time": t["end_time"],
            "duration_ms": t["duration_ms"],
            "status": t["status"],
            "attributes": json.loads(t["attributes_json"] or "{}"),
            "span_count": len(spans),
            "spans": spans,
        })

    return {"trace_count": len(results), "traces": results}


def _export_otlp(args: dict[str, Any], conn: sqlite3.Connection) -> dict[str, Any]:
    """Export traces and spans into standard OpenTelemetry Protocol (OTLP) JSON format."""
    query_res = _query_traces(args, conn)
    traces = query_res["traces"]

    resource_spans = []
    for trace in traces:
        scope_spans = []
        for span in trace["spans"]:
            # Format attributes into OTel key-value format
            otel_attrs = []
            for k, v in span["attributes"].items():
                if isinstance(v, bool):
                    val_dict = {"boolValue": v}
                elif isinstance(v, int):
                    val_dict = {"intValue": v}
                elif isinstance(v, float):
                    val_dict = {"doubleValue": v}
                else:
                    val_dict = {"stringValue": str(v)}
                otel_attrs.append({"key": k, "value": val_dict})

            # Add token usage attributes in OTel GenAI semantic conventions
            tokens = span.get("tokens", {})
            otel_attrs.extend([
                {"key": "gen_ai.usage.prompt_tokens", "value": {"intValue": tokens.get("prompt_tokens", 0)}},
                {"key": "gen_ai.usage.completion_tokens", "value": {"intValue": tokens.get("completion_tokens", 0)}},
                {"key": "gen_ai.usage.total_tokens", "value": {"intValue": tokens.get("total_tokens", 0)}},
            ])

            start_nano = int(span["start_time"] * 1e9)
            end_nano = int((span["end_time"] or span["start_time"]) * 1e9)

            otel_events = [
                {
                    "timeUnixNano": int(ev["timestamp"] * 1e9),
                    "name": ev["event_name"],
                    "attributes": [{"key": ek, "value": {"stringValue": str(ev["data"].get(ek))}} for ek in ev["data"]],
                }
                for ev in span.get("events", [])
            ]

            span_dict = {
                "traceId": trace["trace_id"].replace("-", ""),
                "spanId": span["span_id"],
                "parentSpanId": span.get("parent_span_id") or "",
                "name": span["name"],
                "kind": 1,  # SPAN_KIND_INTERNAL
                "startTimeUnixNano": str(start_nano),
                "endTimeUnixNano": str(end_nano),
                "attributes": otel_attrs,
                "events": otel_events,
                "status": {"code": 1 if span["status"] == "OK" else (2 if span["status"] == "ERROR" else 0)},
            }
            scope_spans.append(span_dict)

        resource_spans.append({
            "resource": {
                "attributes": [
                    {"key": "service.name", "value": {"stringValue": "jarvis-operator"}},
                    {"key": "telemetry.sdk.language", "value": {"stringValue": "python"}},
                    {"key": "trace.name", "value": {"stringValue": trace["name"]}},
                ]
            },
            "scopeSpans": [
                {
                    "scope": {"name": "jarvis.otel_tracer", "version": "1.0.0"},
                    "spans": scope_spans,
                }
            ],
        })

    otlp_payload = {"resourceSpans": resource_spans}

    export_path = args.get("export_path")
    if export_path:
        resolved = _validate_and_resolve_path(export_path, "otlp_export.json")
        atomic_write_text(resolved, json.dumps(otlp_payload, indent=2), dir_mode=None)
        return {"exported_path": str(resolved), "traces_exported": len(traces), "otlp": otlp_payload}

    return {"traces_exported": len(traces), "otlp": otlp_payload}


def _get_metrics(args: dict[str, Any], conn: sqlite3.Connection) -> dict[str, Any]:
    """Compute P50/P90/P95 latency percentiles and token spend across spans."""
    cur = conn.cursor()
    cur.execute("SELECT duration_ms FROM spans WHERE duration_ms IS NOT NULL ORDER BY duration_ms ASC")
    durations = [row[0] for row in cur.fetchall()]

    def _percentile(data: list[float], p: float) -> float:
        if not data:
            return 0.0
        k = (len(data) - 1) * p
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return round(data[int(k)], 2)
        d0 = data[int(f)] * (c - k)
        d1 = data[int(c)] * (k - f)
        return round(d0 + d1, 2)

    tok_row = cur.execute(
        """
        SELECT
            COUNT(*) as total_spans,
            SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) as error_spans,
            SUM(prompt_tokens) as p,
            SUM(completion_tokens) as c,
            SUM(total_tokens) as t
        FROM spans
        """
    ).fetchone()

    # Breakdown by span_type
    type_cur = cur.execute(
        """
        SELECT span_type, COUNT(*) as cnt, AVG(duration_ms) as avg_d, SUM(total_tokens) as tok
        FROM spans GROUP BY span_type
        """
    )
    by_type = {
        row["span_type"]: {
            "count": row["cnt"],
            "avg_duration_ms": round(row["avg_d"] or 0.0, 2),
            "tokens": row["tok"] or 0,
        }
        for row in type_cur.fetchall()
    }

    total_spans = tok_row["total_spans"] or 0
    error_spans = tok_row["error_spans"] or 0
    error_rate = round((error_spans / total_spans) * 100.0, 2) if total_spans > 0 else 0.0

    return {
        "total_spans": total_spans,
        "error_spans": error_spans,
        "error_rate_pct": error_rate,
        "latency_percentiles_ms": {
            "p50": _percentile(durations, 0.50),
            "p90": _percentile(durations, 0.90),
            "p95": _percentile(durations, 0.95),
            "p99": _percentile(durations, 0.99),
        },
        "token_usage": {
            "prompt_tokens": tok_row["p"] or 0,
            "completion_tokens": tok_row["c"] or 0,
            "total_tokens": tok_row["t"] or 0,
        },
        "spans_by_type": by_type,
    }


def otel_tracer(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Main dispatch handler for otel_tracer operator tool."""
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

    db_path_raw = arguments.get("db_path")
    try:
        resolved_db = _validate_and_resolve_path(db_path_raw, "jarvis_otel_traces.sqlite3")
    except Exception as exc:
        return _envelope_error(exc)

    conn = _get_connection(resolved_db)
    try:
        if action == "start_trace":
            res = _start_trace(arguments, conn)
        elif action == "end_trace":
            res = _end_trace(arguments, conn)
        elif action == "start_span":
            res = _start_span(arguments, conn)
        elif action == "end_span":
            res = _end_span(arguments, conn)
        elif action == "record_event":
            res = _record_event(arguments, conn)
        elif action == "query_traces":
            res = _query_traces(arguments, conn)
        elif action == "export_otlp":
            res = _export_otlp(arguments, conn)
        elif action == "get_metrics":
            res = _get_metrics(arguments, conn)
        else:
            return _envelope_error(f"Unhandled action '{action}'.")

        return _envelope_success(res)
    except TracerError as te:
        return _envelope_error(te)
    except (ValueError, TypeError) as err:
        return _envelope_error(err)
    except Exception as exc:
        return _envelope_error(exc)
    finally:
        conn.close()


TOOL = {
    "name": "otel_tracer",
    "description": (
        "Zero-dependency OpenTelemetry flight recorder and trace diagnostics engine. "
        "Captures hierarchical trace trees, span durations, GenAI token consumption, "
        "percentile metrics, and exports standard OTLP JSON format."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "start_trace",
                    "end_trace",
                    "start_span",
                    "end_span",
                    "record_event",
                    "query_traces",
                    "export_otlp",
                    "get_metrics",
                ],
                "description": "Tracer action to execute.",
            },
            "trace_id": {
                "type": "string",
                "description": "Unique identifier for execution trace (UUID4).",
            },
            "span_id": {
                "type": "string",
                "description": "16-hex character Span ID.",
            },
            "parent_span_id": {
                "type": "string",
                "description": "Parent span ID for nested sub-operations.",
            },
            "name": {
                "type": "string",
                "description": "Name of the trace, span, or event.",
            },
            "span_type": {
                "type": "string",
                "description": "Category of span (e.g. agent_turn, tool_call, llm_generation, evaluation).",
            },
            "attributes": {
                "type": "object",
                "description": "Metadata key-value pairs following OTel conventions.",
            },
            "tokens": {
                "type": "object",
                "description": "Token usage dictionary with prompt_tokens, completion_tokens, total_tokens.",
            },
            "status": {
                "type": "string",
                "enum": ["OK", "ERROR", "UNSET"],
                "description": "Completion status code.",
            },
            "event_name": {
                "type": "string",
                "description": "Milestone event name for record_event.",
            },
            "event_data": {
                "type": "object",
                "description": "Event payload or attributes.",
            },
            "db_path": {
                "type": "string",
                "description": "Optional SQLite database path within ALLOWED_ROOTS.",
            },
            "export_path": {
                "type": "string",
                "description": "Optional file path within ALLOWED_ROOTS for export_otlp JSON.",
            },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 500,
                "description": "Maximum records to return.",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": otel_tracer,
    "approval": False,
}
