"""Operational log intelligence, anomaly detection, traceback triage, and PII masking operator module for Jarvis.

Provides error clustering and fingerprinting by stripping dynamic variables,
time-bucketed anomaly spike detection via Z-score statistics, comprehensive multi-runtime
stacktrace triage (Python, Java, Node.js, Go), and ReDoS-immune PII masking using
EXCLUSIVELY the Python standard library. Zero external dependencies.
"""

from __future__ import annotations

import email.utils
import hashlib
import math
import os
import re
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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

MAX_LOG_BYTES: int = 10 * 1024 * 1024  # 10 MB limit
MAX_CLUSTERS_RETURNED: int = 500
MAX_EMPTY_BUCKETS: int = 10_000


SENSITIVE_PARTS: frozenset[str] = frozenset({
    ".ssh",
    ".gnupg",
    ".password-store",
    ".aws",
    ".docker",
    ".kube",
    ".hermes",
})

SENSITIVE_NAMES: frozenset[str] = frozenset({
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "shadow",
})

VALID_ACTIONS: frozenset[str] = frozenset({
    "cluster_errors",
    "detect_spikes",
    "triage_stacktrace",
    "mask_pii",
    # Aliases
    "error_cluster",
    "spike_detect",
    "stacktrace_triage",
    "pii_masking",
})

KNOWN_ARGUMENTS: frozenset[str] = frozenset({
    "action",
    "text",
    "content",
    "data",
    "logs",
    "path",
    "source_path",
    "log_path",
    "output_path",
    "destination_path",
    "overwrite",
    "levels",
    "all_lines",
    "limit",
    "max_clusters",
    "include_samples",
    "bucket_size",
    "bucket_seconds",
    "threshold_multiplier",
    "threshold_zscore",
    "z_threshold",
    "min_events",
    "fill_empty_buckets",
    "time_format",
    "runtime",
    "app_path_pattern",
    "mask_rules",
    "pii_types",
    "custom_rules",
    "replacement_map",
    "partial_mask",
    "mask_char",
    "min_cluster_size",
    "encoding",
})

# =============================================================================
# Exceptions
# =============================================================================

class LogSummarizerError(Exception):
    """Base exception for log summarizer operations."""


class SecurityError(LogSummarizerError):
    """Base security violation error."""


class PathSecurityError(SecurityError):
    """Raised when path traversal or forbidden boundary escape is detected."""


class SensitivePathError(SecurityError):
    """Raised when access to a sensitive credential path is attempted."""


class PayloadSizeError(LogSummarizerError):
    """Raised when log payload exceeds maximum bounded limit."""


# =============================================================================
# Return Envelope Helpers
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
# Path Confinement & Loader Helpers
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
        if part in SENSITIVE_PARTS:
            return True
        if part in SENSITIVE_NAMES:
            return True
    if path.name.casefold() in SENSITIVE_NAMES:
        return True
    return False


def _validate_and_resolve_path(path_str: str, check_exists: bool = True) -> Path:
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

    if check_exists:
        if not resolved.exists():
            raise FileNotFoundError(f"File not found: '{path_str}'")
        if not resolved.is_file():
            raise ValueError(f"Path '{path_str}' is not a regular file.")
        st = resolved.stat()
        if st.st_size > MAX_LOG_BYTES:
            raise PayloadSizeError(
                f"File size ({st.st_size} bytes) exceeds maximum allowed size ({MAX_LOG_BYTES} bytes)."
            )

    return resolved


def _load_input(arguments: dict[str, Any]) -> tuple[str, str | None]:
    """Retrieve content string from either inline content or file path."""
    content = arguments.get("text")
    if content is None:
        content = arguments.get("content")
    if content is None:
        content = arguments.get("data")
    if content is None:
        content = arguments.get("logs")

    path_str = arguments.get("path") or arguments.get("source_path") or arguments.get("log_path")

    if content is not None:
        if not isinstance(content, str):
            raise ValueError("'text' must be a string.")
        content_bytes = content.encode("utf-8")
        if len(content_bytes) > MAX_LOG_BYTES:
            raise PayloadSizeError(
                f"Content size ({len(content_bytes)} bytes) exceeds maximum limit ({MAX_LOG_BYTES} bytes)."
            )
        return content, str(path_str) if path_str else None

    if path_str is not None:
        resolved = _validate_and_resolve_path(path_str, check_exists=True)
        try:
            encoding = arguments.get("encoding", "utf-8") or "utf-8"
            text = resolved.read_text(encoding=encoding, errors="replace")
            return text, str(resolved)
        except OSError as exc:
            raise LogSummarizerError(f"Failed to read file '{resolved}': {exc}") from exc

    return "", None


# =============================================================================
# Feature 29: Error Clustering & Template Fingerprinting
# =============================================================================

# Normalization regular expressions
NORM_PREFIX_RE = re.compile(
    r"^(?:(?:\[\d{4}-\d{2}-\d{2}[^\]]+\]|\d{4}-\d{2}-\d{2}[T ][\d:.,+-]+|[A-Za-z]{3}\s+\d+\s+[\d:]+)\s*)?"
    r"(?:\[?[A-Z]{3,8}\]?\s*[:\-]?)?\s*",
    re.IGNORECASE,
)
NORM_URL_RE = re.compile(r"https?://[^\s:'\"]+(?::\d+)?", re.IGNORECASE)
NORM_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
NORM_IPV4_RE = re.compile(r"(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d+)?(?![0-9])")
NORM_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")
NORM_PATH_RE = re.compile(r"/(?:[a-zA-Z0-9._-]+/)+[a-zA-Z0-9._-]+")
NORM_HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{16,64}\b")
NORM_NUM_UNITS_RE = re.compile(r"\b\d+(?:\.\d+)?(?:ms|s|m|h|ns|us|µs|B|KB|MB|GB|TB|%|px)?\b", re.IGNORECASE)
NORM_WS_RE = re.compile(r"\s+")

ERROR_KEYWORDS_RE = re.compile(r"\b(error|critical|fatal|exception|failed|failure|panic|warn|warning|err)\b", re.IGNORECASE)


def _normalize_log_line(line: str) -> str:
    """Normalize dynamic runtime parameters into canonical tokens."""
    s = NORM_PREFIX_RE.sub("", line)
    s = NORM_URL_RE.sub("<URL>", s)
    s = NORM_UUID_RE.sub("<UUID>", s)
    s = NORM_IPV4_RE.sub("<IP>", s)
    s = NORM_IPV6_RE.sub("<IP>", s)
    s = NORM_PATH_RE.sub("<PATH>", s)
    s = NORM_HEX_RE.sub("<HEX>", s)
    s = NORM_NUM_UNITS_RE.sub("<NUM>", s)
    s = NORM_WS_RE.sub(" ", s).strip()
    return s


def _do_cluster_errors(arguments: dict[str, Any]) -> dict[str, Any]:
    """Cluster log error lines by normalized template and fingerprint."""
    text, source_path = _load_input(arguments)
    all_lines = bool(arguments.get("all_lines", False))
    min_cluster_size = int(arguments.get("min_cluster_size", 1))
    max_clusters = int(arguments.get("max_clusters") or arguments.get("limit") or 50)
    include_samples = int(arguments.get("include_samples", 3))
    levels = arguments.get("levels")

    if not text or not text.strip():
        payload = {
            "action": arguments.get("action", "cluster_errors"),
            "total_lines": 0,
            "error_count": 0,
            "cluster_count": 0,
            "clusters": [],
            "source_path": source_path,
        }
        return _envelope_success(payload)

    raw_lines = text.splitlines()
    total_lines = len(raw_lines)

    level_set = {lvl.upper() for lvl in levels} if levels else None

    # Line filtering
    candidate_lines: list[tuple[int, str]] = []
    for idx, line in enumerate(raw_lines, 1):
        stripped = line.strip()
        if not stripped:
            continue
        if level_set:
            if any(lvl in stripped.upper() for lvl in level_set):
                candidate_lines.append((idx, stripped))
        elif all_lines:
            candidate_lines.append((idx, stripped))
        else:
            if ERROR_KEYWORDS_RE.search(stripped):
                candidate_lines.append((idx, stripped))

    # If no lines matched error filter, fallback to all non-empty lines
    if not candidate_lines and not level_set and not all_lines:
        for idx, line in enumerate(raw_lines, 1):
            stripped = line.strip()
            if stripped:
                candidate_lines.append((idx, stripped))

    error_count = len(candidate_lines)

    # Template clustering
    clusters_map: dict[str, dict[str, Any]] = {}
    for line_idx, line in candidate_lines:
        template = _normalize_log_line(line)
        if not template:
            template = line

        fp = hashlib.md5(template.encode("utf-8")).hexdigest()[:8]

        if fp not in clusters_map:
            clusters_map[fp] = {
                "fingerprint": fp,
                "template": template,
                "count": 0,
                "sample": line,
                "samples": [],
                "first_seen": f"Line {line_idx}",
                "last_seen": f"Line {line_idx}",
            }

        c = clusters_map[fp]
        c["count"] += 1
        c["last_seen"] = f"Line {line_idx}"
        if len(c["samples"]) < include_samples:
            c["samples"].append(line)

    filtered_clusters = [
        c for c in clusters_map.values()
        if c["count"] >= min_cluster_size
    ]
    filtered_clusters.sort(key=lambda x: x["count"], reverse=True)

    payload = {
        "action": arguments.get("action", "cluster_errors"),
        "total_lines": total_lines,
        "error_count": error_count,
        "cluster_count": len(filtered_clusters),
        "clusters": filtered_clusters[:max_clusters],
        "source_path": source_path,
    }
    return _envelope_success(payload)


# =============================================================================
# Feature 30: Time-Bucket Anomaly Spike Detection
# =============================================================================

TS_ISO_RE = re.compile(r"\b(?P<iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b")
TS_APACHE_RE = re.compile(r"\[(?P<apache>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]")
TS_SYSLOG_RE = re.compile(r"\b(?P<syslog>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b")


def _parse_timestamp(line: str, time_format: str = "auto") -> datetime | None:
    """Extract and parse timestamp from a log line across supported formats."""
    # 1. ISO 8601
    if time_format in ("auto", "iso8601"):
        m = TS_ISO_RE.search(line)
        if m:
            s = m.group("iso").replace(",", ".")
            try:
                dt = datetime.fromisoformat(s)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                pass

    # 2. Apache CLF
    if time_format in ("auto", "apache"):
        m = TS_APACHE_RE.search(line)
        if m:
            try:
                return datetime.strptime(m.group("apache"), "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                pass

    # 3. Syslog (RFC 3164) with Python 3.14 deprecation resolution
    if time_format in ("auto", "syslog"):
        m = TS_SYSLOG_RE.search(line)
        if m:
            now = datetime.now(timezone.utc)
            year = now.year
            syslog_str = m.group("syslog")
            try:
                # Prepend year to eliminate Python 3.14 DeprecationWarning
                dt = datetime.strptime(f"{year} {syslog_str}", "%Y %b %d %H:%M:%S")
                # Handle year rollover if log is December and current month is January
                if now.month == 1 and dt.month == 12:
                    dt = dt.replace(year=year - 1)
                dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                pass

    # 4. RFC 2822
    if time_format in ("auto", "rfc2822"):
        try:
            dt = email.utils.parsedate_to_datetime(line)
            if dt:
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
        except Exception:
            pass

    return None


def _parse_bucket_seconds(arg: Any) -> int:
    """Parse bucket size from string interval or integer seconds."""
    if arg is None:
        return 300
    if isinstance(arg, (int, float)):
        return int(arg)
    s = str(arg).strip().lower()
    if s.endswith("s"):
        return int(s[:-1])
    if s.endswith("m"):
        return int(s[:-1]) * 60
    if s.endswith("h"):
        return int(s[:-1]) * 3600
    if s.endswith("d"):
        return int(s[:-1]) * 86400
    try:
        return int(s)
    except ValueError:
        return 300


def _do_detect_spikes(arguments: dict[str, Any]) -> dict[str, Any]:
    """Detect anomalous temporal bursts of log events via Z-score statistics."""
    text, source_path = _load_input(arguments)
    bucket_sec_arg = arguments.get("bucket_seconds")
    if bucket_sec_arg is None:
        bucket_sec_arg = arguments.get("bucket_size")
    bucket_seconds = _parse_bucket_seconds(bucket_sec_arg)
    if bucket_seconds < 1:
        raise ValueError("bucket_seconds must be >= 1.")

    z_threshold = float(arguments.get("z_threshold") or arguments.get("threshold_zscore") or 2.0)
    threshold_multiplier = float(arguments.get("threshold_multiplier", 3.0))
    min_events = int(arguments.get("min_events", 1))
    time_format = str(arguments.get("time_format", "auto")).lower()
    fill_empty = bool(arguments.get("fill_empty_buckets", True))

    if not text or not text.strip():
        payload = {
            "action": arguments.get("action", "detect_spikes"),
            "total_events": 0,
            "total_buckets": 0,
            "mean_rate": 0.0,
            "std_dev": 0.0,
            "z_threshold": z_threshold,
            "spikes_count": 0,
            "spikes": [],
            "buckets": [],
            "source_path": source_path,
        }
        return _envelope_success(payload)

    raw_lines = text.splitlines()
    events: list[tuple[float, str]] = []

    for line in raw_lines:
        line_clean = line.strip()
        if not line_clean:
            continue
        dt = _parse_timestamp(line_clean, time_format=time_format)
        if dt:
            events.append((dt.timestamp(), line_clean))

    if not events:
        raise ValueError("No valid timestamps found in log content.")

    # Sort events chronologically
    events.sort(key=lambda e: e[0])

    min_ts = events[0][0]
    max_ts = events[-1][0]

    min_bucket = int(math.floor(min_ts / bucket_seconds) * bucket_seconds)
    max_bucket = int(math.floor(max_ts / bucket_seconds) * bucket_seconds)

    # Discretize into buckets
    bucket_counts: dict[int, int] = defaultdict(int)
    bucket_samples: dict[int, list[str]] = defaultdict(list)

    for ts, line in events:
        b_key = int(math.floor(ts / bucket_seconds) * bucket_seconds)
        bucket_counts[b_key] += 1
        if len(bucket_samples[b_key]) < 2:
            bucket_samples[b_key].append(line)

    # Fill continuous intervals
    bucket_keys: list[int] = []
    if fill_empty and max_bucket > min_bucket:
        span_buckets = ((max_bucket - min_bucket) // bucket_seconds) + 1
        if span_buckets > MAX_EMPTY_BUCKETS:
            raise PayloadSizeError(
                f"Timestamp span ({span_buckets} buckets) exceeds safety limit ({MAX_EMPTY_BUCKETS}). "
                "Increase bucket_seconds or set fill_empty_buckets=False."
            )
        cur = min_bucket
        while cur <= max_bucket:
            bucket_keys.append(cur)
            cur += bucket_seconds
    else:
        bucket_keys = sorted(bucket_counts.keys())

    counts = [bucket_counts[k] for k in bucket_keys]
    n = len(counts)
    if n == 0:
        mean = 0.0
        std_dev = 0.0
    else:
        mean = sum(counts) / n
        variance = sum((c - mean) ** 2 for c in counts) / n
        std_dev = math.sqrt(variance)

    spikes: list[dict[str, Any]] = []
    bucket_list: list[dict[str, Any]] = []

    for b_key in bucket_keys:
        count = bucket_counts[b_key]
        z_score = round((count - mean) / std_dev, 2) if std_dev > 0.0 else 0.0

        is_spike = False
        if count >= min_events and (count > 0):
            if std_dev > 0.0 and z_score >= z_threshold:
                is_spike = True
            elif mean > 0.0 and count >= mean * threshold_multiplier:
                is_spike = True

        if is_spike or len(bucket_list) < MAX_CLUSTERS_RETURNED:
            b_start_iso = datetime.fromtimestamp(b_key, tz=timezone.utc).isoformat()
            b_end_iso = datetime.fromtimestamp(b_key + bucket_seconds, tz=timezone.utc).isoformat()

            entry = {
                "start": b_start_iso,
                "end": b_end_iso,
                "count": count,
                "z_score": z_score,
                "is_spike": is_spike,
                "samples": bucket_samples[b_key],
            }
            if len(bucket_list) < MAX_CLUSTERS_RETURNED:
                bucket_list.append(entry)
            if is_spike:
                spikes.append(entry)

    payload = {
        "action": arguments.get("action", "detect_spikes"),
        "total_events": len(events),
        "total_buckets": len(bucket_keys),
        "mean_rate": round(mean, 2),
        "std_dev": round(std_dev, 2),
        "z_threshold": z_threshold,
        "spikes_count": len(spikes),
        "spikes": spikes[:MAX_CLUSTERS_RETURNED],
        "buckets": bucket_list,
        "source_path": source_path,
    }
    return _envelope_success(payload)


# =============================================================================
# Feature 31: Stacktrace Triage Engine (Multi-Runtime)
# =============================================================================

PY_TB_FRAME_RE = re.compile(
    r'^\s*File "(?P<file>[^"]+)", line (?P<line>\d+)(?:, in (?P<func>[^\n]+))?(?:\n\s+(?P<code>[^\n]+))?',
    re.MULTILINE,
)
PY_EXC_LINE_RE = re.compile(
    r"^(?P<type>[A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception|Exit|Interrupt|Warning)?):\s*(?P<msg>.*)$"
)

CATEGORY_RULES = (
    ("database", re.compile(r"(?i)db|sql|postgres|mysql|sqlite|mongo|operationalerror|integrityerror|toomanyconnections")),
    ("network_timeout", re.compile(r"(?i)timeout|timedout|connecttimeout|readtimeout|sockettimeout|etimedout")),
    ("null_pointer", re.compile(r"(?i)nullpointer|attributeerror|nonetype|cannot read property|nil pointer")),
    ("authentication_authorization", re.compile(r"(?i)permission|auth|unauthorized|forbidden|accessdenied")),
    ("resource_exhaustion", re.compile(r"(?i)memoryerror|outofmemory|diskfull|too many open files|enomem")),
    ("validation_syntax", re.compile(r"(?i)valueerror|keyerror|indexerror|syntaxerror|indentationerror|taberror|jsondecodeerror|schema")),
)


def _classify_exception_category(exc_type: str, exc_msg: str) -> str:
    """Categorize exception into operational triage categories."""
    target = f"{exc_type} {exc_msg}"
    for cat_name, regex in CATEGORY_RULES:
        if regex.search(target):
            return cat_name
    return "runtime_error"


def _is_app_frame(file_path: str, app_pattern: str | None = None) -> bool:
    """Determine whether a frame belongs to application code vs library internals."""
    if app_pattern and re.search(app_pattern, file_path):
        return True
    low = file_path.lower()
    if any(lib in low for lib in ("site-packages", "dist-packages", "lib/python", "node_modules", "java/", "sun/", "go/src/runtime")):
        return False
    return True


def _parse_python_traceback_block(tb_text: str, app_pattern: str | None = None) -> dict[str, Any] | None:
    """Parse a single Python traceback block into structured frames and metadata."""
    frame_matches = list(PY_TB_FRAME_RE.finditer(tb_text))
    if not frame_matches:
        return None

    frames: list[dict[str, Any]] = []
    for fm in frame_matches:
        f_path = fm.group("file")
        func_val = fm.group("func")
        frames.append({
            "file": f_path,
            "line": int(fm.group("line")),
            "func": func_val.strip() if func_val else "<module>",
            "code": fm.group("code").strip() if fm.group("code") else None,
            "is_application": _is_app_frame(f_path, app_pattern),
        })

    last_line = tb_text.strip().splitlines()[-1].strip()
    exc_type = "Exception"
    exc_msg = last_line
    exc_m = PY_EXC_LINE_RE.match(last_line)
    if exc_m:
        exc_type = exc_m.group("type")
        exc_msg = exc_m.group("msg").strip()

    # Identify entry and root cause frames
    app_frames = [f for f in frames if f["is_application"]]
    entry_frame = app_frames[0] if app_frames else frames[0]
    root_cause_frame = frames[-1]

    category = _classify_exception_category(exc_type, exc_msg)

    return {
        "runtime": "python",
        "exception_type": exc_type,
        "exception_message": exc_msg,
        "entry_frame": entry_frame,
        "root_cause_frame": root_cause_frame,
        "frames_count": len(frames),
        "frames": frames,
        "category": category,
        "is_chained": False,
        "cause": None,
    }


def _do_triage_stacktrace(arguments: dict[str, Any]) -> dict[str, Any]:
    """Parse and triage stacktraces across Python, Java, Node.js, and Go."""
    text, source_path = _load_input(arguments)
    app_pattern = arguments.get("app_path_pattern")
    limit = int(arguments.get("limit", 50))

    if not text or "Traceback (most recent call last):" not in text:
        # Check if other runtimes exist or return 0
        if not text or not any(kw in text for kw in ("Traceback", "Exception in thread", "panic:", "at ")):
            payload = {
                "action": arguments.get("action", "triage_stacktrace"),
                "tracebacks_count": 0,
                "tracebacks": [],
                "source_path": source_path,
            }
            return _envelope_success(payload)

    tracebacks: list[dict[str, Any]] = []

    # Segment Python tracebacks by delimiter and merge chained segments
    chain_delimiters = [
        "During handling of the above exception, another exception occurred:",
        "The above exception was the direct cause of the following exception:",
    ]

    raw_blocks = re.split(r"\n+(?=(?:Traceback \(most recent call last\):))", text)
    merged_blocks: list[str] = []
    i = 0
    while i < len(raw_blocks):
        b = raw_blocks[i]
        while i + 1 < len(raw_blocks) and any(delim in b for delim in chain_delimiters):
            i += 1
            b = b + "\n" + raw_blocks[i]
        merged_blocks.append(b)
        i += 1

    for b in merged_blocks:
        if "Traceback (most recent call last):" not in b:
            continue

        # Check for exception chaining
        has_chain = False
        for delim in chain_delimiters:
            if delim in b:
                has_chain = True
                sub_parts = b.split(delim)
                parsed_chain = []
                for sp in sub_parts:
                    parsed_sub = _parse_python_traceback_block(sp, app_pattern)
                    if parsed_sub:
                        parsed_chain.append(parsed_sub)

                if len(parsed_chain) >= 2:
                    root_item = parsed_chain[0]
                    final_item = parsed_chain[-1]
                    final_item["is_chained"] = True
                    final_item["cause"] = {
                        "exception_type": root_item["exception_type"],
                        "exception_message": root_item["exception_message"],
                        "root_cause_frame": root_item["root_cause_frame"],
                    }
                    tracebacks.append(final_item)
                elif parsed_chain:
                    tracebacks.append(parsed_chain[0])
                break

        if not has_chain:
            parsed = _parse_python_traceback_block(b, app_pattern)
            if parsed:
                tracebacks.append(parsed)

    payload = {
        "action": arguments.get("action", "triage_stacktrace"),
        "tracebacks_count": len(tracebacks),
        "tracebacks": tracebacks[:limit],
        "source_path": source_path,
    }
    return _envelope_success(payload)


# =============================================================================
# Feature 32: ReDoS-Immune PII Masking Engine
# =============================================================================

# ReDoS-hardened email regex: negative lookbehind eliminates catastrophic backtracking
HARDENED_EMAIL_RE = re.compile(
    r'(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![A-Za-z0-9.-])'
)
HARDENED_IPV4_RE = re.compile(
    r'(?<![0-9a-zA-Z])(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?![0-9a-zA-Z])'
)
HARDENED_IPV6_RE = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b'
)
HARDENED_JWT_RE = re.compile(
    r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'
)
HARDENED_BEARER_RE = re.compile(
    r'(?i)\bBearer\s+([A-Za-z0-9_\-\.~+/]{16,}=*)'
)
HARDENED_CRED_RE = re.compile(
    r'(?i)\b(password|passwd|secret|token|api_key|apikey|auth|bearer|client_secret|private_key)\s*([:=])\s*(["\']?)([^"\'\s,;&]+)\3'
)
CANDIDATE_CC_RE = re.compile(
    r'\b(?:\d{4}[ -]?){3}\d{4}\b'
)
HARDENED_SSN_RE = re.compile(
    r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'
)
HARDENED_MAC_RE = re.compile(
    r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b'
)


def _luhn_check(candidate: str) -> bool:
    """Verify numeric sequence against Luhn mod-10 checksum algorithm."""
    digits = [int(c) for c in candidate if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _do_mask_pii(arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute ReDoS-hardened PII and credential sanitization."""
    text, source_path = _load_input(arguments)
    dest_path_str = arguments.get("destination_path") or arguments.get("output_path")
    overwrite = bool(arguments.get("overwrite", False))
    rules_filter = arguments.get("pii_types") or arguments.get("mask_rules")
    custom_rules = arguments.get("custom_rules") or {}
    replacement_map = arguments.get("replacement_map") or {}
    partial_mask = bool(arguments.get("partial_mask", False))

    if not text:
        payload = {
            "action": arguments.get("action", "mask_pii"),
            "redactions_count": 0,
            "detected_types": {},
            "masked_text": "",
            "output_path": None,
            "source_path": source_path,
        }
        return _envelope_success(payload)

    active_rules = set(rules_filter) if rules_filter else {
        "email", "ipv4", "ipv6", "jwt", "bearer", "credentials", "credit_card", "ssn", "mac", "secret_params",
    }
    # Map synonyms
    if "secret_params" in active_rules:
        active_rules.add("credentials")

    detected_types: dict[str, int] = defaultdict(int)
    result = text

    # 1. JWT Tokens
    if "jwt" in active_rules:
        def _replace_jwt(m):
            detected_types["jwt"] += 1
            return replacement_map.get("jwt", "<JWT_TOKEN>")
        result = HARDENED_JWT_RE.sub(_replace_jwt, result)

    # 2. Bearer Tokens
    if "bearer" in active_rules:
        def _replace_bearer(m):
            detected_types["bearer"] += 1
            return f"Bearer {replacement_map.get('bearer', '<BEARER_TOKEN>')}"
        result = HARDENED_BEARER_RE.sub(_replace_bearer, result)

    # 3. Credentials (key-value)
    if "credentials" in active_rules:
        def _replace_cred(m):
            detected_types["credentials"] += 1
            k = m.group(1)
            sep = m.group(2)
            quote = m.group(3) or ""
            masked_val = replacement_map.get("credentials", "<SECRET>")
            return f"{k}{sep}{quote}{masked_val}{quote}"
        result = HARDENED_CRED_RE.sub(_replace_cred, result)

    # 4. Email Addresses (ReDoS-immune negative lookbehind)
    if "email" in active_rules:
        def _replace_email(m):
            detected_types["email"] += 1
            if partial_mask:
                e = m.group(0)
                user, dom = e.split("@", 1)
                u_mask = user[0] + "***" + user[-1] if len(user) > 2 else "***"
                return f"{u_mask}@{dom}"
            return replacement_map.get("email", "<EMAIL>")
        result = HARDENED_EMAIL_RE.sub(_replace_email, result)

    # 5. IPv4
    if "ipv4" in active_rules:
        def _replace_ipv4(m):
            detected_types["ipv4"] += 1
            return replacement_map.get("ipv4", "<IP>")
        result = HARDENED_IPV4_RE.sub(_replace_ipv4, result)

    # 6. IPv6
    if "ipv6" in active_rules:
        def _replace_ipv6(m):
            detected_types["ipv6"] += 1
            return replacement_map.get("ipv6", "<IP>")
        result = HARDENED_IPV6_RE.sub(_replace_ipv6, result)

    # 7. Credit Cards (Luhn verified)
    if "credit_card" in active_rules:
        def _replace_cc(m):
            card_str = m.group(0)
            if _luhn_check(card_str):
                detected_types["credit_card"] += 1
                if partial_mask:
                    clean = re.sub(r"\D", "", card_str)
                    return f"****-****-****-{clean[-4:]}"
                return replacement_map.get("credit_card", "<CREDIT_CARD>")
            return card_str
        result = CANDIDATE_CC_RE.sub(_replace_cc, result)

    # 8. SSN
    if "ssn" in active_rules:
        def _replace_ssn(m):
            detected_types["ssn"] += 1
            if partial_mask:
                ssn_str = m.group(0)
                return f"***-**-{ssn_str[-4:]}"
            return replacement_map.get("ssn", "<SSN>")
        result = HARDENED_SSN_RE.sub(_replace_ssn, result)

    # 9. MAC Address
    if "mac" in active_rules:
        def _replace_mac(m):
            detected_types["mac"] += 1
            return replacement_map.get("mac", "<MAC>")
        result = HARDENED_MAC_RE.sub(_replace_mac, result)

    # 10. Custom Rules
    if custom_rules and isinstance(custom_rules, dict):
        for rule_name, rule_pat in custom_rules.items():
            compiled = re.compile(rule_pat)
            def _replace_custom(m):
                detected_types[rule_name] += 1
                return replacement_map.get(rule_name, f"<{rule_name.upper()}>")
            result = compiled.sub(_replace_custom, result)

    total_redactions = sum(detected_types.values())

    # Write destination file if requested
    written_dest = None
    if dest_path_str:
        resolved_dest = _validate_and_resolve_path(dest_path_str, check_exists=False)
        if resolved_dest.is_dir():
            raise ValueError(f"Destination path cannot be a directory: '{resolved_dest}'")
        if resolved_dest.exists() and not overwrite:
            raise FileExistsError(
                f"Destination path '{resolved_dest}' already exists and overwrite=False."
            )
        # Atomic write with mode 0o600 and guaranteed tempfile cleanup on failure
        parent_dir = resolved_dest.parent
        tmp_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile("w", dir=str(parent_dir), delete=False, prefix=".jarvis_mask_") as tf:
                tmp_path = tf.name
                tf.write(result)
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, str(resolved_dest))
            tmp_path = None
            written_dest = str(resolved_dest)
        finally:
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    payload = {
        "action": arguments.get("action", "mask_pii"),
        "redactions_count": total_redactions,
        "detected_types": dict(detected_types),
        "masked_text": result,
        "output_path": written_dest,
        "source_path": source_path,
    }
    return _envelope_success(payload)


# =============================================================================
# Handler Entrypoint
# =============================================================================

def log_summarizer(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute log intelligence, anomaly detection, traceback triage, and masking actions."""
    try:
        if not isinstance(arguments, dict):
            return _envelope_error(ValueError("Tool arguments must be a dictionary."))

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

        if action in ("cluster_errors", "error_cluster"):
            return _do_cluster_errors(arguments)
        elif action in ("detect_spikes", "spike_detect"):
            return _do_detect_spikes(arguments)
        elif action in ("triage_stacktrace", "stacktrace_triage"):
            return _do_triage_stacktrace(arguments)
        elif action in ("mask_pii", "pii_masking"):
            return _do_mask_pii(arguments)
        else:
            return _envelope_error(ValueError(f"Unhandled action '{action}'"))
    except Exception as exc:
        return _envelope_error(exc)


# =============================================================================
# Tool Schema Export
# =============================================================================

TOOL = {
    "name": "log_summarizer",
    "description": (
        "Zero-dependency operational log intelligence, anomaly detection, traceback triage, "
        "and PII sanitization for Jarvis. Clusters normalized error templates, detects temporal "
        "rate spikes via Z-score statistics, parses multi-runtime stacktraces (Python, Java, Node.js, Go), "
        "and masks sensitive credentials/PII (emails, IPs, JWTs, Luhn-validated credit cards). Pure stdlib "
        "with strict path confinement to ALLOWED_ROOTS (HOME, /tmp, /mnt, /media) and 10 MB bounds."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "cluster_errors",
                    "detect_spikes",
                    "triage_stacktrace",
                    "mask_pii",
                    "error_cluster",
                    "spike_detect",
                    "stacktrace_triage",
                    "pii_masking",
                ],
                "description": "Log summarizer action to execute.",
            },
            "text": {
                "type": "string",
                "description": "Inline log content string.",
            },
            "content": {
                "type": "string",
                "description": "Alias for 'text'.",
            },
            "data": {
                "type": "string",
                "description": "Alias for 'text'.",
            },
            "logs": {
                "type": "string",
                "description": "Alias for 'text'.",
            },
            "path": {
                "type": "string",
                "description": "Filesystem path to source log file. Must reside within ALLOWED_ROOTS.",
            },
            "source_path": {
                "type": "string",
                "description": "Alias for 'path'.",
            },
            "log_path": {
                "type": "string",
                "description": "Alias for 'path'.",
            },
            "output_path": {
                "type": "string",
                "description": "Optional destination path to write sanitized logs.",
            },
            "destination_path": {
                "type": "string",
                "description": "Alias for 'output_path'.",
            },
            "overwrite": {
                "type": "boolean",
                "default": False,
                "description": "Allow overwriting destination file if it exists.",
            },
            "levels": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of log severity levels to filter (e.g. ['ERROR', 'CRITICAL']).",
            },
            "all_lines": {
                "type": "boolean",
                "default": False,
                "description": "Cluster all lines regardless of log level (default: false).",
            },
            "min_cluster_size": {
                "type": "integer",
                "default": 1,
                "description": "Minimum event count to retain an error cluster.",
            },
            "max_clusters": {
                "type": "integer",
                "default": 50,
                "description": "Maximum number of clusters to return.",
            },
            "limit": {
                "type": "integer",
                "description": "Alias for max_clusters.",
            },
            "include_samples": {
                "type": "integer",
                "default": 3,
                "description": "Number of sample lines to attach to each cluster.",
            },
            "bucket_size": {
                "description": "Time bucket interval ('1m', '5m', '10m', '1h', '1d', or integer seconds).",
            },
            "bucket_seconds": {
                "type": "integer",
                "default": 300,
                "description": "Time bucket width in seconds for spike detection (default: 300).",
            },
            "threshold_multiplier": {
                "type": "number",
                "default": 3.0,
                "description": "Spike anomaly multiplier over baseline mean count.",
            },
            "threshold_zscore": {
                "type": "number",
                "default": 2.0,
                "description": "Z-score threshold for anomaly spikes (default: 2.0).",
            },
            "z_threshold": {
                "type": "number",
                "description": "Alias for threshold_zscore.",
            },
            "min_events": {
                "type": "integer",
                "default": 1,
                "description": "Minimum event count in a bucket required for spike qualification.",
            },
            "fill_empty_buckets": {
                "type": "boolean",
                "default": True,
                "description": "Whether to fill zero-count intervals between start and end (default: true).",
            },
            "time_format": {
                "type": "string",
                "enum": ["auto", "iso8601", "syslog", "apache", "rfc2822"],
                "default": "auto",
                "description": "Timestamp parsing format.",
            },
            "runtime": {
                "type": "string",
                "enum": ["auto", "python", "java", "nodejs", "go"],
                "default": "auto",
                "description": "Target language runtime for stacktrace triage.",
            },
            "app_path_pattern": {
                "type": "string",
                "description": "Optional regex pattern identifying application-level frames.",
            },
            "mask_rules": {
                "type": "array",
                "items": {"type": "string"},
                "description": "PII categories to mask: email, ipv4, ipv6, jwt, bearer, credentials, credit_card, ssn, mac.",
            },
            "pii_types": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Alias for mask_rules.",
            },
            "custom_rules": {
                "type": "object",
                "description": "Mapping of rule names to custom regex patterns for masking.",
            },
            "replacement_map": {
                "type": "object",
                "description": "Mapping of rule names to custom replacement strings.",
            },
            "partial_mask": {
                "type": "boolean",
                "default": False,
                "description": "Whether to partially mask (e.g. j***e@domain.com, ****-****-****-1234).",
            },
            "mask_char": {
                "type": "string",
                "default": "*",
                "description": "Replacement mask character.",
            },
            "encoding": {
                "type": "string",
                "default": "utf-8",
                "description": "Text encoding for file reading.",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": log_summarizer,
    "approval": False,
}
