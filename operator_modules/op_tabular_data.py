"""Tabular data processing, format conversion, dialect sniffing, column profiling,
and Markdown table generation for Jarvis.

Exclusively uses the Python standard library. Zero external dependencies.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

# =============================================================================
# Security Perimeter & Boundaries
# =============================================================================

HOME = Path.home().resolve()
ALLOWED_ROOTS: tuple[Path, ...] = (
    HOME,
    Path("/tmp").resolve(),
    Path("/mnt").resolve(),
    Path("/media").resolve(),
)

MAX_INPUT_BYTES: int = 10 * 1024 * 1024  # 10 MB maximum
MAX_ROW_COUNT: int = 50_000             # Safety ceiling against unbounded datasets

# Ensure csv module can handle up to MAX_INPUT_BYTES field sizes
try:
    csv.field_size_limit(MAX_INPUT_BYTES)
except (OverflowError, AttributeError, ValueError):
    pass

SENSITIVE_NAMES: frozenset[str] = frozenset({
    ".env",
    "config.json",
    "secrets.json",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "shadow",
    "passwd",
})

SENSITIVE_PARTS: frozenset[str] = frozenset({
    ".ssh",
    ".gnupg",
    ".password-store",
    ".hermes",
    ".aws",
    ".docker",
    ".kube",
})

SENSITIVE_EXTENSIONS: frozenset[str] = frozenset({
    ".pem",
    ".key",
    ".pkcs12",
    ".pfx",
})

KNOWN_ARGUMENTS: frozenset[str] = frozenset({
    "action",
    "data",
    "path",
    "source_path",
    "output_path",
    "destination_path",
    "from_format",
    "to_format",
    "delimiter",
    "quotechar",
    "has_header",
    "max_rows",
    "max_col_width",
    "alignments",
    "indent",
    "overwrite",
    "encoding",
})

VALID_ACTIONS: frozenset[str] = frozenset({
    "convert_format",
    "sniff_dialect",
    "profile_columns",
    "to_markdown",
})


# =============================================================================
# Custom Exception Hierarchy
# =============================================================================

class TabularDataError(Exception):
    """Base exception for tabular data operations."""


class SecurityError(TabularDataError):
    """Raised for security boundary violations (confinement, traversal, sensitive files)."""


class PayloadSizeError(TabularDataError):
    """Raised when input data or file exceeds MAX_INPUT_BYTES."""


class FormatError(TabularDataError):
    """Raised when data format cannot be parsed or is structurally invalid."""


# =============================================================================
# Envelope Helpers
# =============================================================================

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


# =============================================================================
# Security & Path Validation
# =============================================================================

def _is_safe_path(p: Path) -> bool:
    """Check if resolved path resides within ALLOWED_ROOTS."""
    try:
        resolved = Path(os.path.realpath(str(p)))
        for root in ALLOWED_ROOTS:
            try:
                root_res = Path(os.path.realpath(str(root)))
                if resolved == root_res or resolved.is_relative_to(root_res):
                    return True
            except (OSError, ValueError):
                continue
        return False
    except (OSError, ValueError, RuntimeError):
        return False


def _check_sensitive_target(p: Path) -> None:
    """Check if path targets sensitive files or directories."""
    parts = set(p.parts)
    for sensitive in SENSITIVE_PARTS:
        if sensitive in parts or any(part == sensitive for part in parts):
            raise SecurityError(f"Access to sensitive path '{sensitive}' is blocked: {p}")
    if p.name in SENSITIVE_NAMES or p.name.startswith(".env"):
        raise SecurityError(f"Access to sensitive file '{p.name}' is blocked: {p}")
    if p.suffix.lower() in SENSITIVE_EXTENSIONS:
        raise SecurityError(f"Access to sensitive file extension '{p.suffix}' is blocked: {p}")


def _validate_input_path(path_str: str) -> Path:
    """Validate and resolve an input file path."""
    if not path_str or not isinstance(path_str, str):
        raise ValueError("File path must be a non-empty string.")
    if "\0" in path_str:
        raise SecurityError("Null byte in file path is prohibited.")
    p = Path(path_str)
    if ".." in p.parts:
        raise SecurityError(f"Path traversal '..' detected in file path: {path_str}")
    resolved = Path(os.path.realpath(str(p)))
    if not _is_safe_path(resolved):
        raise SecurityError(f"Path '{path_str}' resolves outside ALLOWED_ROOTS: {resolved}")
    _check_sensitive_target(resolved)
    if not resolved.exists():
        raise FileNotFoundError(f"Input file not found: {path_str}")
    if not resolved.is_file():
        raise IsADirectoryError(f"Path is not a regular file: {path_str}")
    size = resolved.stat().st_size
    if size > MAX_INPUT_BYTES:
        raise PayloadSizeError(f"File size ({size} bytes) exceeds limit ({MAX_INPUT_BYTES} bytes).")
    return resolved


def _validate_output_path(path_str: str, overwrite: bool = False) -> Path:
    """Validate and resolve an output file path."""
    if not path_str or not isinstance(path_str, str):
        raise ValueError("Output path must be a non-empty string.")
    if "\0" in path_str:
        raise SecurityError("Null byte in output path is prohibited.")
    p = Path(path_str)
    if ".." in p.parts:
        raise SecurityError(f"Path traversal '..' detected in output path: {path_str}")
    if p.is_symlink() or os.path.islink(path_str):
        raise SecurityError(f"Refusing to write to symbolic link: {path_str}")
    _check_sensitive_target(p)
    resolved = Path(os.path.realpath(str(p)))
    if not _is_safe_path(resolved):
        raise SecurityError(f"Output path resolves outside ALLOWED_ROOTS: {resolved}")
    _check_sensitive_target(resolved)
    if resolved.is_symlink() or p.is_symlink() or os.path.islink(path_str):
        raise SecurityError(f"Refusing to write to symbolic link: {path_str}")
    if resolved.exists() and not overwrite:
        raise FileExistsError(f"Output file already exists and overwrite is False: {path_str}")
    return resolved


def _atomic_write_file(target: Path, text: str, encoding: str = "utf-8") -> None:
    """Atomically write text to target file with mode 0o600 using a sibling temporary file."""
    if target.is_symlink() or os.path.islink(str(target)):
        raise SecurityError(f"Refusing to write to symbolic link: {target}")
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)
    raw = text.encode(encoding)
    if len(raw) > MAX_INPUT_BYTES:
        raise PayloadSizeError(f"Output payload size ({len(raw)} bytes) exceeds limit ({MAX_INPUT_BYTES} bytes).")

    fd, tmp_name = tempfile.mkstemp(dir=str(parent), prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, str(target))
    except Exception:
        try:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
        except OSError:
            pass
        raise


# =============================================================================
# Ingestion & Canonical Table Parsing
# =============================================================================

def _read_input_text(arguments: dict[str, Any]) -> str:
    """Extract raw string input from either 'data' or 'path'/'source_path'."""
    data = arguments.get("data")
    path_arg = arguments.get("path") or arguments.get("source_path")

    if data is not None:
        if not isinstance(data, str):
            if isinstance(data, (dict, list)):
                return json.dumps(data)
            raise ValueError("'data' parameter must be a string or JSON-serializable structure.")
        raw_bytes = data.encode("utf-8")
        if len(raw_bytes) > MAX_INPUT_BYTES:
            raise PayloadSizeError(f"Input data length ({len(raw_bytes)} bytes) exceeds limit ({MAX_INPUT_BYTES} bytes).")
        # Strip UTF-8 BOM if present
        if data.startswith("\ufeff"):
            data = data[1:]
        return data

    if path_arg is not None:
        file_path = _validate_input_path(str(path_arg))
        encoding = str(arguments.get("encoding") or "utf-8-sig")
        try:
            text = file_path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        if text.startswith("\ufeff"):
            text = text[1:]
        return text

    raise ValueError("Either 'data' (inline string) or 'path' (file path) must be provided.")


def _parse_markdown_table(text: str) -> tuple[list[str], list[list[Any]]]:
    """Parse a GitHub-Flavored Markdown table into (headers, rows)."""
    lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
    table_lines: list[str] = [line for line in lines if "|" in line]
    if not table_lines:
        raise FormatError("No markdown table lines containing '|' found.")

    def _split_row(line: str) -> list[str]:
        cleaned = line
        if cleaned.startswith("|"):
            cleaned = cleaned[1:]
        if cleaned.endswith("|"):
            cleaned = cleaned[:-1]
        cells = re.split(r"(?<!\\)\|", cleaned)
        return [c.replace(r"\|", "|").strip() for c in cells]

    header_cells = _split_row(table_lines[0])
    if not header_cells:
        raise FormatError("Failed to parse headers from Markdown table.")

    start_idx = 1
    if len(table_lines) > 1:
        sep_cells = _split_row(table_lines[1])
        if all(re.match(r"^:?-+:?$", cell) for cell in sep_cells if cell):
            start_idx = 2

    data_lines = table_lines[start_idx:]
    if len(data_lines) > MAX_ROW_COUNT:
        raise PayloadSizeError(f"Row count ({len(data_lines)}) exceeds maximum allowed ({MAX_ROW_COUNT}).")

    rows: list[list[Any]] = []
    col_count = len(header_cells)
    for line in data_lines:
        cells = _split_row(line)
        if len(cells) < col_count:
            cells.extend([""] * (col_count - len(cells)))
        elif len(cells) > col_count:
            cells = cells[:col_count]
        rows.append(cells)

    if len(rows) > MAX_ROW_COUNT:
        raise PayloadSizeError(f"Row count ({len(rows)}) exceeds maximum allowed ({MAX_ROW_COUNT}).")

    return header_cells, rows


def _parse_json_table(data_obj: Any) -> tuple[list[str], list[list[Any]]]:
    """Parse JSON structure (records, split, or index) into (headers, rows)."""
    if isinstance(data_obj, list):
        if not data_obj:
            return [], []
        if len(data_obj) > MAX_ROW_COUNT:
            raise PayloadSizeError(f"Row count ({len(data_obj)}) exceeds maximum allowed ({MAX_ROW_COUNT}).")
        if isinstance(data_obj[0], dict):
            headers: list[str] = []
            seen = set()
            for rec in data_obj:
                if isinstance(rec, dict):
                    for k in rec.keys():
                        if k not in seen:
                            headers.append(k)
                            seen.add(k)
            rows = [[rec.get(h) for h in headers] if isinstance(rec, dict) else [None] * len(headers) for rec in data_obj]
            return headers, rows
        if isinstance(data_obj[0], list):
            headers = [f"col_{i+1}" for i in range(len(data_obj[0]))]
            return headers, data_obj

    elif isinstance(data_obj, dict):
        if "columns" in data_obj and "data" in data_obj and isinstance(data_obj["columns"], list) and isinstance(data_obj["data"], list):
            if len(data_obj["data"]) > MAX_ROW_COUNT:
                raise PayloadSizeError(f"Row count ({len(data_obj['data'])}) exceeds maximum allowed ({MAX_ROW_COUNT}).")
            headers = [str(c) for c in data_obj["columns"]]
            rows = data_obj["data"]
            return headers, rows

        values = list(data_obj.values())
        if len(values) > MAX_ROW_COUNT:
            raise PayloadSizeError(f"Row count ({len(values)}) exceeds maximum allowed ({MAX_ROW_COUNT}).")
        if values and isinstance(values[0], dict):
            headers = []
            seen = set()
            for rec in values:
                if isinstance(rec, dict):
                    for k in rec.keys():
                        if k not in seen:
                            headers.append(k)
                            seen.add(k)
            rows = [[rec.get(h) for h in headers] if isinstance(rec, dict) else [None] * len(headers) for rec in values]
            return headers, rows

    raise FormatError("Unrecognized JSON tabular format. Expected list of records, split dict, or index dict.")


def _detect_format(text: str) -> str:
    """Heuristically detect format ('json', 'markdown', 'tsv', 'csv')."""
    stripped = text.strip()
    if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
        try:
            json.loads(stripped)
            return "json"
        except Exception:
            pass

    lines = [line for line in stripped.splitlines() if line.strip()][:10]
    if any("|" in line for line in lines) and any(re.search(r"\|?\s*:?-+:?\s*\|", line) for line in lines):
        return "markdown"

    sample = stripped[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",\t")
        if dialect.delimiter == "\t":
            return "tsv"
        elif dialect.delimiter == ",":
            return "csv"
    except Exception:
        pass

    # Fallback heuristic: count delimiters outside quoted fields
    tab_count = 0
    comma_count = 0
    for line in lines:
        in_quote = False
        for ch in line:
            if ch in ('"', "'"):
                in_quote = not in_quote
            elif not in_quote:
                if ch == "\t":
                    tab_count += 1
                elif ch == ",":
                    comma_count += 1
    if tab_count > 0 and tab_count >= comma_count:
        return "tsv"

    return "csv"


def _parse_table(
    text: str,
    from_format: str = "auto",
    delimiter: str | None = None,
    quotechar: str | None = None,
    has_header: bool | None = None,
) -> tuple[list[str], list[list[Any]]]:
    """Parse raw text into canonical (headers, rows) representation."""
    fmt = from_format.lower() if from_format else "auto"
    if fmt == "auto":
        fmt = _detect_format(text)

    if fmt in ("json", "json_records", "json_split", "json_index"):
        try:
            parsed = json.loads(text)
        except Exception as exc:
            raise FormatError(f"Failed to parse JSON tabular data: {exc}")
        headers, rows = _parse_json_table(parsed)
        if len(rows) > MAX_ROW_COUNT:
            raise PayloadSizeError(f"Row count ({len(rows)}) exceeds maximum allowed ({MAX_ROW_COUNT}).")
        return headers, rows

    if fmt in ("markdown", "md"):
        headers, rows = _parse_markdown_table(text)
        if len(rows) > MAX_ROW_COUNT:
            raise PayloadSizeError(f"Row count ({len(rows)}) exceeds maximum allowed ({MAX_ROW_COUNT}).")
        return headers, rows

    if fmt in ("csv", "tsv"):
        delim = delimiter if delimiter is not None else ("\t" if fmt == "tsv" else ",")
        quote = quotechar if quotechar is not None else '"'

        reader = csv.reader(io.StringIO(text), delimiter=delim, quotechar=quote)
        raw_rows: list[list[str]] = [row for row in reader if row]
        if not raw_rows:
            return [], []

        if len(raw_rows) > MAX_ROW_COUNT:
            raise PayloadSizeError(f"Row count ({len(raw_rows)}) exceeds maximum allowed ({MAX_ROW_COUNT}).")

        determine_header = has_header
        if determine_header is None:
            sample = text[:4096]
            try:
                determine_header = csv.Sniffer().has_header(sample)
            except Exception:
                determine_header = False

            if not determine_header:
                if raw_rows and all(c.strip() and not _is_numeric(c) for c in raw_rows[0]):
                    determine_header = True

        if determine_header:
            headers = [h.strip() for h in raw_rows[0]]
            rows = raw_rows[1:]
        else:
            col_count = max(len(r) for r in raw_rows)
            headers = [f"col_{i+1}" for i in range(col_count)]
            rows = raw_rows

        col_count = len(headers)
        normalized_rows: list[list[Any]] = []
        for r in rows:
            if len(r) < col_count:
                normalized_rows.append(r + [""] * (col_count - len(r)))
            elif len(r) > col_count:
                normalized_rows.append(r[:col_count])
            else:
                normalized_rows.append(r)

        return headers, normalized_rows

    raise FormatError(f"Unsupported format '{from_format}'. Expected csv, tsv, json, or markdown.")


# =============================================================================
# Action 1: convert_format
# =============================================================================

def _render_csv_or_tsv(headers: list[str], rows: list[list[Any]], delimiter: str = ",") -> str:
    """Render table into CSV or TSV string."""
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=delimiter, lineterminator="\n")
    if headers:
        writer.writerow(headers)
    for row in rows:
        writer.writerow([str(c) if c is not None else "" for c in row])
    return buf.getvalue()


def _render_json(headers: list[str], rows: list[list[Any]], to_format: str, indent: int = 2) -> str:
    """Render table into JSON string (records, split, or index format)."""
    fmt = to_format.lower()
    if fmt in ("json", "json_records", "records"):
        records = [dict(zip(headers, row)) for row in rows]
        return json.dumps(records, indent=indent, ensure_ascii=False)
    elif fmt in ("json_split", "split"):
        split_obj = {"columns": headers, "data": rows}
        return json.dumps(split_obj, indent=indent, ensure_ascii=False)
    elif fmt in ("json_index", "index"):
        index_obj = {str(i): dict(zip(headers, row)) for i, row in enumerate(rows)}
        return json.dumps(index_obj, indent=indent, ensure_ascii=False)
    else:
        raise FormatError(f"Unsupported JSON target format '{to_format}'.")


def _handle_convert_format(arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute bidirectional format conversion."""
    text = _read_input_text(arguments)
    from_fmt = str(arguments.get("from_format") or "auto")
    to_fmt = str(arguments.get("to_format") or "json").lower()
    custom_delim = arguments.get("delimiter")
    custom_quote = arguments.get("quotechar")
    has_header = arguments.get("has_header")
    indent = int(arguments.get("indent", 2))
    max_rows = arguments.get("max_rows")

    headers, rows = _parse_table(
        text,
        from_format=from_fmt,
        delimiter=custom_delim,
        quotechar=custom_quote,
        has_header=has_header,
    )

    if max_rows is not None:
        try:
            mr = int(max_rows)
            if mr > 0:
                rows = rows[:mr]
        except (ValueError, TypeError):
            pass

    output_str: str
    if to_fmt == "csv":
        output_str = _render_csv_or_tsv(headers, rows, delimiter=",")
    elif to_fmt == "tsv":
        output_str = _render_csv_or_tsv(headers, rows, delimiter="\t")
    elif to_fmt in ("json", "json_records", "json_split", "json_index"):
        output_str = _render_json(headers, rows, to_fmt, indent=indent)
    elif to_fmt in ("markdown", "md"):
        output_str = _render_markdown(
            headers,
            rows,
            max_col_width=arguments.get("max_col_width"),
            alignments=arguments.get("alignments"),
        )
    else:
        raise FormatError(f"Unsupported target format '{to_fmt}'.")

    out_path_arg = arguments.get("output_path") or arguments.get("destination_path")
    written_to: str | None = None
    if out_path_arg:
        overwrite = bool(arguments.get("overwrite", False))
        out_path = _validate_output_path(str(out_path_arg), overwrite=overwrite)
        _atomic_write_file(out_path, output_str)
        written_to = str(out_path)

    summary = {
        "format": to_fmt,
        "row_count": len(rows),
        "column_count": len(headers),
        "columns": headers,
        "output": output_str,
        "result": output_str,
        "written_to": written_to,
    }
    return _envelope_success(summary)


# =============================================================================
# Action 2: sniff_dialect
# =============================================================================

def _is_numeric(s: str) -> bool:
    """Check if string represents an integer or float."""
    v = s.strip()
    if not v:
        return False
    return bool(re.match(r"^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$", v))


def _handle_sniff_dialect(arguments: dict[str, Any]) -> dict[str, Any]:
    """Automatically detect delimiter, quotechar, escapechar, and header existence."""
    text = _read_input_text(arguments)
    sample = text[:8192]
    if not sample.strip():
        raise FormatError("Cannot sniff dialect from empty input.")

    detected_delim = ","
    detected_quote = '"'
    detected_escape = None
    detected_doublequote = True
    detected_has_header = False

    sniffer = csv.Sniffer()

    try:
        dialect = sniffer.sniff(sample, delimiters=",\t;| ")
        detected_delim = dialect.delimiter
        detected_quote = dialect.quotechar
        detected_escape = dialect.escapechar
        detected_doublequote = dialect.doublequote
    except csv.Error:
        lines = [line for line in sample.splitlines() if line.strip()][:10]
        if lines:
            counts = {d: [line.count(d) for line in lines] for d in (",", "\t", ";", "|")}
            best_d = ","
            best_score = 0
            for d, cnts in counts.items():
                if all(c > 0 for c in cnts) and len(set(cnts)) == 1:
                    best_d = d
                    best_score = sum(cnts)
                    break
                elif sum(cnts) > best_score:
                    best_score = sum(cnts)
                    best_d = d
            detected_delim = best_d

    try:
        detected_has_header = sniffer.has_header(sample)
    except Exception:
        detected_has_header = False

    if not detected_has_header:
        try:
            reader = csv.reader(io.StringIO(sample), delimiter=detected_delim, quotechar=detected_quote)
            first_rows = [r for r in reader if r][:2]
            if first_rows and all(c.strip() and not _is_numeric(c) for c in first_rows[0]):
                detected_has_header = True
        except Exception:
            detected_has_header = True

    try:
        reader = csv.reader(io.StringIO(sample), delimiter=detected_delim, quotechar=detected_quote)
        sample_rows = [r for r in reader if r]
    except Exception:
        sample_rows = []

    columns: list[str] = []
    preview: list[list[str]] = []
    if sample_rows:
        if detected_has_header:
            columns = [c.strip() for c in sample_rows[0]]
            preview = sample_rows[1:6]
        else:
            col_count = len(sample_rows[0])
            columns = [f"col_{i+1}" for i in range(col_count)]
            preview = sample_rows[:5]

    result = {
        "delimiter": detected_delim,
        "quotechar": detected_quote,
        "escapechar": detected_escape,
        "doublequote": detected_doublequote,
        "has_header": detected_has_header,
        "column_count": len(columns),
        "columns": columns,
        "sample_row_count": len(sample_rows),
        "sample_preview": preview,
    }
    return _envelope_success(result)


# =============================================================================
# Action 3: profile_columns
# =============================================================================

def _infer_value_type(val: Any) -> str:
    """Infer data type of a single value."""
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "boolean"
    if isinstance(val, int):
        return "integer"
    if isinstance(val, float):
        return "float"

    s = str(val).strip()
    if not s or s.lower() in ("null", "none", "nan", "na", "n/a", "nil"):
        return "null"
    if s.lower() in ("true", "false", "yes", "no"):
        return "boolean"
    if re.match(r"^[+-]?\d+$", s):
        return "integer"
    if re.match(r"^[+-]?(?:\d+\.\d*|\.\d+|\d+)(?:[eE][+-]?\d+)?$", s):
        return "float"
    if re.match(r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?$", s):
        return "date"
    return "string"


def _handle_profile_columns(arguments: dict[str, Any]) -> dict[str, Any]:
    """Profile tabular data columns (null counts, distinct counts, min/max, type inference)."""
    text = _read_input_text(arguments)
    from_fmt = str(arguments.get("from_format") or "auto")
    headers, rows = _parse_table(
        text,
        from_format=from_fmt,
        delimiter=arguments.get("delimiter"),
        quotechar=arguments.get("quotechar"),
        has_header=arguments.get("has_header"),
    )

    total_rows = len(rows)
    total_cols = len(headers)
    profiles: list[dict[str, Any]] = []

    for col_idx, col_name in enumerate(headers):
        raw_values = [row[col_idx] if col_idx < len(row) else None for row in rows]
        null_count = 0
        non_null_values: list[Any] = []
        type_counts: dict[str, int] = {
            "boolean": 0,
            "integer": 0,
            "float": 0,
            "date": 0,
            "string": 0,
        }

        for v in raw_values:
            vt = _infer_value_type(v)
            if vt == "null":
                null_count += 1
            else:
                non_null_values.append(v)
                type_counts[vt] += 1

        non_null_count = len(non_null_values)
        distinct_set = {str(v) for v in non_null_values}
        distinct_count = len(distinct_set)
        null_pct = round((null_count / total_rows) * 100, 2) if total_rows > 0 else 0.0

        if non_null_count == 0:
            inferred_type = "null"
        elif type_counts["integer"] == non_null_count:
            inferred_type = "integer"
        elif type_counts["integer"] + type_counts["float"] == non_null_count:
            inferred_type = "float"
        elif type_counts["boolean"] == non_null_count:
            inferred_type = "boolean"
        elif type_counts["date"] == non_null_count:
            inferred_type = "date"
        else:
            inferred_type = "string"

        min_val: Any = None
        max_val: Any = None
        if non_null_count > 0:
            if inferred_type == "integer":
                int_vals = [int(v) for v in non_null_values]
                min_val = min(int_vals)
                max_val = max(int_vals)
            elif inferred_type == "float":
                flt_vals = [float(v) for v in non_null_values]
                min_val = min(flt_vals)
                max_val = max(flt_vals)
            elif inferred_type in ("date", "string"):
                str_vals = [str(v) for v in non_null_values]
                min_val = min(str_vals)
                max_val = max(str_vals)
            elif inferred_type == "boolean":
                bool_vals = [str(v).lower() in ("true", "yes", "t", "1") for v in non_null_values]
                min_val = min(bool_vals)
                max_val = max(bool_vals)

        sample_values: list[Any] = []
        for v in non_null_values:
            if v not in sample_values:
                sample_values.append(v)
            if len(sample_values) >= 5:
                break

        profiles.append({
            "name": col_name,
            "inferred_type": inferred_type,
            "total_count": total_rows,
            "null_count": null_count,
            "null_percentage": null_pct,
            "distinct_count": distinct_count,
            "is_unique": (distinct_count == total_rows and null_count == 0),
            "min_value": min_val,
            "max_value": max_val,
            "sample_values": sample_values,
        })

    result = {
        "row_count": total_rows,
        "column_count": total_cols,
        "columns": profiles,
    }
    return _envelope_success(result)


# =============================================================================
# Action 4: to_markdown
# =============================================================================

def _escape_cell_markdown(cell: Any, max_col_width: int | None = None) -> str:
    """Format cell for Markdown: escape pipes, replace newlines, and truncate if needed."""
    s = str(cell) if cell is not None else ""
    s = s.replace("\r\n", "<br>").replace("\n", "<br>").replace("\r", "<br>")
    s = s.replace("|", r"\|")
    if max_col_width is not None and max_col_width >= 4:
        if len(s) > max_col_width:
            s = s[:max_col_width - 3] + "..."
    return s


def _render_markdown(
    headers: list[str],
    rows: list[list[Any]],
    max_col_width: int | None = None,
    max_rows: int | None = None,
    alignments: dict[str, str] | list[str] | str | None = None,
) -> str:
    """Render table into clean GitHub-Flavored Markdown with column alignment and padding."""
    if not headers and not rows:
        return ""

    if not headers and rows:
        headers = [f"col_{i+1}" for i in range(len(rows[0]))]

    truncated_count = 0
    displayed_rows = rows
    if max_rows is not None and max_rows > 0 and len(rows) > max_rows:
        displayed_rows = rows[:max_rows]
        truncated_count = len(rows) - max_rows

    formatted_headers = [_escape_cell_markdown(h, max_col_width) for h in headers]
    formatted_rows: list[list[str]] = []
    for r in displayed_rows:
        formatted_rows.append([_escape_cell_markdown(c, max_col_width) for c in r])

    col_aligns: list[str] = []
    for i, h in enumerate(headers):
        align: str = "left"
        if isinstance(alignments, dict):
            align = alignments.get(h, alignments.get(str(i), "left")).lower()
        elif isinstance(alignments, list) and i < len(alignments):
            align = str(alignments[i]).lower()
        elif alignments in ("left", "center", "right"):
            align = alignments
        else:
            col_vals = [r[i] for r in displayed_rows if i < len(r)]
            if col_vals and all(_is_numeric(str(v)) for v in col_vals if str(v).strip()):
                align = "right"
            else:
                align = "left"
        if align not in ("left", "center", "right"):
            align = "left"
        col_aligns.append(align)

    widths: list[int] = []
    for i, h in enumerate(formatted_headers):
        col_max = len(h)
        for r in formatted_rows:
            if i < len(r):
                col_max = max(col_max, len(r[i]))
        widths.append(max(col_max, 3))

    lines: list[str] = []

    hdr_cells = [h.ljust(w) for h, w in zip(formatted_headers, widths)]
    lines.append("| " + " | ".join(hdr_cells) + " |")

    delims: list[str] = []
    for align, w in zip(col_aligns, widths):
        if align == "center":
            delims.append(":" + "-" * (w - 2) + ":")
        elif align == "right":
            delims.append("-" * (w - 1) + ":")
        else:
            delims.append(":" + "-" * (w - 1))
    lines.append("| " + " | ".join(delims) + " |")

    for r in formatted_rows:
        row_cells: list[str] = []
        for i, (cell, w, align) in enumerate(zip(r, widths, col_aligns)):
            if align == "right":
                row_cells.append(cell.rjust(w))
            elif align == "center":
                row_cells.append(cell.center(w))
            else:
                row_cells.append(cell.ljust(w))
        lines.append("| " + " | ".join(row_cells) + " |")

    if truncated_count > 0:
        lines.append(f"\n*... ({truncated_count} more rows truncated) ...*")

    return "\n".join(lines)


def _handle_to_markdown(arguments: dict[str, Any]) -> dict[str, Any]:
    """Format tabular data into clean GitHub-flavored Markdown tables."""
    text = _read_input_text(arguments)
    from_fmt = str(arguments.get("from_format") or "auto")
    max_col_width = arguments.get("max_col_width")
    max_rows = arguments.get("max_rows")
    alignments = arguments.get("alignments")

    headers, rows = _parse_table(
        text,
        from_format=from_fmt,
        delimiter=arguments.get("delimiter"),
        quotechar=arguments.get("quotechar"),
        has_header=arguments.get("has_header"),
    )

    truncated = False
    if max_rows is not None and max_rows > 0 and len(rows) > max_rows:
        truncated = True

    md_output = _render_markdown(
        headers,
        rows,
        max_col_width=max_col_width,
        max_rows=max_rows,
        alignments=alignments,
    )

    out_path_arg = arguments.get("output_path") or arguments.get("destination_path")
    written_to: str | None = None
    if out_path_arg:
        overwrite = bool(arguments.get("overwrite", False))
        out_path = _validate_output_path(str(out_path_arg), overwrite=overwrite)
        _atomic_write_file(out_path, md_output)
        written_to = str(out_path)

    summary = {
        "markdown": md_output,
        "row_count": len(rows),
        "column_count": len(headers),
        "columns": headers,
        "truncated": truncated,
        "written_to": written_to,
    }
    return _envelope_success(summary)


# =============================================================================
# Primary Dispatcher & Tool Registration
# =============================================================================

def tabular_data(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute tabular data operations."""
    try:
        if not isinstance(arguments, dict):
            return _envelope_error(ValueError("Tool arguments must be a dictionary."))

        action = str(arguments.get("action") or "").strip()
        if not action:
            return _envelope_error(ValueError("Parameter 'action' is required."))

        if action not in VALID_ACTIONS:
            return _envelope_error(ValueError(f"Invalid or unsupported action '{action}'."))

        unknown = set(arguments.keys()) - KNOWN_ARGUMENTS
        if unknown:
            return _envelope_error(ValueError(f"Unexpected argument(s) provided: {sorted(unknown)}"))

        if action == "convert_format":
            return _handle_convert_format(arguments)
        elif action == "sniff_dialect":
            return _handle_sniff_dialect(arguments)
        elif action == "profile_columns":
            return _handle_profile_columns(arguments)
        elif action == "to_markdown":
            return _handle_to_markdown(arguments)
        else:
            return _envelope_error(ValueError(f"Unhandled action '{action}'"))
    except Exception as exc:
        return _envelope_error(exc)


TOOL = {
    "name": "tabular_data",
    "description": (
        "Zero-dependency tabular data transformation, dialect sniffing, column profiling, "
        "and Markdown table generation for Jarvis. Converts between CSV, TSV, JSON (records, split, "
        "or index orientations), and Markdown tables. Operates read-only with path confinement "
        "to ALLOWED_ROOTS and 10 MB input bounds."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "convert_format",
                    "sniff_dialect",
                    "profile_columns",
                    "to_markdown",
                ],
                "description": "Tabular data action to perform.",
            },
            "data": {
                "type": "string",
                "description": "Inline tabular data string (CSV, TSV, JSON, or Markdown).",
            },
            "path": {
                "type": "string",
                "description": "Filesystem path to source tabular file. Must reside within ALLOWED_ROOTS.",
            },
            "source_path": {
                "type": "string",
                "description": "Alias for 'path'.",
            },
            "output_path": {
                "type": "string",
                "description": "Optional destination file path to write converted or formatted table to.",
            },
            "destination_path": {
                "type": "string",
                "description": "Alias for 'output_path'.",
            },
            "from_format": {
                "type": "string",
                "enum": [
                    "auto",
                    "csv",
                    "tsv",
                    "json",
                    "json_records",
                    "json_split",
                    "json_index",
                    "markdown",
                ],
                "description": "Input format specification. Default: 'auto'.",
            },
            "to_format": {
                "type": "string",
                "enum": [
                    "csv",
                    "tsv",
                    "json",
                    "json_records",
                    "json_split",
                    "json_index",
                    "markdown",
                ],
                "description": "Target format for 'convert_format'. Default: 'json'.",
            },
            "delimiter": {
                "type": "string",
                "description": "Custom delimiter for CSV parsing or formatting (e.g. ',', ';', '\\t', '|').",
            },
            "quotechar": {
                "type": "string",
                "description": "Custom quote character for CSV parsing or formatting (e.g. '\"').",
            },
            "has_header": {
                "type": "boolean",
                "description": "Explicitly specify whether the tabular data has a header row.",
            },
            "max_rows": {
                "type": "integer",
                "minimum": 1,
                "description": "Maximum number of rows to process or display in Markdown.",
            },
            "max_col_width": {
                "type": "integer",
                "minimum": 1,
                "description": "Maximum column cell width before truncation in Markdown generation.",
            },
            "alignments": {
                "description": "Column alignments for Markdown ('left', 'center', 'right', or per-column map/list).",
            },
            "indent": {
                "type": "integer",
                "minimum": 0,
                "maximum": 8,
                "description": "JSON indentation spaces (default: 2).",
            },
            "overwrite": {
                "type": "boolean",
                "description": "Allow overwriting destination file if output_path already exists (default: false).",
            },
            "encoding": {
                "type": "string",
                "description": "Text encoding for file reading and writing (default: 'utf-8').",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": tabular_data,
    "approval": False,
}
