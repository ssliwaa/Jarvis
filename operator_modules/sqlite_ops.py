"""Safe SQLite Database Inspector and Read-Only Query Runner for Jarvis."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any

import operator_tools as ops

FORBIDDEN_SQL = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|ATTACH|DETACH|CREATE|REPLACE|VACUUM|REINDEX|TRUNCATE|GRANT|REVOKE)\b",
    re.IGNORECASE,
)

TABLE_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,127}$")


def _clean_sql(sql: str) -> str:
    """Strip SQL comments and leading/trailing whitespace."""
    no_block = re.sub(r"/\*.*?\*/", " ", str(sql or ""), flags=re.DOTALL)
    no_line = re.sub(r"--[^\n]*", " ", no_block)
    return no_line.strip()


def _validate_readonly_query(sql: str) -> tuple[bool, str]:
    """Verify that a SQL query is strictly single-statement and read-only."""
    cleaned = _clean_sql(sql)
    if not cleaned:
        return False, "Query cannot be empty."

    # Strip trailing semicolon and check for multi-statement execution
    stmt = cleaned.rstrip(";").strip()
    if ";" in stmt:
        return False, "Multiple SQL statements in a single execution are forbidden."

    if FORBIDDEN_SQL.search(stmt):
        return False, "Write, DDL, and ATTACH statements are strictly forbidden in read-only mode."

    first_word = stmt.split()[0].upper()
    if first_word not in ("SELECT", "WITH", "EXPLAIN", "PRAGMA"):
        return False, f"Disallowed statement type {first_word!r}. Only SELECT and EXPLAIN queries are permitted."

    if first_word == "PRAGMA":
        if not re.match(
            r"^PRAGMA\s+(table_info|table_list|index_list|index_info|foreign_key_list)\s*(\(.*\))?$",
            stmt,
            re.IGNORECASE,
        ):
            return False, "Only inspection PRAGMAs (table_info, index_list, foreign_key_list) are allowed."

    return True, stmt


def _connect_ro(path: Path) -> sqlite3.Connection:
    """Open an SQLite connection in strict read-only mode with query_only=ON."""
    uri = f"file:{path.resolve().as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    if hasattr(conn, "enable_load_extension"):
        try:
            conn.enable_load_extension(False)
        except (AttributeError, sqlite3.OperationalError):
            pass
    conn.execute("PRAGMA query_only = ON")
    return conn


def sqlite_ops(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute safe read-only operations on a local SQLite database."""
    args = arguments if isinstance(arguments, dict) else {}
    action = str(args.get("action") or "list_tables").strip().lower()
    raw_path = args.get("path")

    if not raw_path or not isinstance(raw_path, str):
        return {"ok": False, "error": "Parameter 'path' is required and must be a string."}

    workspace = (context or {}).get("workspace")
    base = Path(workspace) if workspace else ops.HOME

    try:
        db_path = ops.resolve_path(raw_path, base=base, must_exist=True)
    except ops.ToolError as err:
        return {"ok": False, "error": str(err)}

    if ops.is_credential_target(db_path):
        return {"ok": False, "error": f"Access to sensitive database target {db_path.name!r} is refused."}

    if not db_path.is_file():
        return {"ok": False, "error": f"Database path is not a regular file: {db_path}"}

    try:
        conn = _connect_ro(db_path)
    except sqlite3.Error as err:
        return {"ok": False, "error": f"Could not open SQLite database: {err}"}

    try:
        if action == "list_tables":
            cur = conn.execute(
                "SELECT name, type FROM sqlite_master WHERE type IN ('table', 'view') "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
            tables = [{"name": row["name"], "type": row["type"]} for row in cur.fetchall()]
            return {"ok": True, "result": {"path": str(db_path), "tables": tables, "count": len(tables)}}

        if action == "describe_table":
            table_name = str(args.get("table") or "").strip()
            if not table_name:
                return {"ok": False, "error": "Parameter 'table' is required for describe_table."}
            if not TABLE_NAME_RE.fullmatch(table_name):
                return {"ok": False, "error": f"Invalid table name format: {table_name!r}"}

            cur = conn.execute("SELECT name FROM sqlite_master WHERE name = ? AND type IN ('table', 'view')", (table_name,))
            if not cur.fetchone():
                return {"ok": False, "error": f"Table or view {table_name!r} not found in database."}

            col_cur = conn.execute(f"PRAGMA table_info({table_name})")
            columns = [
                {
                    "cid": row["cid"],
                    "name": row["name"],
                    "type": row["type"],
                    "notnull": bool(row["notnull"]),
                    "default_value": row["dflt_value"],
                    "pk": bool(row["pk"]),
                }
                for row in col_cur.fetchall()
            ]

            fk_cur = conn.execute(f"PRAGMA foreign_key_list({table_name})")
            foreign_keys = [
                {
                    "id": row["id"],
                    "seq": row["seq"],
                    "table": row["table"],
                    "from": row["from"],
                    "to": row["to"],
                }
                for row in fk_cur.fetchall()
            ]

            idx_cur = conn.execute(f"PRAGMA index_list({table_name})")
            indexes = [
                {"name": row["name"], "unique": bool(row["unique"]), "origin": row["origin"]}
                for row in idx_cur.fetchall()
            ]

            return {
                "ok": True,
                "result": {
                    "table": table_name,
                    "columns": columns,
                    "foreign_keys": foreign_keys,
                    "indexes": indexes,
                },
            }

        if action == "query":
            raw_query = args.get("query")
            if not raw_query or not isinstance(raw_query, str):
                return {"ok": False, "error": "Parameter 'query' is required for query action."}

            valid, stmt = _validate_readonly_query(raw_query)
            if not valid:
                return {"ok": False, "error": stmt}

            raw_limit = args.get("limit")
            try:
                limit = max(1, min(int(raw_limit if raw_limit is not None else 50), 500))
            except (ValueError, TypeError):
                return {"ok": False, "error": "Parameter 'limit' must be an integer."}

            params = args.get("params")
            if params is not None and not isinstance(params, (list, tuple)):
                return {"ok": False, "error": "Parameter 'params' must be an array of positional values."}
            param_seq = list(params) if params is not None else []

            cur = conn.execute(stmt, param_seq)
            rows_raw = cur.fetchmany(limit + 1)
            truncated = len(rows_raw) > limit
            rows = rows_raw[:limit]

            column_names = [desc[0] for desc in cur.description] if cur.description else []
            formatted_rows = [
                {name: row[name] for name in column_names}
                for row in rows
            ]

            return {
                "ok": True,
                "result": {
                    "columns": column_names,
                    "rows": formatted_rows,
                    "row_count": len(formatted_rows),
                    "truncated": truncated,
                    "limit": limit,
                },
            }

        if action == "explain":
            raw_query = args.get("query")
            if not raw_query or not isinstance(raw_query, str):
                return {"ok": False, "error": "Parameter 'query' is required for explain action."}

            valid, stmt = _validate_readonly_query(raw_query)
            if not valid:
                return {"ok": False, "error": stmt}

            explain_stmt = f"EXPLAIN QUERY PLAN {stmt}"
            cur = conn.execute(explain_stmt)
            plan = [
                {"id": row[0], "parent": row[1], "notused": row[2], "detail": row[3]}
                if len(row) >= 4 else dict(row)
                for row in cur.fetchall()
            ]
            return {"ok": True, "result": {"query": stmt, "plan": plan}}

        return {"ok": False, "error": f"Unsupported action: {action!r}"}

    except sqlite3.Error as err:
        return {"ok": False, "error": f"SQLite execution failed: {err}"}
    finally:
        conn.close()


TOOL = {
    "name": "sqlite_ops",
    "description": (
        "Inspect and query local SQLite databases in strict read-only mode. "
        "Actions: 'list_tables', 'describe_table', 'query' (SELECT only with row limits), 'explain'."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["list_tables", "describe_table", "query", "explain"],
                "description": "Operation to perform (default: 'list_tables').",
            },
            "path": {
                "type": "string",
                "description": "Path to the SQLite database file.",
            },
            "table": {
                "type": "string",
                "description": "Table or view name to describe (for 'describe_table').",
            },
            "query": {
                "type": "string",
                "description": "SQL SELECT query to execute or explain (read-only).",
            },
            "params": {
                "type": "array",
                "items": {},
                "description": "Optional parameterized query values (array).",
            },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 500,
                "description": "Maximum rows to return for 'query' (default 50, max 500).",
            },
        },
        "required": ["path"],
        "additionalProperties": False,
    },
    "handler": sqlite_ops,
    "approval": False,
}
