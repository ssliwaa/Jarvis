"""Zero-dependency cyclic state machine and checkpointing engine inspired by LangGraph and Dify.

Manages multi-step workflows as directed cyclic graphs, persists state snapshots to SQLite
within ALLOWED_ROOTS, supports stepping, execution loops, checkpoint rollbacks (time-travel),
and state history auditing. Exclusively uses the Python standard library.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

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
    "create_graph",
    "init",
    "add_node",
    "add_edge",
    "step",
    "run_graph",
    "run_until_complete",
    "save_checkpoint",
    "checkpoint",
    "rollback_checkpoint",
    "rollback",
    "list_checkpoints",
    "get_state",
    "reset",
})

KNOWN_ARGUMENTS: frozenset[str] = frozenset({
    "action",
    "graph_id",
    "initial_state",
    "state_delta",
    "node_name",
    "target_node",
    "condition",
    "checkpoint_id",
    "max_steps",
    "db_path",
    "limit",
})


class StateGraphError(Exception):
    """Base exception for state_graph."""


class PathSecurityError(StateGraphError):
    """Raised when db_path resolves outside ALLOWED_ROOTS."""


class SensitivePathError(StateGraphError):
    """Raised when db_path touches sensitive directories or files."""


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


def _validate_and_resolve_db_path(raw_path: Any) -> Path:
    """Validate and canonically resolve target SQLite database path within ALLOWED_ROOTS."""
    if raw_path is None or raw_path == "":
        default_dir = Path("/tmp")
        p = default_dir / "jarvis_state_graphs.sqlite3"
    elif isinstance(raw_path, (str, Path)):
        path_str = str(raw_path).strip()
        if not path_str:
            p = Path("/tmp/jarvis_state_graphs.sqlite3")
        else:
            if len(path_str) > 4096 or "\x00" in path_str:
                raise ValueError("Invalid db_path string: exceeds length limit or contains null bytes.")
            p = Path(path_str).expanduser()
            if not p.is_absolute():
                p = Path.cwd() / p
    else:
        raise ValueError("Parameter 'db_path' must be a valid string.")

    try:
        resolved = Path(os.path.realpath(str(p)))
    except (OSError, ValueError) as err:
        raise ValueError(f"Path resolution error for db_path: {err}") from err

    if not _is_inside_allowed_roots(resolved):
        raise PathSecurityError(
            f"Target db_path '{p}' resolves to '{resolved}', which is outside "
            "allowed roots (HOME, /tmp, /mnt, /media)."
        )

    if _is_sensitive_path(resolved):
        raise SensitivePathError(f"Access to sensitive path '{resolved}' is restricted.")

    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def _get_connection(db_path: Path) -> sqlite3.Connection:
    """Open SQLite connection and ensure schema tables exist."""
    conn = sqlite3.connect(str(db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    with conn:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS graphs (
                graph_id TEXT PRIMARY KEY,
                current_node TEXT NOT NULL,
                current_step INTEGER NOT NULL DEFAULT 0,
                state_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'running',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS nodes (
                graph_id TEXT NOT NULL,
                node_name TEXT NOT NULL,
                config_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (graph_id, node_name)
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS edges (
                graph_id TEXT NOT NULL,
                source_node TEXT NOT NULL,
                target_node TEXT NOT NULL,
                condition_json TEXT,
                created_at REAL NOT NULL,
                PRIMARY KEY (graph_id, source_node, target_node)
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS checkpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                graph_id TEXT NOT NULL,
                checkpoint_id TEXT NOT NULL,
                step INTEGER NOT NULL,
                node TEXT NOT NULL,
                state_json TEXT NOT NULL,
                created_at REAL NOT NULL
            );
        """)
    return conn


def _evaluate_condition(condition_json: str | None, state: dict[str, Any]) -> bool:
    """Evaluate whether edge transition condition is satisfied by current state."""
    if not condition_json:
        return True
    try:
        cond = json.loads(condition_json)
    except (ValueError, TypeError):
        return True

    if isinstance(cond, str):
        # Truthiness of state variable named by string
        return bool(state.get(cond))

    if not isinstance(cond, dict):
        return True

    field = cond.get("field") or cond.get("key")
    if not field or not isinstance(field, str):
        return True

    val = state.get(field)
    op = cond.get("op", "==")
    target = cond.get("value", cond.get("equals"))

    if op in ("==", "eq"):
        return val == target
    elif op in ("!=", "neq"):
        return val != target
    elif op in (">", "gt"):
        try:
            return float(val) > float(target)
        except (TypeError, ValueError):
            return False
    elif op in (">=", "gte"):
        try:
            return float(val) >= float(target)
        except (TypeError, ValueError):
            return False
    elif op in ("<", "lt"):
        try:
            return float(val) < float(target)
        except (TypeError, ValueError):
            return False
    elif op in ("<=", "lte"):
        try:
            return float(val) <= float(target)
        except (TypeError, ValueError):
            return False
    elif op == "in":
        try:
            return val in target
        except TypeError:
            return False
    elif op == "not_in":
        try:
            return val not in target
        except TypeError:
            return False
    elif op == "truthy":
        return bool(val)
    elif op == "falsy":
        return not bool(val)
    return True


def state_graph(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute cyclic state graph actions with durable SQLite checkpoints."""
    if not isinstance(arguments, dict):
        return _envelope_error(ValueError("Arguments must be a dictionary."))

    for key in arguments:
        if key not in KNOWN_ARGUMENTS:
            return _envelope_error(ValueError(f"Unknown argument '{key}' or schema violation"))

    action = arguments.get("action")
    if not action or not isinstance(action, str):
        return _envelope_error(ValueError("Missing required parameter 'action'"))

    if action not in VALID_ACTIONS:
        return _envelope_error(ValueError(f"Invalid or unsupported action '{action}'"))

    try:
        db_path = _validate_and_resolve_db_path(arguments.get("db_path"))
        conn = _get_connection(db_path)
    except Exception as exc:
        return _envelope_error(exc)

    try:
        with conn:
            if action in ("create_graph", "init"):
                graph_id = arguments.get("graph_id")
                if not graph_id or not isinstance(graph_id, str):
                    raise ValueError("Parameter 'graph_id' must be a non-empty string.")

                initial_state = arguments.get("initial_state") or {}
                if not isinstance(initial_state, dict):
                    raise ValueError("Parameter 'initial_state' must be a dictionary.")

                start_node = arguments.get("node_name") or "START"
                now = time.time()
                state_str = json.dumps(initial_state)

                conn.execute("""
                    INSERT INTO graphs (graph_id, current_node, current_step, state_json, status, created_at, updated_at)
                    VALUES (?, ?, 0, ?, 'running', ?, ?)
                    ON CONFLICT(graph_id) DO UPDATE SET
                        current_node = excluded.current_node,
                        current_step = 0,
                        state_json = excluded.state_json,
                        status = 'running',
                        updated_at = excluded.updated_at;
                """, (graph_id, start_node, state_str, now, now))

                conn.execute("""
                    INSERT OR IGNORE INTO nodes (graph_id, node_name, config_json, created_at)
                    VALUES (?, ?, '{}', ?);
                """, (graph_id, start_node, now))

                init_chk_id = f"chk_0_{uuid.uuid4().hex[:8]}"
                conn.execute("""
                    INSERT INTO checkpoints (graph_id, checkpoint_id, step, node, state_json, created_at)
                    VALUES (?, ?, 0, ?, ?, ?);
                """, (graph_id, init_chk_id, start_node, state_str, now))

                return _envelope_success({
                    "graph_id": graph_id,
                    "status": "initialized",
                    "current_node": start_node,
                    "current_step": 0,
                    "state": initial_state,
                    "checkpoint_id": init_chk_id,
                    "db_path": str(db_path),
                })

            graph_id = arguments.get("graph_id")
            if not graph_id or not isinstance(graph_id, str):
                raise ValueError("Parameter 'graph_id' must be specified.")

            cur = conn.execute("SELECT * FROM graphs WHERE graph_id = ?", (graph_id,))
            graph_row = cur.fetchone()
            if not graph_row and action != "reset":
                raise KeyError(f"Graph '{graph_id}' does not exist. Call create_graph first.")

            if action == "add_node":
                node_name = arguments.get("node_name")
                if not node_name or not isinstance(node_name, str):
                    raise ValueError("Parameter 'node_name' must be a non-empty string.")
                now = time.time()
                conn.execute("""
                    INSERT INTO nodes (graph_id, node_name, config_json, created_at)
                    VALUES (?, ?, '{}', ?)
                    ON CONFLICT(graph_id, node_name) DO UPDATE SET created_at = excluded.created_at;
                """, (graph_id, node_name, now))
                return _envelope_success({
                    "graph_id": graph_id,
                    "node_name": node_name,
                    "status": "node_added",
                })

            elif action == "add_edge":
                source_node = arguments.get("node_name")
                target_node = arguments.get("target_node")
                if not source_node or not isinstance(source_node, str):
                    raise ValueError("Parameter 'node_name' (source) must be a non-empty string.")
                if not target_node or not isinstance(target_node, str):
                    raise ValueError("Parameter 'target_node' must be a non-empty string.")

                condition = arguments.get("condition")
                cond_str = json.dumps(condition) if condition is not None else None
                now = time.time()

                conn.execute("""
                    INSERT OR IGNORE INTO nodes (graph_id, node_name, config_json, created_at)
                    VALUES (?, ?, '{}', ?);
                """, (graph_id, source_node, now))
                conn.execute("""
                    INSERT OR IGNORE INTO nodes (graph_id, node_name, config_json, created_at)
                    VALUES (?, ?, '{}', ?);
                """, (graph_id, target_node, now))

                conn.execute("""
                    INSERT INTO edges (graph_id, source_node, target_node, condition_json, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(graph_id, source_node, target_node) DO UPDATE SET
                        condition_json = excluded.condition_json,
                        created_at = excluded.created_at;
                """, (graph_id, source_node, target_node, cond_str, now))

                return _envelope_success({
                    "graph_id": graph_id,
                    "source_node": source_node,
                    "target_node": target_node,
                    "condition": condition,
                    "status": "edge_added",
                })

            elif action == "step":
                current_node = graph_row["current_node"]
                current_step = int(graph_row["current_step"])
                state = json.loads(graph_row["state_json"])
                status = graph_row["status"]

                if current_node == "END" or status == "completed":
                    return _envelope_success({
                        "graph_id": graph_id,
                        "current_node": "END",
                        "current_step": current_step,
                        "state": state,
                        "status": "completed",
                        "is_terminal": True,
                        "message": "Graph execution has already completed.",
                    })

                state_delta = arguments.get("state_delta")
                if state_delta:
                    if not isinstance(state_delta, dict):
                        raise ValueError("Parameter 'state_delta' must be a dictionary.")
                    state.update(state_delta)

                override_node = arguments.get("node_name")
                if override_node:
                    next_node = override_node
                else:
                    edges_cur = conn.execute(
                        "SELECT target_node, condition_json FROM edges WHERE graph_id = ? AND source_node = ? ORDER BY rowid ASC",
                        (graph_id, current_node),
                    )
                    edge_rows = edges_cur.fetchall()
                    next_node = "END"
                    for erow in edge_rows:
                        if _evaluate_condition(erow["condition_json"], state):
                            next_node = erow["target_node"]
                            break

                new_step = current_step + 1
                new_status = "completed" if next_node == "END" else "running"
                now = time.time()
                new_state_str = json.dumps(state)

                conn.execute("""
                    UPDATE graphs
                    SET current_node = ?, current_step = ?, state_json = ?, status = ?, updated_at = ?
                    WHERE graph_id = ?;
                """, (next_node, new_step, new_state_str, new_status, now, graph_id))

                chk_id = f"chk_{new_step}_{uuid.uuid4().hex[:8]}"
                conn.execute("""
                    INSERT INTO checkpoints (graph_id, checkpoint_id, step, node, state_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?);
                """, (graph_id, chk_id, new_step, next_node, new_state_str, now))

                return _envelope_success({
                    "graph_id": graph_id,
                    "previous_node": current_node,
                    "current_node": next_node,
                    "current_step": new_step,
                    "state": state,
                    "status": new_status,
                    "is_terminal": next_node == "END",
                    "checkpoint_id": chk_id,
                })

            elif action in ("run_graph", "run_until_complete"):
                max_steps = int(arguments.get("max_steps", 20))
                if max_steps < 1 or max_steps > 500:
                    raise ValueError("Parameter 'max_steps' must be between 1 and 500.")

                current_node = graph_row["current_node"]
                current_step = int(graph_row["current_step"])
                state = json.loads(graph_row["state_json"])
                status = graph_row["status"]

                state_delta = arguments.get("state_delta")
                if state_delta and isinstance(state_delta, dict):
                    state.update(state_delta)

                steps_executed = 0
                history: list[dict[str, Any]] = []

                while current_node != "END" and status != "completed" and steps_executed < max_steps:
                    edges_cur = conn.execute(
                        "SELECT target_node, condition_json FROM edges WHERE graph_id = ? AND source_node = ? ORDER BY rowid ASC",
                        (graph_id, current_node),
                    )
                    edge_rows = edges_cur.fetchall()
                    next_node = "END"
                    for erow in edge_rows:
                        if _evaluate_condition(erow["condition_json"], state):
                            next_node = erow["target_node"]
                            break

                    current_step += 1
                    steps_executed += 1
                    status = "completed" if next_node == "END" else "running"
                    now = time.time()
                    new_state_str = json.dumps(state)

                    chk_id = f"chk_{current_step}_{uuid.uuid4().hex[:8]}"
                    conn.execute("""
                        INSERT INTO checkpoints (graph_id, checkpoint_id, step, node, state_json, created_at)
                        VALUES (?, ?, ?, ?, ?, ?);
                    """, (graph_id, chk_id, current_step, next_node, new_state_str, now))

                    history.append({
                        "step": current_step,
                        "from_node": current_node,
                        "to_node": next_node,
                        "checkpoint_id": chk_id,
                    })
                    current_node = next_node

                now = time.time()
                conn.execute("""
                    UPDATE graphs
                    SET current_node = ?, current_step = ?, state_json = ?, status = ?, updated_at = ?
                    WHERE graph_id = ?;
                """, (current_node, current_step, json.dumps(state), status, now, graph_id))

                return _envelope_success({
                    "graph_id": graph_id,
                    "steps_executed": steps_executed,
                    "current_node": current_node,
                    "current_step": current_step,
                    "state": state,
                    "status": status,
                    "is_terminal": current_node == "END",
                    "history": history,
                })

            elif action in ("save_checkpoint", "checkpoint"):
                chk_id = arguments.get("checkpoint_id") or f"chk_{graph_row['current_step']}_{uuid.uuid4().hex[:8]}"
                now = time.time()
                conn.execute("""
                    INSERT INTO checkpoints (graph_id, checkpoint_id, step, node, state_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?);
                """, (graph_id, chk_id, graph_row["current_step"], graph_row["current_node"], graph_row["state_json"], now))

                return _envelope_success({
                    "graph_id": graph_id,
                    "checkpoint_id": chk_id,
                    "step": int(graph_row["current_step"]),
                    "node": graph_row["current_node"],
                    "saved": True,
                })

            elif action in ("rollback_checkpoint", "rollback"):
                target_chk = arguments.get("checkpoint_id")
                if not target_chk:
                    raise ValueError("Parameter 'checkpoint_id' must be specified for rollback.")

                target_str = str(target_chk).strip()
                if target_str.isdigit():
                    chk_cur = conn.execute(
                        "SELECT * FROM checkpoints WHERE graph_id = ? AND step = ? ORDER BY id DESC LIMIT 1",
                        (graph_id, int(target_str)),
                    )
                else:
                    chk_cur = conn.execute(
                        "SELECT * FROM checkpoints WHERE graph_id = ? AND checkpoint_id = ? ORDER BY id DESC LIMIT 1",
                        (graph_id, target_str),
                    )
                chk_row = chk_cur.fetchone()
                if not chk_row:
                    raise KeyError(f"Checkpoint '{target_chk}' not found for graph '{graph_id}'.")

                now = time.time()
                conn.execute("""
                    UPDATE graphs
                    SET current_node = ?, current_step = ?, state_json = ?, status = 'running', updated_at = ?
                    WHERE graph_id = ?;
                """, (chk_row["node"], chk_row["step"], chk_row["state_json"], now, graph_id))

                return _envelope_success({
                    "graph_id": graph_id,
                    "restored_checkpoint_id": chk_row["checkpoint_id"],
                    "current_node": chk_row["node"],
                    "current_step": int(chk_row["step"]),
                    "state": json.loads(chk_row["state_json"]),
                    "status": "rolled_back",
                })

            elif action == "list_checkpoints":
                limit = int(arguments.get("limit", 50))
                limit = max(1, min(200, limit))
                cur = conn.execute(
                    "SELECT checkpoint_id, step, node, state_json, created_at FROM checkpoints WHERE graph_id = ? ORDER BY step ASC, id ASC LIMIT ?",
                    (graph_id, limit),
                )
                rows = cur.fetchall()
                results: list[dict[str, Any]] = []
                for r in rows:
                    st = json.loads(r["state_json"])
                    results.append({
                        "checkpoint_id": r["checkpoint_id"],
                        "step": int(r["step"]),
                        "node": r["node"],
                        "state_keys": list(st.keys()),
                        "created_at": r["created_at"],
                    })
                return _envelope_success({
                    "graph_id": graph_id,
                    "count": len(results),
                    "checkpoints": results,
                })

            elif action == "get_state":
                return _envelope_success({
                    "graph_id": graph_id,
                    "current_node": graph_row["current_node"],
                    "current_step": int(graph_row["current_step"]),
                    "state": json.loads(graph_row["state_json"]),
                    "status": graph_row["status"],
                    "created_at": graph_row["created_at"],
                    "updated_at": graph_row["updated_at"],
                })

            elif action == "reset":
                conn.execute("DELETE FROM graphs WHERE graph_id = ?", (graph_id,))
                conn.execute("DELETE FROM nodes WHERE graph_id = ?", (graph_id,))
                conn.execute("DELETE FROM edges WHERE graph_id = ?", (graph_id,))
                conn.execute("DELETE FROM checkpoints WHERE graph_id = ?", (graph_id,))
                return _envelope_success({
                    "graph_id": graph_id,
                    "status": "reset_complete",
                })

            else:
                return _envelope_error(ValueError(f"Unhandled action '{action}'"))
    except Exception as exc:
        return _envelope_error(exc)
    finally:
        conn.close()


TOOL = {
    "name": "state_graph",
    "description": (
        "Zero-dependency cyclic state machine and checkpointing engine inspired by LangGraph and Dify. "
        "Manages multi-step workflows, persists step-by-step state snapshots to SQLite within ALLOWED_ROOTS, "
        "and supports stepping, loop execution, checkpoint rollbacks (time-travel), and state history inspection."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "create_graph",
                    "init",
                    "add_node",
                    "add_edge",
                    "step",
                    "run_graph",
                    "run_until_complete",
                    "save_checkpoint",
                    "checkpoint",
                    "rollback_checkpoint",
                    "rollback",
                    "list_checkpoints",
                    "get_state",
                    "reset",
                ],
                "description": "Graph execution or checkpoint operation to perform.",
            },
            "graph_id": {
                "type": "string",
                "description": "Unique identifier for the state graph session (alphanumeric and underscores).",
            },
            "initial_state": {
                "type": "object",
                "description": "Initial state dictionary for create_graph.",
            },
            "state_delta": {
                "type": "object",
                "description": "State updates/mutations to merge into current graph state during step.",
            },
            "node_name": {
                "type": "string",
                "description": "Name of the node being added, started, or transitioned to.",
            },
            "target_node": {
                "type": "string",
                "description": "Target destination node for an edge.",
            },
            "condition": {
                "type": "object",
                "description": "Optional condition predicate dictionary (e.g. {'field': 'status', 'equals': 'ok'}).",
            },
            "checkpoint_id": {
                "type": "string",
                "description": "Target checkpoint identifier or step number for save/rollback operations.",
            },
            "max_steps": {
                "type": "integer",
                "minimum": 1,
                "maximum": 500,
                "description": "Maximum number of steps before loop termination in run_graph (default: 20).",
            },
            "db_path": {
                "type": "string",
                "description": "Optional path to SQLite checkpoint database (must be within ALLOWED_ROOTS).",
            },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 200,
                "description": "Maximum number of checkpoints to return in list_checkpoints (default: 50).",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": state_graph,
    "approval": False,
}
