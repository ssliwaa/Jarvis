#!/usr/bin/env python3
"""Jarvis as an MCP server: a stdio bridge over the local Jarvis HTTP API.

Jarvis (``./server.py``, ``http://127.0.0.1:4700``) already owns the vault index
at ``~/notes``, the grounded chat brain, personal memory, the Operator
lane, skills and web research. This module exposes those lanes as MCP tools so
any MCP client can drive Jarvis instead of re-implementing the vault.

Transport: stdio, newline-delimited JSON-RPC 2.0 (LSP ``Content-Length``
framing is accepted too). Only protocol frames reach stdout; diagnostics go to
stderr.

Hermes config (``~/.hermes/config.yaml``)::

    mcp_servers:
      jarvis:
        command: /path/to/jarvis/.venv/bin/python
        args: [/path/to/jarvis/jarvis_mcp_server.py]
        timeout: 600
        connect_timeout: 30
        enabled: true

Environment:
  JARVIS_BASE_URL      Jarvis HTTP origin, loopback only (default
                       ``http://127.0.0.1:4700``)
  JARVIS_MCP_READONLY  ``1`` hides the tools that write or spend money

The bridge never imports the Jarvis application: one writer per resource stays
in ``server.py``, and a protocol client cannot restart the app by accident.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE_URL = (os.environ.get("JARVIS_BASE_URL") or "http://127.0.0.1:4700").rstrip("/")
SERVER_NAME = "jarvis"
SERVER_VERSION = "1.0.0"
PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
DEFAULT_TIMEOUT = 60.0
MAX_TEXT_CHARS = 120_000
TRUTHY = {"1", "true", "yes", "on"}
READONLY = (os.environ.get("JARVIS_MCP_READONLY") or "").strip().casefold() in TRUTHY

INSTRUCTIONS = (
    "Jarvis is the local knowledge galaxy and computer operator of this machine. "
    "Its notes live in ~/notes and are indexed for grounded answers. "
    "Use 'ask' for questions about the notes, 'remember' to file a new note, "
    "'memory_recall' for durable personal facts, 'operator_task' for real computer "
    "tasks, 'research' for public web sources, and 'status' to check the app. "
    "A Jarvis answer that cites note numbers comes from the owner's notes; "
    "'general knowledge' answers do not."
)


def log(message: str) -> None:
    print(f"[jarvis-mcp] {message}", file=sys.stderr, flush=True)


class BridgeError(Exception):
    """A failure the calling model can read and act on."""

    def __init__(self, message: str, code: str = "BRIDGE_ERROR"):
        super().__init__(message)
        self.code = code


def _error_payload(raw: bytes) -> tuple[str, str]:
    try:
        body = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return "", raw.decode("utf-8", "replace").strip()[:400]
    if not isinstance(body, dict):
        return "", ""
    error = body.get("error")
    if isinstance(error, dict):
        return str(error.get("code") or ""), str(error.get("message") or "")
    answer = body.get("answer")
    return "", str(answer or "")[:400]


def api(method: str, path: str, payload=None, timeout: float = DEFAULT_TIMEOUT):
    """Call the Jarvis HTTP API and return the decoded JSON body."""
    data = None
    headers = {"Accept": "application/json", "Origin": BASE_URL}
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(BASE_URL + path, data=data, headers=headers,
                                     method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as error:
        raw = error.read()
        code, detail = _error_payload(raw)
        detail = detail or str(error.reason)
        raise BridgeError(f"Jarvis answered HTTP {error.code}: {detail}",
                          code=code or f"HTTP_{error.code}") from None
    except urllib.error.URLError as error:
        raise BridgeError(
            f"Jarvis is unreachable at {BASE_URL} ({error.reason}). Start it with "
            "'systemctl --user start jarvis.service' and retry.",
            code="JARVIS_UNREACHABLE") from None
    except TimeoutError:
        raise BridgeError(f"Jarvis did not answer within {timeout:.0f}s.",
                          code="JARVIS_TIMEOUT") from None
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except ValueError:
        raise BridgeError("Jarvis returned a body that is not JSON.",
                          code="JARVIS_BAD_BODY") from None


def soft(method: str, path: str, payload=None, timeout: float = 20.0) -> dict:
    """A sub-lane that is allowed to fail without failing the whole tool."""
    try:
        return {"ok": True, "data": api(method, path, payload, timeout)}
    except BridgeError as error:
        return {"ok": False, "error": error.code, "message": str(error)}


def need_text(args: dict, name: str, maximum: int = 4000) -> str:
    value = args.get(name)
    if not isinstance(value, str):
        raise BridgeError(f"'{name}' must be a string.", "INVALID_ARGUMENT")
    value = value.strip()
    if not value:
        raise BridgeError(f"'{name}' is required.", "INVALID_ARGUMENT")
    if len(value) > maximum:
        raise BridgeError(f"'{name}' is limited to {maximum} characters.",
                          "INVALID_ARGUMENT")
    return value


def opt_text(args: dict, name: str, maximum: int = 4000) -> str:
    value = args.get(name)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise BridgeError(f"'{name}' must be a string.", "INVALID_ARGUMENT")
    value = value.strip()
    if len(value) > maximum:
        raise BridgeError(f"'{name}' is limited to {maximum} characters.",
                          "INVALID_ARGUMENT")
    return value


def opt_bool(args: dict, name: str):
    value = args.get(name)
    if value is None:
        return None
    if not isinstance(value, bool):
        raise BridgeError(f"'{name}' must be a boolean.", "INVALID_ARGUMENT")
    return value


def _query(params: dict) -> str:
    clean = {key: value for key, value in params.items() if value not in (None, "")}
    return f"?{urllib.parse.urlencode(clean)}" if clean else ""


def tool_ask(args: dict):
    payload: dict[str, object] = {"question": need_text(args, "question")}
    language = opt_text(args, "language", 8)
    if language:
        if language not in ("pl", "en"):
            raise BridgeError("'language' must be 'pl' or 'en'.", "INVALID_ARGUMENT")
        payload["language"] = language
    return api("POST", "/chat", payload, timeout=300.0)


def tool_remember(args: dict):
    return api("POST", "/remember", {"text": need_text(args, "text")}, timeout=120.0)


def _memory_fields(args: dict, action: str, keys: tuple) -> dict:
    payload: dict[str, object] = {"action": action}
    for key, limit in keys:
        text = opt_text(args, key, limit)
        if text:
            payload[key] = text
    identifier = args.get("id")
    if identifier is not None:
        if not isinstance(identifier, int) or isinstance(identifier, bool):
            raise BridgeError("'id' must be an integer event id.", "INVALID_ARGUMENT")
        payload["id"] = identifier
    return payload


def tool_memory_recall(args: dict):
    action = opt_text(args, "action", 16) or "recall"
    if action not in {"recall", "list", "events"}:
        raise BridgeError("'action' must be recall, list or events.", "INVALID_ARGUMENT")
    payload = _memory_fields(args, action, (("value", 2000), ("category", 40)))
    return api("POST", "/memory", payload, timeout=30.0)


def tool_memory_write(args: dict):
    if READONLY:
        raise BridgeError("This bridge is read-only (JARVIS_MCP_READONLY=1).", "READ_ONLY")
    action = opt_text(args, "action", 16) or "add"
    if action not in {"add", "forget"}:
        raise BridgeError("'action' must be add or forget.", "INVALID_ARGUMENT")
    payload = _memory_fields(args, action, (("key", 200), ("value", 2000),
                                           ("category", 40)))
    confirm = opt_bool(args, "confirm")
    if confirm is not None:
        payload["confirm"] = confirm
    if payload.get("confirm") is not True:
        raise BridgeError("Writing personal memory needs confirm=true.",
                          "CONFIRM_REQUIRED")
    return api("POST", "/memory", payload, timeout=30.0)


def tool_operator_status(args: dict):
    action = opt_text(args, "action", 16) or "status"
    if action == "status":
        return api("GET", "/agent/status" + _query({"job_id": opt_text(args, "job_id", 64)}),
                   timeout=30.0)
    if action == "history":
        return api("GET", "/agent/history" + _query({"status": opt_text(args, "status", 16)}),
                   timeout=30.0)
    if action == "queue":
        return api("GET", "/agent/queue", timeout=30.0)
    raise BridgeError("'action' must be status, history or queue.", "INVALID_ARGUMENT")


def tool_operator_task(args: dict):
    if READONLY:
        raise BridgeError("This bridge is read-only (JARVIS_MCP_READONLY=1).",
                          "READ_ONLY")
    action = opt_text(args, "action", 16) or "run"
    if action == "run":
        payload: dict[str, object] = {"task": need_text(args, "task")}
        queue = opt_bool(args, "queue")
        if queue is not None:
            payload["queue"] = queue
        language = opt_text(args, "language", 8)
        if language:
            if language not in ("pl", "en"):
                raise BridgeError("'language' must be 'pl' or 'en'.", "INVALID_ARGUMENT")
            payload["language"] = language
        return api("POST", "/agent/run", payload, timeout=180.0)
    if action == "approve":
        approve = opt_bool(args, "approve")
        if approve is None:
            raise BridgeError("'approve' is required for the approve action.",
                              "INVALID_ARGUMENT")
        payload: dict[str, object] = {"job_id": need_text(args, "job_id", 64),
                                      "approve": approve,
                                      "token": need_text(args, "token", 200)}
        return api("POST", "/agent/approve", payload, timeout=60.0)
    if action == "stop":
        return api("POST", "/agent/stop", {"job_id": need_text(args, "job_id", 64)},
                   timeout=60.0)
    if action == "resume":
        return api("POST", "/agent/queue/resume", timeout=60.0)
    raise BridgeError("'action' must be run, approve, stop or resume.",
                      "INVALID_ARGUMENT")


def tool_research(args: dict):
    query = need_text(args, "query", 500)
    return api("GET", "/research" + _query({"q": query}), timeout=180.0)


def tool_skills(args: dict):
    name = opt_text(args, "name", 128)
    if name:
        return api("GET", "/skills/view" + _query({"name": name,
                                                   "file": opt_text(args, "file", 256)}),
                   timeout=30.0)
    return api("GET", "/skills" + _query({"q": opt_text(args, "query", 200)}), timeout=30.0)


def tool_briefing(_args: dict):
    return api("GET", "/briefing", timeout=180.0)


def tool_system(_args: dict):
    return api("GET", "/system", timeout=60.0)


def tool_sessions_search(args: dict):
    return api("GET", "/sessions/search" + _query({"q": need_text(args, "query", 500)}),
               timeout=60.0)


def tool_status(_args: dict):
    health = soft("GET", "/health", timeout=15.0)
    if health.get("ok") and isinstance(health.get("data"), dict):
        body = health["data"]
        health["data"] = {"status": body.get("status"),
                          "source_files": len(body.get("sources") or {})}
    capabilities = soft("GET", "/capabilities", timeout=15.0)
    if capabilities.get("ok") and isinstance(capabilities.get("data"), dict):
        rows = capabilities["data"].get("capabilities") or []
        capabilities["data"] = {
            "available": [row.get("id") for row in rows if row.get("available")],
            "unavailable": [row.get("id") for row in rows if not row.get("available")],
        }
    return {
        "base_url": BASE_URL,
        "read_only": READONLY,
        "health": health,
        "capabilities": capabilities,
        "services": soft("GET", "/services", timeout=15.0),
        "agent": soft("GET", "/agent/status", timeout=20.0),
        "retrieval": soft("GET", "/retrieval/status", timeout=20.0),
        "metrics": soft("GET", "/metrics", timeout=15.0),
    }


TOOLS = [
    {
        "name": "ask",
        "title": "Ask Jarvis about the notes",
        "description": "Ask Jarvis a question. It answers from the indexed markdown "
                       "vault at ~/notes with numeric citations, or falls back "
                       "to general knowledge / web research and labels which lane it "
                       "used. One paid model call, no data change.",
        "readOnlyHint": True,
        "handler": tool_ask,
        "inputSchema": {
            "type": "object",
            "properties": {
                "question": {"type": "string", "minLength": 1, "maxLength": 4000},
                "language": {"type": "string", "enum": ["pl", "en"],
                             "description": "Force the answer language."},
            },
            "required": ["question"],
            "additionalProperties": False,
        },
    },
    {
        "name": "remember",
        "title": "File a note in the vault",
        "description": "Write a new note into the Jarvis vault, index it in the graph "
                       "and return the new node. Persistent side effect on the owner's "
                       "notes.",
        "readOnlyHint": False,
        "handler": tool_remember,
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string", "minLength": 1, "maxLength": 4000}},
            "required": ["text"],
            "additionalProperties": False,
        },
    },
    {
        "name": "memory_recall",
        "title": "Recall personal memory",
        "description": "Recall, list or inspect Jarvis's durable personal memory. "
                       "Read-only.",
        "readOnlyHint": True,
        "handler": tool_memory_recall,
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["recall", "list", "events"]},
                "value": {"type": "string", "maxLength": 2000,
                          "description": "What to recall."},
                "category": {"type": "string", "maxLength": 40},
                "id": {"type": "integer", "description": "Event id for 'events'."},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "memory_write",
        "title": "Write personal memory",
        "description": "Add or forget one durable personal fact. Needs confirm=true; "
                       "hidden on a read-only bridge.",
        "readOnlyHint": False,
        "handler": tool_memory_write,
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["add", "forget"]},
                "key": {"type": "string", "maxLength": 200},
                "value": {"type": "string", "maxLength": 2000},
                "category": {"type": "string", "maxLength": 40},
                "id": {"type": "integer"},
                "confirm": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "operator_status",
        "title": "Operator jobs",
        "description": "Inspect the Operator lane: current job, history or queue. "
                       "Read-only.",
        "readOnlyHint": True,
        "handler": tool_operator_status,
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["status", "history", "queue"]},
                "job_id": {"type": "string", "maxLength": 64},
                "status": {"type": "string", "enum": ["done", "error", "stopped"]},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "operator_task",
        "title": "Run an Operator task",
        "description": "Start, approve, stop or resume a real computer task: shell, "
                       "files, browser, desktop. Paid and consequential; hidden on a "
                       "read-only bridge.",
        "readOnlyHint": False,
        "handler": tool_operator_task,
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string",
                           "enum": ["run", "approve", "stop", "resume"]},
                "task": {"type": "string", "maxLength": 4000,
                         "description": "The task for action=run."},
                "queue": {"type": "boolean"},
                "language": {"type": "string", "enum": ["pl", "en"]},
                "job_id": {"type": "string", "maxLength": 64},
                "approve": {"type": "boolean"},
                "token": {"type": "string", "maxLength": 200,
                          "description": "One-time approval token from the job snapshot."},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "research",
        "title": "Web research",
        "description": "Run Jarvis's public web research lane and return sources with "
                       "titles, URLs and snippets. Read-only, needs the network.",
        "readOnlyHint": True,
        "handler": tool_research,
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string", "minLength": 1, "maxLength": 500}},
            "required": ["query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "skills",
        "title": "Jarvis skills",
        "description": "List or search Jarvis skills, or read one skill's files. "
                       "Reading never executes the skill.",
        "readOnlyHint": True,
        "handler": tool_skills,
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "maxLength": 200},
                "name": {"type": "string", "maxLength": 128,
                         "description": "Read this skill instead of listing."},
                "file": {"type": "string", "maxLength": 256},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "briefing",
        "title": "Briefing",
        "description": "Build Jarvis's briefing: notes, schedules, memory and system "
                       "state in one payload. Read-only.",
        "readOnlyHint": True,
        "handler": tool_briefing,
        "inputSchema": {"type": "object", "properties": {},
                        "additionalProperties": False},
    },
    {
        "name": "system",
        "title": "System metrics",
        "description": "Machine metrics and processes as Jarvis sees them. Read-only.",
        "readOnlyHint": True,
        "handler": tool_system,
        "inputSchema": {"type": "object", "properties": {},
                        "additionalProperties": False},
    },
    {
        "name": "sessions_search",
        "title": "Search chat history",
        "description": "Search past Jarvis conversations for a phrase. Read-only.",
        "readOnlyHint": True,
        "handler": tool_sessions_search,
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string", "minLength": 1, "maxLength": 500}},
            "required": ["query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "status",
        "title": "Jarvis status",
        "description": "Health, live capabilities, services, Operator registry, "
                       "retrieval index and usage metrics in one call. Read-only.",
        "readOnlyHint": True,
        "handler": tool_status,
        "inputSchema": {"type": "object", "properties": {},
                        "additionalProperties": False},
    },
]

TOOLS_BY_NAME = {tool["name"]: tool for tool in TOOLS}


def visible_tools() -> list[dict]:
    return [tool for tool in TOOLS if not (READONLY and not tool["readOnlyHint"])]


def tool_result(result) -> dict:
    text = json.dumps(result, ensure_ascii=False, indent=2, default=str)
    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS] + "\n… truncated by the Jarvis bridge"
    payload = {"content": [{"type": "text", "text": text}], "isError": False}
    if isinstance(result, dict):
        payload["structuredContent"] = result
    return payload


def tool_error(message: str) -> dict:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def _success(msg_id, result) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _failure(msg_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id,
            "error": {"code": code, "message": message}}


def dispatch(message):
    """One JSON-RPC message in, one reply or None (for notifications)."""
    if not isinstance(message, dict):
        return _failure(None, -32600, "Invalid Request: a message must be an object.")
    method = message.get("method")
    msg_id = message.get("id")
    raw_params = message.get("params")
    params = raw_params if isinstance(raw_params, dict) else {}
    if msg_id is None and isinstance(method, str) and method.startswith("notifications/"):
        return None
    if not isinstance(method, str):
        return _failure(msg_id, -32600, "Invalid Request: method is missing.")

    if method == "initialize":
        requested = params.get("protocolVersion")
        version = requested if requested in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
        return _success(msg_id, {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "title": "Jarvis (local knowledge galaxy)",
                           "version": SERVER_VERSION},
            "instructions": INSTRUCTIONS,
        })
    if method == "ping":
        return _success(msg_id, {})
    if method == "tools/list":
        rows = []
        for tool in visible_tools():
            rows.append({
                "name": tool["name"],
                "title": tool["title"],
                "description": tool["description"],
                "inputSchema": tool["inputSchema"],
                "annotations": {"title": tool["title"],
                                "readOnlyHint": bool(tool["readOnlyHint"]),
                                "destructiveHint": not bool(tool["readOnlyHint"])},
            })
        return _success(msg_id, {"tools": rows})
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments")
        arguments = {} if arguments is None else arguments
        if not isinstance(name, str) or name not in TOOLS_BY_NAME:
            return _success(msg_id, tool_error(f"No Jarvis tool named {name!r}."))
        if not isinstance(arguments, dict):
            return _success(msg_id, tool_error("Tool arguments must be an object."))
        tool = TOOLS_BY_NAME[name]
        if READONLY and not tool["readOnlyHint"]:
            return _success(msg_id, tool_error(
                "This bridge is read-only (JARVIS_MCP_READONLY=1)."))
        try:
            result = tool["handler"](arguments)
        except BridgeError as error:
            return _success(msg_id, tool_error(f"{error.code}: {error}"))
        except Exception as error:  # a tool must never kill the bridge
            log(f"tool {name} failed: {type(error).__name__}: {error}")
            return _success(msg_id, tool_error(f"{type(error).__name__}: {error}"))
        return _success(msg_id, tool_result(result))
    if method == "resources/list":
        return _success(msg_id, {"resources": []})
    if method == "resources/templates/list":
        return _success(msg_id, {"resourceTemplates": []})
    if method == "prompts/list":
        return _success(msg_id, {"prompts": []})
    if method == "logging/setLevel":
        return _success(msg_id, {})
    return _failure(msg_id, -32601, f"Method not found: {method}")


def read_message(stream):
    """Read one JSON-RPC message: newline-delimited JSON or LSP Content-Length."""
    line = stream.readline()
    while line and not line.strip():
        line = stream.readline()
    if not line:
        return None
    stripped = line.strip()
    if stripped.lower().startswith(b"content-length:"):
        try:
            length = int(stripped.split(b":", 1)[1].strip())
        except (IndexError, ValueError):
            raise BridgeError("Malformed Content-Length header.", "BAD_FRAME") from None
        while True:
            header = stream.readline()
            if header in (b"\r\n", b"\n", b""):
                break
        body = stream.read(length)
        return json.loads(body.decode("utf-8"))
    return json.loads(stripped.decode("utf-8"))


def write_message(message) -> None:
    sys.stdout.write(json.dumps(message, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def serve() -> int:
    log(f"ready; api={BASE_URL} tools={len(visible_tools())} read_only={READONLY}")
    stream = sys.stdin.buffer
    while True:
        try:
            message = read_message(stream)
        except BridgeError as error:
            write_message(_failure(None, -32700, str(error)))
            continue
        except ValueError as error:
            write_message(_failure(None, -32700, f"Parse error: {error}"))
            continue
        if message is None:
            break
        try:
            if isinstance(message, list):
                replies = [reply for reply in (dispatch(item) for item in message)
                           if reply is not None]
                if replies:
                    write_message(replies)
                continue
            reply = dispatch(message)
            if reply is not None:
                write_message(reply)
        except Exception as error:  # keep the transport alive
            log(f"dispatch failed: {type(error).__name__}: {error}")
            write_message(_failure(getattr(message, "get", lambda _k, _d=None: None)("id"),
                                   -32603, f"Internal error: {error}"))
    log("stdin closed; stopping")
    return 0


def selftest() -> int:
    """Prove the tool table and the live Jarvis API without an MCP client."""
    names = [tool["name"] for tool in visible_tools()]
    print(f"tools ({len(names)}): {', '.join(names)}")
    print(f"api: {BASE_URL} read_only={READONLY}")
    status = tool_status({})
    health = status["health"]
    print(f"health: {json.dumps(health, ensure_ascii=False)}")
    if not health.get("ok") or (health.get("data") or {}).get("status") != "ok":
        print("SELFTEST FAIL: Jarvis /health is not ok", file=sys.stderr)
        return 1
    retrieval = status["retrieval"]
    if retrieval.get("ok"):
        data = retrieval["data"]
        print(f"retrieval: indexed_notes={data.get('indexed_notes')} "
              f"engine={data.get('engine')} semantic={data.get('semantic')}")
    agent = status["agent"]
    if agent.get("ok"):
        data = agent["data"]
        print(f"operator: available={data.get('available')} mode={data.get('mode')} "
              f"tool_count={data.get('tool_count')}")
    print("SELFTEST OK")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv[1:]:
        sys.exit(selftest())
    sys.exit(serve())
