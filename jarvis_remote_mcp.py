#!/usr/bin/env python3
"""Jarvis Remote MCP Bridge (Streamable HTTP + OAuth 2.0 / Secret URL Path) for business.gemini.google.

Zero external dependencies (Python standard library only).
Strictly sandboxes file operations to ~/Jarvis, blocks secret files (.env, keys),
and exposes safe tools for reading/editing Jarvis code, running lint/tests, restarting
jarvis.service, and controlling Jarvis external coding agents.

Usage:
    python3 jarvis_remote_mcp.py              # starts on 127.0.0.1:8788
    python3 jarvis_remote_mcp.py --show-auth  # prints generated secret URL & OAuth credentials
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent
CONFIG_DIR = Path.home() / ".jarvis-tools"
AUTH_CONFIG_PATH = CONFIG_DIR / "remote-mcp-auth.json"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8788
MAX_READ_BYTES = 200_000
MAX_WRITE_BYTES = 400_000
PROTOCOL_VERSION = "2025-03-26"

FORBIDDEN_NAMES = {
    ".env", "secrets.json", "consent.json", "id_rsa", "id_ed25519",
    "remote-mcp-auth.json", "credentials.json",
}
FORBIDDEN_PARTS = {".git", ".ssh", ".gnupg", "__pycache__", ".venv", "node_modules"}
FORBIDDEN_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".sqlite", ".db"}


def load_or_create_auth() -> dict[str, str]:
    CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if AUTH_CONFIG_PATH.is_file():
        try:
            data = json.loads(AUTH_CONFIG_PATH.read_text(encoding="utf-8"))
            if all(k in data for k in ("secret_slug", "client_id", "client_secret", "signing_key")):
                return data
        except (OSError, ValueError):
            pass
    data = {
        "secret_slug": secrets.token_urlsafe(24),
        "client_id": "jarvis-mcp-" + secrets.token_hex(8),
        "client_secret": secrets.token_urlsafe(32),
        "signing_key": secrets.token_hex(32),
    }
    # atomic_io: the static '.tmp' suffix raced on a threaded server and a
    # crash mid-write left the credential config torn; mkstemp + replace
    # keeps one consistent generation, 0600.
    from atomic_io import atomic_write_text
    atomic_write_text(AUTH_CONFIG_PATH, json.dumps(data, indent=2), dir_mode=None)
    return data


def _sign_token(payload: dict[str, Any], key: str) -> str:
    raw = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("ascii").rstrip("=")
    sig = hmac.new(key.encode("utf-8"), raw.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"


def _verify_token(token: str, key: str) -> bool:
    if not token or "." not in token:
        return False
    raw, _, sig = token.partition(".")
    expected = hmac.new(key.encode("utf-8"), raw.encode("ascii"), hashlib.sha256).hexdigest()
    if not secrets.compare_digest(sig, expected):
        return False
    try:
        padded = raw + "=" * (-len(raw) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        return float(payload.get("exp", 0)) > time.time()
    except Exception:
        return False


def _safe_project_path(rel_path: str, *, allow_missing: bool = False) -> Path:
    clean = str(rel_path or "").strip().lstrip("/")
    if not clean or ".." in Path(clean).parts:
        raise ValueError("Ścieżka musi być względna wewnątrz katalogu projektu Jarvis (bez '..').")
    candidate = (PROJECT_ROOT / clean).resolve()
    if candidate != PROJECT_ROOT and PROJECT_ROOT not in candidate.parents:
        raise ValueError("Odmowa dostępu: ścieżka wychodzi poza katalog projektu Jarvis.")
    rel_parts = candidate.relative_to(PROJECT_ROOT).parts
    if any(p in FORBIDDEN_PARTS for p in rel_parts):
        raise ValueError(f"Odmowa dostępu do chronionego katalogu: {rel_parts[0]}")
    if candidate.name in FORBIDDEN_NAMES or candidate.name.startswith(".env."):
        raise ValueError("Odmowa dostępu do pliku z sekretami.")
    if candidate.suffix.lower() in FORBIDDEN_SUFFIXES:
        raise ValueError("Odmowa dostępu do kluczy/baz binarnych.")
    if not allow_missing and not candidate.exists():
        raise ValueError(f"Plik nie istnieje: {clean}")
    return candidate


def _venv_python() -> str:
    vpy = PROJECT_ROOT / ".venv" / "bin" / "python"
    return str(vpy) if vpy.is_file() else sys.executable


# ----------------- MCP Tool Definitions & Handlers -----------------

TOOLS: list[dict[str, Any]] = [
    {
        "name": "jarvis_list_files",
        "description": "Wypisz pliki źródłowe w projekcie ~/Jarvis (opcjonalnie filtrując po podkatalogu lub wzorcu nazwy).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "subdir": {"type": "string", "description": "Opcjonalny podkatalog, np. 'operator_modules', 'viewer', 'tests'."},
                "query": {"type": "string", "description": "Opcjonalny fragment nazwy pliku."},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "jarvis_read_file",
        "description": "Odczytaj zawartość pliku z projektu Jarvis (z opcjonalnym zakresem linii start_line..end_line).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Ścieżka względna w projekcie, np. 'router.py' lub 'viewer/app.js'."},
                "start_line": {"type": "integer", "minimum": 1},
                "end_line": {"type": "integer", "minimum": 1},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "jarvis_search_code",
        "description": "Przeszukaj kod projektu Jarvis wyrażeniem regularnym lub frazą (zwraca dopasowane linie z numerami).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Szukana fraza lub wyrażenie regularne."},
                "subdir": {"type": "string", "description": "Opcjonalne zawężenie do katalogu/pliku."},
                "max_hits": {"type": "integer", "minimum": 1, "maximum": 120},
            },
            "required": ["pattern"],
            "additionalProperties": False,
        },
    },
    {
        "name": "jarvis_write_file",
        "description": "Zapisz lub utwórz plik w projekcie Jarvis (tworzy automatyczny backup i weryfikuje składnię AST dla plików .py).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Ścieżka względna w projekcie."},
                "content": {"type": "string", "description": "Pełna docelowa zawartość pliku."},
            },
            "required": ["path", "content"],
            "additionalProperties": False,
        },
    },
    {
        "name": "jarvis_patch_file",
        "description": "Podmień dokładny fragment tekstu (old_text -> new_text) w istniejącym pliku projektu Jarvis z walidacją AST i kopią zapasową.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "old_text": {"type": "string", "description": "Unikalny fragment do zastąpienia."},
                "new_text": {"type": "string", "description": "Nowy fragment kodu."},
            },
            "required": ["path", "old_text", "new_text"],
            "additionalProperties": False,
        },
    },
    {
        "name": "jarvis_run_checks",
        "description": "Uruchom lokalny linter (scripts/lint.py) oraz wskazane testy jednostkowe (unittest) na komputerze właściciela.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "lint": {"type": "boolean", "description": "Czy uruchomić scripts/lint.py (domyślnie true)."},
                "tests": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Lista plików testowych, np. ['tests/test_agent_consent.py', 'tests/test_evolution.py'].",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "jarvis_service_control",
        "description": "Sprawdź status, zrestartuj usługę systemd jarvis.service lub pobierz ostatnie logi journalctl.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["status", "restart", "logs"]},
                "lines": {"type": "integer", "minimum": 10, "maximum": 200},
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    },
    {
        "name": "jarvis_agents_bridge",
        "description": "Zarządzaj lokalnymi agentami kodującymi Jarvisa (antigravity, claude, opencode, hermes): sprawdź postęp na żywo, outbox lub zleć zadanie w tle.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "list", "progress", "outbox", "logs", "run_background", "stop",
                        "team_list", "team_status", "team_start", "team_chat",
                        "team_nudge", "team_stop", "team_diff", "team_apply",
                        "router", "watchdog", "context_search", "owner_questions",
                        "owner_reply", "rollback",
                    ],
                },
                "agent": {"type": "string", "enum": ["antigravity", "claude", "opencode", "hermes"]},
                "task": {"type": "string"},
                "project_id": {"type": "string"},
                "title": {"type": "string"},
                "participants": {"type": "array", "items": {"type": "string"}},
                "assignments": {"type": "array", "items": {"type": "object"}},
                "review_agent": {"type": "string"},
                "architect_agent": {"type": "string"},
                "plan_first": {"type": "boolean"},
                "use_worktrees": {"type": "boolean"},
                "max_total_runs": {"type": "integer"},
                "max_project_minutes": {"type": "integer"},
                "seed_dir": {"type": "string"},
                "target": {"type": "string"},
                "req_id": {"type": "string"},
                "auto_repair": {"type": "boolean"},
                "message": {"type": "string"},
                "to": {"type": "string"},
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    },
]


def _backup_before_edit(target: Path) -> str | None:
    if not target.is_file():
        return None
    bdir = PROJECT_ROOT / ".jarvis-mcp-backups"
    bdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    safe_name = str(target.relative_to(PROJECT_ROOT)).replace("/", "__")
    dest = bdir / f"{stamp}-{safe_name}.bak"
    shutil.copy2(target, dest)
    return str(dest.relative_to(PROJECT_ROOT))


def _atomic_save_code(target: Path, content: str) -> dict[str, Any]:
    raw_bytes = content.encode("utf-8")
    if len(raw_bytes) > MAX_WRITE_BYTES:
        raise ValueError(f"Plik przekracza limit {MAX_WRITE_BYTES} bajtów.")
    if target.suffix.lower() == ".py":
        import ast
        try:
            ast.parse(content, filename=str(target.name))
        except SyntaxError as exc:
            raise ValueError(f"Odrzucono zapis — błąd składni Python w linii {exc.lineno}: {exc.msg}") from None
    backup_rel = _backup_before_edit(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f".{target.name}.tmp-{uuid.uuid4().hex[:8]}")
    tmp.write_bytes(raw_bytes)
    tmp.replace(target)
    return {"ok": True, "path": str(target.relative_to(PROJECT_ROOT)), "bytes": len(raw_bytes), "backup": backup_rel}


def execute_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    if name == "jarvis_list_files":
        sub = str(args.get("subdir") or "").strip().lstrip("/")
        base = _safe_project_path(sub) if sub else PROJECT_ROOT
        q = str(args.get("query") or "").strip().lower()
        rows = []
        for p in sorted(base.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(PROJECT_ROOT)
            if any(part in FORBIDDEN_PARTS or part.startswith(".jarvis-") for part in rel.parts):
                continue
            if p.name in FORBIDDEN_NAMES or p.suffix.lower() in FORBIDDEN_SUFFIXES:
                continue
            rel_str = str(rel)
            if q and q not in rel_str.lower():
                continue
            rows.append({"path": rel_str, "bytes": p.stat().st_size})
            if len(rows) >= 300:
                break
        return {"ok": True, "root": str(PROJECT_ROOT), "count": len(rows), "files": rows}

    if name == "jarvis_read_file":
        target = _safe_project_path(args.get("path", ""))
        oversized = target.stat().st_size > MAX_READ_BYTES
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        s = max(1, int(args.get("start_line") or 1))
        explicit_end = args.get("end_line")
        e = min(len(lines), int(explicit_end or len(lines)))
        # hardening: bez jawnego end_line plik ponad limit jest okrojony do
        # okna 250 linii — samo 'start_line' nie może obejść MAX_READ_BYTES.
        capped = oversized and not explicit_end
        if capped:
            e = min(e, s + 250)
        numbered = "\n".join(f"{i}: {lines[i-1]}" for i in range(s, e + 1))
        result = {
            "ok": True, "path": str(target.relative_to(PROJECT_ROOT)),
            "total_lines": len(lines), "shown_lines": f"{s}..{e}", "content": numbered,
        }
        if capped:
            result["truncated"] = True
        return result

    if name == "jarvis_search_code":
        pat = str(args.get("pattern") or "")
        if not pat:
            raise ValueError("Podaj 'pattern'.")
        rx = re.compile(pat, re.I)
        sub = str(args.get("subdir") or "").strip().lstrip("/")
        base = _safe_project_path(sub) if sub else PROJECT_ROOT
        limit = max(1, min(int(args.get("max_hits") or 60), 120))
        hits = []
        targets = [base] if base.is_file() else sorted(base.rglob("*"))
        for p in targets:
            if not p.is_file() or p.stat().st_size > 600_000:
                continue
            rel = p.relative_to(PROJECT_ROOT)
            if any(part in FORBIDDEN_PARTS or part.startswith(".jarvis-") for part in rel.parts):
                continue
            if p.name in FORBIDDEN_NAMES or p.suffix.lower() in (FORBIDDEN_SUFFIXES | {".png", ".jpg", ".woff2"}):
                continue
            try:
                for lineno, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    if rx.search(line):
                        hits.append({"path": str(rel), "line": lineno, "text": line.strip()[:220]})
                        if len(hits) >= limit:
                            return {"ok": True, "hits": hits, "truncated": True}
            except OSError:
                continue
        return {"ok": True, "hits": hits, "truncated": False}

    if name == "jarvis_write_file":
        target = _safe_project_path(args.get("path", ""), allow_missing=True)
        return _atomic_save_code(target, str(args.get("content") or ""))

    if name == "jarvis_patch_file":
        target = _safe_project_path(args.get("path", ""))
        current = target.read_text(encoding="utf-8")
        old_t = str(args.get("old_text") or "")
        new_t = str(args.get("new_text") or "")
        if not old_t or old_t not in current:
            raise ValueError("Nie znaleziono dokładnego fragmentu 'old_text' w pliku.")
        if current.count(old_t) > 1:
            raise ValueError("Fragment 'old_text' występuje wielokrotnie — podaj więcej kontekstu.")
        updated = current.replace(old_t, new_t, 1)
        return _atomic_save_code(target, updated)

    if name == "jarvis_run_checks":
        py = _venv_python()
        out_parts = {}
        if args.get("lint", True):
            r_lint = subprocess.run(
                [py, "scripts/lint.py"], cwd=str(PROJECT_ROOT),
                capture_output=True, text=True, timeout=45, check=False,
            )
            out_parts["lint"] = {
                "exit_code": r_lint.returncode,
                "output": (r_lint.stdout + r_lint.stderr).strip()[-3000:],
            }
        tests = args.get("tests") or []
        if isinstance(tests, list) and tests:
            safe_tests = [str(_safe_project_path(t).relative_to(PROJECT_ROOT)) for t in tests[:12]]
            r_test = subprocess.run(
                [py, "-m", "unittest", *safe_tests], cwd=str(PROJECT_ROOT),
                capture_output=True, text=True, timeout=90, check=False,
            )
            out_parts["unittest"] = {
                "exit_code": r_test.returncode,
                "output": (r_test.stdout + r_test.stderr).strip()[-4000:],
            }
        return {"ok": True, **out_parts}

    if name == "jarvis_service_control":
        act = str(args.get("action") or "status")
        if act == "restart":
            r = subprocess.run(["systemctl", "--user", "restart", "jarvis.service"],
                               capture_output=True, text=True, timeout=25, check=False)
            return {"ok": r.returncode == 0, "exit_code": r.returncode, "stderr": r.stderr.strip()}
        if act == "status":
            r = subprocess.run(["systemctl", "--user", "is-active", "jarvis.service"],
                               capture_output=True, text=True, timeout=10, check=False)
            return {"ok": True, "state": r.stdout.strip() or r.stderr.strip()}
        if act == "logs":
            n = max(10, min(int(args.get("lines") or 50), 200))
            r = subprocess.run(["journalctl", "--user", "-u", "jarvis.service", "-n", str(n), "--no-pager"],
                               capture_output=True, text=True, timeout=15, check=False)
            return {"ok": True, "logs": (r.stdout or r.stderr)[-5000:]}
        raise ValueError("Nieznana akcja jarvis_service_control.")

    if name == "jarvis_agents_bridge":
        if str(PROJECT_ROOT) not in sys.path:
            sys.path.insert(0, str(PROJECT_ROOT))
        import agent_cli
        import agent_team
        act = str(args.get("action") or "list")
        aid = str(args.get("agent") or "").strip().lower()
        pid = str(args.get("project_id") or "").strip().lower()
        if act == "list":
            return {"ok": True, **agent_cli.summary(), "projects": agent_team.list_projects(10)}
        if act == "progress":
            if aid and hasattr(agent_cli, "live_progress"):
                return {"ok": True, **agent_cli.live_progress(aid)}
            if hasattr(agent_cli, "live_progress"):
                return {"ok": True, "agents": [agent_cli.live_progress(x) for x in agent_cli.agent_ids()]}
            return {"ok": False, "error": "live_progress unavailable"}
        if act == "outbox":
            return {"ok": True, "agent": aid, "files": agent_cli.outbox(aid)}
        if act == "logs":
            return {"ok": True, "agent": aid, "log": agent_cli.tail(aid)}
        if act == "run_background":
            chosen_aid = aid
            if not chosen_aid:
                import agent_router
                chosen_aid = agent_router.pick_best_agent(task=str(args.get("task") or ""))
            return agent_cli.start_async(
                chosen_aid, str(args.get("task") or ""),
                approved=True, consent="remote-mcp", target_hint=str(args.get("target") or PROJECT_ROOT),
            )
        if act == "stop":
            return agent_cli.stop(aid)
        if act == "team_list":
            return {"ok": True, "projects": agent_team.list_projects()}
        if act == "team_status":
            return {"ok": True, **agent_team.project_status(pid)}
        if act == "team_start":
            goal = str(args.get("task") or "").strip()
            if pid and not goal:
                return agent_team.start_parallel_wave(
                    pid,
                    assignments=args.get("assignments"),
                    review_agent=str(args.get("review_agent") or ""),
                    approved=True,
                    consent="remote-mcp",
                )
            return agent_team.start_team_project(
                goal=goal,
                participants=args.get("participants"),
                assignments=args.get("assignments"),
                title=str(args.get("title") or ""),
                project_id=pid,
                review_agent=str(args.get("review_agent") or ""),
                architect_agent=str(args.get("architect_agent") or ""),
                plan_first=bool(args.get("plan_first")),
                use_worktrees=bool(args.get("use_worktrees", True)),
                max_total_runs=int(args.get("max_total_runs") or 12),
                max_project_minutes=int(args.get("max_project_minutes") or 30),
                seed_dir=str(args.get("seed_dir") or ""),
                approved=True,
                consent="remote-mcp",
            )
        if act == "team_chat":
            msg_text = str(args.get("message") or args.get("task") or "").strip()
            if msg_text:
                posted = agent_team.post_message(
                    pid, sender="owner", text=msg_text, to=str(args.get("to") or "all")
                )
                return {"ok": True, "posted": posted, "messages": agent_team.read_messages(pid, limit=30)}
            return {"ok": True, "messages": agent_team.read_messages(pid, limit=50)}
        if act == "team_nudge":
            return agent_team.nudge_agent(
                pid, aid, str(args.get("message") or args.get("task") or ""),
                approved=True, consent="remote-mcp",
            )
        if act == "team_stop":
            return agent_team.stop_project(pid)
        if act == "team_diff":
            import agent_review
            target = str(args.get("target") or PROJECT_ROOT)
            return agent_review.diff_outbox(f"team:{pid}", target)
        if act == "team_apply":
            import agent_review
            target = str(args.get("target") or PROJECT_ROOT)
            return agent_review.apply_outbox(f"team:{pid}", target)
        if act == "router":
            import agent_router
            return {"ok": True, **agent_router.router_summary()}
        if act == "watchdog":
            import health_watchdog
            return health_watchdog.scan_logs(
                auto_repair=bool(args.get("auto_repair")),
                project_root=str(args.get("target") or PROJECT_ROOT),
            )
        if act == "context_search":
            import code_index
            q = str(args.get("task") or args.get("message") or "").strip()
            target = str(args.get("target") or PROJECT_ROOT)
            return {"ok": True, "hits": code_index.search_context(q, root_dir=target)}
        if act == "owner_questions":
            import voice_bridge
            return {"ok": True, "questions": voice_bridge.pending_owner_questions(pid)}
        if act == "owner_reply":
            import voice_bridge
            ans = voice_bridge.answer_owner_question(
                str(args.get("message") or args.get("task") or ""),
                req_id=str(args.get("req_id") or ""),
                project_id=pid,
                source="remote-mcp",
            )
            return {"ok": True, "question": ans}
        if act == "rollback":
            import agent_review
            target = str(args.get("target") or PROJECT_ROOT)
            return agent_review.rollback_last_checkpoint(target)

    raise ValueError(f"Nieznane narzędzie MCP: {name}")


# ----------------- Streamable HTTP + OAuth 2.0 Handler -----------------

_AUTH_CODES: dict[str, float] = {}
_SESSIONS: set[str] = set()
_LOCK = threading.Lock()


class MCPBridgeHandler(BaseHTTPRequestHandler):
    auth_cfg: dict[str, str] = {}

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write(f"[jarvis-mcp] {self.address_string()} - {fmt % args}\n")

    def _send_json(self, code: int, payload: Any, extra_headers: dict[str, str] | None = None) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(raw)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, code: int, html: str) -> None:
        raw = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _external_base_url(self) -> str:
        url_file = Path(os.environ.get("JARVIS_MCP_PUBLIC_URL_FILE") or (CONFIG_DIR / "remote-mcp-public-url.txt"))
        if url_file.is_file():
            try:
                val = url_file.read_text(encoding="utf-8").strip()
                if val.startswith("http"):
                    return val.rstrip("/")
            except OSError:
                pass
        env_url = (os.environ.get("JARVIS_MCP_PUBLIC_URL") or "").rstrip("/")
        if env_url:
            return env_url
        proto = self.headers.get("X-Forwarded-Proto") or "https"
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or f"localhost:{DEFAULT_PORT}"
        return f"{proto}://{host}"

    def _authorized(self, parsed_path: str) -> bool:
        slug = self.auth_cfg["secret_slug"]
        # 1. Secret capability path `/mcp/<secret_slug>` (works cleanly with "No authentication" mode!)
        if parsed_path.rstrip("/") == f"/mcp/{slug}":
            return True
        # 2. OAuth 2.0 Bearer token on `/mcp`
        auth_hdr = self.headers.get("Authorization") or ""
        if auth_hdr.lower().startswith("bearer "):
            token = auth_hdr[7:].strip()
            if _verify_token(token, self.auth_cfg["signing_key"]) or secrets.compare_digest(token, slug):
                return True
        return False

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        base = self._external_base_url()

        if parsed.path == "/health":
            return self._send_json(200, {"ok": True, "service": "jarvis-remote-mcp", "project": str(PROJECT_ROOT)})

        if parsed.path in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
            return self._send_json(200, {
                "issuer": base,
                "authorization_endpoint": f"{base}/oauth/authorize",
                "token_endpoint": f"{base}/oauth/token",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
                "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            })

        if parsed.path == "/oauth/authorize":
            qs = urllib.parse.parse_qs(parsed.query)
            client_id = (qs.get("client_id") or [""])[0]
            redirect_uri = (qs.get("redirect_uri") or [""])[0]
            state = (qs.get("state") or [""])[0]
            if client_id != self.auth_cfg["client_id"]:
                return self._send_html(403, "<h3>Invalid client_id</h3>")
            html = (
                "<!doctype html><html><head><meta charset='utf-8'><title>Autoryzacja Jarvis MCP</title>"
                "<style>body{font-family:system-ui;background:#0f172a;color:#f8fafc;display:grid;place-items:center;height:95vh}"
                ".box{background:#1e293b;padding:28px;border-radius:12px;max-width:420px;border:1px solid #38bdf8}"
                "input,button{width:100%;padding:10px;margin-top:10px;border-radius:8px;border:1px solid #475569;box-sizing:border-box}"
                "button{background:#0284c7;color:#fff;font-weight:600;cursor:pointer;border:none}</style></head>"
                "<body><form class='box' method='POST' action='/oauth/authorize'>"
                "<h3>Połącz Gemini Enterprise z Jarvisem</h3>"
                f"<p style='font-size:13px;color:#94a3b8'>Katalog: <code>{PROJECT_ROOT}</code></p>"
                "<label style='font-size:13px'>Wklej Client Secret serwera MCP:</label>"
                "<input type='password' name='secret' required autofocus />"
                f"<input type='hidden' name='redirect_uri' value='{redirect_uri}' />"
                f"<input type='hidden' name='state' value='{state}' />"
                "<button type='submit'>Autoryzuj dostęp</button></form></body></html>"
            )
            return self._send_html(200, html)

        # Streamable HTTP allows GET on MCP endpoint (returns 405 when SSE push stream is not needed)
        if parsed.path == "/mcp" or parsed.path.startswith("/mcp/"):
            if not self._authorized(parsed.path):
                return self._send_json(401, {"error": "unauthorized"})
            self.send_response(405)
            self.send_header("Allow", "POST, DELETE")
            self.end_headers()
            return

        self._send_json(404, {"error": "not_found"})

    def do_DELETE(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/mcp" or parsed.path.startswith("/mcp/"):
            sid = self.headers.get("Mcp-Session-Id") or ""
            with _LOCK:
                _SESSIONS.discard(sid)
            self.send_response(204)
            self.end_headers()
            return
        self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw_body = self.rfile.read(min(length, 2_000_000)) if length > 0 else b""

        if parsed.path == "/oauth/authorize":
            form = urllib.parse.parse_qs(raw_body.decode("utf-8", "replace"))
            given = (form.get("secret") or [""])[0].strip()
            redirect_uri = (form.get("redirect_uri") or [""])[0]
            state = (form.get("state") or [""])[0]
            if not secrets.compare_digest(given, self.auth_cfg["client_secret"]):
                return self._send_html(403, "<h3>Błędny Client Secret.</h3>")
            code = secrets.token_urlsafe(24)
            with _LOCK:
                _AUTH_CODES[code] = time.time() + 300
            sep = "&" if "?" in redirect_uri else "?"
            target = f"{redirect_uri}{sep}code={urllib.parse.quote(code)}"
            if state:
                target += f"&state={urllib.parse.quote(state)}"
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
            return

        if parsed.path == "/oauth/token":
            ctype = (self.headers.get("Content-Type") or "").lower()
            if "application/json" in ctype:
                try:
                    params = {k: [str(v)] for k, v in json.loads(raw_body.decode("utf-8")).items()}
                except ValueError:
                    params = {}
            else:
                params = urllib.parse.parse_qs(raw_body.decode("utf-8", "replace"))

            cid = (params.get("client_id") or [""])[0]
            csec = (params.get("client_secret") or [""])[0]
            basic = self.headers.get("Authorization") or ""
            if basic.lower().startswith("basic "):
                try:
                    dec = base64.b64decode(basic[6:].strip()).decode("utf-8")
                    cid, _, csec = dec.partition(":")
                except Exception:
                    pass

            if not (secrets.compare_digest(cid, self.auth_cfg["client_id"])
                    and secrets.compare_digest(csec, self.auth_cfg["client_secret"])):
                return self._send_json(401, {"error": "invalid_client"})

            grant_type = (params.get("grant_type") or ["authorization_code"])[0]
            if grant_type == "authorization_code":
                code = (params.get("code") or [""])[0]
                with _LOCK:
                    exp = _AUTH_CODES.pop(code, 0.0)
                if exp < time.time():
                    return self._send_json(400, {"error": "invalid_grant"})

            access = _sign_token({"sub": "jarvis-owner", "exp": time.time() + 86400 * 30}, self.auth_cfg["signing_key"])
            refresh = _sign_token({"sub": "jarvis-refresh", "exp": time.time() + 86400 * 90}, self.auth_cfg["signing_key"])
            return self._send_json(200, {
                "access_token": access,
                "token_type": "Bearer",
                "expires_in": 86400 * 30,
                "refresh_token": refresh,
                "scope": "mcp",
            })

        if parsed.path == "/mcp" or parsed.path.startswith("/mcp/"):
            if not self._authorized(parsed.path):
                return self._send_json(401, {"error": "unauthorized"})
            try:
                payload = json.loads(raw_body.decode("utf-8"))
            except ValueError:
                return self._send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})

            if isinstance(payload, list):
                responses = []
                extra_h: dict[str, str] = {}
                for item in payload:
                    resp, hdrs = self._dispatch_rpc(item)
                    extra_h.update(hdrs)
                    if resp is not None:
                        responses.append(resp)
                if not responses:
                    self.send_response(202)
                    self.end_headers()
                    return
                return self._send_json(200, responses, extra_headers=extra_h)

            resp, hdrs = self._dispatch_rpc(payload)
            if resp is None:
                self.send_response(202)
                for k, v in hdrs.items():
                    self.send_header(k, v)
                self.end_headers()
                return
            return self._send_json(200, resp, extra_headers=hdrs)

        self._send_json(404, {"error": "not_found"})

    def _dispatch_rpc(self, msg: Any) -> tuple[dict[str, Any] | None, dict[str, str]]:
        if not isinstance(msg, dict):
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}, {}
        req_id = msg.get("id")
        method = str(msg.get("method") or "")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}

        # Notifications have no 'id' -> return 202 Accepted per MCP Streamable HTTP spec
        if "id" not in msg:
            return None, {}

        if method == "initialize":
            sid = uuid.uuid4().hex
            with _LOCK:
                _SESSIONS.add(sid)
            client_proto = str(params.get("protocolVersion") or PROTOCOL_VERSION)
            negotiated = client_proto if client_proto in ("2024-11-05", "2025-03-26", "2025-06-18") else PROTOCOL_VERSION
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": negotiated,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "jarvis-ubuntu-mcp", "version": "1.0.0"},
                },
            }, {"Mcp-Session-Id": sid}

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}, {}

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}, {}

        if method == "resources/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"resources": []}}, {}

        if method == "prompts/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"prompts": []}}, {}

        if method == "tools/call":
            tool_name = str(params.get("name") or "")
            tool_args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            try:
                out = execute_tool(tool_name, tool_args)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False, indent=2)}],
                        "isError": False,
                    },
                }, {}
            except Exception as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Błąd wykonania {tool_name}: {exc}"}],
                        "isError": True,
                    },
                }, {}

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }, {}


def print_banner(auth: dict[str, str], host: str, port: int, public_base: str = "") -> None:
    base = (public_base or "https://TWOJA-DOMENA-TUNELU").rstrip("/")
    slug = auth["secret_slug"]
    print("=" * 72)
    print(" JARVIS CUSTOM MCP SERVER — GOTOWY DO PODPIĘCIA W business.gemini.google")
    print("=" * 72)
    print(f" Lokalny adres nasłuchu : http://{host}:{port}")
    print(f" Chroniony katalog      : {PROJECT_ROOT}")
    print("-" * 72)
    print(" WARIANT A (NAJSZYBSZY — 'No authentication' + tajny token w ścieżce URL):")
    print(f"   MCP Server URL : {base}/mcp/{slug}")
    print("-" * 72)
    print(" WARIANT B (PEŁNE OAUTH 2.0 w formularzu Add MCP Server):")
    print(f"   MCP Server URL : {base}/mcp")
    print(f"   Client ID      : {auth['client_id']}")
    print(f"   Client Secret  : {auth['client_secret']}")
    print(f"   Auth URL       : {base}/oauth/authorize")
    print(f"   Token URL      : {base}/oauth/token")
    print("   Scopes         : mcp")
    print("=" * 72, flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Jarvis Remote MCP Server for Gemini Enterprise.")
    parser.add_argument("--host", default=os.environ.get("JARVIS_MCP_HOST", DEFAULT_HOST))
    parser.add_argument("--port", type=int, default=int(os.environ.get("JARVIS_MCP_PORT", DEFAULT_PORT)))
    parser.add_argument("--public-url", default="", help="Opcjonalny adres HTTPS z cloudflared do wyświetlenia gotowych linków.")
    parser.add_argument("--show-auth", action="store_true", help="Tylko wypisz dane konfiguracyjne i zakończ.")
    args = parser.parse_args()

    auth = load_or_create_auth()
    print_banner(auth, args.host, args.port, args.public_url)
    if args.show_auth:
        return 0

    MCPBridgeHandler.auth_cfg = auth
    server = ThreadingHTTPServer((args.host, args.port), MCPBridgeHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[jarvis-mcp] Zatrzymano.", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
