"""Persistent SQLite FTS5 episodic & decision memory for Jarvis and its coding agents.

Stores high-signal episodes across sessions with zero persistent RAM footprint:
  - Owner architectural answers (`owner.answered`)
  - Solved incidents & circuit-breaker anomalies (`router.circuit_tripped`)
  - Night Shift maintenance outcomes (`night_shift.completed`)
  - Explicit user/agent lessons (`remember_episode`)

Recalled episodes are injected into `code_index.build_context_pack()` so background
agents automatically reuse past decisions and bug root-causes.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from pathlib import Path

import agent_cli

VALID_KINDS = ("decision", "bugfix", "preference", "incident", "maintenance", "note")
TOKEN_RE = re.compile(r"[A-Za-zĄĆĘŁŃÓŚŹŻąćęłńóśźż0-9_]{3,}")
STOPWORDS = frozenset({
    "the", "and", "for", "with", "from", "that", "this", "jest", "oraz",
    "aby", "dla", "czy", "jak", "nie", "tak", "plik", "kod", "przy", "przez",
})
MAX_EPISODES = 2000


def _db_path() -> Path:
    base = agent_cli.ROOT.parent
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    return base / "episodic_memory.sqlite3"


def _connect() -> sqlite3.Connection:
    path = _db_path()
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS episodes ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  created_at REAL NOT NULL,"
        "  kind TEXT NOT NULL,"
        "  project_id TEXT NOT NULL DEFAULT '',"
        "  title TEXT NOT NULL,"
        "  summary TEXT NOT NULL,"
        "  tags TEXT NOT NULL DEFAULT ''"
        ")"
    )
    conn.execute(
        "CREATE VIRTUAL TABLE IF NOT EXISTS episodes_fts USING fts5("
        "  episode_id UNINDEXED,"
        "  kind,"
        "  title,"
        "  summary,"
        "  tags,"
        "  tokenize='unicode61'"
        ")"
    )
    return conn


def remember_episode(title: str, summary: str, *, kind: str = "decision",
                     tags: list[str] | str = "", project_id: str = "") -> dict:
    """Persist a structured episode into SQLite FTS5 and enforce bounded retention."""
    clean_title = str(title or "").strip()[:200]
    clean_summary = str(summary or "").strip()[:3000]
    if not clean_title or not clean_summary:
        raise ValueError("Wymagane są pola title oraz summary dla pamięci epizodycznej.")

    eff_kind = str(kind or "note").strip().lower()
    if eff_kind not in VALID_KINDS:
        eff_kind = "note"

    if isinstance(tags, (list, tuple, set)):
        tag_str = " ".join(str(t).strip() for t in tags if str(t).strip())[:240]
    else:
        tag_str = str(tags or "").strip()[:240]

    clean_pid = str(project_id or "").strip()[:80]
    now = round(time.time(), 3)

    conn = _connect()
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO episodes (created_at, kind, project_id, title, summary, tags) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (now, eff_kind, clean_pid, clean_title, clean_summary, tag_str),
            )
            ep_id = int(cur.lastrowid)
            conn.execute(
                "INSERT INTO episodes_fts (episode_id, kind, title, summary, tags) VALUES (?, ?, ?, ?, ?)",
                (ep_id, eff_kind, clean_title, clean_summary, tag_str),
            )
            total = conn.execute("SELECT COUNT(*) AS c FROM episodes").fetchone()["c"]
            if total > MAX_EPISODES:
                overflow = total - MAX_EPISODES
                old_ids = [
                    r["id"]
                    for r in conn.execute(
                        "SELECT id FROM episodes ORDER BY created_at ASC LIMIT ?",
                        (overflow,),
                    ).fetchall()
                ]
                for oid in old_ids:
                    conn.execute("DELETE FROM episodes WHERE id = ?", (oid,))
                    conn.execute("DELETE FROM episodes_fts WHERE episode_id = ?", (oid,))
    finally:
        conn.close()

    return {
        "id": ep_id,
        "created_at": now,
        "kind": eff_kind,
        "project_id": clean_pid,
        "title": clean_title,
        "summary": clean_summary,
        "tags": tag_str,
    }


def _fts_query(raw: str) -> str:
    tokens: list[str] = []
    for tok in TOKEN_RE.findall(str(raw or "").lower()):
        if tok in STOPWORDS or tok in tokens:
            continue
        tokens.append(tok)
        if len(tokens) >= 12:
            break
    if not tokens:
        return ""
    return " OR ".join(f'"{t}"*' for t in tokens)


def recall_episodes(query: str = "", *, limit: int = 6, kind: str = "") -> list[dict]:
    """Search past episodes via FTS5 BM25 (or return latest episodes if query is empty)."""
    cap = max(1, min(int(limit or 6), 30))
    clean_kind = str(kind or "").strip().lower()
    fts_q = _fts_query(query)

    conn = _connect()
    try:
        if not fts_q:
            if clean_kind:
                rows = conn.execute(
                    "SELECT id, created_at, kind, project_id, title, summary, tags "
                    "FROM episodes WHERE kind = ? ORDER BY created_at DESC LIMIT ?",
                    (clean_kind, cap),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, created_at, kind, project_id, title, summary, tags "
                    "FROM episodes ORDER BY created_at DESC LIMIT ?",
                    (cap,),
                ).fetchall()
            return [dict(r) for r in rows]

        if clean_kind:
            rows = conn.execute(
                "SELECT e.id, e.created_at, e.kind, e.project_id, e.title, e.summary, e.tags, "
                "bm25(episodes_fts, 0.0, 2.0, 5.0, 2.5, 3.0) AS rank "
                "FROM episodes_fts f JOIN episodes e ON e.id = f.episode_id "
                "WHERE episodes_fts MATCH ? AND e.kind = ? "
                "ORDER BY rank LIMIT ?",
                (fts_q, clean_kind, cap),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT e.id, e.created_at, e.kind, e.project_id, e.title, e.summary, e.tags, "
                "bm25(episodes_fts, 0.0, 2.0, 5.0, 2.5, 3.0) AS rank "
                "FROM episodes_fts f JOIN episodes e ON e.id = f.episode_id "
                "WHERE episodes_fts MATCH ? "
                "ORDER BY rank LIMIT ?",
                (fts_q, cap),
            ).fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()

    out = []
    for r in rows:
        d = dict(r)
        rank = float(d.pop("rank", 0.0) or 0.0)
        d["score"] = round(-rank, 3)
        out.append(d)
    return out


def memory_stats() -> dict:
    """Return total stored episodes and breakdown by kind."""
    conn = _connect()
    try:
        total = int(conn.execute("SELECT COUNT(*) AS c FROM episodes").fetchone()["c"])
        by_kind = {
            r["kind"]: int(r["c"])
            for r in conn.execute("SELECT kind, COUNT(*) AS c FROM episodes GROUP BY kind").fetchall()
        }
        recent = [
            dict(r)
            for r in conn.execute(
                "SELECT id, created_at, kind, project_id, title, tags "
                "FROM episodes ORDER BY created_at DESC LIMIT 5"
            ).fetchall()
        ]
    finally:
        conn.close()
    return {"ok": True, "total": total, "by_kind": by_kind, "recent": recent}


def handle_bus_event(event: dict) -> None:
    """Subscriber hook for `event_bus` that auto-records high-signal episodes."""
    if not isinstance(event, dict):
        return
    topic = str(event.get("topic") or "")
    data = event.get("data") if isinstance(event.get("data"), dict) else {}

    try:
        if topic == "owner.answered":
            q = str(data.get("question") or "").strip()
            a = str(data.get("answer") or "").strip()
            if q and a:
                remember_episode(
                    title=f"Decyzja właściciela: {q[:120]}",
                    summary=f"Pytanie agenta ({data.get('from', 'agent')}): {q}\nOdpowiedź właściciela: {a}",
                    kind="decision",
                    tags=["owner", str(data.get("from") or ""), str(data.get("source") or "")],
                    project_id=str(data.get("project_id") or ""),
                )
        elif topic == "router.circuit_tripped":
            aid = str(data.get("agent") or "agent")
            ekind = str(data.get("error_kind") or "error")
            hint = str(data.get("error_hint") or "")
            remember_episode(
                title=f"Bezpiecznik API agenta {aid}: {ekind}",
                summary=f"Agent {aid} przeszedł w kwarantannę ({ekind}). Szczegóły: {hint}",
                kind="incident",
                tags=[aid, ekind, "circuit_breaker"],
            )
        elif topic == "night_shift.completed":
            remember_episode(
                title="Zakończono cykl Nocnej Zmiany",
                summary=json.dumps(data, ensure_ascii=False),
                kind="maintenance",
                tags=["night_shift", "qa_ok" if data.get("viewer_qa_ok") else "qa_issue"],
            )
    except Exception:
        return
