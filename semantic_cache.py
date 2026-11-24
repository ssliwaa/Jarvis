"""Zero-RAM SQLite exact & high-similarity prompt cache with mtime invalidation.

Avoids redundant paid cloud calls on ThinkCentre M720q when identical or
near-identical (`cosine >= 0.92`) read-only queries are issued within TTL, while
automatically invalidating entries whenever the workspace `mtime` watermark advances.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import time
from pathlib import Path

import agent_cli

DEFAULT_TTL_SECONDS = 6 * 3600
SIMILARITY_THRESHOLD = 0.92
MAX_CACHE_ENTRIES = 600
VEC_BUCKETS = 96
TOKEN_RE = re.compile(r"[A-Za-zĄĆĘŁŃÓŚŹŻąćęłńóśźż0-9_]{2,}")


def _db_path() -> Path:
    base = agent_cli.ROOT.parent
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    return base / "semantic_cache.sqlite3"


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
        "CREATE TABLE IF NOT EXISTS prompt_cache ("
        "  key_hash TEXT PRIMARY KEY,"
        "  scope TEXT NOT NULL,"
        "  watermark REAL NOT NULL,"
        "  created_at REAL NOT NULL,"
        "  expires_at REAL NOT NULL,"
        "  norm_prompt TEXT NOT NULL,"
        "  vec_json TEXT NOT NULL,"
        "  response_text TEXT NOT NULL,"
        "  model TEXT NOT NULL,"
        "  est_usd REAL NOT NULL DEFAULT 0.0,"
        "  hits INTEGER NOT NULL DEFAULT 0"
        ")"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cache_metrics ("
        "  id INTEGER PRIMARY KEY CHECK (id = 1),"
        "  total_hits INTEGER NOT NULL DEFAULT 0,"
        "  total_misses INTEGER NOT NULL DEFAULT 0,"
        "  saved_usd REAL NOT NULL DEFAULT 0.0"
        ")"
    )
    conn.execute(
        "INSERT OR IGNORE INTO cache_metrics (id, total_hits, total_misses, saved_usd) VALUES (1, 0, 0, 0.0)"
    )
    return conn


def normalize_prompt(prompt: str) -> str:
    tokens = TOKEN_RE.findall(str(prompt or "").lower())
    return " ".join(tokens)


def _prompt_key(norm: str, scope: str) -> str:
    h = hashlib.sha256()
    h.update(scope.encode("utf-8"))
    h.update(b"\x00")
    h.update(norm.encode("utf-8"))
    return h.hexdigest()


def _sparse_vec(norm: str) -> dict[str, float]:
    counts: dict[str, float] = {}
    words = norm.split()
    for i, w in enumerate(words):
        b = str(hash(w) % VEC_BUCKETS)
        counts[b] = counts.get(b, 0.0) + 1.0
        if i + 1 < len(words):
            bg = str(hash(f"{w}_{words[i + 1]}") % VEC_BUCKETS)
            counts[bg] = counts.get(bg, 0.0) + 0.7
    mag = math.sqrt(sum(v * v for v in counts.values()))
    if mag <= 0.0:
        return {}
    return {k: round(v / mag, 5) for k, v in counts.items()}


def _cosine(a: dict[str, float], b: dict[str, float]) -> float:
    if not a or not b:
        return 0.0
    if len(a) > len(b):
        a, b = b, a
    return sum(val * b.get(k, 0.0) for k, val in a.items())


def directory_watermark(root_dir: str | Path | None) -> float:
    """Compute latest file mtime across top-level & 1-level source/note files for invalidation."""
    if not root_dir:
        return 0.0
    root = Path(root_dir).expanduser()
    if not root.is_dir():
        return 0.0
    latest = 0.0
    try:
        for entry in os.scandir(root):
            if entry.name.startswith("."):
                continue
            try:
                st = entry.stat(follow_symlinks=False)
                if st.st_mtime > latest:
                    latest = st.st_mtime
                if entry.is_dir(follow_symlinks=False) and entry.name not in ("node_modules", "__pycache__", "venv", ".venv"):
                    for sub in os.scandir(entry.path):
                        if not sub.name.startswith("."):
                            sst = sub.stat(follow_symlinks=False)
                            if sst.st_mtime > latest:
                                latest = sst.st_mtime
            except OSError:
                continue
    except OSError:
        return 0.0
    return round(latest, 3)


def put(prompt: str, response_text: str, *, scope: str = "default",
        watermark: float = 0.0, model: str = "cloud", est_usd: float = 0.002,
        ttl_seconds: int = DEFAULT_TTL_SECONDS) -> dict:
    """Store a prompt->response pair in SQLite cache with TTL and watermark."""
    norm = normalize_prompt(prompt)
    clean_resp = str(response_text or "").strip()
    if not norm or not clean_resp:
        return {"ok": False, "stored": False}

    clean_scope = str(scope or "default").strip()[:64]
    key = _prompt_key(norm, clean_scope)
    now = round(time.time(), 3)
    exp = round(now + max(10, int(ttl_seconds)), 3)
    vec = _sparse_vec(norm)

    conn = _connect()
    try:
        with conn:
            conn.execute("DELETE FROM prompt_cache WHERE expires_at <= ?", (now,))
            conn.execute(
                "INSERT OR REPLACE INTO prompt_cache "
                "(key_hash, scope, watermark, created_at, expires_at, norm_prompt, vec_json, response_text, model, est_usd, hits) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT hits FROM prompt_cache WHERE key_hash = ?), 0))",
                (
                    key, clean_scope, round(float(watermark), 3), now, exp,
                    norm[:2000], json.dumps(vec), clean_resp[:24000],
                    str(model or "cloud")[:64], max(0.0, float(est_usd)), key,
                ),
            )
            total = int(conn.execute("SELECT COUNT(*) AS c FROM prompt_cache").fetchone()["c"])
            if total > MAX_CACHE_ENTRIES:
                overflow = total - MAX_CACHE_ENTRIES
                conn.execute(
                    "DELETE FROM prompt_cache WHERE key_hash IN "
                    "(SELECT key_hash FROM prompt_cache ORDER BY created_at ASC LIMIT ?)",
                    (overflow,),
                )
    finally:
        conn.close()
    return {"ok": True, "stored": True, "key": key[:16], "expires_at": exp}


def get(prompt: str, *, scope: str = "default", watermark: float = 0.0,
        allow_semantic: bool = True) -> dict | None:
    """Look up an exact or high-similarity (`>=0.92`) cached response if fresh and watermark matches."""
    norm = normalize_prompt(prompt)
    if not norm:
        return None
    clean_scope = str(scope or "default").strip()[:64]
    key = _prompt_key(norm, clean_scope)
    now = round(time.time(), 3)
    wm = round(float(watermark), 3)

    conn = _connect()
    try:
        with conn:
            row = conn.execute(
                "SELECT key_hash, response_text, model, est_usd, watermark, expires_at, hits "
                "FROM prompt_cache WHERE key_hash = ? AND scope = ?",
                (key, clean_scope),
            ).fetchone()

            matched_row = None
            match_kind = "exact"
            similarity = 1.0

            if row and float(row["expires_at"]) > now and abs(float(row["watermark"]) - wm) < 0.002:
                matched_row = row
            elif allow_semantic:
                q_vec = _sparse_vec(norm)
                candidates = conn.execute(
                    "SELECT key_hash, response_text, model, est_usd, vec_json, hits "
                    "FROM prompt_cache WHERE scope = ? AND expires_at > ? AND ABS(watermark - ?) < 0.002 "
                    "ORDER BY created_at DESC LIMIT 80",
                    (clean_scope, now, wm),
                ).fetchall()
                best_sim = 0.0
                for cand in candidates:
                    try:
                        c_vec = json.loads(cand["vec_json"])
                    except ValueError:
                        continue
                    sim = _cosine(q_vec, c_vec)
                    if sim >= SIMILARITY_THRESHOLD and sim > best_sim:
                        best_sim = sim
                        matched_row = cand
                        match_kind = "semantic"
                        similarity = round(sim, 4)

            if matched_row is None:
                conn.execute("UPDATE cache_metrics SET total_misses = total_misses + 1 WHERE id = 1")
                return None

            est = float(matched_row["est_usd"] or 0.0)
            conn.execute(
                "UPDATE prompt_cache SET hits = hits + 1 WHERE key_hash = ?",
                (matched_row["key_hash"],),
            )
            conn.execute(
                "UPDATE cache_metrics SET total_hits = total_hits + 1, saved_usd = ROUND(saved_usd + ?, 6) WHERE id = 1",
                (est,),
            )
            return {
                "hit": True,
                "match_kind": match_kind,
                "similarity": similarity,
                "response_text": matched_row["response_text"],
                "model": matched_row["model"],
                "saved_usd": est,
                "hits": int(matched_row["hits"]) + 1,
            }
    finally:
        conn.close()


def clear(scope: str = "") -> dict:
    conn = _connect()
    try:
        with conn:
            if scope:
                cur = conn.execute("DELETE FROM prompt_cache WHERE scope = ?", (scope,))
            else:
                cur = conn.execute("DELETE FROM prompt_cache")
            removed = int(cur.rowcount or 0)
    finally:
        conn.close()
    return {"ok": True, "removed": removed}


def cache_summary() -> dict:
    conn = _connect()
    try:
        now = time.time()
        active = int(conn.execute("SELECT COUNT(*) AS c FROM prompt_cache WHERE expires_at > ?", (now,)).fetchone()["c"])
        m = conn.execute("SELECT total_hits, total_misses, saved_usd FROM cache_metrics WHERE id = 1").fetchone()
        hits = int(m["total_hits"]) if m else 0
        misses = int(m["total_misses"]) if m else 0
        saved = round(float(m["saved_usd"] or 0.0), 4) if m else 0.0
    finally:
        conn.close()
    total = hits + misses
    return {
        "ok": True,
        "active_entries": active,
        "total_hits": hits,
        "total_misses": misses,
        "hit_rate": round(hits / total, 3) if total else 0.0,
        "saved_usd": saved,
    }
