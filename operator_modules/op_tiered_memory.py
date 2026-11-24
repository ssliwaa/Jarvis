"""Zero-dependency Multi-Tiered Persistent Memory and Entity Knowledge Graph for Jarvis.

Synthesizes architectural patterns from:
- Letta / MemGPT (#24): Hierarchical OS memory architecture (L1 Core Memory blocks with size ceilings,
  self-editing memory primitives: core_read, core_write, core_append, core_replace).
- Mem0 (#23): Entity-Relation Graph triple store (subject, predicate, object) with evidence counting,
  temporal confirmation timestamps, and automated contradiction/superseding resolution.
- SQLite FTS5: L3 Archival full-text indexed memory with BM25 ranking and search.

Exclusively uses the Python standard library. Zero external dependencies.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
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
    "core_read",
    "core_write",
    "core_append",
    "core_replace",
    "entity_upsert",
    "entity_merge",
    "entity_retire",
    "entity_query",
    "archival_search",
    "archival_insert",
    "list_entities",
})

KNOWN_ARGUMENTS: frozenset[str] = frozenset({
    "action",
    "block_name",
    "section",
    "content",
    "old_content",
    "new_content",
    "subject",
    "predicate",
    "object",
    "query",
    "category",
    "limit",
    "include_superseded",
    "reason",
    "db_path",
    "export_path",
})

# Maximum character capacity per L1 Core Memory block (Letta constraint)
MAX_CORE_BLOCK_CHARS = 2000

DEFAULT_CORE_BLOCKS = {
    "human_profile": "Developer environment: Linux, Python 3.10+, strict standard library preference.",
    "persona_spec": "Jarvis Operator: autonomous developer assistant delivering truthful, verified results.",
    "scratchpad": "Active tasks: maintain system integrity, verify preflight checks, execute zero-regression operations.",
}


class MemoryError(Exception):
    """Base exception for tiered_memory."""


class PathSecurityError(MemoryError):
    """Raised when db_path or export_path resolves outside ALLOWED_ROOTS."""


class SensitivePathError(MemoryError):
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
    """Open SQLite connection and initialize memory schemas."""
    conn = sqlite3.connect(str(db_path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    with conn:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")

        # L1 Core Memory Table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS core_memory (
                block_name TEXT PRIMARY KEY,
                content TEXT NOT NULL,
                updated_at REAL NOT NULL
            );
        """)

        # Initialize defaults if missing
        now = time.time()
        for bname, bcontent in DEFAULT_CORE_BLOCKS.items():
            conn.execute(
                "INSERT OR IGNORE INTO core_memory (block_name, content, updated_at) VALUES (?, ?, ?)",
                (bname, bcontent, now),
            )

        # L3 Archival Memory Table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS archival_memory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL NOT NULL,
                category TEXT NOT NULL,
                content TEXT NOT NULL
            );
        """)

        # FTS5 Virtual Table for Archival Search
        try:
            conn.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS archival_fts USING fts5(
                    content,
                    category,
                    content='archival_memory',
                    content_rowid='id'
                );
            """)
        except sqlite3.OperationalError:
            # Fallback if SQLite was compiled without FTS5
            pass

        # L4 Entity Knowledge Graph Table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS entity_triples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject TEXT NOT NULL,
                predicate TEXT NOT NULL,
                object TEXT NOT NULL,
                evidence_count INTEGER DEFAULT 1,
                is_active INTEGER DEFAULT 1,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_triples_sub ON entity_triples(subject, is_active);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_triples_pred ON entity_triples(predicate, is_active);")

    return conn


def _resolve_block_name(args: dict[str, Any]) -> str | None:
    """Extract block_name or section alias."""
    name = args.get("block_name") or args.get("section")
    return str(name).strip() if name else None


def _core_read(args: dict[str, Any], conn: sqlite3.Connection) -> dict[str, Any]:
    """Read one or all L1 Core Memory blocks with character counters."""
    target_block = _resolve_block_name(args)
    cur = conn.cursor()

    if target_block:
        row = cur.execute("SELECT * FROM core_memory WHERE block_name = ?", (target_block,)).fetchone()
        if not row:
            return {
                "block_name": target_block,
                "exists": False,
                "content": "",
                "char_count": 0,
                "max_chars": MAX_CORE_BLOCK_CHARS,
                "updated_at": None,
            }
        content = row["content"]
        return {
            "block_name": target_block,
            "exists": True,
            "content": content,
            "char_count": len(content),
            "max_chars": MAX_CORE_BLOCK_CHARS,
            "updated_at": row["updated_at"],
        }
    else:
        rows = cur.execute("SELECT * FROM core_memory ORDER BY block_name ASC").fetchall()
        blocks = {}
        total_chars = 0
        for r in rows:
            cnt = len(r["content"])
            total_chars += cnt
            blocks[r["block_name"]] = {
                "content": r["content"],
                "char_count": cnt,
                "max_chars": MAX_CORE_BLOCK_CHARS,
                "updated_at": r["updated_at"],
            }
        return {
            "total_blocks": len(blocks),
            "total_chars": total_chars,
            "blocks": blocks,
        }


def _core_write(args: dict[str, Any], conn: sqlite3.Connection) -> dict[str, Any]:
    """Overwrite or create an L1 Core Memory block, enforcing capacity limit."""
    target_block = _resolve_block_name(args)
    if not target_block:
        raise MemoryError("Parameter 'block_name' or 'section' is required for core_write.")

    content = args.get("content")
    if content is None:
        raise MemoryError("Parameter 'content' is required for core_write.")

    content_str = str(content)
    if len(content_str) > MAX_CORE_BLOCK_CHARS:
        raise MemoryError(
            f"Core memory block '{target_block}' exceeds capacity limit: "
            f"{len(content_str)} chars > {MAX_CORE_BLOCK_CHARS} max allowed."
        )

    now = time.time()
    with conn:
        conn.execute(
            """
            INSERT INTO core_memory (block_name, content, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(block_name) DO UPDATE SET
                content = excluded.content,
                updated_at = excluded.updated_at
            """,
            (target_block, content_str, now),
        )

    return {
        "status": "written",
        "block_name": target_block,
        "content": content_str,
        "char_count": len(content_str),
        "max_chars": MAX_CORE_BLOCK_CHARS,
        "updated_at": now,
    }


def _core_append(args: dict[str, Any], conn: sqlite3.Connection) -> dict[str, Any]:
    """Append text to an existing L1 Core Memory block."""
    target_block = _resolve_block_name(args)
    if not target_block:
        raise MemoryError("Parameter 'block_name' or 'section' is required for core_append.")

    to_append = args.get("content")
    if not to_append:
        raise MemoryError("Parameter 'content' is required for core_append.")

    cur = conn.cursor()
    row = cur.execute("SELECT content FROM core_memory WHERE block_name = ?", (target_block,)).fetchone()
    old_content = row["content"] if row else ""
    new_content = (old_content + "\n" + str(to_append)).strip()

    if len(new_content) > MAX_CORE_BLOCK_CHARS:
        raise MemoryError(
            f"Appending to core block '{target_block}' would exceed capacity: "
            f"{len(new_content)} chars > {MAX_CORE_BLOCK_CHARS} max allowed."
        )

    now = time.time()
    with conn:
        conn.execute(
            """
            INSERT INTO core_memory (block_name, content, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(block_name) DO UPDATE SET
                content = excluded.content,
                updated_at = excluded.updated_at
            """,
            (target_block, new_content, now),
        )

    return {
        "status": "appended",
        "block_name": target_block,
        "content": new_content,
        "char_count": len(new_content),
        "max_chars": MAX_CORE_BLOCK_CHARS,
        "updated_at": now,
    }


def _core_replace(args: dict[str, Any], conn: sqlite3.Connection) -> dict[str, Any]:
    """Find and replace text within an L1 Core Memory block."""
    target_block = _resolve_block_name(args)
    if not target_block:
        raise MemoryError("Parameter 'block_name' or 'section' is required for core_replace.")

    old_text = args.get("old_content")
    new_text = args.get("new_content")
    if old_text is None or new_text is None:
        raise MemoryError("Both 'old_content' and 'new_content' are required for core_replace.")

    cur = conn.cursor()
    row = cur.execute("SELECT content FROM core_memory WHERE block_name = ?", (target_block,)).fetchone()
    if not row:
        raise MemoryError(f"Core memory block '{target_block}' not found.")

    curr_content = row["content"]
    if str(old_text) not in curr_content:
        raise MemoryError(f"Target substring '{old_text}' not found in core block '{target_block}'.")

    updated_content = curr_content.replace(str(old_text), str(new_text), 1)
    if len(updated_content) > MAX_CORE_BLOCK_CHARS:
        raise MemoryError(
            f"Replacement in core block '{target_block}' exceeds capacity: "
            f"{len(updated_content)} chars > {MAX_CORE_BLOCK_CHARS} max allowed."
        )

    now = time.time()
    with conn:
        conn.execute(
            "UPDATE core_memory SET content = ?, updated_at = ? WHERE block_name = ?",
            (updated_content, now, target_block),
        )

    return {
        "status": "replaced",
        "block_name": target_block,
        "content": updated_content,
        "char_count": len(updated_content),
        "max_chars": MAX_CORE_BLOCK_CHARS,
        "updated_at": now,
    }


def _archival_insert(args: dict[str, Any], conn: sqlite3.Connection) -> dict[str, Any]:
    """Insert long-term document or lesson into L3 Archival Memory with full-text indexing."""
    content = args.get("content")
    if not content:
        raise MemoryError("Parameter 'content' is required for archival_insert.")

    category = str(args.get("category") or "general").strip()
    now = time.time()

    with conn:
        cur = conn.execute(
            "INSERT INTO archival_memory (created_at, category, content) VALUES (?, ?, ?)",
            (now, category, str(content)),
        )
        row_id = cur.lastrowid
        # Sync with FTS5 if table exists
        try:
            conn.execute(
                "INSERT INTO archival_fts (rowid, content, category) VALUES (?, ?, ?)",
                (row_id, str(content), category),
            )
        except sqlite3.OperationalError:
            pass

    return {
        "status": "inserted",
        "id": row_id,
        "category": category,
        "content": str(content),
        "created_at": now,
    }


def _archival_search(args: dict[str, Any], conn: sqlite3.Connection) -> dict[str, Any]:
    """Search L3 Archival Memory using FTS5 full-text search with LIKE fallback."""
    query = args.get("query")
    if not query:
        raise MemoryError("Parameter 'query' is required for archival_search.")

    category = args.get("category")
    limit = max(1, min(int(args.get("limit") or 10), 100))
    query_str = str(query).strip()

    cur = conn.cursor()
    results = []

    # 1. Attempt FTS5 search
    fts_success = False
    try:
        # Sanitize query for FTS5 (strip punctuation that breaks FTS syntax)
        clean_fts_query = re.sub(r'["\*\?\^\(\)\{\}\[\]\:\;]', " ", query_str).strip()
        if clean_fts_query:
            fts_sql = """
                SELECT a.id, a.created_at, a.category, a.content, rank
                FROM archival_fts f
                JOIN archival_memory a ON f.rowid = a.id
                WHERE archival_fts MATCH ?
            """
            params = [clean_fts_query]
            if category:
                fts_sql += " AND a.category = ?"
                params.append(category)
            fts_sql += " ORDER BY rank LIMIT ?"
            params.append(limit)

            rows = cur.execute(fts_sql, tuple(params)).fetchall()
            for r in rows:
                results.append({
                    "id": r["id"],
                    "created_at": r["created_at"],
                    "category": r["category"],
                    "content": r["content"],
                    "rank": round(float(r["rank"]), 4) if "rank" in r.keys() else 0.0,
                })
            fts_success = True
    except sqlite3.OperationalError:
        fts_success = False

    # 2. Fallback to LIKE query if FTS5 not present or query syntax returned empty/error
    if not fts_success or len(results) == 0:
        like_sql = "SELECT id, created_at, category, content FROM archival_memory WHERE content LIKE ?"
        params = [f"%{query_str}%"]
        if category:
            like_sql += " AND category = ?"
            params.append(category)
        like_sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = cur.execute(like_sql, tuple(params)).fetchall()
        results = [
            {
                "id": r["id"],
                "created_at": r["created_at"],
                "category": r["category"],
                "content": r["content"],
                "rank": 0.0,
            }
            for r in rows
        ]

    return {
        "query": query_str,
        "category_filter": category,
        "match_count": len(results),
        "results": results,
    }


def _entity_upsert(args: dict[str, Any], conn: sqlite3.Connection) -> dict[str, Any]:
    """Upsert an entity-relation triple with automated contradiction resolution (Mem0 pattern)."""
    subj = args.get("subject")
    pred = args.get("predicate")
    obj = args.get("object")

    if not subj or not pred or not obj:
        raise MemoryError("Parameters 'subject', 'predicate', and 'object' are required for entity_upsert.")

    subj_s = str(subj).strip()
    pred_s = str(pred).strip()
    obj_s = str(obj).strip()
    now = time.time()

    cur = conn.cursor()
    # Check existing active triples with same (subject, predicate).
    # Identity is case-insensitive: facts about the same entity arrive with
    # drifting capitalisation ("Jarvis"/"jarvis"), and the Mem0-style
    # contradiction resolution must fold those into one identity instead of
    # minting parallel active triples. The object below is already compared
    # with str.casefold(), so the lookup uses the same full-Unicode folding
    # (SQLite's NOCASE collation would only fold ASCII letters).
    subject_fold = subj_s.casefold()
    predicate_fold = pred_s.casefold()
    cur.execute("SELECT * FROM entity_triples WHERE is_active = 1")
    existing_actives = [
        row for row in cur.fetchall()
        if row["subject"].casefold() == subject_fold
        and row["predicate"].casefold() == predicate_fold
    ]

    superseded_records = []
    exact_match = None

    for row in existing_actives:
        if row["object"].casefold() == obj_s.casefold():
            exact_match = row
        else:
            superseded_records.append({
                "id": row["id"],
                "old_object": row["object"],
                "superseded_at": now,
            })

    with conn:
        if exact_match:
            # Re-confirmation: increment evidence_count
            new_count = exact_match["evidence_count"] + 1
            conn.execute(
                "UPDATE entity_triples SET evidence_count = ?, updated_at = ? WHERE id = ?",
                (new_count, now, exact_match["id"]),
            )
            return {
                "status": "reconfirmed",
                "triple": {"subject": subj_s, "predicate": pred_s, "object": obj_s},
                "evidence_count": new_count,
                "contradiction_resolved": False,
                "updated_at": now,
            }

        # If contradictory active records exist for this (subject, predicate), supersede them
        if superseded_records:
            for s in superseded_records:
                conn.execute(
                    "UPDATE entity_triples SET is_active = 0, updated_at = ? WHERE id = ?",
                    (now, s["id"]),
                )

        # Insert new active triple
        cur_ins = conn.execute(
            """
            INSERT INTO entity_triples (
                subject, predicate, object, evidence_count, is_active, created_at, updated_at
            ) VALUES (?, ?, ?, 1, 1, ?, ?)
            """,
            (subj_s, pred_s, obj_s, now, now),
        )
        triple_id = cur_ins.lastrowid

    return {
        "status": "inserted",
        "id": triple_id,
        "triple": {"subject": subj_s, "predicate": pred_s, "object": obj_s},
        "evidence_count": 1,
        "contradiction_resolved": len(superseded_records) > 0,
        "superseded_triples": superseded_records,
        "updated_at": now,
    }


def _entity_merge(args: dict[str, Any], conn: sqlite3.Connection) -> dict[str, Any]:
    """Fold case-variant spellings of one subject into a canonical row set.

    Maintenance action for stores written before the casefold identity fix:
    back then "Alice"/"ALICE" minted parallel active triples. The merge is
    gated to a single casefold identity (the same rule entity_upsert uses),
    so it can never conflate two different entities that merely look alike.
    Legacy/history rows keep their spellings: superseding hides facts,
    it does not delete them (Mem0's expiration semantics).
    """
    canonical = str(args.get("subject") or "").strip()
    if not canonical:
        raise MemoryError("Parameter 'subject' (canonical spelling) is required for entity_merge.")

    now = time.time()
    identity = canonical.casefold()
    cur = conn.cursor()
    cur.execute("SELECT * FROM entity_triples WHERE is_active = 1")
    identity_rows = [row for row in cur.fetchall()
                     if row["subject"].casefold() == identity]
    variants = [row for row in identity_rows if row["subject"] != canonical]

    # Canonical anchor per predicate (first row wins on legacy duplicates).
    canon_by_pred: dict[str, Any] = {}
    evidence_now: dict[int, int] = {}
    for row in identity_rows:
        if row["subject"] != canonical:
            continue
        pred_fold = row["predicate"].casefold()
        if pred_fold not in canon_by_pred:
            canon_by_pred[pred_fold] = row
            evidence_now[row["id"]] = row["evidence_count"]

    moved, reconfirmed, conflicts = [], [], []
    with conn:
        for row in variants:
            pred_fold = row["predicate"].casefold()
            target = canon_by_pred.get(pred_fold)
            if target is None:
                # No canonical fact for this predicate: repoint in place,
                # keeping the row id, evidence and created_at history.
                conn.execute(
                    "UPDATE entity_triples SET subject = ?, updated_at = ? WHERE id = ?",
                    (canonical, now, row["id"]),
                )
                canon_by_pred[pred_fold] = row
                evidence_now[row["id"]] = row["evidence_count"]
                moved.append({"predicate": row["predicate"],
                              "object": row["object"]})
            else:
                conn.execute(
                    "UPDATE entity_triples SET is_active = 0, updated_at = ? WHERE id = ?",
                    (now, row["id"]),
                )
                if target["object"].casefold() == row["object"].casefold():
                    total = evidence_now[target["id"]] + row["evidence_count"]
                    conn.execute(
                        "UPDATE entity_triples SET evidence_count = ?, updated_at = ? "
                        "WHERE id = ?",
                        (total, now, target["id"]),
                    )
                    evidence_now[target["id"]] = total
                    reconfirmed.append({"predicate": row["predicate"],
                                        "object": target["object"],
                                        "evidence_count": total})
                else:
                    conflicts.append({"predicate": row["predicate"],
                                      "kept_object": target["object"],
                                      "superseded_object": row["object"]})

    return {
        "status": "merged" if (moved or reconfirmed or conflicts) else "noop",
        "canonical": canonical,
        "merged_spellings": sorted({row["subject"] for row in variants}),
        "moved": moved,
        "reconfirmed": reconfirmed,
        "conflicts_superseded": conflicts,
        "rows_affected": len(moved) + len(reconfirmed) + len(conflicts),
        "history_preserved": True,
    }


def _entity_retire(args: dict[str, Any], conn: sqlite3.Connection) -> dict[str, Any]:
    """Soft-retire active facts of one (subject, predicate) identity.

    First-class forgetting (agent-memory practice): a wrong or stale fact
    can be retired without inventing a replacement value (supersede on
    upsert always needs one). This is a soft delete - rows flip to
    is_active=0 so the audit trail stays queryable through
    include_superseded; nothing is ever removed from the store.
    """
    subject = str(args.get("subject") or "").strip()
    predicate = str(args.get("predicate") or "").strip()
    raw_object = args.get("object")
    object_filter = str(raw_object).strip().casefold() if raw_object else ""
    reason = str(args.get("reason") or "").strip()

    if not subject or not predicate:
        raise MemoryError(
            "Parameters 'subject' and 'predicate' are required for entity_retire."
        )

    now = time.time()
    cur = conn.cursor()
    cur.execute("SELECT * FROM entity_triples WHERE is_active = 1")
    matches = [
        row for row in cur.fetchall()
        if row["subject"].casefold() == subject.casefold()
        and row["predicate"].casefold() == predicate.casefold()
        and (not object_filter
             or row["object"].casefold() == object_filter)
    ]

    retired = []
    with conn:
        for row in matches:
            conn.execute(
                "UPDATE entity_triples SET is_active = 0, updated_at = ? WHERE id = ?",
                (now, row["id"]),
            )
            retired.append({
                "id": row["id"],
                "subject": row["subject"],
                "predicate": row["predicate"],
                "object": row["object"],
                "evidence_count": row["evidence_count"],
            })

    return {
        "status": "retired" if retired else "noop",
        "retired": retired,
        "retired_count": len(retired),
        "reason": reason,
        "soft_delete": True,
        "recreate_hint": (
            "entity_upsert the same (subject, predicate, object) to"
            " re-activate the fact with fresh evidence."
        ) if retired else "",
    }


def _entity_query(args: dict[str, Any], conn: sqlite3.Connection) -> dict[str, Any]:
    """Query entity relationships by subject, predicate, object, or free-text search."""
    subj = args.get("subject")
    pred = args.get("predicate")
    obj = args.get("object")
    query = args.get("query")
    include_superseded = bool(args.get("include_superseded", False))
    limit = max(1, min(int(args.get("limit") or 50), 200))

    cur = conn.cursor()
    sql_parts = ["SELECT * FROM entity_triples"]
    conds = []
    params = []

    if not include_superseded:
        conds.append("is_active = 1")
    if subj:
        conds.append("subject LIKE ?")
        params.append(f"%{subj}%")
    if pred:
        conds.append("predicate LIKE ?")
        params.append(f"%{pred}%")
    if obj:
        conds.append("object LIKE ?")
        params.append(f"%{obj}%")
    if query:
        conds.append("(subject LIKE ? OR predicate LIKE ? OR object LIKE ?)")
        params.extend([f"%{query}%", f"%{query}%", f"%{query}%"])

    if conds:
        sql_parts.append("WHERE " + " AND ".join(conds))
    sql_parts.append("ORDER BY updated_at DESC LIMIT ?")
    params.append(limit)

    rows = cur.execute(" ".join(sql_parts), tuple(params)).fetchall()
    triples = [
        {
            "id": r["id"],
            "subject": r["subject"],
            "predicate": r["predicate"],
            "object": r["object"],
            "evidence_count": r["evidence_count"],
            "is_active": bool(r["is_active"]),
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        }
        for r in rows
    ]

    return {
        "match_count": len(triples),
        "include_superseded": include_superseded,
        "triples": triples,
    }


def _list_entities(args: dict[str, Any], conn: sqlite3.Connection) -> dict[str, Any]:
    """List distinct known entity subjects and summary relation statistics."""
    limit = max(1, min(int(args.get("limit") or 50), 200))
    cur = conn.cursor()
    rows = cur.execute(
        """
        SELECT
            subject,
            COUNT(*) as relation_count,
            SUM(evidence_count) as total_evidence,
            MAX(updated_at) as last_updated
        FROM entity_triples
        WHERE is_active = 1
        GROUP BY subject
        ORDER BY total_evidence DESC, last_updated DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    entities = [
        {
            "subject": r["subject"],
            "relation_count": r["relation_count"],
            "total_evidence": r["total_evidence"],
            "last_updated": r["last_updated"],
        }
        for r in rows
    ]

    return {"entity_count": len(entities), "entities": entities}


def tiered_memory(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Main dispatch handler for tiered_memory operator tool."""
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
        resolved_db = _validate_and_resolve_path(db_path_raw, "jarvis_tiered_memory.sqlite3")
    except Exception as exc:
        return _envelope_error(exc)

    conn = _get_connection(resolved_db)
    try:
        if action == "core_read":
            res = _core_read(arguments, conn)
        elif action == "core_write":
            res = _core_write(arguments, conn)
        elif action == "core_append":
            res = _core_append(arguments, conn)
        elif action == "core_replace":
            res = _core_replace(arguments, conn)
        elif action == "entity_upsert":
            res = _entity_upsert(arguments, conn)
        elif action == "entity_merge":
            res = _entity_merge(arguments, conn)
        elif action == "entity_retire":
            res = _entity_retire(arguments, conn)
        elif action == "entity_query":
            res = _entity_query(arguments, conn)
        elif action == "archival_search":
            res = _archival_search(arguments, conn)
        elif action == "archival_insert":
            res = _archival_insert(arguments, conn)
        elif action == "list_entities":
            res = _list_entities(arguments, conn)
        else:
            return _envelope_error(f"Unhandled action '{action}'.")

        export_path = arguments.get("export_path")
        if export_path:
            resolved_export = _validate_and_resolve_path(export_path, "memory_export.json")
            atomic_write_text(resolved_export, json.dumps(res, indent=2), dir_mode=None)
            res["exported_to"] = str(resolved_export)

        return _envelope_success(res)
    except MemoryError as me:
        return _envelope_error(me)
    except (ValueError, TypeError) as err:
        return _envelope_error(err)
    except Exception as exc:
        return _envelope_error(exc)
    finally:
        conn.close()


TOOL = {
    "name": "tiered_memory",
    "description": (
        "Zero-dependency multi-tiered persistent memory and knowledge graph engine. "
        "Provides prompt-resident Core Memory blocks with size ceilings (Letta / MemGPT), "
        "FTS5-indexed Archival Memory search, and Entity-Relation Graph triple store "
        "with evidence counting and automated contradiction resolution (Mem0)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "core_read",
                    "core_write",
                    "core_append",
                    "core_replace",
                    "entity_upsert",
                    "entity_merge",
                    "entity_retire",
                    "entity_query",
                    "archival_search",
                    "archival_insert",
                    "list_entities",
                ],
                "description": "Memory tier action to execute.",
            },
            "block_name": {
                "type": "string",
                "description": "Core memory block name (e.g. human_profile, persona_spec, scratchpad).",
            },
            "section": {
                "type": "string",
                "description": "Alias for block_name.",
            },
            "content": {
                "type": "string",
                "description": "Text content to write, append, or insert into memory.",
            },
            "old_content": {
                "type": "string",
                "description": "Existing text substring to replace (for core_replace).",
            },
            "new_content": {
                "type": "string",
                "description": "Replacement text substring (for core_replace).",
            },
            "subject": {
                "type": "string",
                "description": (
                    "Entity knowledge graph subject. For entity_merge this is the"
                    " canonical spelling that case-variant rows fold into."
                ),
            },
            "predicate": {
                "type": "string",
                "description": "Entity knowledge graph relation/predicate.",
            },
            "object": {
                "type": "string",
                "description": "Entity knowledge graph target value/object.",
            },
            "query": {
                "type": "string",
                "description": "Search query for archival search or entity lookup.",
            },
            "category": {
                "type": "string",
                "description": "Category tag for archival memory (e.g. project, preference, tool_rule).",
            },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 200,
                "description": "Maximum memory records to return.",
            },
            "reason": {
                "type": "string",
                "description": (
                    "Audit note for entity_retire; returned with the retired"
                    " rows. Rows are only deactivated, never deleted."
                ),
            },
            "include_superseded": {
                "type": "boolean",
                "description": "Whether to include superseded/inactive entity triples in entity_query.",
            },
            "db_path": {
                "type": "string",
                "description": "Optional SQLite database path within ALLOWED_ROOTS.",
            },
            "export_path": {
                "type": "string",
                "description": "Optional file path within ALLOWED_ROOTS to export memory snapshot.",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": tiered_memory,
    "approval": False,
}
