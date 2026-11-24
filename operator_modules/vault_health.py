"""Vault Health audit (2A) and Map-of-Content (MOC) synthesizer (2C) for the Knowledge Galaxy."""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from atomic_io import atomic_write_text

ROOT = Path(__file__).resolve().parents[1]
from jarvis_paths import resolve_config_path
CONFIG_PATH = resolve_config_path(ROOT)
STATE_ROOT = Path.home() / ".jarvis-tools"
BACKUPS_DIR = STATE_ROOT / "backups"
MAX_TOPIC_LEN = 120
MAX_NOTE_CACHE = 5000
_NOTE_CACHE_LOCK = threading.Lock()
_NOTE_CACHE: dict[str, tuple[int, int, dict[str, Any]]] = {}
_WORD_RE = re.compile(r"\w{3,}")


def _yaml_quote(value: str) -> str:
    """Return a double-quoted YAML scalar safe against line breaks and quote injection."""
    single_line = re.sub(r"[\r\n\t]+", " ", str(value or "")).strip()
    cleaned = "".join(ch for ch in single_line if ch.isprintable())
    escaped = cleaned.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _safe_wikilink_label(value: str) -> str:
    """Strip characters that break Obsidian [[target|label]] syntax."""
    cleaned = re.sub(r"[\r\n\[\]|]+", " ", str(value or "")).strip()
    return re.sub(r"\s+", " ", cleaned)


def _atomic_vault_write(
    root: Path, filename: str, content: str, backup_root: Path | None = None
) -> tuple[Path, Path | None]:
    """Write a note inside `root` atomically, refusing symlinks/traversal and backing up existing files."""
    resolved_root = root.resolve()
    if not resolved_root.is_dir():
        raise ValueError("Vault directory does not exist.")
    if not filename or "/" in filename or "\\" in filename or filename in (".", ".."):
        raise ValueError("Invalid target filename.")
    candidate = resolved_root / filename
    if candidate.is_symlink():
        raise ValueError("Refusing to overwrite a symbolic link in the vault.")
    resolved_parent = candidate.parent.resolve()
    if resolved_parent != resolved_root and not resolved_parent.is_relative_to(resolved_root):
        raise ValueError("Target path escapes the vault root.")
    target = resolved_parent / candidate.name
    if target.exists() and (target.is_symlink() or not target.is_file()):
        raise ValueError("Target path is not a regular file.")
    backup_path = atomic_write_text(
        target,
        content,
        mode=0o644,
        dir_mode=None,
        backup_dir=Path(backup_root or BACKUPS_DIR),
    )
    return target, backup_path


def _vault_dir() -> Path:
    try:
        cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        raw = cfg.get("vault_dir") or "~/notes/Bot"
        return Path(raw).expanduser().resolve()
    except Exception:
        return (Path.home() / "notes" / "Bot").resolve()


def _parse_note(path: Path, root: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    rel = str(path.relative_to(root)).replace("\\", "/")
    title = path.stem
    tags: list[str] = []
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        if end != -1:
            fm = text[4:end]
            for line in fm.splitlines():
                if line.lower().startswith("title:"):
                    val = line.split(":", 1)[1].strip().strip("\"'")
                    if val:
                        title = val
                elif line.lower().startswith("tags:"):
                    inline = line.split(":", 1)[1].strip()
                    tags.extend(re.findall(r"[A-Za-z0-9ąćęłńóśźżĄĆĘŁŃÓŚŹŻ_-]{2,}", inline))
    links = [m.split("|", 1)[0].split("#", 1)[0].strip() for m in re.findall(r"\[\[([^\]]+)\]\]", text)]
    body_clean = re.sub(r"^---\n.*?\n---\n", "", text, count=1, flags=re.S).strip()
    summary = re.sub(r"\s+", " ", body_clean)[:260]
    return {
        "path": rel,
        "stem": path.stem,
        "title": title,
        "tags": tags,
        "links": [lnk for lnk in links if lnk],
        "body": body_clean,
        "summary": summary,
    }


def _cached_parse_note(path: Path, root: Path) -> dict[str, Any]:
    """Return parsed note metadata cached by `(st_mtime_ns, st_size)`."""
    cache_key = f"{root.resolve()}::{path}"
    try:
        st = path.stat()
        stamp = (st.st_mtime_ns, st.st_size)
    except OSError:
        return _parse_note(path, root)
    with _NOTE_CACHE_LOCK:
        hit = _NOTE_CACHE.get(cache_key)
        if hit is not None and hit[0] == stamp[0] and hit[1] == stamp[1]:
            return dict(hit[2])
    parsed = _parse_note(path, root)
    with _NOTE_CACHE_LOCK:
        if len(_NOTE_CACHE) >= MAX_NOTE_CACHE:
            _NOTE_CACHE.clear()
        _NOTE_CACHE[cache_key] = (stamp[0], stamp[1], parsed)
    return dict(parsed)


def _scan_vault(vault: Path) -> list[dict[str, Any]]:
    if not vault.is_dir():
        return []
    resolved_vault = vault.resolve()
    notes = []
    for path in sorted(vault.rglob("*.md")):
        try:
            rel_parts = path.relative_to(vault).parts
        except ValueError:
            continue
        if any(part.startswith(".") or part in ("node_modules", "__pycache__", ".obsidian", ".trash")
               for part in rel_parts):
            continue
        if path.is_symlink():
            try:
                if not path.resolve().is_relative_to(resolved_vault):
                    continue
            except OSError:
                continue
        if not path.is_file():
            continue
        notes.append(_cached_parse_note(path, vault))
    return notes


def _semantic_duplicates(threshold: float = 0.92, limit: int = 15) -> list[dict[str, Any]]:
    try:
        dbs = sorted(STATE_ROOT.glob("embeddings-*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        return []
    if not dbs:
        return []
    try:
        import numpy as np
    except ImportError:
        return []
    try:
        conn = sqlite3.connect(f"file:{dbs[0]}?mode=ro", uri=True, timeout=5)
        try:
            rows = conn.execute("SELECT path, dim, vector FROM note_vectors").fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return []
    if len(rows) < 2:
        return []
    target_dim = rows[0][1]
    paths: list[str] = []
    vecs = []
    for path, dim, blob in rows:
        if dim != target_dim or not blob:
            continue
        arr = np.frombuffer(blob, dtype=np.float32)
        if arr.size == target_dim:
            paths.append(str(path))
            vecs.append(arr)
    if len(vecs) < 2:
        return []
    mat = np.vstack(vecs)
    norms = np.linalg.norm(mat, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    normed = mat / norms
    sim = normed @ normed.T
    # Vectorized upper-triangle threshold filter instead of O(N^2) Python loops.
    upper_i, upper_j = np.triu_indices(len(paths), k=1)
    scores = sim[upper_i, upper_j]
    mask = scores >= threshold
    if not np.any(mask):
        return []
    hit_i = upper_i[mask]
    hit_j = upper_j[mask]
    hit_scores = scores[mask]
    order = np.argsort(-hit_scores)[:limit]
    return [
        {
            "note_a": paths[int(hit_i[idx])],
            "note_b": paths[int(hit_j[idx])],
            "similarity": round(float(hit_scores[idx]), 4),
        }
        for idx in order
    ]


def _find_unlinked_mentions(
    notes: list[dict[str, Any]], adj: dict[str, set[str]], limit: int
) -> list[dict[str, Any]]:
    """Find unlinked note-title mentions using an anchor-token inverted index."""
    if limit <= 0 or len(notes) < 2:
        return []
    anchor_index: dict[str, list[tuple[str, str, str, re.Pattern[str]]]] = {}
    fallback_candidates: list[tuple[str, str, str, re.Pattern[str]]] = []
    for note in notes:
        title = note["title"]
        if len(title) < 5:
            continue
        title_cf = title.casefold()
        pattern = re.compile(r"\b" + re.escape(title) + r"\b", re.I)
        words = _WORD_RE.findall(title_cf)
        entry = (note["path"], title, title_cf, pattern)
        if words:
            anchor = max(words, key=len)
            anchor_index.setdefault(anchor, []).append(entry)
        else:
            fallback_candidates.append(entry)

    unlinked: list[dict[str, Any]] = []
    for note in notes:
        if len(unlinked) >= limit:
            break
        src = note["path"]
        linked = adj.get(src, set())
        body_sample = note["body"][:4000]
        if not body_sample:
            continue
        body_cf = body_sample.casefold()
        present_tokens = set(_WORD_RE.findall(body_cf))
        candidates: list[tuple[str, str, str, re.Pattern[str]]] = list(fallback_candidates)
        for token in present_tokens:
            bucket = anchor_index.get(token)
            if bucket:
                candidates.extend(bucket)
        candidates.sort(key=lambda item: item[0])
        for dst_path, dst_title, dst_title_cf, pattern in candidates:
            if dst_path == src or dst_path in linked:
                continue
            if dst_title_cf in body_cf and pattern.search(body_sample):
                unlinked.append({
                    "source": src,
                    "target": dst_path,
                    "mentioned_title": dst_title,
                })
                if len(unlinked) >= limit:
                    break
    return unlinked


def audit_vault(vault: Path | None = None, limit: int = 20) -> dict[str, Any]:
    root = Path(vault or _vault_dir())
    notes = _scan_vault(root)
    by_key: dict[str, str] = {}
    for note in notes:
        by_key[note["stem"].casefold()] = note["path"]
        by_key[note["title"].casefold()] = note["path"]
        by_key[note["path"].removesuffix(".md").casefold()] = note["path"]

    adj: dict[str, set[str]] = {note["path"]: set() for note in notes}
    for note in notes:
        src = note["path"]
        for raw_target in note["links"]:
            dst = by_key.get(raw_target.casefold())
            if dst and dst != src:
                adj[src].add(dst)
                adj.setdefault(dst, set()).add(src)

    orphans = [
        {"path": note["path"], "title": note["title"]}
        for note in notes
        if not adj.get(note["path"])
    ]

    unlinked = _find_unlinked_mentions(notes, adj, limit)

    folder_counts: dict[str, list[str]] = {}
    for note in notes:
        folder = str(Path(note["path"]).parent)
        if folder != ".":
            folder_counts.setdefault(folder, []).append(note["title"])
    moc_candidates = [
        {"cluster": folder, "note_count": len(titles), "sample_titles": titles[:5]}
        for folder, titles in sorted(folder_counts.items(), key=lambda kv: len(kv[1]), reverse=True)
        if len(titles) >= 4 and not any("moc" in t.casefold() or "index" in t.casefold() for t in titles)
    ][:limit]

    duplicates = _semantic_duplicates(limit=limit)
    return {
        "ok": True,
        "total_notes": len(notes),
        "orphan_count": len(orphans),
        "orphans": orphans[:limit],
        "unlinked_mentions": unlinked[:limit],
        "semantic_duplicates": duplicates,
        "moc_candidates": moc_candidates,
    }


def synthesize_moc(
    topic: str,
    vault: Path | None = None,
    write: bool = False,
    backup_root: Path | None = None,
) -> dict[str, Any]:
    raw_topic = re.sub(r"[\r\n\t]+", " ", str(topic or "")).strip()
    topic_clean = "".join(ch for ch in raw_topic if ch.isprintable())[:MAX_TOPIC_LEN].strip()
    if not topic_clean:
        return {"ok": False, "error": "Topic is required to synthesize a Map of Content (MOC)."}
    root = Path(vault or _vault_dir())
    notes = _scan_vault(root)
    tokens = [tok.casefold() for tok in re.findall(r"\w{2,}", topic_clean)]
    if not tokens:
        return {"ok": False, "topic": topic_clean, "error": "Topic must contain at least one searchable word."}
    matched = []
    for note in notes:
        haystack = f"{note['path']} {note['title']} {' '.join(note['tags'])} {note['summary']}".casefold()
        score = sum(3 if tok in note["title"].casefold() or tok in note["path"].casefold() else 1
                    for tok in tokens if tok in haystack)
        if score > 0:
            matched.append((score, note))
    matched.sort(key=lambda item: (-item[0], item[1]["title"].casefold()))
    selected = [item[1] for item in matched[:25]]
    if not selected:
        return {"ok": False, "topic": topic_clean, "error": f"No notes matched topic {topic_clean!r}."}

    safe_slug = re.sub(r"\s+", " ", re.sub(r"[^\w\s-]", "", topic_clean)).strip(" .-")[:80]
    if not safe_slug:
        return {"ok": False, "topic": topic_clean, "error": "Topic cannot form a safe filename."}
    filename = f"MOC - {safe_slug}.md"
    lines = [
        "---",
        f"title: {_yaml_quote(f'MOC: {topic_clean}')}",
        "type: moc",
        f"created: {time.strftime('%Y-%m-%d')}",
        "tags: [moc, synthesis]",
        "---",
        "",
        f"# MOC: {topic_clean}",
        "",
        f"Synteza konstelacji tematycznej ({len(selected)} powiązanych notatek):",
        "",
        "## Powiązane notatki",
    ]
    for note in selected:
        blurb = note["summary"][:140].strip()
        safe_stem = _safe_wikilink_label(note["stem"])
        safe_title = _safe_wikilink_label(note["title"]) or safe_stem
        link_expr = f"[[{safe_stem}|{safe_title}]]" if safe_title != safe_stem else f"[[{safe_stem}]]"
        lines.append(f"- {link_expr} — {blurb}" if blurb else f"- {link_expr}")
    markdown = "\n".join(lines) + "\n"

    saved_path = None
    backup_path = None
    if write:
        if not root.is_dir():
            return {"ok": False, "topic": topic_clean, "error": "Vault directory does not exist."}
        try:
            written_target, written_backup = _atomic_vault_write(
                root, filename, markdown, backup_root=backup_root
            )
            saved_path = str(written_target)
            backup_path = str(written_backup) if written_backup else None
        except (OSError, ValueError) as exc:
            return {"ok": False, "topic": topic_clean, "error": str(exc)}

    return {
        "ok": True,
        "topic": topic_clean,
        "matched_count": len(selected),
        "notes": [{"path": n["path"], "title": n["title"]} for n in selected],
        "filename": filename,
        "written": bool(saved_path),
        "saved_path": saved_path,
        "backup": backup_path,
        "markdown": markdown,
    }



_PROTECTED_MD_SPAN_RE = re.compile(
    r"(^---\n.*?\n---\n|```.*?```|`[^`\n]+`|\[\[[^\]]+\]\]|!?\[[^\]]*\]\([^)]*\)|https?://\S+)",
    re.S | re.M,
)
_KV_FACT_RE = re.compile(
    r"^(?:[-*]\s*)?([A-Za-z0-9ąćęłńóśźżĄĆĘŁŃÓŚŹŻ_ /-]{3,40})\s*[:=]\s*([^\n#]{1,80})$",
    re.M,
)
_STOPWORDS_CLUSTER = frozenset({
    "notatka", "notatki", "projekt", "system", "opis", "test", "plik", "dane",
    "note", "notes", "the", "and", "for", "with", "from", "into", "jest", "oraz",
})


def _atomic_vault_rel_write(
    root: Path, rel_path: str, content: str, backup_root: Path | None = None
) -> tuple[Path, Path | None]:
    """Atomically update a relative `.md` path inside `root`, refusing symlinks and traversal."""
    resolved_root = root.resolve()
    if not resolved_root.is_dir():
        raise ValueError("Vault directory does not exist.")
    rel = Path(str(rel_path or "").strip())
    if not rel.parts or rel.is_absolute() or any(part in ("", ".", "..") for part in rel.parts):
        raise ValueError("Invalid relative vault path.")
    cur = resolved_root
    for part in rel.parts[:-1]:
        cur = cur / part
        if cur.is_symlink():
            raise ValueError("Refusing to traverse symbolic link inside vault.")
    candidate = cur / rel.parts[-1]
    if candidate.is_symlink():
        raise ValueError("Refusing to overwrite a symbolic link in the vault.")
    resolved_parent = candidate.parent.resolve()
    if resolved_parent != resolved_root and not resolved_parent.is_relative_to(resolved_root):
        raise ValueError("Target path escapes the vault root.")
    target = resolved_parent / candidate.name
    if target.exists() and (target.is_symlink() or not target.is_file()):
        raise ValueError("Target path is not a regular file.")
    backup_path = atomic_write_text(
        target,
        content,
        mode=0o644,
        dir_mode=0o755,
        backup_dir=Path(backup_root or BACKUPS_DIR),
    )
    return target, backup_path


def _inject_first_wikilink(raw_markdown: str, target_stem: str, target_title: str) -> tuple[str, bool]:
    """Replace the first plain-text mention of `target_title` outside protected spans with a wikilink."""
    safe_stem = _safe_wikilink_label(target_stem)
    safe_title = _safe_wikilink_label(target_title)
    if not safe_stem or not safe_title:
        return raw_markdown, False
    pattern = re.compile(r"\b(" + re.escape(target_title) + r")\b", re.I)

    protected: list[tuple[int, int]] = [
        (m.start(), m.end()) for m in _PROTECTED_MD_SPAN_RE.finditer(raw_markdown)
    ]
    for hm in re.finditer(r"^#+\s+.*$", raw_markdown, re.M):
        protected.append((hm.start(), hm.end()))

    def _in_protected(start: int, end: int) -> bool:
        return any(s <= start < e or s < end <= e for s, e in protected)

    for match in pattern.finditer(raw_markdown):
        start, end = match.span(1)
        if _in_protected(start, end):
            continue
        matched_surface = match.group(1)
        replacement = (
            f"[[{safe_stem}]]"
            if matched_surface == safe_stem
            else f"[[{safe_stem}|{matched_surface}]]"
        )
        updated = raw_markdown[:start] + replacement + raw_markdown[end:]
        return updated, True
    return raw_markdown, False


def auto_link_vault(
    vault: Path | None = None,
    limit: int = 15,
    write: bool = False,
    backup_root: Path | None = None,
) -> dict[str, Any]:
    """Preview or transactionally insert missing `[[wikilinks]]` across vault notes."""
    root = Path(vault or _vault_dir())
    if not root.is_dir():
        return {"ok": False, "error": "Vault directory does not exist."}
    notes = _scan_vault(root)
    by_path = {note["path"]: note for note in notes}
    by_key: dict[str, str] = {}
    for note in notes:
        by_key[note["stem"].casefold()] = note["path"]
        by_key[note["title"].casefold()] = note["path"]
        by_key[note["path"].removesuffix(".md").casefold()] = note["path"]

    adj: dict[str, set[str]] = {note["path"]: set() for note in notes}
    for note in notes:
        src = note["path"]
        for raw_target in note["links"]:
            dst = by_key.get(raw_target.casefold())
            if dst and dst != src:
                adj[src].add(dst)
                adj.setdefault(dst, set()).add(src)

    mentions = _find_unlinked_mentions(notes, adj, limit=max(1, min(limit, 50)))
    by_source: dict[str, list[dict[str, Any]]] = {}
    for item in mentions:
        by_source.setdefault(item["source"], []).append(item)

    changes: list[dict[str, Any]] = []
    backups: list[str] = []
    for src_rel, items in by_source.items():
        src_file = root / src_rel
        try:
            original = src_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        updated = original
        applied_targets: list[str] = []
        for item in items:
            dst_note = by_path.get(item["target"])
            if not dst_note:
                continue
            updated, changed = _inject_first_wikilink(updated, dst_note["stem"], item["mentioned_title"])
            if changed:
                applied_targets.append(item["target"])
        if not applied_targets:
            continue
        backup_str = None
        if write:
            try:
                _, bpath = _atomic_vault_rel_write(root, src_rel, updated, backup_root=backup_root)
                backup_str = str(bpath) if bpath else None
                if backup_str:
                    backups.append(backup_str)
            except (OSError, ValueError) as exc:
                return {"ok": False, "error": f"Failed updating {src_rel}: {exc}"}
        changes.append({
            "source": src_rel,
            "linked_targets": applied_targets,
            "written": bool(write),
            "backup": backup_str,
        })

    return {
        "ok": True,
        "mode": "applied" if write else "preview",
        "files_modified" if write else "files_with_candidates": len(changes),
        "total_links": sum(len(c["linked_targets"]) for c in changes),
        "changes": changes,
        "backups": backups,
    }


def _load_vault_vectors() -> tuple[list[str], Any]:
    try:
        dbs = sorted(STATE_ROOT.glob("embeddings-*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        return [], None
    if not dbs:
        return [], None
    try:
        import numpy as np
    except ImportError:
        return [], None
    try:
        conn = sqlite3.connect(f"file:{dbs[0]}?mode=ro", uri=True, timeout=5)
        try:
            rows = conn.execute("SELECT path, dim, vector FROM note_vectors").fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return [], None
    if not rows:
        return [], None
    target_dim = rows[0][1]
    paths: list[str] = []
    vecs = []
    for path, dim, blob in rows:
        if dim != target_dim or not blob:
            continue
        arr = np.frombuffer(blob, dtype=np.float32)
        if arr.size == target_dim:
            paths.append(str(path).replace("\\", "/"))
            vecs.append(arr)
    if not vecs:
        return [], None
    mat = np.vstack(vecs)
    norms = np.linalg.norm(mat, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return paths, (mat / norms)


def cluster_orphans(
    vault: Path | None = None,
    threshold: float = 0.72,
    write: bool = False,
    limit: int = 10,
    backup_root: Path | None = None,
) -> dict[str, Any]:
    """Group orphan notes into semantic constellations using embeddings (with token fallback)."""
    root = Path(vault or _vault_dir())
    if not root.is_dir():
        return {"ok": False, "error": "Vault directory does not exist."}
    notes = _scan_vault(root)
    by_key: dict[str, str] = {}
    for note in notes:
        by_key[note["stem"].casefold()] = note["path"]
        by_key[note["title"].casefold()] = note["path"]
        by_key[note["path"].removesuffix(".md").casefold()] = note["path"]

    adj: dict[str, set[str]] = {note["path"]: set() for note in notes}
    for note in notes:
        src = note["path"]
        for raw_target in note["links"]:
            dst = by_key.get(raw_target.casefold())
            if dst and dst != src:
                adj[src].add(dst)
                adj.setdefault(dst, set()).add(src)

    orphan_notes = [n for n in notes if not adj.get(n["path"])]
    if len(orphan_notes) < 2:
        return {"ok": True, "orphan_count": len(orphan_notes), "cluster_count": 0, "clusters": [], "written_mocs": []}

    vec_paths, normed = _load_vault_vectors()
    vec_map = {p: idx for idx, p in enumerate(vec_paths)}
    orphan_paths = [n["path"] for n in orphan_notes]
    n_orph = len(orphan_notes)

    parent = list(range(n_orph))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    if normed is not None and sum(1 for p in orphan_paths if p in vec_map) >= 2:
        indexed = [(i, vec_map[p]) for i, p in enumerate(orphan_paths) if p in vec_map]
        sub_mat = normed[[row_idx for _, row_idx in indexed]]
        sim = sub_mat @ sub_mat.T
        for a_pos in range(len(indexed)):
            for b_pos in range(a_pos + 1, len(indexed)):
                if float(sim[a_pos, b_pos]) >= threshold:
                    union(indexed[a_pos][0], indexed[b_pos][0])
    else:
        token_sets = [
            {
                w for w in re.findall(r"\w{4,}", f"{n['title']} {' '.join(n['tags'])} {n['summary']}".casefold())
                if w not in _STOPWORDS_CLUSTER
            }
            for n in orphan_notes
        ]
        for i in range(n_orph):
            if not token_sets[i]:
                continue
            for j in range(i + 1, n_orph):
                if not token_sets[j]:
                    continue
                inter = len(token_sets[i] & token_sets[j])
                union_sz = len(token_sets[i] | token_sets[j])
                if inter >= 2 and (inter / union_sz) >= 0.18:
                    union(i, j)

    groups: dict[int, list[dict[str, Any]]] = {}
    for idx, note in enumerate(orphan_notes):
        groups.setdefault(find(idx), []).append(note)

    clusters = []
    written_mocs = []
    sorted_groups = sorted(
        (members for members in groups.values() if len(members) >= 2),
        key=lambda m: len(m),
        reverse=True,
    )[:max(1, min(limit, 20))]

    for members in sorted_groups:
        freq: dict[str, int] = {}
        for m in members:
            for tok in re.findall(r"\w{4,}", f"{m['title']} {' '.join(m['tags'])}".casefold()):
                if tok not in _STOPWORDS_CLUSTER:
                    freq[tok] = freq.get(tok, 0) + 1
        top_words = [w.capitalize() for w, _ in sorted(freq.items(), key=lambda kv: (-kv[1], kv[0]))[:2]]
        label = " ".join(top_words) if top_words else members[0]["title"][:40]
        safe_slug = re.sub(r"\s+", " ", re.sub(r"[^\w\s-]", "", label)).strip(" .-")[:60] or "Klaster"
        filename = f"MOC - Klaster {safe_slug}.md"
        lines = [
            "---",
            f"title: {_yaml_quote(f'MOC: Klaster {label}')}",
            "type: moc",
            f"created: {time.strftime('%Y-%m-%d')}",
            "tags: [moc, auto-cluster]",
            "---",
            "",
            f"# MOC: Klaster {label}",
            "",
            f"Automatycznie wykryta konstelacja powiązanych notatek-sierot ({len(members)}):",
            "",
        ]
        for m in members:
            s_stem = _safe_wikilink_label(m["stem"])
            s_title = _safe_wikilink_label(m["title"]) or s_stem
            link = f"[[{s_stem}|{s_title}]]" if s_title != s_stem else f"[[{s_stem}]]"
            blurb = m["summary"][:120].strip()
            lines.append(f"- {link} — {blurb}" if blurb else f"- {link}")
        md = "\n".join(lines) + "\n"
        saved = None
        backup = None
        if write:
            try:
                tpath, bpath = _atomic_vault_write(root, filename, md, backup_root=backup_root)
                saved = str(tpath)
                backup = str(bpath) if bpath else None
                written_mocs.append(saved)
            except (OSError, ValueError) as exc:
                return {"ok": False, "error": str(exc)}
        clusters.append({
            "topic": label,
            "filename": filename,
            "note_count": len(members),
            "notes": [{"path": m["path"], "title": m["title"]} for m in members],
            "written": bool(saved),
            "saved_path": saved,
            "backup": backup,
        })

    return {
        "ok": True,
        "orphan_count": len(orphan_notes),
        "cluster_count": len(clusters),
        "clusters": clusters,
        "written_mocs": written_mocs,
    }


def _extract_facts(note: dict[str, Any], raw_text: str) -> dict[str, str]:
    facts: dict[str, str] = {}
    if raw_text.startswith("---\n"):
        end = raw_text.find("\n---\n", 4)
        if end != -1:
            for line in raw_text[4:end].splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    key = k.strip().casefold()
                    val = v.strip().strip("\"'")
                    if key and val and key not in ("title", "tags", "created", "updated", "date", "aliases"):
                        facts[key] = val
    for match in _KV_FACT_RE.finditer(note["body"][:4000]):
        key = re.sub(r"\s+", " ", match.group(1).strip()).casefold()
        val = match.group(2).strip().strip("\"'")
        if 2 <= len(key) <= 35 and val and not key.startswith("http"):
            facts.setdefault(key, val)
    return facts


def detect_contradictions(vault: Path | None = None, limit: int = 15) -> dict[str, Any]:
    """Detect conflicting key/value parameters or status claims across related notes."""
    root = Path(vault or _vault_dir())
    if not root.is_dir():
        return {"ok": False, "error": "Vault directory does not exist."}
    notes = _scan_vault(root)
    if len(notes) < 2:
        return {"ok": True, "count": 0, "contradictions": []}

    note_facts: dict[str, dict[str, str]] = {}
    note_tokens: dict[str, set[str]] = {}
    for note in notes:
        try:
            raw = (root / note["path"]).read_text(encoding="utf-8", errors="replace")
        except OSError:
            raw = note["body"]
        facts = _extract_facts(note, raw)
        if facts:
            note_facts[note["path"]] = facts
            note_tokens[note["path"]] = {
                w for w in re.findall(r"\w{3,}", f"{note['title']} {' '.join(note['tags'])}".casefold())
                if w not in _STOPWORDS_CLUSTER
            }

    vec_paths, normed = _load_vault_vectors()
    vec_map = {p: idx for idx, p in enumerate(vec_paths)}

    fact_paths = sorted(note_facts.keys())
    contradictions: list[dict[str, Any]] = []
    for i in range(len(fact_paths)):
        p_a = fact_paths[i]
        for j in range(i + 1, len(fact_paths)):
            p_b = fact_paths[j]
            shared_keys = set(note_facts[p_a].keys()) & set(note_facts[p_b].keys())
            if not shared_keys:
                continue
            related = bool(note_tokens[p_a] & note_tokens[p_b])
            if not related and normed is not None and p_a in vec_map and p_b in vec_map:
                sim = float(normed[vec_map[p_a]] @ normed[vec_map[p_b]])
                related = sim >= 0.70
            if not related:
                continue
            for key in sorted(shared_keys):
                val_a = note_facts[p_a][key]
                val_b = note_facts[p_b][key]
                if val_a.casefold() != val_b.casefold():
                    contradictions.append({
                        "note_a": p_a,
                        "note_b": p_b,
                        "field": key,
                        "value_a": val_a[:120],
                        "value_b": val_b[:120],
                    })
                    if len(contradictions) >= limit:
                        return {"ok": True, "count": len(contradictions), "contradictions": contradictions}
    return {"ok": True, "count": len(contradictions), "contradictions": contradictions}


def _requires_approval(arguments: dict[str, Any] | None = None) -> bool:
    """Read-only audits/previews run freely; any vault write (`write=True`) needs approval."""
    args = arguments if isinstance(arguments, dict) else {}
    action = str(args.get("action") or "").strip().lower()
    return action in ("synthesize_moc", "auto_link", "cluster_orphans") and bool(args.get("write"))


def vault_health_handler(arguments: dict[str, Any], context=None) -> dict[str, Any]:
    args = arguments if isinstance(arguments, dict) else {}
    action = str(args.get("action") or "audit").strip().lower()
    raw_limit = args.get("limit")
    try:
        limit = max(1, min(int(raw_limit if raw_limit is not None else 15), 50))
    except (TypeError, ValueError):
        return {"ok": False, "error": "Parameter 'limit' must be an integer."}
    state_root = Path((context or {}).get("state_root") or STATE_ROOT)
    backup_root = state_root / "backups"
    write = bool(args.get("write", False))

    if action == "audit":
        return audit_vault(limit=limit)
    if action == "synthesize_moc":
        return synthesize_moc(
            topic=str(args.get("topic") or ""),
            write=write,
            backup_root=backup_root,
        )
    if action == "auto_link":
        return auto_link_vault(limit=limit, write=write, backup_root=backup_root)
    if action == "cluster_orphans":
        raw_thresh = args.get("threshold")
        try:
            threshold = max(0.3, min(float(raw_thresh if raw_thresh is not None else 0.72), 0.99))
        except (TypeError, ValueError):
            return {"ok": False, "error": "Parameter 'threshold' must be a number."}
        return cluster_orphans(threshold=threshold, write=write, limit=limit, backup_root=backup_root)
    if action == "contradictions":
        return detect_contradictions(limit=limit)
    return {"ok": False, "error": f"Unsupported action: {action!r}"}


TOOL = {
    "name": "vault_health",
    "description": (
        "Intelligent Knowledge Gardener for Obsidian/Sejf: audit vault health ('audit'), "
        "synthesize a topic MOC ('synthesize_moc'), preview or insert missing [[wikilinks]] ('auto_link'), "
        "cluster orphan notes into semantic MOCs ('cluster_orphans'), or detect conflicting facts ('contradictions')."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["audit", "synthesize_moc", "auto_link", "cluster_orphans", "contradictions"],
                "description": "Gardener operation to perform (default: 'audit').",
            },
            "topic": {
                "type": "string",
                "description": "Topic or cluster name when action='synthesize_moc'.",
            },
            "write": {
                "type": "boolean",
                "description": "Apply changes to disk with automatic backup (default: false preview).",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of findings/modifications (default: 15).",
            },
            "threshold": {
                "type": "number",
                "description": "Cosine similarity threshold (0.3-0.99) when action='cluster_orphans'.",
            },
        },
        "additionalProperties": False,
    },
    "handler": vault_health_handler,
    "approval": True,
    "approval_predicate": _requires_approval,
}

