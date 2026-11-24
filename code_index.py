"""Hybrid Code RAG index (`FTS5 BM25 + Subword Semantic Vectors + AST Import Graph`) for Jarvis.

1. Incremental SQLite FTS5 indexing with `mtime` tracking, AST symbol extraction,
   and Python/JS import-graph edges (`files_meta.imports`).
2. Reciprocal Rank Fusion (`RRF`) blending FTS5 BM25 lexical hits, hashed character/concept
   cosine vectors, and 1-hop AST import-graph neighbors (`related_files`).
3. Lazy in-memory vector cache with automatic **5-minute (`300s`) idle eviction**
   so RAM usage on ThinkCentre M720q stays ~200 MB.
"""

from __future__ import annotations

import ast
import math
import os
import re
import sqlite3
import threading
import time
import zlib
from pathlib import Path

import agent_cli

INDEXABLE_SUFFIXES = {
    '.py', '.js', '.ts', '.tsx', '.jsx', '.css', '.html', '.md', '.json', '.sh', '.toml', '.yaml', '.yml',
}
SKIP_DIRS = {
    '.git', 'node_modules', '.venv', 'venv', '__pycache__', 'dist', 'build',
    '.pytest_cache', '.mypy_cache', '.ruff_cache', 'artifacts', '.orbit-backup',
    '.jarvis-mcp-backups', '.ssh', '.gnupg', '.password-store', '.aws', '.kube',
    '.docker', '.hermes', '.jarvis-tools',
}
ALLOWED_ROOTS = ('~', '/tmp', '/mnt', '/media')
FORBIDDEN_HOME_REL = (
    '.ssh', '.gnupg', '.password-store', '.aws', '.kube', '.docker',
    '.hermes', '.jarvis-tools', '.mozilla', '.config/google-chrome',
    '.config/chromium', '.config/google-chrome-for-testing', '.local/share/keyrings',
)
SECRET_NAMES = {'.env', 'secrets.json', 'auth.json', '.netrc', '.git-credentials', 'id_rsa', 'id_ed25519'}
SECRET_SUFFIXES = {'.pem', '.key', '.p12', '.pfx', '.sqlite', '.sqlite3', '.db'}
MAX_INDEX_FILE_BYTES = 250_000
MAX_FILES_PER_ROOT = 1500
IDLE_EVICT_SECONDS = 300.0
VEC_DIM = 2048

JS_SYMBOL_RE = re.compile(
    r'\b(?:function|class)\s+([A-Za-z_][A-Za-z0-9_]*)|\bconst\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:async\s*)?\('
)
JS_IMPORT_RE = re.compile(
    r"""(?:import\s+[^'"]*from\s+|require\(\s*)['"]([^'"]+)['"]"""
)
TOKEN_RE = re.compile(r'[A-Za-zĄĆĘŁŃÓŚŹŻąćęłńóśźż0-9_]{3,}')
CAMEL_SPLIT_RE = re.compile(r'[A-Z]?[a-z0-9ąćęłńóśźż]+|[A-Z]+(?=[A-Z]|$)')
STOPWORDS = frozenset({
    'the', 'and', 'for', 'with', 'from', 'that', 'this', 'into', 'jest', 'oraz',
    'aby', 'dla', 'czy', 'jak', 'nie', 'tak', 'plik', 'kod', 'zrób', 'dodaj',
    'popraw', 'sprawdź', 'który', 'która', 'które', 'przez', 'przy',
})

_CACHE_LOCK = threading.Lock()
_SEMANTIC_CACHE: dict[str, dict] = {}
_LAST_CACHE_ACCESS: float = 0.0


def evict_idle_cache(now: float | None = None, force: bool = False) -> int:
    """Release cached semantic vectors if idle for >= 300s (or when `force=True`)."""
    ts = float(now if now is not None else time.monotonic())
    with _CACHE_LOCK:
        if not _SEMANTIC_CACHE:
            return 0
        if force or (ts - _LAST_CACHE_ACCESS) >= IDLE_EVICT_SECONDS:
            removed = len(_SEMANTIC_CACHE)
            _SEMANTIC_CACHE.clear()
            return removed
    return 0


def cache_stats() -> dict:
    with _CACHE_LOCK:
        return {
            'roots_cached': len(_SEMANTIC_CACHE),
            'idle_seconds': round(max(0.0, time.monotonic() - _LAST_CACHE_ACCESS), 1) if _LAST_CACHE_ACCESS else 0.0,
        }


def _db_path() -> Path:
    base = agent_cli.ROOT.parent
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    return base / 'code_index.sqlite3'


def _connect() -> sqlite3.Connection:
    path = _db_path()
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute(
        'CREATE TABLE IF NOT EXISTS files_meta ('
        '  root TEXT NOT NULL,'
        '  rel_path TEXT NOT NULL,'
        '  mtime REAL NOT NULL,'
        '  size INTEGER NOT NULL,'
        '  symbols TEXT NOT NULL,'
        "  imports TEXT NOT NULL DEFAULT '',"
        '  PRIMARY KEY (root, rel_path)'
        ')'
    )
    try:
        conn.execute("ALTER TABLE files_meta ADD COLUMN imports TEXT NOT NULL DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    conn.execute(
        'CREATE VIRTUAL TABLE IF NOT EXISTS docs_fts USING fts5('
        '  root UNINDEXED,'
        '  rel_path,'
        '  symbols,'
        '  body,'
        "  tokenize='unicode61'"
        ')'
    )
    return conn


def _extract_symbols(path: Path, text: str) -> str:
    suffix = path.suffix.lower()
    found = []
    if suffix == '.py':
        try:
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    found.append(node.name)
        except SyntaxError:
            pass
    elif suffix in ('.js', '.ts', '.tsx', '.jsx'):
        for m in JS_SYMBOL_RE.finditer(text):
            sym = m.group(1) or m.group(2)
            if sym:
                found.append(sym)
    dedup = list(dict.fromkeys(found))[:60]
    return ' '.join(dedup)


def _extract_imports(path: Path, text: str) -> str:
    """Extract imported module names from Python AST or JS/TS ES/CommonJS imports."""
    suffix = path.suffix.lower()
    mods: list[str] = []
    if suffix == '.py':
        try:
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        mods.append(alias.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom) and node.module:
                    mods.append(node.module.split('.')[0])
        except SyntaxError:
            pass
    elif suffix in ('.js', '.ts', '.tsx', '.jsx'):
        for m in JS_IMPORT_RE.finditer(text):
            raw = m.group(1).strip()
            stem = Path(raw).stem
            if stem:
                mods.append(stem)
    dedup = list(dict.fromkeys(m for m in mods if m))[:50]
    return ' '.join(dedup)


def _embed_sparse(text: str) -> dict[int, float]:
    """Compute L2-normalized hashed subword/identifier vector (`VEC_DIM` buckets)."""
    counts: dict[int, float] = {}
    for raw_tok in TOKEN_RE.findall(str(text or '')):
        parts = [p.lower() for p in CAMEL_SPLIT_RE.findall(raw_tok)] or [raw_tok.lower()]
        for part in parts:
            if len(part) < 3 or part in STOPWORDS:
                continue
            bucket = zlib.crc32(part.encode('utf-8')) % VEC_DIM
            counts[bucket] = counts.get(bucket, 0.0) + 1.0
            if len(part) >= 5:
                prefix_b = zlib.crc32(part[:4].encode('utf-8')) % VEC_DIM
                counts[prefix_b] = counts.get(prefix_b, 0.0) + 0.5
    norm = math.sqrt(sum(v * v for v in counts.values()))
    if norm <= 0.0:
        return {}
    return {k: v / norm for k, v in counts.items()}


def _cosine_sparse(a: dict[int, float], b: dict[int, float]) -> float:
    if not a or not b:
        return 0.0
    if len(a) > len(b):
        a, b = b, a
    return sum(val * b.get(idx, 0.0) for idx, val in a.items())


def _is_safe_source(path: Path) -> bool:
    if path.name in SECRET_NAMES or path.name.startswith('.env.'):
        return False
    if path.suffix.lower() in SECRET_SUFFIXES:
        return False
    return path.suffix.lower() in INDEXABLE_SUFFIXES


def validate_safe_project_dir(raw_path: str | Path) -> Path:
    """Validate that `raw_path` is inside allowed roots and outside secret/credential directories."""
    raw_str = str(raw_path or '').strip()
    if not raw_str:
        raise ValueError('Wymagana jest ścieżka katalogu projektu.')
    expanded = Path(raw_str).expanduser()
    if '..' in expanded.parts:
        raise ValueError('Ścieżka katalogu nie może zawierać "..".')
    resolved = expanded.resolve()

    allowed = [Path(r).expanduser().resolve() for r in (*ALLOWED_ROOTS, '/var/tmp') if Path(r).expanduser().exists()]
    if not any(resolved == root or root in resolved.parents for root in allowed):
        raise ValueError(f'Katalog znajduje się poza dozwolonymi strefami: {resolved}')

    forbidden_parts = {'.ssh', '.gnupg', '.password-store', '.aws', '.kube', '.docker', '.hermes', '.jarvis-tools'}
    # The multi-agent team workspace lives under ~/.jarvis-tools/projects: it is the
    # app's own sandbox, not a credential store, and blocking it silently disabled
    # the code-context pack for every team run.
    home_dir = Path(os.environ.get('HOME') or str(Path.home())).expanduser().resolve()
    team_projects = (home_dir / '.jarvis-tools' / 'projects').resolve()
    inside_team_projects = (resolved == team_projects or team_projects in resolved.parents)
    if not inside_team_projects and any(part in forbidden_parts for part in resolved.parts):
        raise ValueError(f'Dostęp do katalogu wrażliwego jest zablokowany: {resolved}')

    home = home_dir
    for rel in FORBIDDEN_HOME_REL:
        secret_dir = (home / rel).resolve()
        if resolved == secret_dir or secret_dir in resolved.parents:
            if inside_team_projects:
                continue  # ~/.jarvis-tools/projects is the app's own sandbox
            raise ValueError(f'Dostęp do katalogu poświadczeń jest zablokowany: {resolved}')

    if not resolved.is_dir():
        raise ValueError(f'Katalog nie istnieje: {resolved}')
    return resolved


def index_directory(root_dir: str | Path) -> dict:
    """Incrementally index all source files under root_dir using mtime change detection."""
    evict_idle_cache()
    try:
        root = validate_safe_project_dir(root_dir)
    except ValueError as err:
        return {'ok': False, 'root': str(root_dir), 'error': str(err), 'indexed': 0, 'skipped': 0, 'removed': 0}

    root_key = str(root)
    started = time.time()
    indexed = 0
    skipped = 0
    seen_rels = set()

    conn = _connect()
    try:
        existing = {
            row['rel_path']: (float(row['mtime']), int(row['size']))
            for row in conn.execute(
                'SELECT rel_path, mtime, size FROM files_meta WHERE root = ?',
                (root_key,),
            ).fetchall()
        }

        file_count = 0
        with conn:
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [
                    d for d in sorted(dirnames)
                    if d not in SKIP_DIRS and not d.startswith('.jarvis-')
                ]
                for fname in sorted(filenames):
                    if file_count >= MAX_FILES_PER_ROOT:
                        break
                    fpath = Path(dirpath) / fname
                    if fpath.is_symlink() or not _is_safe_source(fpath):
                        continue
                    try:
                        st = fpath.stat()
                    except OSError:
                        continue
                    if st.st_size > MAX_INDEX_FILE_BYTES:
                        continue
                    rel = str(fpath.relative_to(root)).replace('\\', '/')
                    seen_rels.add(rel)
                    file_count += 1

                    prev = existing.get(rel)
                    if prev and abs(prev[0] - st.st_mtime) < 0.001 and prev[1] == st.st_size:
                        skipped += 1
                        continue

                    try:
                        text = fpath.read_text(encoding='utf-8', errors='replace')
                    except OSError:
                        continue
                    symbols = _extract_symbols(fpath, text)
                    imports = _extract_imports(fpath, text)
                    snippet = text[:16_000]

                    conn.execute(
                        'DELETE FROM docs_fts WHERE root = ? AND rel_path = ?',
                        (root_key, rel),
                    )
                    conn.execute(
                        'INSERT INTO docs_fts (root, rel_path, symbols, body) VALUES (?, ?, ?, ?)',
                        (root_key, rel, symbols, snippet),
                    )
                    conn.execute(
                        'INSERT OR REPLACE INTO files_meta (root, rel_path, mtime, size, symbols, imports) '
                        'VALUES (?, ?, ?, ?, ?, ?)',
                        (root_key, rel, st.st_mtime, st.st_size, symbols, imports),
                    )
                    indexed += 1

            stale = set(existing) - seen_rels
            for rel in stale:
                conn.execute('DELETE FROM docs_fts WHERE root = ? AND rel_path = ?', (root_key, rel))
                conn.execute('DELETE FROM files_meta WHERE root = ? AND rel_path = ?', (root_key, rel))
    finally:
        conn.close()

    if indexed or stale:
        with _CACHE_LOCK:
            _SEMANTIC_CACHE.pop(root_key, None)

    return {
        'ok': True,
        'root': root_key,
        'indexed': indexed,
        'skipped': skipped,
        'removed': len(stale),
        'elapsed_ms': round((time.time() - started) * 1000, 1),
    }


def related_files(rel_path: str, root_dir: str | Path) -> dict:
    """Return 1-hop AST import-graph neighbors (`imports` callees and `imported_by` callers)."""
    root = validate_safe_project_dir(root_dir)
    root_key = str(root)
    clean_rel = str(rel_path or '').replace('\\', '/').lstrip('/')
    stem = Path(clean_rel).stem

    conn = _connect()
    try:
        rows = conn.execute(
            'SELECT rel_path, imports FROM files_meta WHERE root = ?',
            (root_key,),
        ).fetchall()
    finally:
        conn.close()

    by_stem = {Path(r['rel_path']).stem: r['rel_path'] for r in rows}
    target_imports: list[str] = []
    imported_by: list[str] = []

    for r in rows:
        imps = str(r['imports'] or '').split()
        if r['rel_path'] == clean_rel:
            for mod in imps:
                if mod in by_stem and by_stem[mod] != clean_rel:
                    target_imports.append(by_stem[mod])
        elif stem and stem in imps:
            imported_by.append(r['rel_path'])

    return {
        'path': clean_rel,
        'imports': sorted(set(target_imports)),
        'imported_by': sorted(set(imported_by)),
    }


def _load_semantic_vectors(root_key: str) -> dict[str, dict]:
    global _LAST_CACHE_ACCESS
    evict_idle_cache()
    with _CACHE_LOCK:
        _LAST_CACHE_ACCESS = time.monotonic()
        cached = _SEMANTIC_CACHE.get(root_key)
        if cached is not None:
            return cached

    conn = _connect()
    try:
        rows = conn.execute(
            'SELECT rel_path, symbols, substr(body, 1, 4000) AS head FROM docs_fts WHERE root = ?',
            (root_key,),
        ).fetchall()
    finally:
        conn.close()

    built = {}
    for r in rows:
        rel = r['rel_path']
        built[rel] = {
            'symbols': r['symbols'],
            'excerpt': ' '.join(str(r['head'] or '').split())[:260],
            'vec': _embed_sparse(f"{rel} {r['symbols']} {r['head']}"),
        }
    with _CACHE_LOCK:
        _SEMANTIC_CACHE[root_key] = built
        _LAST_CACHE_ACCESS = time.monotonic()
    return built


def _fts_query(raw_query: str) -> str:
    tokens = []
    for tok in TOKEN_RE.findall(str(raw_query or '').lower()):
        if tok in STOPWORDS:
            continue
        if tok not in tokens:
            tokens.append(tok)
        if len(tokens) >= 14:
            break
    if not tokens:
        return ''
    return ' OR '.join(f'"{t}"*' for t in tokens)


def search_context(query: str, root_dir: str | Path | None = None,
                   limit: int = 8, auto_index: bool = True) -> list[dict]:
    """Hybrid search via Reciprocal Rank Fusion (FTS5 BM25 + subword vectors + AST import graph)."""
    evict_idle_cache()
    root_key = None
    if root_dir:
        resolved = validate_safe_project_dir(root_dir)
        root_key = str(resolved)
        if auto_index:
            index_directory(resolved)

    fts_q = _fts_query(query)
    if not fts_q:
        return []

    cap = max(1, min(int(limit or 8), 25))
    conn = _connect()
    try:
        if root_key:
            rows = conn.execute(
                'SELECT root, rel_path, symbols, '
                "snippet(docs_fts, 3, '[', ']', ' … ', 24) AS excerpt, "
                'bm25(docs_fts, 0.0, 6.0, 4.0, 1.0) AS rank '
                'FROM docs_fts WHERE docs_fts MATCH ? AND root = ? '
                'ORDER BY rank LIMIT ?',
                (fts_q, root_key, cap * 2),
            ).fetchall()
        else:
            rows = conn.execute(
                'SELECT root, rel_path, symbols, '
                "snippet(docs_fts, 3, '[', ']', ' … ', 24) AS excerpt, "
                'bm25(docs_fts, 0.0, 6.0, 4.0, 1.0) AS rank '
                'FROM docs_fts WHERE docs_fts MATCH ? '
                'ORDER BY rank LIMIT ?',
                (fts_q, cap * 2),
            ).fetchall()
    except sqlite3.OperationalError:
        rows = []
    finally:
        conn.close()

    if not root_key:
        return [
            {
                'root': r['root'],
                'path': r['rel_path'],
                'symbols': r['symbols'],
                'excerpt': ' '.join(str(r['excerpt'] or '').split())[:320],
                'score': round(-float(r['rank'] or 0.0), 3),
            }
            for r in rows[:cap]
        ]

    # Reciprocal Rank Fusion (RRF, k=60) across BM25 + subword cosine + 1-hop AST imports
    rrf_scores: dict[str, float] = {}
    meta_by_path: dict[str, dict] = {}

    for idx, r in enumerate(rows):
        rel = r['rel_path']
        rrf_scores[rel] = rrf_scores.get(rel, 0.0) + (1.0 / (60.0 + idx + 1)) + 0.01 * max(0.0, -float(r['rank'] or 0.0))
        meta_by_path[rel] = {
            'root': root_key,
            'path': rel,
            'symbols': r['symbols'],
            'excerpt': ' '.join(str(r['excerpt'] or '').split())[:320],
        }

    q_vec = _embed_sparse(query)
    sem_map = _load_semantic_vectors(root_key)
    sem_scored = []
    threshold = 0.20 if not rows else 0.14
    for rel, info in sem_map.items():
        sim = _cosine_sparse(q_vec, info['vec'])
        if sim >= threshold:
            sem_scored.append((sim, rel, info))
    sem_scored.sort(key=lambda x: x[0], reverse=True)

    for idx, (sim, rel, info) in enumerate(sem_scored[:cap * 2]):
        rrf_scores[rel] = rrf_scores.get(rel, 0.0) + (0.85 / (60.0 + idx + 1)) * (0.5 + sim)
        if rel not in meta_by_path:
            meta_by_path[rel] = {
                'root': root_key,
                'path': rel,
                'symbols': info['symbols'],
                'excerpt': info['excerpt'],
            }

    # Boost 1-hop AST callers/callees of top 2 lexical matches
    for r in rows[:2]:
        try:
            neighbors = related_files(r['rel_path'], root_key)
            for nb in (*neighbors['imports'][:4], *neighbors['imported_by'][:4]):
                if nb in sem_map:
                    rrf_scores[nb] = rrf_scores.get(nb, 0.0) + 0.0045
                    if nb not in meta_by_path:
                        info = sem_map[nb]
                        meta_by_path[nb] = {
                            'root': root_key,
                            'path': nb,
                            'symbols': info['symbols'],
                            'excerpt': info['excerpt'],
                        }
        except Exception:
            pass

    ordered = sorted(rrf_scores.items(), key=lambda kv: kv[1], reverse=True)[:cap]
    out = []
    for rel, sc in ordered:
        item = dict(meta_by_path[rel])
        item['score'] = round(sc * 100.0, 3)
        out.append(item)
    return out


def build_context_pack(task: str, root_dir: str | Path | None = None,
                       limit: int = 6) -> str:
    """Build a concise Markdown context block (hybrid RRF files + AST links + episodic memory + agent notes)."""
    hits = search_context(task, root_dir=root_dir, limit=limit, auto_index=bool(root_dir))
    episode_hits = []
    try:
        import episodic_memory
        episode_hits = episodic_memory.recall_episodes(str(task or '')[:160], limit=3)
    except Exception:
        episode_hits = []
    note_hits = []
    try:
        import agent_notes
        if hasattr(agent_notes, 'search'):
            note_hits = agent_notes.search(str(task or '')[:120])[:3]
    except Exception:
        note_hits = []

    if not hits and not episode_hits and not note_hits:
        return ''

    lines = ['## Trafny kontekst z hybrydowego indeksu kodu Jarvisa (FTS5 + AST + RRF)']
    for h in hits:
        sym_part = f" — symbole: `{h['symbols'][:140]}`" if h.get('symbols') else ''
        rel_info = ''
        if root_dir:
            try:
                nb = related_files(h['path'], root_dir)
                linked = (nb['imports'][:2] + nb['imported_by'][:2])[:3]
                if linked:
                    rel_info = f" (powiązane AST: {', '.join(f'`{p}`' for p in linked)})"
            except Exception:
                rel_info = ''
        lines.append(f"- `{h['path']}`{sym_part}{rel_info}")
        if h.get('excerpt'):
            lines.append(f"  > {h['excerpt']}")
    if root_dir and hits and str(hits[0].get('path') or '').endswith('.py'):
        try:
            import context_compressor
            top_file = validate_safe_project_dir(root_dir) / hits[0]['path']
            if top_file.is_file() and top_file.stat().st_size <= MAX_INDEX_FILE_BYTES:
                skel = context_compressor.skeletonize_python(
                    top_file.read_text(encoding='utf-8', errors='replace'),
                    max_chars=1200,
                )
                if skel:
                    lines.append(f"- Szkielet sygnatur AST (`{hits[0]['path']}`):\n```python\n{skel}\n```")
        except Exception:
            pass
    if episode_hits:
        lines.append('- Pamięć epizodyczna (wcześniejsze decyzje i rozwiązania):')
        for ep in episode_hits:
            sc = ep.get('score')
            score_part = f' (trafność: {sc})' if isinstance(sc, (int, float)) else ''
            lines.append(f"  - [{ep.get('kind', 'note')}] **{ep.get('title', '')}**{score_part}: "
                         f"{str(ep.get('summary', ''))[:200]}")
    if note_hits:
        lines.append('- Powiązane wcześniejsze notatki agentów:')
        for n in note_hits:
            title = n.get('title') or n.get('path') or str(n)
            lines.append(f"  - {title}")
    return '\n'.join(lines)
