"""Jarvis Cortex: Persistent SQLite Knowledge & Architecture Topology Graph (`knowledge_graph.py`).

Unifies codebase structural awareness and durable semantic knowledge in zero idle RAM:
  1. AST Architecture Harvester (`rebuild_code_graph`): extracts modules, classes,
     HTTP endpoints (`/mission/...`, `/voice/...`, `/agents/...`), `event_bus` pub/sub
     topics, and SQLite stores as typed graph nodes & directed edges.
  2. Anomaly & Cycle Detector (`detect_anomalies`): finds circular module imports
     (`A -> B -> ... -> A`), high-fan-in bottlenecks, and unsubscribed SSE topics.
  3. Semantic Triples & Multi-Hop BFS (`upsert_triple`, `query_subgraph`): persists
     user/system domain facts (`subject --[relation]--> object`) alongside code topology.
"""

from __future__ import annotations

import ast
import os
import re
import sqlite3
import time
from collections import deque
from pathlib import Path

import agent_cli

HTTP_ROUTE_RE = re.compile(r"^/(?:mission|agents|voice|tts|chat|studio|health|api)(?:/[A-Za-z0-9_\-]+)*$")
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".jarvis-mcp-backups",
    ".hermes", ".jarvis-tools", "tests",
}


def _db_path() -> Path:
    base = agent_cli.ROOT.parent
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    return base / "knowledge_graph.sqlite3"


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
        "CREATE TABLE IF NOT EXISTS kg_nodes ("
        "  node_id TEXT PRIMARY KEY,"
        "  kind TEXT NOT NULL,"
        "  label TEXT NOT NULL,"
        "  meta_json TEXT NOT NULL DEFAULT '{}',"
        "  source TEXT NOT NULL DEFAULT 'manual',"
        "  updated_at REAL NOT NULL"
        ")"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS kg_edges ("
        "  src TEXT NOT NULL,"
        "  rel TEXT NOT NULL,"
        "  dst TEXT NOT NULL,"
        "  weight REAL NOT NULL DEFAULT 1.0,"
        "  source TEXT NOT NULL DEFAULT 'manual',"
        "  updated_at REAL NOT NULL,"
        "  PRIMARY KEY (src, rel, dst)"
        ")"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_kg_edges_src ON kg_edges(src)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_kg_edges_dst ON kg_edges(dst)")
    return conn


def upsert_triple(subject: str, relation: str, obj: str, *,
                  subj_kind: str = "entity", obj_kind: str = "entity",
                  weight: float = 1.0, source: str = "manual") -> dict:
    """Insert or update a directed knowledge triple `subject --[relation]--> obj`."""
    s = str(subject or "").strip()[:160]
    r = str(relation or "").strip().lower().replace(" ", "_")[:64]
    o = str(obj or "").strip()[:160]
    if not s or not r or not o:
        raise ValueError("Trójka grafu wiedzy wymaga niepustych pól subject, relation i obj.")

    now = round(time.time(), 3)
    conn = _connect()
    try:
        with conn:
            conn.execute(
                "INSERT INTO kg_nodes (node_id, kind, label, source, updated_at) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(node_id) DO UPDATE SET kind = excluded.kind, updated_at = excluded.updated_at",
                (s, subj_kind, s, source, now),
            )
            conn.execute(
                "INSERT INTO kg_nodes (node_id, kind, label, source, updated_at) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(node_id) DO UPDATE SET kind = excluded.kind, updated_at = excluded.updated_at",
                (o, obj_kind, o, source, now),
            )
            conn.execute(
                "INSERT INTO kg_edges (src, rel, dst, weight, source, updated_at) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(src, rel, dst) DO UPDATE SET weight = excluded.weight, updated_at = excluded.updated_at",
                (s, r, o, float(weight), source, now),
            )
    finally:
        conn.close()
    return {"ok": True, "subject": s, "relation": r, "object": o}


def _extract_module_topology(rel_path: str, source_code: str, known_modules: dict[str, str]) -> dict:
    imports: set[str] = set()
    classes: list[str] = []
    routes: set[str] = set()
    pub_topics: set[str] = set()
    sub_topics: set[str] = set()
    sqlite_dbs: set[str] = set()

    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return {
            "imports": [], "classes": [], "routes": [],
            "pub_topics": [], "sub_topics": [], "sqlite_dbs": [],
        }

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            classes.append(node.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in known_modules and known_modules[top] != rel_path:
                    imports.add(known_modules[top])
        elif isinstance(node, ast.ImportFrom) and node.module:
            top = node.module.split(".")[0]
            if top in known_modules and known_modules[top] != rel_path:
                imports.add(known_modules[top])
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            val = node.value.strip()
            if HTTP_ROUTE_RE.match(val):
                routes.add(val)
            elif val.endswith(".sqlite3") and "/" not in val and len(val) <= 64:
                sqlite_dbs.add(val)
        elif isinstance(node, ast.Call):
            fn = node.func
            attr_name = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")
            mod_name = fn.value.id if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) else ""
            if attr_name == "publish" and (mod_name == "event_bus" or "event_bus" in source_code):
                if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    pub_topics.add(node.args[0].value.strip())
            elif attr_name == "subscribe" and (mod_name == "event_bus" or "event_bus" in source_code):
                if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    sub_topics.add(node.args[0].value.strip())

    return {
        "imports": sorted(imports),
        "classes": sorted(classes)[:15],
        "routes": sorted(routes),
        "pub_topics": sorted(pub_topics),
        "sub_topics": sorted(sub_topics),
        "sqlite_dbs": sorted(sqlite_dbs),
    }


def rebuild_code_graph(project_dir: str | Path) -> dict:
    """Harvest AST imports, HTTP endpoints, SSE topics, and SQLite stores into Cortex KG."""
    root = Path(project_dir).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Brak katalogu projektu: {root}")

    py_files: list[tuple[str, Path]] = []
    known_modules: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in sorted(dirnames) if d not in SKIP_DIRS and not d.startswith(".jarvis-")]
        for fname in sorted(filenames):
            if not fname.endswith(".py") or fname.startswith("test_"):
                continue
            fpath = Path(dirpath) / fname
            if fpath.is_symlink():
                continue
            rel = str(fpath.relative_to(root)).replace("\\", "/")
            py_files.append((rel, fpath))
            known_modules[Path(rel).stem] = rel

    now = round(time.time(), 3)
    nodes_to_insert: list[tuple[str, str, str, str, float]] = []
    edges_to_insert: list[tuple[str, str, str, float, str, float]] = []

    for rel, fpath in py_files:
        try:
            src = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        nodes_to_insert.append((f"mod:{rel}", "module", rel, "ast", now))
        topo = _extract_module_topology(rel, src, known_modules)

        for imp in topo["imports"]:
            edges_to_insert.append((f"mod:{rel}", "imports", f"mod:{imp}", 1.0, "ast", now))
        for cls in topo["classes"]:
            cid = f"class:{rel}:{cls}"
            nodes_to_insert.append((cid, "class", cls, "ast", now))
            edges_to_insert.append((f"mod:{rel}", "defines_class", cid, 1.0, "ast", now))
        for route in topo["routes"]:
            rid = f"route:{route}"
            nodes_to_insert.append((rid, "http_route", route, "ast", now))
            edges_to_insert.append((f"mod:{rel}", "serves_route", rid, 1.2, "ast", now))
        for topic in topo["pub_topics"]:
            tid = f"topic:{topic}"
            nodes_to_insert.append((tid, "sse_topic", topic, "ast", now))
            edges_to_insert.append((f"mod:{rel}", "publishes_event", tid, 1.2, "ast", now))
        for topic in topo["sub_topics"]:
            tid = f"topic:{topic}"
            nodes_to_insert.append((tid, "sse_topic", topic, "ast", now))
            edges_to_insert.append((f"mod:{rel}", "subscribes_event", tid, 1.2, "ast", now))
        for db_name in topo["sqlite_dbs"]:
            did = f"db:{db_name}"
            nodes_to_insert.append((did, "sqlite_db", db_name, "ast", now))
            edges_to_insert.append((f"mod:{rel}", "persists_in", did, 1.1, "ast", now))

    conn = _connect()
    try:
        with conn:
            conn.execute("DELETE FROM kg_edges WHERE source = 'ast'")
            conn.execute("DELETE FROM kg_nodes WHERE source = 'ast'")
            conn.executemany(
                "INSERT OR REPLACE INTO kg_nodes (node_id, kind, label, source, updated_at) VALUES (?, ?, ?, ?, ?)",
                nodes_to_insert,
            )
            conn.executemany(
                "INSERT OR REPLACE INTO kg_edges (src, rel, dst, weight, source, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                edges_to_insert,
            )
    finally:
        conn.close()

    anomalies = detect_anomalies()
    stats = graph_summary()
    return {"ok": True, **stats, "anomalies": anomalies}


def detect_anomalies() -> dict:
    """Detect circular module imports (`A -> B -> ... -> A`) and high-fan-in hubs."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT src, dst FROM kg_edges WHERE rel = 'imports'"
        ).fetchall()
    finally:
        conn.close()

    adj: dict[str, list[str]] = {}
    fan_in: dict[str, int] = {}
    for r in rows:
        s, d = str(r["src"]), str(r["dst"])
        adj.setdefault(s, []).append(d)
        fan_in[d] = fan_in.get(d, 0) + 1

    cycles: list[list[str]] = []
    seen_cycle_keys: set[tuple[str, ...]] = set()

    for start in sorted(adj):
        # Bounded BFS cycle search up to depth 4
        q: deque[tuple[str, list[str]]] = deque([(start, [start])])
        while q:
            curr, path = q.popleft()
            if len(path) > 5:
                continue
            for nxt in adj.get(curr, ()):
                if nxt == start and len(path) >= 2:
                    cyc = [p.removeprefix("mod:") for p in path]
                    norm_key = tuple(sorted(cyc))
                    if norm_key not in seen_cycle_keys:
                        seen_cycle_keys.add(norm_key)
                        cycles.append(cyc + [start.removeprefix("mod:")])
                elif nxt not in path and len(path) < 4:
                    q.append((nxt, path + [nxt]))

    hubs = sorted(
        [{"module": k.removeprefix("mod:"), "imported_by_count": v} for k, v in fan_in.items()],
        key=lambda item: item["imported_by_count"],
        reverse=True,
    )[:8]

    return {
        "circular_imports": cycles[:10],
        "core_hubs": hubs,
    }


def query_subgraph(query: str, *, hops: int = 2, limit_edges: int = 40) -> dict:
    """Find matching seed nodes and expand a bidirectional `hops`-step neighborhood."""
    q = str(query or "").strip().lower()
    max_hops = max(1, min(int(hops), 3))
    conn = _connect()
    try:
        if q:
            seeds = conn.execute(
                "SELECT node_id, kind, label FROM kg_nodes "
                "WHERE LOWER(node_id) LIKE ? OR LOWER(label) LIKE ? LIMIT 10",
                (f"%{q}%", f"%{q}%"),
            ).fetchall()
        else:
            seeds = conn.execute(
                "SELECT node_id, kind, label FROM kg_nodes ORDER BY updated_at DESC LIMIT 8"
            ).fetchall()

        visited: set[str] = {str(r["node_id"]) for r in seeds}
        frontier: set[str] = set(visited)
        collected_edges: list[dict] = []
        seen_edges: set[tuple[str, str, str]] = set()

        for _ in range(max_hops):
            if not frontier or len(collected_edges) >= limit_edges:
                break
            placeholders = ",".join("?" for _ in frontier)
            params = tuple(frontier)
            erows = conn.execute(
                f"SELECT src, rel, dst, weight FROM kg_edges "
                f"WHERE src IN ({placeholders}) OR dst IN ({placeholders}) LIMIT ?",
                (*params, *params, limit_edges),
            ).fetchall()
            next_frontier: set[str] = set()
            for er in erows:
                key = (str(er["src"]), str(er["rel"]), str(er["dst"]))
                if key not in seen_edges and len(collected_edges) < limit_edges:
                    seen_edges.add(key)
                    collected_edges.append({
                        "src": key[0],
                        "rel": key[1],
                        "dst": key[2],
                        "weight": float(er["weight"]),
                    })
                for endpoint in (key[0], key[2]):
                    if endpoint not in visited:
                        visited.add(endpoint)
                        next_frontier.add(endpoint)
            frontier = next_frontier

        nodes: list[dict] = []
        if visited:
            vp = ",".join("?" for _ in visited)
            nrows = conn.execute(
                f"SELECT node_id, kind, label, source FROM kg_nodes WHERE node_id IN ({vp})",
                tuple(visited),
            ).fetchall()
            nodes = [
                {"id": str(r["node_id"]), "kind": str(r["kind"]), "label": str(r["label"]), "source": str(r["source"])}
                for r in nrows
            ]
    finally:
        conn.close()

    lines = [f"{e['src']} --[{e['rel']}]--> {e['dst']}" for e in collected_edges[:20]]
    return {
        "ok": True,
        "query": query,
        "nodes": nodes,
        "edges": collected_edges,
        "ascii_map": "\n".join(lines),
    }


def graph_summary() -> dict:
    conn = _connect()
    try:
        total_nodes = int(conn.execute("SELECT COUNT(*) AS c FROM kg_nodes").fetchone()["c"])
        total_edges = int(conn.execute("SELECT COUNT(*) AS c FROM kg_edges").fetchone()["c"])
        by_kind_rows = conn.execute("SELECT kind, COUNT(*) AS c FROM kg_nodes GROUP BY kind").fetchall()
    finally:
        conn.close()
    return {
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "by_kind": {str(r["kind"]): int(r["c"]) for r in by_kind_rows},
    }
