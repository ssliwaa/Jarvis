"""Server-side hardening for Jarvis: graph as JSON and Server-Sent Events.

The module is deliberately standalone: it imports nothing from ``server.py`` so
that unit tests, the deploy kit and the running server can all load it.  The
server only has to delegate to :func:`handle_get` early in ``do_GET``.

Routes
------
``GET /graph.json``
    The note graph as ``{"nodes": [...], "links": [...], "meta": {...}}``.
    ``?node=<id>&depth=<n>`` narrows the answer to the neighbourhood of one
    node (BFS, undirected, ``depth`` capped at :data:`MAX_DEPTH`).

``GET /events?topics=agent/status,teardown,metrics``
    One ``text/event-stream`` frame per published event plus a heartbeat every
    :data:`HEARTBEAT_SECONDS`.  Publishing is thread-safe and bounded:
    :func:`publish` never blocks a producer and never grows without limit.

Fixes: P2 (graph as JSON), P5 (SSE instead of blind polling).
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from collections import deque
from pathlib import Path

__all__ = [
    "Broker",
    "BROKER",
    "DEFAULT_TOPICS",
    "HEARTBEAT_SECONDS",
    "MAX_DEPTH",
    "MAX_SUBSCRIBERS",
    "MAX_TOPICS",
    "QUEUE_SIZE",
    "build_subgraph",
    "handle_get",
    "parse_graph_source",
    "publish",
    "select_topics",
    "split_topics",
]

#: Deeper neighbourhoods stop being useful for the 3D viewer and cost memory.
MAX_DEPTH = 4
#: Clients must see a frame at least this often (proxies drop silent streams).
HEARTBEAT_SECONDS = 10.0
#: Bounded per-subscriber queue: a stalled reader drops old events, not RAM.
QUEUE_SIZE = 64
#: Hard cap on concurrent streams so one tab farm cannot pin the server.
MAX_SUBSCRIBERS = 32
#: Topics the viewer can subscribe to; anything else is rejected.
VALID_TOPICS = ("agent/status", "teardown", "metrics")
DEFAULT_TOPICS = VALID_TOPICS
MAX_TOPICS = len(VALID_TOPICS)
MAX_NODES = 10000
MAX_LINKS = 100000

_GRAPH_SOURCE = re.compile(r"\s*const\s+GRAPH\s*=\s*(\{.*\})\s*;?\s*", re.DOTALL)


class Broker:
    """Fan-out of topic-tagged events to SSE subscribers.

    Each subscriber owns a bounded ``deque``.  ``publish`` appends without ever
    waiting for a reader, so one slow client cannot stall the producer; when a
    queue is full the oldest event is discarded and ``dropped`` is bumped.
    """

    def __init__(self, queue_size: int = QUEUE_SIZE, max_subscribers: int = MAX_SUBSCRIBERS) -> None:
        self.queue_size = int(queue_size)
        self.max_subscribers = int(max_subscribers)
        self._lock = threading.Lock()
        self._queues: dict[int, tuple[frozenset[str], deque]] = {}
        self._next_token = 0
        self.dropped = 0
        self.published = 0

    def subscribe(self, topics=None):
        """Return ``(token, queue)`` or ``None`` when the cap is reached."""
        wanted = frozenset(topics) if topics else frozenset(DEFAULT_TOPICS)
        with self._lock:
            if len(self._queues) >= self.max_subscribers:
                return None
            token = self._next_token
            self._next_token += 1
            queue: deque = deque(maxlen=self.queue_size)
            self._queues[token] = (wanted, queue)
            return token, queue

    def unsubscribe(self, token) -> None:
        with self._lock:
            self._queues.pop(token, None)

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._queues)

    def publish(self, topic: str, payload) -> int:
        """Deliver one event to every subscriber of ``topic``; returns count."""
        frame = {"topic": topic, "ts": round(time.time(), 3), "payload": payload}
        with self._lock:
            self.published += 1
            delivered = 0
            for wanted, queue in self._queues.values():
                if topic not in wanted:
                    continue
                if len(queue) >= self.queue_size:
                    self.dropped += 1
                queue.append(frame)
                delivered += 1
            return delivered


BROKER = Broker()


def publish(topic: str, payload) -> int:
    """Publish to the module-level broker (used by other Jarvis modules)."""
    return BROKER.publish(topic, payload)


def split_topics(raw) -> list[str]:
    """Parse ``?topics=a,b``; unknown topics raise ``ValueError``."""
    if not raw:
        return list(DEFAULT_TOPICS)
    seen: list[str] = []
    for chunk in str(raw).replace(";", ",").split(","):
        name = chunk.strip()
        if not name:
            continue
        if name not in VALID_TOPICS:
            raise ValueError(f"unknown topic: {name!r}")
        if name not in seen:
            seen.append(name)
    return seen or list(DEFAULT_TOPICS)


def select_topics(raw) -> list[str]:
    """Lenient wrapper: unknown names are ignored instead of raising."""
    try:
        return split_topics(raw)
    except ValueError:
        return list(DEFAULT_TOPICS)


def parse_graph_source(text: str) -> dict:
    """Extract ``const GRAPH = {...}`` from ``viewer/graph-data.js``."""
    match = _GRAPH_SOURCE.fullmatch(text or "")
    if not match:
        raise ValueError("graph declaration not found")
    graph = json.loads(match.group(1))
    if not isinstance(graph, dict) or not isinstance(graph.get("nodes"), list) or not isinstance(graph.get("links"), list):
        raise ValueError("graph must carry nodes and links lists")
    return graph


def build_subgraph(graph: dict, node=None, depth: int = 1) -> dict:
    """Return the whole graph or the undirected neighbourhood of ``node``.

    ``node=None`` returns every node and link (the viewer's initial load).
    Node ids in the result are the original ids, so ``links`` stay valid and
    the viewer can merge subgraphs without remapping.
    """
    nodes = graph.get("nodes") or []
    links = graph.get("links") or []
    meta = {
        "node": None if node is None else int(node),
        "depth": max(0, min(int(depth), MAX_DEPTH)),
        "total_nodes": len(nodes),
        "total_links": len(links),
    }
    if node is None:
        meta.update({"subgraph": False, "nodes": len(nodes), "links": len(links)})
        return {"nodes": list(nodes), "links": list(links), "meta": meta}

    root = int(node)
    index = {}
    for position, item in enumerate(nodes):
        if isinstance(item, dict):
            index[item.get("id", position)] = position
    if root not in index:
        raise KeyError(f"unknown node id: {root}")

    adjacency: dict[int, set[int]] = {key: set() for key in index}
    for link in links:
        if not isinstance(link, dict):
            continue
        source, target = link.get("source"), link.get("target")
        if source in adjacency and target in adjacency:
            adjacency[source].add(target)
            adjacency[target].add(source)

    limit = max(0, min(int(depth), MAX_DEPTH))
    keep = {root}
    frontier = [root]
    for _ in range(limit):
        nxt = []
        for current in frontier:
            for neighbour in adjacency.get(current, ()):
                if neighbour not in keep:
                    keep.add(neighbour)
                    nxt.append(neighbour)
        frontier = nxt
        if not frontier:
            break

    kept_nodes = [nodes[index[key]] for key in sorted(keep, key=lambda k: index[k])]
    kept_links = [link for link in links
                  if isinstance(link, dict) and link.get("source") in keep and link.get("target") in keep]
    if len(kept_nodes) > MAX_NODES or len(kept_links) > MAX_LINKS:
        raise ValueError("subgraph too large")
    meta.update({"subgraph": True, "nodes": len(kept_nodes), "links": len(kept_links),
                 "truncated": False})
    return {"nodes": kept_nodes, "links": kept_links, "meta": meta}


def _graph_for(handler) -> dict:
    """Prefer the server's cached parser, fall back to the bundle on disk."""
    injected = getattr(handler, "graph", None)
    if isinstance(injected, dict):
        return injected
    app = getattr(getattr(handler, "server", None), "app", None)
    loader = getattr(app, "load_graph", None)
    if callable(loader):
        return loader()
    root = getattr(app, "root", None) or os.environ.get("JARVIS_TARGET") or str(Path(__file__).resolve().parent)
    with open(os.path.join(str(root), "viewer", "graph-data.js"), "rb") as handle:
        return parse_graph_source(handle.read(16 * 1024 * 1024).decode("utf-8"))


def _serve_graph(handler, query) -> None:
    graph = _graph_for(handler)
    raw_node = (query.get("node") or [None])[0]
    raw_depth = (query.get("depth") or ["1"])[0]
    try:
        node = None if raw_node in (None, "") else int(raw_node)
    except (TypeError, ValueError):
        # A malformed id is not a server fault: answer as "unknown node".
        handler.send_json(404, {"error": {"code": "UNKNOWN_NODE",
                                          "message": "The node id must be an integer."}})
        return
    try:
        depth = int(raw_depth)
    except (TypeError, ValueError):
        depth = 1
    try:
        payload = build_subgraph(graph, node=node, depth=depth)
    except KeyError:
        handler.send_json(404, {"error": {"code": "UNKNOWN_NODE", "message": "No such node in the note index."}})
        return
    handler.send_json(200, payload)


def _serve_events(handler, query) -> None:
    raw = (query.get("topics") or [""])[0]
    try:
        topics = split_topics(raw)
    except ValueError as error:
        # Unknown topic names must not surface as a generic 500.
        handler.send_json(400, {"error": {"code": "INVALID_TOPICS",
                                          "message": str(error)}})
        return
    subscription = BROKER.subscribe(topics)
    if subscription is None:
        handler.send_json(503, {"error": {"code": "TOO_MANY_STREAMS",
                                         "message": "Too many event streams; close another tab first."}})
        return
    token, queue = subscription
    try:
        handler.start_event_stream()
        handler.write_event({"event": "hello", "topics": topics, "heartbeat": HEARTBEAT_SECONDS})
        deadline = time.monotonic() + HEARTBEAT_SECONDS
        while True:
            frame = None
            try:
                frame = queue.popleft()
            except IndexError:
                frame = None
            now = time.monotonic()
            if frame is not None:
                handler.write_event(frame)
                deadline = now + HEARTBEAT_SECONDS
                continue
            if now >= deadline:
                handler.wfile.write(b": heartbeat\n\n")
                handler.wfile.flush()
                deadline = now + HEARTBEAT_SECONDS
            time.sleep(0.1)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        BROKER.unsubscribe(token)


def handle_get(handler, parsed) -> bool:
    """Answer the hardened GET routes; ``True`` when the request was served."""
    path = getattr(parsed, "path", "") or ""
    if path not in ("/graph.json", "/events"):
        return False
    from urllib.parse import parse_qs  # local import keeps module import cheap

    query = parse_qs(getattr(parsed, "query", "") or "", keep_blank_values=True)
    validator = getattr(handler, "validate_origin", None)
    if callable(validator):
        validator()
    if path == "/graph.json":
        _serve_graph(handler, query)
        return True
    _serve_events(handler, query)
    return True
