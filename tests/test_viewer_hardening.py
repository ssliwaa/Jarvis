"""viewer_hardening: /graph.json + SSE broker contracts.

The module is deliberately standalone (no server import), so each route is
exercised with a fake handler: BFS subgraphs, depth caps, origin validation,
error envelopes for malformed node ids and topics, and the bounded Broker
(fan-out, overflow drops, subscriber cap, concurrent publish). The real
viewer/graph-data.js carries integer node ids, which the tested route contract
assumes.
"""
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import viewer_hardening as vh
from viewer_hardening import (
    DEFAULT_TOPICS,
    HEARTBEAT_SECONDS,
    MAX_DEPTH,
    VALID_TOPICS,
    Broker,
)


def graph_fixture():
    """1-2-3-4 chain plus an isolated 5-6 pair; links are walked undirected."""
    nodes = [{"id": i, "label": f"n{i}"} for i in range(1, 7)]
    links = [
        {"source": 1, "target": 2},
        {"source": 2, "target": 3},
        {"source": 3, "target": 4},
        {"source": 5, "target": 6},
    ]
    return {"nodes": nodes, "links": links}


class FakeHandler:
    """Records send_json / event writes; can simulate a vanished client."""

    def __init__(self, graph=None, drop_after=None, fail_origin=False):
        self.graph = graph
        self.drop_after = drop_after
        self.fail_origin = fail_origin
        self.json_sent = []
        self.frames = []
        self.origin_checked = 0
        self.stream_started = 0
        self.server = SimpleNamespace(app=None)

    def validate_origin(self):
        self.origin_checked += 1
        if self.fail_origin:
            raise PermissionError("cross-origin")

    def send_json(self, status, payload):
        self.json_sent.append((status, payload))

    def start_event_stream(self):
        self.stream_started += 1

    def write_event(self, frame):
        self.frames.append(frame)
        if self.drop_after is not None and len(self.frames) >= self.drop_after:
            raise ConnectionResetError("client gone")


class ParseGraphSourceTests(unittest.TestCase):
    def test_extracts_const_graph_declaration(self):
        graph = vh.parse_graph_source('const GRAPH = {"nodes": [1], "links": []};\n')
        self.assertEqual(graph, {"nodes": [1], "links": []})

    def test_fullmatch_requires_clean_edges(self):
        for bad in ("", None, "const GRAPH = {}", "x const GRAPH = {\"nodes\": [], \"links\": []}",
                    "{\"nodes\": [], \"links\": []} // no declaration"):
            with self.assertRaises((ValueError, AttributeError)):
                vh.parse_graph_source(bad)

    def test_rejects_graph_without_lists(self):
        for source in ('const GRAPH = {"nodes": {}, "links": []};',
                       'const GRAPH = ["nodes", "links"];',
                       "const GRAPH = 42;"):
            with self.assertRaises(ValueError):
                vh.parse_graph_source(source)


class BuildSubgraphTests(unittest.TestCase):
    def test_full_graph_passes_through_with_meta(self):
        graph = graph_fixture()
        payload = vh.build_subgraph(graph)
        self.assertEqual(len(payload["nodes"]), 6)
        self.assertEqual(len(payload["links"]), 4)
        self.assertFalse(payload["meta"]["subgraph"])
        self.assertIsNone(payload["meta"]["node"])
        self.assertEqual(payload["meta"], {"node": None, "depth": 1, "total_nodes": 6,
                                           "total_links": 4, "subgraph": False,
                                           "nodes": 6, "links": 4})
        # The returned node list is a copy, not the source list object.
        self.assertIsNot(payload["nodes"], graph["nodes"])

    def test_neighbourhood_is_undirected_bfs(self):
        payload = vh.build_subgraph(graph_fixture(), node=3, depth=1)
        # Link 3->2 is walked in reverse: the neighbourhood is {2, 3, 4}.
        self.assertEqual([n["id"] for n in payload["nodes"]], [2, 3, 4])
        self.assertEqual(payload["links"], [{"source": 2, "target": 3},
                                            {"source": 3, "target": 4}])
        meta = payload["meta"]
        self.assertTrue(meta["subgraph"])
        self.assertEqual(meta["nodes"], 3)
        self.assertEqual(meta["links"], 2)
        self.assertFalse(meta["truncated"])

    def test_depth_expands_and_clamps(self):
        graph = graph_fixture()
        two = vh.build_subgraph(graph, node=1, depth=2)
        self.assertEqual([n["id"] for n in two["nodes"]], [1, 2, 3])
        four = vh.build_subgraph(graph, node=1, depth=99)
        self.assertEqual(four["meta"]["depth"], MAX_DEPTH)
        self.assertEqual([n["id"] for n in four["nodes"]], [1, 2, 3, 4])
        zero = vh.build_subgraph(graph, node=2, depth=0)
        self.assertEqual([n["id"] for n in zero["nodes"]], [2])
        self.assertEqual(zero["meta"]["depth"], 0)
        # The isolated 5-6 pair never leaks into the answer.
        none_adjacent = vh.build_subgraph(graph, node=5, depth=9)
        self.assertEqual([n["id"] for n in none_adjacent["nodes"]], [5, 6])

    def test_unknown_node_raises(self):
        with self.assertRaises(KeyError):
            vh.build_subgraph(graph_fixture(), node=99)

    def test_malformed_entries_are_skipped(self):
        graph = {"nodes": [{"id": 1}, {"id": 2}, "junk"],
                 "links": [{"source": 1, "target": 2}, "junk", {"source": 1, "target": 404}]}
        payload = vh.build_subgraph(graph, node=1, depth=1)
        self.assertEqual([n["id"] for n in payload["nodes"]], [1, 2])
        self.assertEqual(payload["links"], [{"source": 1, "target": 2}])

    def test_oversized_neighbourhood_is_refused(self):
        nodes = [{"id": 0, "label": "hub"}] + [{"id": i} for i in range(1, vh.MAX_NODES + 3)]
        links = [{"source": 0, "target": i} for i in range(1, vh.MAX_NODES + 3)]
        with self.assertRaises(ValueError):
            vh.build_subgraph({"nodes": nodes, "links": links}, node=0, depth=1)


class TopicTests(unittest.TestCase):
    def test_split_defaults_and_parses(self):
        self.assertEqual(vh.split_topics(None), list(DEFAULT_TOPICS))
        self.assertEqual(vh.split_topics(""), list(DEFAULT_TOPICS))
        self.assertEqual(vh.split_topics("metrics;agent/status, teardown"),
                         ["metrics", "agent/status", "teardown"])
        self.assertEqual(vh.split_topics("agent/status,agent/status"),
                         ["agent/status"])
        self.assertEqual(vh.split_topics(",, ;,"), list(DEFAULT_TOPICS))

    def test_split_rejects_unknown_topics(self):
        with self.assertRaises(ValueError):
            vh.split_topics("teardown,live")

    def test_select_is_lenient(self):
        self.assertEqual(vh.select_topics("teardown,live"), list(DEFAULT_TOPICS))
        self.assertEqual(vh.select_topics("teardown"), ["teardown"])
        self.assertEqual(set(VALID_TOPICS), set(vh.split_topics("")))


class BrokerTests(unittest.TestCase):
    def test_subscribe_delivers_by_topic_and_counts(self):
        broker = Broker()
        token, queue = broker.subscribe(["teardown"])
        self.assertEqual(broker.subscriber_count(), 1)
        self.assertEqual(broker.publish("metrics", {"cpu": 1}), 0)
        self.assertEqual(broker.publish("teardown", {"step": 1}), 1)
        frame = queue.popleft()
        self.assertEqual(frame["topic"], "teardown")
        self.assertEqual(frame["payload"], {"step": 1})
        self.assertIn("ts", frame)
        broker.unsubscribe(token)
        self.assertEqual(broker.subscriber_count(), 0)
        default_token, _ = broker.subscribe()
        self.assertEqual(broker.subscriber_count(), 1)
        broker.unsubscribe(default_token)

    def test_default_subscription_gets_every_topic(self):
        broker = Broker()
        token, queue = broker.subscribe()
        for topic in VALID_TOPICS:
            self.assertEqual(broker.publish(topic, None), 1)
        self.assertEqual(len(queue), len(VALID_TOPICS))
        broker.unsubscribe(token)

    def test_queue_overflow_drops_oldest_and_bumps_dropped(self):
        broker = Broker(queue_size=2)
        token, queue = broker.subscribe(["metrics"])
        for i in range(5):
            broker.publish("metrics", i)
        self.assertEqual(broker.dropped, 3)
        self.assertEqual([frame["payload"] for frame in queue], [3, 4])
        broker.unsubscribe(token)

    def test_subscriber_cap_returns_none(self):
        broker = Broker(max_subscribers=2)
        first = broker.subscribe()
        second = broker.subscribe()
        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        self.assertIsNone(broker.subscribe())
        broker.unsubscribe(first[0])
        self.assertIsNotNone(broker.subscribe())

    def test_concurrent_publishers_are_counted_safely(self):
        broker = Broker(queue_size=512)
        tokens = [broker.subscribe() for _ in range(2)]
        self.assertEqual(len(tokens), 2)
        errors = []

        def hammer(worker):
            try:
                for i in range(25):
                    broker.publish("metrics", {"worker": worker, "i": i})
            except Exception as error:  # pragma: no cover - reported below
                errors.append(error)

        threads = [threading.Thread(target=hammer, args=(w,)) for w in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(errors, [])
        self.assertEqual(broker.published, 100)
        for _, queue in broker._queues.values():
            self.assertLessEqual(len(queue), 512)

    def test_module_level_broker_and_publish_helper(self):
        token, queue = vh.BROKER.subscribe(["teardown"])
        try:
            self.assertEqual(vh.publish("teardown", {"x": 1}), 1)
            self.assertEqual(len(queue), 1)
            self.assertGreaterEqual(vh.BROKER.published, 1)
        finally:
            vh.BROKER.unsubscribe(token)
        self.assertIsInstance(vh.QUEUE_SIZE, int)


class GraphRouteTests(unittest.TestCase):
    def call(self, handler, path, query):
        parsed = SimpleNamespace(path=path, query=query)
        return vh.handle_get(handler, parsed)

    def test_other_paths_are_not_handled(self):
        handler = FakeHandler()
        self.assertFalse(self.call(handler, "/teardown/status", ""))
        self.assertEqual(handler.json_sent, [])

    def test_full_graph_served_with_origin_check(self):
        handler = FakeHandler(graph=graph_fixture())
        self.assertTrue(self.call(handler, "/graph.json", ""))
        status, payload = handler.json_sent[0]
        self.assertEqual(status, 200)
        self.assertEqual(payload["meta"]["total_nodes"], 6)
        self.assertEqual(handler.origin_checked, 1)

    def test_node_query_builds_neighbourhood(self):
        handler = FakeHandler(graph=graph_fixture())
        self.assertTrue(self.call(handler, "/graph.json", "node=1&depth=2"))
        status, payload = handler.json_sent[0]
        self.assertEqual(status, 200)
        self.assertEqual([n["id"] for n in payload["nodes"]], [1, 2, 3])
        self.assertTrue(payload["meta"]["subgraph"])

    def test_blank_node_and_bad_depth_fall_back(self):
        handler = FakeHandler(graph=graph_fixture())
        self.assertTrue(self.call(handler, "/graph.json", "node=&depth=abc"))
        status, payload = handler.json_sent[0]
        self.assertEqual(status, 200)
        self.assertFalse(payload["meta"]["subgraph"])
        self.assertEqual(payload["meta"]["depth"], 1)

    def test_malformed_node_id_answers_404_envelope(self):
        handler = FakeHandler(graph=graph_fixture())
        self.assertTrue(self.call(handler, "/graph.json", "node=abc"))
        status, payload = handler.json_sent[0]
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "UNKNOWN_NODE")
        self.assertIn("integer", payload["error"]["message"])

    def test_unknown_numeric_node_answers_404_envelope(self):
        handler = FakeHandler(graph=graph_fixture())
        self.assertTrue(self.call(handler, "/graph.json", "node=99"))
        status, payload = handler.json_sent[0]
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "UNKNOWN_NODE")

    def test_origin_failure_aborts_before_any_body(self):
        handler = FakeHandler(graph=graph_fixture(), fail_origin=True)
        with self.assertRaises(PermissionError):
            self.call(handler, "/graph.json", "")
        self.assertEqual(handler.json_sent, [])

    def test_graph_loader_fallbacks(self):
        class App:
            def load_graph(self):
                return {"nodes": [{"id": 1}], "links": []}

        # 1. the server's cached parser wins
        handler = FakeHandler()
        handler.server = SimpleNamespace(app=App())
        self.assertTrue(self.call(handler, "/graph.json", ""))
        self.assertEqual(handler.json_sent[0][1]["meta"]["total_nodes"], 1)
        # 2. nothing injectable -> read viewer/graph-data.js from app root
        with tempfile.TemporaryDirectory() as tmp:
            viewer = Path(tmp) / "viewer"
            viewer.mkdir()
            (viewer / "graph-data.js").write_text(
                'const GRAPH = {"nodes": [{"id": 1}], "links": []};', encoding="utf-8")
            handler = FakeHandler()
            handler.server = SimpleNamespace(app=SimpleNamespace(root=tmp))
            self.assertTrue(self.call(handler, "/graph.json", ""))
            self.assertEqual(handler.json_sent[0][1]["meta"]["total_nodes"], 1)


class EventsRouteTests(unittest.TestCase):
    def call(self, handler, query):
        parsed = SimpleNamespace(path="/events", query=query)
        return vh.handle_get(handler, parsed)

    def test_hello_frame_then_disconnect_unsubscribes(self):
        handler = FakeHandler(drop_after=1)
        self.assertTrue(self.call(handler, "topics=teardown"))
        self.assertEqual(handler.stream_started, 1)
        self.assertEqual(len(handler.frames), 1)
        self.assertEqual(handler.frames[0]["event"], "hello")
        self.assertEqual(handler.frames[0]["topics"], ["teardown"])
        self.assertEqual(handler.frames[0]["heartbeat"], HEARTBEAT_SECONDS)
        self.assertEqual(vh.BROKER.subscriber_count(), 0)

    def test_published_event_reaches_the_stream(self):
        def publish_once(_seconds):
            vh.BROKER.publish("teardown", {"note": "reached"})

        with patch.object(time, "sleep", side_effect=publish_once):
            handler = FakeHandler(drop_after=2)
            self.assertTrue(self.call(handler, "topics=teardown"))
        self.assertEqual(handler.frames[0]["event"], "hello")
        self.assertEqual(handler.frames[1]["payload"], {"note": "reached"})
        self.assertEqual(handler.frames[1]["topic"], "teardown")
        self.assertEqual(vh.BROKER.subscriber_count(), 0)

    def test_malformed_topics_answer_400_envelope(self):
        handler = FakeHandler()
        self.assertTrue(self.call(handler, "topics=teardown,live"))
        status, payload = handler.json_sent[0]
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "INVALID_TOPICS")
        self.assertIn("live", payload["error"]["message"])
        self.assertEqual(handler.stream_started, 0)
        self.assertEqual(vh.BROKER.subscriber_count(), 0)

    def test_subscriber_cap_answers_503_envelope(self):
        tiny = Broker(max_subscribers=0)
        with patch.object(vh, "BROKER", tiny):
            handler = FakeHandler()
            self.assertTrue(self.call(handler, "topics=metrics"))
        status, payload = handler.json_sent[0]
        self.assertEqual(status, 503)
        self.assertEqual(payload["error"]["code"], "TOO_MANY_STREAMS")
        self.assertEqual(handler.stream_started, 0)
        self.assertEqual(tiny.subscriber_count(), 0)


if __name__ == "__main__":
    unittest.main()
