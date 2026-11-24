"""event_bus: SSE ring buffer, subscribers and blocking waits.

This suite pins the in-process event bus: publish() normalisation (missing
topic falling back to 'system.event', blank topics likewise, 64-char clip,
payload wrapping where non-dict payloads become {'value': ...} and None
stays {'value': None}), the 200-entry ring buffer with monotonic ids and
eviction of the oldest events, recent() filtering with the limit=0 fallback
to 50 and the hard cap of 200, subscriber semantics (exact-topic buckets,
the '*' wildcard, duplicate-callback dedup, empty topic names resolving to
'*', listener exceptions swallowed without breaking publish), the special
episodic_memory forwarding for exactly three topics with failures isolated,
the blocking wait_next() (immediate timeout expiry, ready events returned
without waiting, a wake-up from another thread via the shared Condition),
format_sse() wire frames (exact layout, newline sanitisation of topics,
'message' and 0 defaults, UTF-8 payloads with ensure_ascii=False) and
reset_for_tests().

All assertions were pinned empirically before writing. The module keeps
global state, so every test resets buffers and subscribers for isolation.
"""
import sys
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import event_bus


class EventBusBase(unittest.TestCase):
    def setUp(self):
        event_bus.reset_for_tests()
        with event_bus._COND:
            event_bus._SUBSCRIBERS.clear()
        self.addCleanup(self._cleanup_bus)

    def _cleanup_bus(self):
        event_bus.reset_for_tests()
        with event_bus._COND:
            event_bus._SUBSCRIBERS.clear()


class TestPublish(EventBusBase):
    def test_event_shape_and_monotonic_ids(self):
        first = event_bus.publish("ui.test", {"k": 1})
        second = event_bus.publish("ui.test", {"k": 2})
        self.assertEqual(sorted(first), ["data", "id", "topic", "ts"])
        self.assertEqual(first["data"], {"k": 1})
        self.assertIsInstance(first["ts"], float)
        self.assertEqual(second["id"], first["id"] + 1)
        self.assertEqual(event_bus.latest_id(), second["id"])

    def test_topic_defaults_and_clip(self):
        self.assertEqual(event_bus.publish(None, {})["topic"], "system.event")
        self.assertEqual(event_bus.publish("   ", {})["topic"], "system.event")
        clipped = event_bus.publish("t" * 80, {})
        self.assertEqual(len(clipped["topic"]), 64)

    def test_payload_wrapping(self):
        self.assertEqual(event_bus.publish("a.b", None)["data"], {"value": None})
        self.assertEqual(event_bus.publish("a.b", "plain-string")["data"],
                         {"value": "plain-string"})
        passthrough = {"x": 1, "y": [2]}
        self.assertEqual(event_bus.publish("a.b", passthrough)["data"], passthrough)


class TestBuffer(EventBusBase):
    def test_recent_filters_by_after_id(self):
        for i in range(4):
            event_bus.publish("batch", {"i": i})
        self.assertEqual([ev["id"] for ev in event_bus.recent(1)], [2, 3, 4])
        self.assertEqual([ev["id"] for ev in event_bus.recent(0)], [1, 2, 3, 4])

    def test_limit_zero_defaults_to_fifty_and_caps_at_200(self):
        for i in range(60):
            event_bus.publish("bulk", {"i": i})
        self.assertEqual(len(event_bus.recent(0, limit=0)), 50)   # fallback default
        self.assertEqual(len(event_bus.recent(0, limit=10)), 10)
        for i in range(200):
            event_bus.publish("flood", {"i": i})
        self.assertEqual(len(event_bus.recent(0, limit=999)), 200)  # hard cap

    def test_ring_evicts_oldest_events(self):
        for i in range(205):
            event_bus.publish("ring", {"i": i})
        buffered = event_bus.recent(0, limit=999)
        self.assertEqual(len(buffered), 200)
        self.assertEqual(buffered[0]["id"], 6)  # ids 1-5 evicted by maxlen
        self.assertEqual(buffered[-1]["id"], 205)

    def test_latest_id_zero_when_empty(self):
        self.assertEqual(event_bus.latest_id(), 0)


class TestSubscribe(EventBusBase):
    def test_exact_topic_and_wildcard_buckets(self):
        topic_hits, star_hits = [], []
        event_bus.subscribe("app.topic", lambda ev: topic_hits.append(ev["id"]))
        event_bus.subscribe("*", lambda ev: star_hits.append(ev["id"]))
        event_bus.publish("app.topic", {})
        event_bus.publish("other.topic", {})
        self.assertEqual(topic_hits, [1])          # exact match only
        self.assertEqual(star_hits, [1, 2])        # wildcard sees everything

    def test_duplicate_callbacks_are_deduplicated(self):
        seen = []
        callback = lambda ev: seen.append(ev["id"])  # noqa: E731
        event_bus.subscribe("dedup.topic", callback)
        event_bus.subscribe("dedup.topic", callback)
        with event_bus._COND:
            bucket = event_bus._SUBSCRIBERS["dedup.topic"]
        self.assertEqual(len(bucket), 1)          # same callable stored once
        event_bus.publish("dedup.topic", {})
        self.assertEqual(seen, [1])                # callback fired exactly once

    def test_empty_topic_resolves_to_wildcard_bucket(self):
        star_hits = []
        event_bus.subscribe("", lambda ev: star_hits.append(ev["id"]))
        event_bus.publish("somewhere.else", {})
        self.assertEqual(star_hits, [1])           # '' -> '*' bucket

    def test_listener_exception_is_swallowed(self):
        def exploding(ev):
            raise RuntimeError("listener exploded")
        event_bus.subscribe("boom.topic", exploding)
        result = event_bus.publish("boom.topic", {"still": "fine"})
        self.assertEqual(result["data"], {"still": "fine"})  # publish unaffected
        self.assertEqual(event_bus.latest_id(), result["id"])


class TestEpisodicForwarding(EventBusBase):
    def test_only_the_three_special_topics_are_forwarded(self):
        captured = []
        fake = SimpleNamespace(handle_bus_event=lambda ev: captured.append(ev["topic"]))
        with patch.dict(sys.modules, {"episodic_memory": fake}):
            event_bus.publish("owner.answered", {"a": 1})
            event_bus.publish("router.circuit_tripped", {})
            event_bus.publish("night_shift.completed", {})
            event_bus.publish("unrelated.topic", {})
        self.assertEqual(captured, ["owner.answered", "router.circuit_tripped",
                                   "night_shift.completed"])

    def test_episodic_failure_is_isolated(self):
        def crashing(ev):
            raise RuntimeError("episodic store down")
        fake = SimpleNamespace(handle_bus_event=crashing)
        with patch.dict(sys.modules, {"episodic_memory": fake}):
            result = event_bus.publish("owner.answered", {"resilient": True})
        self.assertEqual(result["data"], {"resilient": True})
        self.assertEqual(event_bus.latest_id(), result["id"])


class TestWaitNext(EventBusBase):
    def test_times_out_to_empty_list(self):
        start = time.monotonic()
        self.assertEqual(event_bus.wait_next(0, timeout=0.15), [])
        self.assertGreaterEqual(time.monotonic() - start, 0.1)

    def test_returns_ready_events_without_blocking(self):
        event_bus.publish("ready.event", {"v": 1})
        events = event_bus.wait_next(0, timeout=0.1)
        self.assertEqual([ev["id"] for ev in events], [1])
        # an after_id covering everything leaves nothing to wait for
        self.assertEqual(event_bus.wait_next(1, timeout=0.1), [])

    def test_wakes_from_another_thread_on_publish(self):
        box = []

        def waiter():
            box.append(event_bus.wait_next(0, timeout=3.0))

        thread = threading.Thread(target=waiter)
        thread.start()
        time.sleep(0.15)
        event_bus.publish("wake.up", {"v": 2})
        thread.join(timeout=3.0)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(box), 1)
        self.assertEqual([ev["topic"] for ev in box[0]], ["wake.up"])


class TestFormatSse(unittest.TestCase):
    def test_wire_frame_layout(self):
        frame = event_bus.format_sse({"id": 7, "topic": "a.b", "data": {"x": "ż"}})
        lines = frame.decode("utf-8").split("\n")
        self.assertEqual(lines[0], "id: 7")
        self.assertEqual(lines[1], "event: a.b")
        self.assertTrue(lines[2].startswith("data: "))
        self.assertIn('"x": "ż"', lines[2])       # ensure_ascii=False UTF-8
        self.assertTrue(frame.endswith(b"\n\n"))  # SSE frame terminator

    def test_topic_newlines_sanitised_with_defaults(self):
        frame = event_bus.format_sse({"topic": "bad\ntopic\r", "data": {}})
        lines = frame.decode("utf-8").split("\n")
        self.assertEqual(lines[0], "id: 0")        # missing id defaults to 0
        self.assertEqual(lines[1], "event: bad topic ")  # newlines -> spaces
        self.assertEqual(lines[2], 'data: {"topic": "bad\\ntopic\\r", "data": {}}')
        # an event without a topic inherits the 'message' wire default
        empty = event_bus.format_sse({}).decode("utf-8")
        self.assertIn("event: message", empty)
        self.assertTrue(empty.startswith("id: 0"))


if __name__ == "__main__":
    unittest.main()
