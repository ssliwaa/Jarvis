"""Automated test suite for operator_modules/op_otel_tracer.py.

Tests the dispatch contract, db_path guardrails, trace lifecycle
(start/upsert/end with duration and token aggregation across spans),
span lifecycle (custom ids, parent links, attribute merging, token
defaults), milestone events, tree queries with filters, OTLP JSON
export (traceId normalization, GenAI semantic-convention attributes,
status codes, file snapshot), and P50-P99 latency/token metrics with
error-rate accounting. 100% offline: every test builds its own
TemporaryDirectory SQLite flight recorder; no network, no globals.
"""

from __future__ import annotations

import json
import tempfile
import unittest

import operator_modules.op_otel_tracer as ot


def _build_trace(db: str) -> None:
    """Seed one trace with an ended span and a recorded event."""
    ot.otel_tracer({"action": "start_trace", "db_path": db,
                    "trace_id": "tr-1", "name": "mytrace",
                    "attributes": {"env": "test"}})
    ot.otel_tracer({"action": "start_span", "db_path": db,
                    "trace_id": "tr-1", "span_id": "s1",
                    "name": "op", "span_type": "llm_call"})
    ot.otel_tracer({"action": "end_span", "db_path": db, "span_id": "s1",
                    "tokens": {"prompt_tokens": 10,
                               "completion_tokens": 5},
                    "attributes": {"done": True}})
    ot.otel_tracer({"action": "record_event", "db_path": db,
                    "span_id": "s1", "trace_id": "tr-1",
                    "event_name": "note",
                    "event_data": {"kind": "info"}})


class TestDispatch(unittest.TestCase):
    """Handler contract: envelope and argument validation."""

    def test_rejects_non_dict_arguments(self):
        res = ot.otel_tracer("nope")
        self.assertFalse(res["ok"])
        self.assertIn("JSON dictionary", res["error"])

    def test_rejects_disallowed_extra_keys(self):
        with tempfile.TemporaryDirectory() as td:
            res = ot.otel_tracer({"action": "start_trace",
                                  "db_path": td + "/t.sqlite3",
                                  "rogue": 1})
        self.assertFalse(res["ok"])
        self.assertIn("Disallowed additional arguments", res["error"])
        self.assertIn("rogue", res["error"])

    def test_invalid_action(self):
        with tempfile.TemporaryDirectory() as td:
            res = ot.otel_tracer({"action": "detonate",
                                  "db_path": td + "/t.sqlite3"})
        self.assertFalse(res["ok"])
        self.assertIn("Invalid or missing action 'detonate'", res["error"])
        self.assertIn("start_trace", res["error"])

    def test_success_envelope_shape(self):
        with tempfile.TemporaryDirectory() as td:
            res = ot.otel_tracer({"action": "start_trace",
                                  "trace_id": "env-check",
                                  "db_path": td + "/t.sqlite3"})
        self.assertEqual(set(res), {"ok", "success", "data", "result",
                                    "error"})
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"], res["result"])
        self.assertIsNone(res["error"])


class TestDbPathGuardrails(unittest.TestCase):
    """db_path validation: perimeter and sensitive blocklist."""

    def test_outside_allowed_roots_rejected(self):
        res = ot.otel_tracer({"action": "start_trace",
                              "db_path": "/proc/forbidden/t.sqlite3"})
        self.assertFalse(res["ok"])
        self.assertIn("PathSecurityError", res["error"])

    def test_sensitive_path_rejected(self):
        res = ot.otel_tracer({"action": "start_trace",
                              "db_path": "/tmp/ot_probe/.ssh/t.sqlite3"})
        self.assertFalse(res["ok"])
        self.assertIn("SensitivePathError", res["error"])


class TestTraceLifecycle(unittest.TestCase):
    """start_trace/start_span/end_span/end_trace lifecycle."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.db = self._td.name + "/t.sqlite3"

    def tearDown(self):
        self._td.cleanup()

    def test_start_trace_defaults_and_upsert(self):
        res = ot.otel_tracer({"action": "start_trace", "db_path": self.db})
        data = res["data"]
        self.assertEqual(data["name"], "agent_execution")
        self.assertEqual(data["status"], "UNSET")
        self.assertEqual(data["attributes"], {})
        self.assertTrue(data["trace_id"])
        # Re-start with same id upserts the column set
        res2 = ot.otel_tracer({"action": "start_trace",
                               "db_path": self.db,
                               "trace_id": data["trace_id"],
                               "name": "renamed"})
        self.assertEqual(res2["data"]["trace_id"], data["trace_id"])
        self.assertEqual(res2["data"]["name"], "renamed")

    def test_nested_span_end_and_trace_close(self):
        _build_trace(self.db)
        ot.otel_tracer({"action": "start_span", "db_path": self.db,
                        "trace_id": "tr-1", "span_id": "child1",
                        "parent_span_id": "s1"})
        res = ot.otel_tracer({"action": "end_span", "db_path": self.db,
                              "span_id": "child1",
                              "tokens": {}})
        self.assertEqual(res["data"]["trace_id"], "tr-1")
        self.assertEqual(res["data"]["prompt_tokens"], 0)
        self.assertEqual(res["data"]["total_tokens"], 0)
        closed = ot.otel_tracer({"action": "end_trace",
                                 "db_path": self.db,
                                 "trace_id": "tr-1", "status": "OK"})
        data = closed["data"]
        self.assertEqual(data["name"], "mytrace")
        self.assertGreaterEqual(data["duration_ms"], 0)
        self.assertEqual(data["total_prompt_tokens"], 10)
        self.assertEqual(data["total_completion_tokens"], 5)
        self.assertEqual(data["total_tokens"], 15)

    def test_end_span_missing_and_not_found(self):
        res = ot.otel_tracer({"action": "end_span", "db_path": self.db})
        self.assertFalse(res["ok"])
        self.assertIn("'span_id' for end_span", res["error"])
        res2 = ot.otel_tracer({"action": "end_span", "db_path": self.db,
                               "span_id": "ghost"})
        self.assertFalse(res2["ok"])
        self.assertIn("not found", res2["error"])

    def test_end_trace_missing_and_not_found(self):
        res = ot.otel_tracer({"action": "end_trace", "db_path": self.db})
        self.assertFalse(res["ok"])
        self.assertIn("'trace_id' for end_trace", res["error"])
        res2 = ot.otel_tracer({"action": "end_trace", "db_path": self.db,
                               "trace_id": "ghost"})
        self.assertFalse(res2["ok"])
        self.assertIn("not found", res2["error"])

    def test_span_merges_end_attributes(self):
        ot.otel_tracer({"action": "start_trace", "db_path": self.db,
                        "trace_id": "tr-2"})
        ot.otel_tracer({"action": "start_span", "db_path": self.db,
                        "trace_id": "tr-2", "span_id": "sx",
                        "attributes": {"phase": "init"}})
        res = ot.otel_tracer({"action": "end_span", "db_path": self.db,
                              "span_id": "sx",
                              "attributes": {"phase": "done"}})
        self.assertEqual(res["data"]["attributes"], {"phase": "done"})
        self.assertEqual(res["data"]["total_tokens"],
                         res["data"]["prompt_tokens"]
                         + res["data"]["completion_tokens"])


class TestRecordEvent(unittest.TestCase):
    """record_event: milestone entries inside a span."""

    def test_event_defaults_and_echo(self):
        with tempfile.TemporaryDirectory() as td:
            db = td + "/t.sqlite3"
            ot.otel_tracer({"action": "start_trace", "db_path": db,
                            "trace_id": "tr-3"})
            ot.otel_tracer({"action": "start_span", "db_path": db,
                            "trace_id": "tr-3", "span_id": "sev"})
            res = ot.otel_tracer({"action": "record_event",
                                  "db_path": db,
                                  "span_id": "sev", "trace_id": "tr-3"})
            data = res["data"]
            self.assertEqual(data["event_name"], "milestone")
            self.assertEqual(data["data"], {})
            self.assertEqual(data["span_id"], "sev")
            self.assertGreater(data["event_id"], 0)


class TestQueryTraces(unittest.TestCase):
    """query_traces: tree assembly and filters."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.db = self._td.name + "/t.sqlite3"
        _build_trace(self.db)

    def tearDown(self):
        self._td.cleanup()

    def test_query_returns_tree_with_events(self):
        res = ot.otel_tracer({"action": "query_traces",
                              "db_path": self.db,
                              "trace_id": "tr-1"})
        data = res["data"]
        self.assertEqual(data["trace_count"], 1)
        trace = data["traces"][0]
        self.assertEqual(trace["name"], "mytrace")
        self.assertEqual(trace["span_count"], 1)
        span = trace["spans"][0]
        self.assertEqual(span["span_id"], "s1")
        self.assertEqual(span["span_type"], "llm_call")
        self.assertEqual(span["tokens"]["total_tokens"], 15)
        self.assertEqual(span["events"][0]["event_name"], "note")
        self.assertEqual(span["events"][0]["data"], {"kind": "info"})

    def test_query_filters_exclude(self):
        res = ot.otel_tracer({"action": "query_traces",
                              "db_path": self.db,
                              "trace_id": "tr-1",
                              "status": "ERROR"})
        self.assertEqual(res["data"]["trace_count"], 0)
        res2 = ot.otel_tracer({"action": "query_traces",
                               "db_path": self.db,
                               "name": "missing_keyword"})
        self.assertEqual(res2["data"]["trace_count"], 0)


class TestExportOTLP(unittest.TestCase):
    """export_otlp: OTLP JSON structure and file snapshot."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.db = self._td.name + "/t.sqlite3"
        _build_trace(self.db)

    def tearDown(self):
        self._td.cleanup()

    def test_otlp_payload_structure(self):
        res = ot.otel_tracer({"action": "export_otlp",
                              "db_path": self.db,
                              "trace_id": "tr-1"})
        payload = res["data"]["otlp"]
        self.assertEqual(res["data"]["traces_exported"], 1)
        rs = payload["resourceSpans"][0]
        svc = {a["key"]: a["value"]["stringValue"]
               for a in rs["resource"]["attributes"]}
        self.assertEqual(svc["service.name"], "jarvis-operator")
        span = rs["scopeSpans"][0]["spans"][0]
        self.assertEqual(span["traceId"], "tr1")   # dashes removed
        self.assertEqual(span["spanId"], "s1")
        self.assertEqual(span["status"]["code"], 1)  # OK
        keys = {a["key"] for a in span["attributes"]}
        self.assertIn("gen_ai.usage.total_tokens", keys)
        self.assertIn("done", keys)
        bool_attr = next(a for a in span["attributes"]
                         if a["key"] == "done")
        self.assertEqual(bool_attr["value"], {"boolValue": True})
        event = span["events"][0]
        self.assertEqual(event["name"], "note")

    def test_export_to_file(self):
        target = self._td.name + "/export.json"
        res = ot.otel_tracer({"action": "export_otlp",
                              "db_path": self.db,
                              "trace_id": "tr-1",
                              "export_path": target})
        self.assertEqual(res["data"]["exported_path"], target)
        loaded = json.loads(open(target, encoding="utf-8").read())
        self.assertIn("resourceSpans", loaded)

    def test_export_outside_roots_rejected(self):
        res = ot.otel_tracer({"action": "export_otlp",
                              "db_path": self.db,
                              "trace_id": "tr-1",
                              "export_path": "/proc/no/no.json"})
        self.assertFalse(res["ok"])
        self.assertIn("PathSecurityError", res["error"])


class TestGetMetrics(unittest.TestCase):
    """get_metrics: percentiles, token spend, error rate, by-type."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.db = self._td.name + "/t.sqlite3"
        _build_trace(self.db)
        # Add one ERROR and one OK tool_call span
        ot.otel_tracer({"action": "start_span", "db_path": self.db,
                        "trace_id": "tr-1", "span_id": "s2",
                        "span_type": "tool_call"})
        ot.otel_tracer({"action": "end_span", "db_path": self.db,
                        "span_id": "s2", "status": "ERROR",
                        "tokens": {"total_tokens": 7}})
        ot.otel_tracer({"action": "start_span", "db_path": self.db,
                        "trace_id": "tr-1", "span_id": "s3",
                        "span_type": "tool_call"})
        ot.otel_tracer({"action": "end_span", "db_path": self.db,
                        "span_id": "s3",
                        "tokens": {"total_tokens": 3}})

    def tearDown(self):
        self._td.cleanup()

    def test_metrics_aggregation(self):
        res = ot.otel_tracer({"action": "get_metrics",
                              "db_path": self.db})
        data = res["data"]
        self.assertEqual(data["total_spans"], 3)
        self.assertEqual(data["error_spans"], 1)
        self.assertEqual(data["error_rate_pct"], 33.33)
        self.assertEqual(data["token_usage"]["prompt_tokens"], 10)
        self.assertEqual(data["token_usage"]["completion_tokens"], 5)
        self.assertEqual(data["token_usage"]["total_tokens"], 25)
        by_type = data["spans_by_type"]
        self.assertEqual(by_type["tool_call"]["count"], 2)
        self.assertEqual(by_type["tool_call"]["tokens"], 10)
        self.assertEqual(by_type["llm_call"]["count"], 1)
        for p in ("p50", "p90", "p95", "p99"):
            self.assertGreaterEqual(data["latency_percentiles_ms"][p], 0.0)

    def test_metrics_on_empty_database(self):
        with tempfile.TemporaryDirectory() as td:
            res = ot.otel_tracer({"action": "get_metrics",
                                  "db_path": td + "/empty.sqlite3"})
            data = res["data"]
            self.assertEqual(data["total_spans"], 0)
            self.assertEqual(data["error_rate_pct"], 0.0)
            self.assertEqual(data["latency_percentiles_ms"]["p50"], 0.0)
            self.assertEqual(data["spans_by_type"], {})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
