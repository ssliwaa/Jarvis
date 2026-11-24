"""Jarvis stdio MCP bridge: API error mapping, argument validation, tool routes,
JSON-RPC dispatch, framing and the serve loop -- all against a fake HTTP layer."""
import io
import json
import sys
import urllib.error
import urllib.request
from types import SimpleNamespace
from unittest import TestCase, mock
from unittest.mock import patch

import jarvis_mcp_server as bridge

BASE = "http://127.0.0.1:4700"


class _FakeResponse:
    def __init__(self, raw):
        self._raw = raw

    def read(self):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class ApiTests(TestCase):
    """api()/soft() with a fake urlopen -- the live Jarvis API is never touched."""

    def setUp(self):
        self.calls = []

    def _install(self, raw=b"{}", error=None, url_error=None, timeout_error=False):
        def fake(request, timeout=None):
            self.calls.append({"url": request.full_url, "method": request.method,
                               "data": request.data, "timeout": timeout})
            if error is not None:
                raise error
            if url_error is not None:
                raise url_error
            if timeout_error:
                raise TimeoutError()
            return _FakeResponse(raw)

        patcher = patch.object(urllib.request, "urlopen", fake)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_api_happy_sends_json_and_maps_body(self):
        self._install(raw=b'{"answer": "tak"}')
        result = bridge.api("POST", "/chat", {"question": "ę"}, timeout=300.0)
        self.assertEqual(result, {"answer": "tak"})
        call = self.calls[0]
        self.assertEqual(call["url"], BASE + "/chat")
        self.assertEqual(call["method"], "POST")
        self.assertEqual(json.loads(call["data"]), {"question": "ę"})
        self.assertEqual(call["timeout"], 300.0)

    def test_api_accepts_empty_body_and_rejects_bad_json(self):
        self._install(raw=b"")
        self.assertEqual(bridge.api("GET", "/system", timeout=5.0), {})
        self._install(raw=b"not json")
        with self.assertRaises(bridge.BridgeError) as ctx:
            bridge.api("GET", "/x")
        self.assertEqual(ctx.exception.code, "JARVIS_BAD_BODY")
        self.assertEqual(str(ctx.exception), "Jarvis returned a body that is not JSON.")

    def test_api_maps_http_errors_to_bridge_errors(self):
        cases = (
            (500, b'{"error": {"code": "BOOM", "message": "exploded"}}', "BOOM",
             "Jarvis answered HTTP 500: exploded"),
            (503, b"<html>oops", "HTTP_503", "Jarvis answered HTTP 503: <html>oops"),
            (404, b'{"answer": "no such thing here at all"}', "HTTP_404",
             "Jarvis answered HTTP 404: no such thing here at all"),
        )
        for code, body, want_code, want_msg in cases:
            error = urllib.error.HTTPError("u://x", code, "Reasony", None, io.BytesIO(body))
            self._install(error=error)
            with self.assertRaises(bridge.BridgeError) as ctx:
                bridge.api("GET", "/x")
            self.assertEqual((ctx.exception.code, str(ctx.exception)), (want_code, want_msg), code)

    def test_api_unreachable_and_timeout_and_soft(self):
        self._install(url_error=urllib.error.URLError("connection refused"))
        with self.assertRaises(bridge.BridgeError) as ctx:
            bridge.api("GET", "/x", None, 5.0)
        self.assertEqual(ctx.exception.code, "JARVIS_UNREACHABLE")
        self.assertIn("systemctl --user start jarvis.service", str(ctx.exception))
        self.assertIn(BASE, str(ctx.exception))
        self._install(timeout_error=True)
        with self.assertRaises(bridge.BridgeError) as ctx:
            bridge.api("GET", "/x", None, 15.0)
        self.assertEqual((ctx.exception.code, str(ctx.exception)),
                         ("JARVIS_TIMEOUT", "Jarvis did not answer within 15s."))
        self._install(timeout_error=True)
        soft = bridge.soft("GET", "/x", None, 15.0)
        self.assertEqual(soft["ok"], False)
        self.assertEqual(soft["error"], "JARVIS_TIMEOUT")
        self._install(raw=b'{"a": 1}')
        self.assertEqual(bridge.soft("GET", "/x"), {"ok": True, "data": {"a": 1}})


class ValidationTests(TestCase):
    """need_text / opt_text / opt_bool / _query exact message contracts."""

    def _raises(self, fn, *args, want_code, want_msg):
        with self.assertRaises(bridge.BridgeError) as ctx:
            fn(*args)
        self.assertEqual((ctx.exception.code, str(ctx.exception)), (want_code, want_msg))

    def test_need_text_matrix(self):
        self.assertEqual(bridge.need_text({"q": "  hi  "}, "q", 10), "hi")
        self._raises(bridge.need_text, {}, "q",
                     want_code="INVALID_ARGUMENT", want_msg="'q' must be a string.")
        self._raises(bridge.need_text, {"q": 5}, "q",
                     want_code="INVALID_ARGUMENT", want_msg="'q' must be a string.")
        self._raises(bridge.need_text, {"q": "  "}, "q",
                     want_code="INVALID_ARGUMENT", want_msg="'q' is required.")
        self._raises(bridge.need_text, {"q": "x" * 11}, "q", 10,
                     want_code="INVALID_ARGUMENT", want_msg="'q' is limited to 10 characters.")

    def test_opt_text_opt_bool_and_query(self):
        self.assertEqual(bridge.opt_text({}, "k"), "")
        self.assertEqual(bridge.opt_text({"k": " v "}, "k"), "v")
        self._raises(bridge.opt_text, {"k": 3}, "k",
                     want_code="INVALID_ARGUMENT", want_msg="'k' must be a string.")
        self._raises(bridge.opt_text, {"k": "x" * 9}, "k", 8,
                     want_code="INVALID_ARGUMENT", want_msg="'k' is limited to 8 characters.")
        self.assertIsNone(bridge.opt_bool({}, "b"))
        self.assertTrue(bridge.opt_bool({"b": True}, "b"))
        self._raises(bridge.opt_bool, {"b": "yes"}, "b",
                     want_code="INVALID_ARGUMENT", want_msg="'b' must be a boolean.")
        self.assertEqual(bridge._query({"a": 1, "b": None, "c": "", "d": "ę"}),
                         "?a=1&d=%C4%99")
        self.assertEqual(bridge._query({}), "")


class ToolContractTests(TestCase):
    """Each MCP tool's routing, payload shaping and validation (URIs captured)."""

    def setUp(self):
        self.calls = []

        def fake(request, timeout=None):
            self.calls.append({"url": request.full_url, "method": request.method,
                               "data": request.data, "timeout": timeout})
            return _FakeResponse(b"{}")

        patcher = patch.object(urllib.request, "urlopen", fake)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _data(self):
        return json.loads(self.calls[0]["data"]) if self.calls[0]["data"] else None

    def test_ask_validates_language_and_length(self):
        bridge.tool_ask({"question": "  co?  ", "language": "en"})
        self.assertEqual(self.calls[0]["url"], BASE + "/chat")
        self.assertEqual(self._data(), {"question": "co?", "language": "en"})
        with self.assertRaises(bridge.BridgeError) as ctx:
            bridge.tool_ask({"question": "x", "language": "EN"})
        self.assertEqual(str(ctx.exception), "'language' must be 'pl' or 'en'.")
        with self.assertRaises(bridge.BridgeError) as ctx:
            bridge.tool_ask({"question": "x" * 4001})
        self.assertEqual(str(ctx.exception), "'question' is limited to 4000 characters.")

    def test_memory_tools_shape_confirm_and_readonly(self):
        bridge.tool_memory_recall({"action": "events", "id": 7})
        self.assertEqual(self._data(), {"action": "events", "id": 7})
        with mock.patch.object(bridge, "READONLY", True):
            with self.assertRaises(bridge.BridgeError) as ctx:
                bridge.tool_memory_write({"confirm": True})
            self.assertEqual(ctx.exception.code, "READ_ONLY")
        bridge.tool_memory_write({"key": "k", "value": "v", "confirm": True})
        self.assertEqual(json.loads(self.calls[1]["data"]),
                         {"action": "add", "key": "k", "value": "v", "confirm": True})
        with self.assertRaises(bridge.BridgeError) as ctx:
            bridge.tool_memory_write({"key": "k"})
        self.assertEqual(ctx.exception.code, "CONFIRM_REQUIRED")
        with self.assertRaises(bridge.BridgeError) as ctx:
            bridge.tool_memory_recall({"action": "nope", "id": True})
        self.assertEqual(str(ctx.exception), "'action' must be recall, list or events.")

    def test_operator_routes_matrix(self):
        bridge.tool_operator_status({"action": "status", "job_id": "j-9"})
        self.assertEqual((self.calls[0]["url"], self.calls[0]["method"]),
                         (BASE + "/agent/status?job_id=j-9", "GET"))
        bridge.tool_operator_status({"action": "history", "status": "done"})
        self.assertEqual(self.calls[1]["url"], BASE + "/agent/history?status=done")
        bridge.tool_operator_status({})
        self.assertEqual(self.calls[2]["url"], BASE + "/agent/status")
        with self.assertRaises(bridge.BridgeError) as ctx:
            bridge.tool_operator_status({"action": "nope"})
        self.assertEqual(str(ctx.exception), "'action' must be status, history or queue.")

    def test_operator_task_actions(self):
        bridge.tool_operator_task({"action": "run", "task": "clean", "queue": True})
        self.assertEqual(self._data(), {"task": "clean", "queue": True})
        with mock.patch.object(bridge, "READONLY", True):
            with self.assertRaises(bridge.BridgeError) as ctx:
                bridge.tool_operator_task({"task": "x"})
            self.assertEqual(ctx.exception.code, "READ_ONLY")
        with self.assertRaises(bridge.BridgeError) as ctx:
            bridge.tool_operator_task({"action": "approve", "job_id": "j", "token": "t"})
        self.assertEqual(str(ctx.exception), "'approve' is required for the approve action.")
        with self.assertRaises(bridge.BridgeError) as ctx:
            bridge.tool_operator_task({"action": "approve", "approve": "yes",
                                       "job_id": "j", "token": "t"})
        self.assertEqual(str(ctx.exception), "'approve' must be a boolean.")
        with self.assertRaises(bridge.BridgeError) as ctx:
            bridge.tool_operator_task({"action": "zap"})
        self.assertEqual(str(ctx.exception), "'action' must be run, approve, stop or resume.")

    def test_query_tools_and_status_projection(self):
        bridge.tool_research({"query": "kot i pies"})
        self.assertEqual(self.calls[0]["url"], BASE + "/research?q=kot+i+pies")
        self.assertEqual(self.calls[0]["timeout"], 180.0)
        bridge.tool_skills({"name": "web_search", "file": "SKILL.md"})
        self.assertEqual(self.calls[1]["url"], BASE + "/skills/view?name=web_search&file=SKILL.md")
        bridge.tool_skills({"query": "vue"})
        self.assertEqual(self.calls[2]["url"], BASE + "/skills?q=vue")
        bridge.tool_skills({})
        self.assertEqual(self.calls[3]["url"], BASE + "/skills")
        with self.assertRaises(bridge.BridgeError) as ctx:
            bridge.tool_sessions_search({"query": "y" * 501})
        self.assertEqual(str(ctx.exception), "'query' is limited to 500 characters.")


class StatusProjectionTests(TestCase):
    """tool_status summarizes six soft lanes and never fails when one is down."""

    def _install_routing(self, data):
        def fake(request, timeout=None):
            body = data.get(request.full_url.rsplit(BASE, 1)[1], {})
            return _FakeResponse(json.dumps(body).encode())

        patcher = patch.object(urllib.request, "urlopen", fake)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_status_projects_health_and_capabilities(self):
        data = {
            "/health": {"status": "ok", "sources": {"a": 1, "b": 2}, "extra": "drop"},
            "/capabilities": {"capabilities": [{"id": "c1", "available": True},
                                               {"id": "c2", "available": False}]},
            "/services": {"svc": 1}, "/agent/status": {"available": True, "mode": "x"},
            "/retrieval/status": {"indexed_notes": 5}, "/metrics": {"m": 1},
        }
        self._install_routing(data)
        status = bridge.tool_status({})
        self.assertEqual(sorted(status),
                         ["agent", "base_url", "capabilities", "health", "metrics",
                          "read_only", "retrieval", "services"])
        self.assertEqual(status["base_url"], BASE)
        self.assertFalse(status["read_only"])
        self.assertEqual(status["health"]["data"], {"status": "ok", "source_files": 2})
        self.assertEqual(status["capabilities"]["data"],
                         {"available": ["c1"], "unavailable": ["c2"]})

    def test_status_tolerates_failing_lanes(self):
        def fake(request, timeout=None):
            if request.full_url.endswith("/health"):
                return _FakeResponse(b'{"status": "ok"}')
            raise urllib.error.URLError("down")

        patcher = patch.object(urllib.request, "urlopen", fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        status = bridge.tool_status({})
        self.assertTrue(status["health"]["ok"])
        caps = status["capabilities"]
        self.assertEqual(sorted(caps), ["error", "message", "ok"])
        self.assertEqual((caps["ok"], caps["error"]), (False, "JARVIS_UNREACHABLE"))
        self.assertIn("(down).", caps["message"])


class DispatchTests(TestCase):
    """JSON-RPC dispatch: initialize, lists, tools/call and error envelopes."""

    def _install(self, raw=b'{}'):
        patcher = patch.object(urllib.request, "urlopen", lambda request, timeout=None: _FakeResponse(raw))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_initialize_negotiates_protocol_and_advertises_server(self):
        reply = bridge.dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                 "params": {"protocolVersion": "1999-01-01"}})
        result = reply["result"]
        self.assertEqual(result["protocolVersion"], "2025-06-18")
        self.assertEqual(result["capabilities"], {"tools": {"listChanged": False}})
        self.assertEqual(result["serverInfo"], {"name": "jarvis",
                                               "title": "Jarvis (local knowledge galaxy)",
                                               "version": "1.0.0"})
        self.assertTrue(result["instructions"].startswith("Jarvis is the local"))
        newer = bridge.dispatch({"jsonrpc": "2.0", "id": 2, "method": "initialize",
                                 "params": {"protocolVersion": "2024-11-05"}})
        self.assertEqual(newer["result"]["protocolVersion"], "2024-11-05")

    def test_simple_methods_and_error_envelopes(self):
        self.assertEqual(bridge.dispatch({"jsonrpc": "2.0", "id": 1, "method": "ping"})["result"], {})
        self.assertIsNone(bridge.dispatch({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        self.assertEqual(bridge.dispatch({"jsonrpc": "2.0", "id": 6, "method": "resources/list"})
                         ["result"], {"resources": []})
        self.assertEqual(bridge.dispatch({"jsonrpc": "2.0", "id": 7,
                                          "method": "resources/templates/list"})["result"],
                         {"resourceTemplates": []})
        self.assertEqual(bridge.dispatch({"jsonrpc": "2.0", "id": 8, "method": "prompts/list"})
                         ["result"], {"prompts": []})
        self.assertEqual(bridge.dispatch({"jsonrpc": "2.0", "id": 9,
                                          "method": "logging/setLevel"})["result"], {})
        missing = bridge.dispatch({"jsonrpc": "2.0", "id": 3})
        self.assertEqual(missing["error"], {"code": -32600, "message": "Invalid Request: method is missing."})
        invalid = bridge.dispatch("nope")
        self.assertEqual(invalid["error"]["message"],
                         "Invalid Request: a message must be an object.")
        self.assertIsNone(invalid["id"])
        unknown = bridge.dispatch({"jsonrpc": "2.0", "id": 4, "method": "zap"})
        self.assertEqual(unknown["error"], {"code": -32601, "message": "Method not found: zap"})

    def test_tools_list_annotations_and_readonly_filter(self):
        rows = bridge.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]
        self.assertEqual(len(rows), 12)
        self.assertEqual(sorted(row["name"] for row in rows),
                         ["ask", "briefing", "memory_recall", "memory_write", "operator_status",
                          "operator_task", "remember", "research", "sessions_search", "skills",
                          "status", "system"])
        first = rows[0]
        self.assertEqual(first["name"], "ask")
        self.assertEqual(first["annotations"], {"title": first["title"], "readOnlyHint": True,
                                                "destructiveHint": False})
        self.assertTrue(all("handler" not in row for row in rows))
        self.assertTrue(all("inputSchema" in row for row in rows))
        with mock.patch.object(bridge, "READONLY", True):
            visible = bridge.visible_tools()
        self.assertEqual(sorted(tool["name"] for tool in visible),
                         ["ask", "briefing", "memory_recall", "operator_status", "research",
                          "sessions_search", "skills", "status", "system"])

    def test_tools_call_envelopes(self):
        self._install(raw=b'{"answer": "tak"}')
        happy = bridge.dispatch({"jsonrpc": "2.0", "id": 12, "method": "tools/call",
                                 "params": {"name": "ask", "arguments": {"question": "hej?"}}})
        result = happy["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"], {"answer": "tak"})
        self.assertEqual(json.loads(result["content"][0]["text"]), {"answer": "tak"})
        unknown = bridge.dispatch({"jsonrpc": "2.0", "id": 13, "method": "tools/call",
                                   "params": {"name": "nope", "arguments": {}}})
        self.assertEqual(unknown["result"]["content"][0]["text"], "No Jarvis tool named 'nope'.")
        bad_args = bridge.dispatch({"jsonrpc": "2.0", "id": 14, "method": "tools/call",
                                    "params": {"name": "status", "arguments": "x"}})
        self.assertEqual(bad_args["result"]["content"][0]["text"], "Tool arguments must be an object.")
        invalid = bridge.dispatch({"jsonrpc": "2.0", "id": 15, "method": "tools/call",
                                   "params": {"name": "ask", "arguments": {"question": "  "}}})
        self.assertEqual(invalid["result"]["content"][0]["text"],
                         "INVALID_ARGUMENT: 'question' is required.")
        self.assertTrue(invalid["result"]["isError"])
        with mock.patch.object(bridge, "READONLY", True), self._install_nocalls_guard():
            masked = bridge.dispatch({"jsonrpc": "2.0", "id": 16, "method": "tools/call",
                                      "params": {"name": "remember", "arguments": {"text": "x"}}})
        self.assertEqual(masked["result"]["content"][0]["text"],
                         "This bridge is read-only (JARVIS_MCP_READONLY=1).")

    @staticmethod
    def _install_nocalls_guard():
        """remember must be masked BEFORE any HTTP call happens."""
        def fail(request, timeout=None):
            raise AssertionError("HTTP must not be called for a read-only mask")
        return patch.object(urllib.request, "urlopen", fail)

    def test_tool_error_envelope_and_unexpected_exception(self):
        self.assertEqual(bridge.tool_error("wiadomosc"),
                         {"content": [{"type": "text", "text": "wiadomosc"}], "isError": True})
        def exploding(_args):
            raise ValueError("kaboom")
        with mock.patch.dict(bridge.TOOLS_BY_NAME, {
                "explode": {"name": "explode", "title": "E", "description": "E",
                            "readOnlyHint": True, "handler": exploding, "inputSchema": {}}}):
            reply = bridge.dispatch({"jsonrpc": "2.0", "id": 15, "method": "tools/call",
                                      "params": {"name": "explode", "arguments": {}}})
        self.assertEqual(reply["result"]["content"][0]["text"], "ValueError: kaboom")
        self.assertTrue(reply["result"]["isError"])

    def test_tool_result_shapes_and_truncation(self):
        small = bridge.tool_result({"a": 1})
        self.assertEqual(small["isError"], False)
        self.assertEqual(small["structuredContent"], {"a": 1})
        self.assertEqual(json.loads(small["content"][0]["text"]), {"a": 1})
        listed = bridge.tool_result([1, 2])
        self.assertNotIn("structuredContent", listed)
        self.assertEqual(json.loads(listed["content"][0]["text"]), [1, 2])
        big = bridge.tool_result({"x": "y" * 200_000})
        text = big["content"][0]["text"]
        self.assertEqual(len(text), 120_033)
        self.assertTrue(text.endswith("\n… truncated by the Jarvis bridge"))


class FramingTests(TestCase):
    """read_message framing and the serve loop on fake stdin/stdout."""

    def test_read_message_lines_blank_skip_and_eof(self):
        stream = io.BytesIO(b'{"a": 1}\n\n  \n{"c": 3}\n')
        self.assertEqual(bridge.read_message(stream), {"a": 1})
        self.assertEqual(bridge.read_message(stream), {"c": 3})
        self.assertIsNone(bridge.read_message(io.BytesIO(b"")))
        self.assertIsNone(bridge.read_message(io.BytesIO(b"\n\n")))

    def test_read_message_lsp_framing_and_errors(self):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"})
        frame = f"Content-Length: {len(body)}\r\nContent-Type: application/vscode-jsonrpc\r\n\r\n{body}"
        self.assertEqual(bridge.read_message(io.BytesIO(frame.encode())),
                         {"jsonrpc": "2.0", "id": 1, "method": "ping"})
        self.assertEqual(bridge.read_message(io.BytesIO(b'Content-Length: 8\r\nX: y\r\n\r\n{"x": 2}')),
                         {"x": 2})
        with self.assertRaises(bridge.BridgeError) as ctx:
            bridge.read_message(io.BytesIO(b"Content-Length: abc\r\n\r\n"))
        self.assertEqual((ctx.exception.code, str(ctx.exception)),
                         ("BAD_FRAME", "Malformed Content-Length header."))
        with self.assertRaises(ValueError):
            bridge.read_message(io.BytesIO(b"{oops"))

    def _serve(self, payload):
        sent = io.StringIO()
        with mock.patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload))), \
                mock.patch.object(sys, "stdout", sent):
            rc = bridge.serve()
        return rc, sent.getvalue()

    def test_serve_replies_and_skips_notifications(self):
        payload = (json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n"
                   + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}) + "\n"
                   + json.dumps({"jsonrpc": "2.0", "method": "notifications/x"}) + "\n")
        rc, raw = self._serve(payload.encode())
        self.assertEqual(rc, 0)
        replies = [json.loads(line) for line in raw.strip().splitlines()]
        self.assertEqual([reply.get("id") for reply in replies], [1, 2])
        self.assertEqual(replies[1]["result"], {})

    def test_serve_batch_and_parse_error(self):
        batch = json.dumps([{"jsonrpc": "2.0", "method": "ping"},
                            {"jsonrpc": "2.0", "id": 9, "method": "ping"}]) + "\n"
        rc, raw = self._serve(batch.encode())
        self.assertEqual(rc, 0)
        replies = json.loads(raw.strip())
        self.assertEqual([reply.get("id") for reply in replies], [None, 9])
        rc, raw = self._serve(b"{oops\n")
        self.assertEqual(rc, 0)
        failure = json.loads(raw.strip())
        self.assertEqual(failure["error"]["code"], -32700)
        self.assertTrue(failure["error"]["message"].startswith("Parse error:"))


if __name__ == "__main__":
    import unittest
    unittest.main()
