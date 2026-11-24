"""Unit tests for tools_api: loopback HTTP mini-client, fully offline.

`urllib.request.urlopen` is patched everywhere (the real :4700 server is
never touched); responses and HTTPError bodies come from fakes. The
__main__ entry point runs via runpy with a patched `call` so the output
format is tested without any network.
"""
import contextlib
import io
import json
import re
import runpy
import sys
import unittest
import urllib.error
import urllib.request
from unittest import mock

import tools_api


class _FakeResponse:
    """Context-manager response good enough for json.load()."""

    def __init__(self, status, payload):
        self.status = status
        self._payload = payload

    def read(self, *args, **kwargs):
        return json.dumps(self._payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _Capture:
    """urlopen stand-in that records the request and returns a response."""

    def __init__(self, response=None, http_error=None):
        self.response = response
        self.http_error = http_error
        self.requests = []

    def __call__(self, request, timeout=None):
        self.requests.append((request, timeout))
        if self.http_error is not None:
            raise self.http_error
        return self.response


class TestCall(unittest.TestCase):
    """call(): request shape, success and error decoding."""

    def call(self, capture, *args, **kwargs):
        with mock.patch.object(tools_api.urllib.request, "urlopen", capture):
            return tools_api.call(*args, **kwargs)

    def test_get_without_payload_sends_no_data(self):
        capture = _Capture(_FakeResponse(200, {"ok": True}))
        status, body = self.call(capture, "/api/status")
        self.assertEqual((status, body), (200, {"ok": True}))
        request, timeout = capture.requests[0]
        self.assertEqual(request.full_url,
                         tools_api.BASE + "/api/status")
        self.assertIsNone(request.data)
        self.assertEqual(request.get_header("Content-type"),
                         "application/json")
        self.assertEqual(request.get_header("Origin"), tools_api.ORIGIN)
        self.assertEqual(timeout, 380)  # documented default

    def test_custom_timeout_forwarded(self):
        capture = _Capture(_FakeResponse(200, {}))
        self.call(capture, "/x", timeout=5)
        self.assertEqual(capture.requests[0][1], 5)

    def test_payload_serialized_as_json_bytes(self):
        capture = _Capture(_FakeResponse(200, {"echo": True}))
        payload = {"tool": "remember", "args": [1, 2]}
        self.call(capture, "/api/run", payload)
        request, _ = capture.requests[0]
        self.assertEqual(json.loads(request.data.decode()), payload)
        self.assertIsInstance(request.data, bytes)

    def test_http_error_with_json_body_decoded(self):
        body = b'{"error": "teapot", "status": 418}'
        http_error = urllib.error.HTTPError(
            "u", 418, "teapot", None, io.BytesIO(body))
        capture = _Capture(http_error=http_error)
        status, parsed = self.call(capture, "/api/x", payload={"a": 1})
        self.assertEqual((status, parsed),
                         (418, {"error": "teapot", "status": 418}))

    def test_http_error_with_raw_body_wrapped(self):
        http_error = urllib.error.HTTPError(
            "u", 500, "boom", None, io.BytesIO(b"not-json{{"))
        capture = _Capture(http_error=http_error)
        status, parsed = self.call(capture, "/api/x")
        self.assertEqual(status, 500)
        self.assertEqual(parsed, {"raw": "not-json{{"})

    def test_localhost_constants(self):
        self.assertEqual(tools_api.BASE, "http://127.0.0.1:4700")
        self.assertEqual(tools_api.ORIGIN, tools_api.BASE)


class TestMainEntry(unittest.TestCase):
    """python tools_api.py path [payload]: status + pretty JSON lines.

    runpy executes a FRESH copy of the module, so patching
    tools_api.call is useless here (the new __main__ namespace has its
    own). The global urllib.request.urlopen is patched instead - the
    fresh module resolves it at call time, so no real request to the
    loopback server can ever escape.
    """

    def run_module(self, argv, capture, timeout=None):
        stdout = io.StringIO()
        with mock.patch.object(urllib.request, "urlopen", capture), \
                mock.patch.object(sys, "argv", ["tools_api.py"] + argv), \
                contextlib.redirect_stdout(stdout):
            runpy.run_module("tools_api", run_name="__main__")
        return stdout.getvalue()

    def test_main_prints_status_and_pretty_json(self):
        capture = _Capture(_FakeResponse(200, {"tools": ["alpha", "beta"]}))
        out = self.run_module(["/api/tools"], capture)
        self.assertEqual(out.splitlines()[0], "200")
        self.assertIn('"tools"', out)
        self.assertIn("alpha", out)
        # exactly one request, aimed at the patched BASE (never the wire)
        request, timeout = capture.requests[0]
        self.assertEqual(request.full_url, tools_api.BASE + "/api/tools")

    def test_main_payload_argument_parsed_and_sent(self):
        capture = _Capture(_FakeResponse(201, {"created": {"k": "v"}}))
        out = self.run_module(["/api/remember", '{"k": "v"}'], capture)
        self.assertIn("201", out)
        self.assertIn('"created"', out)
        request, _ = capture.requests[0]
        self.assertEqual(json.loads(request.data.decode()), {"k": "v"})

    def test_main_without_payload_sends_no_data(self):
        capture = _Capture(_FakeResponse(200, {}))
        self.run_module(["/api/x"], capture)
        self.assertIsNone(capture.requests[0][0].data)

    def test_main_dump_truncated_to_3000_chars(self):
        capture = _Capture(_FakeResponse(200, {"blob": "z" * 5000}))
        out = self.run_module(["/api/x"], capture)
        # The [:3000] slice cuts the dumped JSON string: the status
        # line is printed whole, then up to 3000 chars of the dump.
        longest = max(len(chunk) for chunk in re.findall(r"z+", out))
        self.assertGreater(longest, 2500)   # bulk of the blob survives
        self.assertLess(longest, 5000)      # but the whole blob cannot
        self.assertLessEqual(len(out), len("200\n") + 3000 + len("\n"))


if __name__ == "__main__":
    unittest.main()
