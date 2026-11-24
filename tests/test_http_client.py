"""Tests for operator_modules/http_client.py (Safe HTTP & REST Client)."""

from __future__ import annotations

import http.server
import socket
import threading
import time
import unittest
from unittest.mock import patch

import operator_modules.http_client as http_client


class _MockHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress stderr logging during tests

    def do_GET(self):
        if self.path == "/json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok", "count": 42}')
        elif self.path == "/headers":
            self.send_response(200)
            self.send_header("X-Custom", "safe-header")
            self.send_header("Set-Cookie", "session=secret_token")
            self.end_headers()
            self.wfile.write(b"ok")
        elif self.path.startswith("/query"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(f'{{"path": "{self.path}"}}'.encode("utf-8"))
        elif self.path == "/large":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"A" * 5000)
        elif self.path == "/slow":
            time.sleep(1.5)
            try:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"done")
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found Error")

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8")
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(f'{{"received": {body}}}'.encode("utf-8"))

    def do_PUT(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(f'{{"updated": "{body}"}}'.encode("utf-8"))


class TestHttpClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), _MockHandler)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_tool_declaration_contract(self):
        tool = http_client.TOOL
        self.assertEqual(tool["name"], "http_client")
        self.assertTrue(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        self.assertEqual(tool["input_schema"]["type"], "object")
        self.assertFalse(tool["input_schema"]["additionalProperties"])

    def test_ssrf_rejection_for_loopback_without_allow_local(self):
        res = http_client.http_client({"url": f"http://127.0.0.1:{self.port}/json"})
        self.assertFalse(res["ok"])
        self.assertFalse(res["success"])
        self.assertIn("Refusing", res["error"])

    def test_ssrf_rejection_for_private_ip(self):
        res = http_client.http_client({"url": "http://192.168.1.1/api"})
        self.assertFalse(res["ok"])
        self.assertIn("Refusing", res["error"])

    def test_successful_get_with_allow_local(self):
        res = http_client.http_client({
            "url": f"http://127.0.0.1:{self.port}/json",
            "allow_local": True,
        })
        self.assertTrue(res["ok"])
        self.assertTrue(res["success"])
        data = res["data"]
        self.assertEqual(data["status_code"], 200)
        self.assertEqual(data["json"], {"status": "ok", "count": 42})
        self.assertEqual(res["result"], data)

    def test_successful_post_with_json_body(self):
        res = http_client.http_client({
            "url": f"http://127.0.0.1:{self.port}/submit",
            "method": "POST",
            "json_body": {"name": "jarvis_test"},
            "allow_local": True,
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["status_code"], 201)
        self.assertEqual(res["data"]["json"]["received"], {"name": "jarvis_test"})

    def test_successful_put_with_data(self):
        res = http_client.http_client({
            "url": f"http://127.0.0.1:{self.port}/update",
            "method": "PUT",
            "data": "payload_test",
            "allow_local": True,
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["status_code"], 200)
        self.assertEqual(res["data"]["json"]["updated"], "payload_test")

    def test_header_redaction(self):
        res = http_client.http_client({
            "url": f"http://127.0.0.1:{self.port}/headers",
            "headers": {"Authorization": "Bearer sensitive_token", "X-Key": "my-key"},
            "allow_local": True,
        })
        self.assertTrue(res["ok"])
        headers = res["data"]["headers"]
        self.assertEqual(headers.get("Set-Cookie"), "[REDACTED]")

    def test_query_parameters(self):
        res = http_client.http_client({
            "url": f"http://127.0.0.1:{self.port}/query",
            "params": {"search": "test", "limit": "10"},
            "allow_local": True,
        })
        self.assertTrue(res["ok"])
        self.assertIn("search=test", res["data"]["json"]["path"])
        self.assertIn("limit=10", res["data"]["json"]["path"])

    def test_invalid_scheme_rejected(self):
        res = http_client.http_client({"url": "ftp://example.com/file"})
        self.assertFalse(res["ok"])
        self.assertIn("Unsupported scheme", res["error"])

    def test_missing_url_error(self):
        res = http_client.http_client({})
        self.assertFalse(res["ok"])
        self.assertIn("required", res["error"])

    def test_invalid_method_rejected(self):
        res = http_client.http_client({
            "url": f"http://127.0.0.1:{self.port}/json",
            "method": "INVALID_ACTION",
            "allow_local": True,
        })
        self.assertFalse(res["ok"])
        self.assertIn("not allowed", res["error"])

    def test_http_404_error_handling(self):
        res = http_client.http_client({
            "url": f"http://127.0.0.1:{self.port}/not-found",
            "allow_local": True,
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["status_code"], 404)
        self.assertIn("Not Found Error", res["data"]["text"])

    def test_response_truncation_max_bytes(self):
        res = http_client.http_client({
            "url": f"http://127.0.0.1:{self.port}/large",
            "max_bytes": 1024,
            "allow_local": True,
        })
        self.assertTrue(res["ok"])
        self.assertTrue(res["data"]["truncated"])
        self.assertEqual(res["data"]["bytes_read"], 1024)

    def test_timeout_handling(self):
        res = http_client.http_client({
            "url": f"http://127.0.0.1:{self.port}/slow",
            "timeout": 1.0,
            "allow_local": True,
        })
        self.assertFalse(res["ok"])
        self.assertIn("timed out", res["error"].lower())

    def test_invalid_headers_type_rejected(self):
        for invalid_headers in ["Authorization: Bearer secret", ["invalid"], 12345, True]:
            res = http_client.http_client({
                "url": f"http://127.0.0.1:{self.port}/json",
                "headers": invalid_headers,
                "allow_local": True,
            })
            self.assertFalse(res["ok"])
            self.assertFalse(res["success"])
            self.assertIn("Parameter 'headers' must be a dictionary", res["error"])

    def test_fallback_ssrf_blocks_172_subnet(self):
        with patch.object(http_client, "net_guard", None):
            valid_start, reason_start = http_client._is_url_allowed("http://172.16.0.1:80", allow_local=False)
            self.assertFalse(valid_start)
            self.assertIn("Refusing connection to private subnet", reason_start)

            valid_mid, _ = http_client._is_url_allowed("http://172.20.10.5:80", allow_local=False)
            self.assertFalse(valid_mid)

            valid_end, _ = http_client._is_url_allowed("http://172.31.255.255:80", allow_local=False)
            self.assertFalse(valid_end)

    def test_fallback_ssrf_resolves_dns_and_refuses_private_records(self):
        # Standalone mode (net_guard unavailable) used to check only literal
        # IP prefixes: a hostname resolving into a private range was fetched.
        fake_records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 0)),
                        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        with patch.object(http_client, "net_guard", None), \
             patch.object(http_client.socket, "getaddrinfo", return_value=fake_records):
            valid, reason = http_client._is_url_allowed("http://internal.service/api", allow_local=False)
        self.assertFalse(valid)
        self.assertIn("SSRF protection", reason)

        public_records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        with patch.object(http_client, "net_guard", None), \
             patch.object(http_client.socket, "getaddrinfo", return_value=public_records):
            valid, reason = http_client._is_url_allowed("http://public.example/api", allow_local=False)
        self.assertTrue(valid, reason)

    def test_fallback_ssrf_failures_on_unresolvable_host(self):
        with patch.object(http_client, "net_guard", None), \
             patch.object(http_client.socket, "getaddrinfo",
                          side_effect=OSError("name or service not known")):
            valid, reason = http_client._is_url_allowed("http://no.such.host.invalid/", allow_local=False)
        self.assertFalse(valid)
        self.assertIn("Could not resolve", reason)

    def test_network_timeout_is_capped_at_the_contract_ceiling(self):
        # PROJECT.md: socket/network timeout is 10 seconds maximum.
        self.assertEqual(http_client.MAX_TIMEOUT, 10.0)
        self.assertEqual(http_client.TOOL["input_schema"]["properties"]["timeout"]["maximum"], 10)

        class FakeResponse:
            headers = {"Content-Type": "application/json"}
            def read(self, _n=None):
                return b'{"ok": true}'
            def close(self):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *exc):
                return False

        seen = {}
        def fake_urlopen(req, timeout=None):
            seen["timeout"] = timeout
            return FakeResponse()

        class FakeOpener:
            def open(self, req, timeout=None):
                return fake_urlopen(req, timeout=timeout)

        with patch.object(http_client, "net_guard", None), \
             patch.object(http_client.socket, "getaddrinfo",
                          return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]), \
             patch.object(http_client.urllib.request, "build_opener", return_value=FakeOpener()):
            res = http_client.http_client({"action": "fetch", "url": "http://public.example/api", "timeout": 999})
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["result"]["timeout_used"], 10.0)
        self.assertEqual(seen["timeout"], 10.0)


if __name__ == "__main__":
    unittest.main()
