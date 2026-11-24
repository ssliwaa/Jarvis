"""Automated test suite for operator_modules/op_net_probe.py (Milestone M1).

Tests tool contract, 5-key return envelope, all actions (tcp_ping, dns_lookup, cert_inspect,
http_head), parameter boundaries, SSRF guardrails, and error handling.
100% offline-reliable using ephemeral local sockets, daemon HTTP server, and mocks.
"""

from __future__ import annotations

import http.server
import socket
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

import operator_modules.op_net_probe as op_net_probe


class _MockHTTPHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress stderr logging during test runs

    def do_HEAD(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("X-Jarvis-Probe", "ok")
            self.send_header("Set-Cookie", "session_secret=sensitive_123")
            self.send_header("Authorization", "Bearer token_abc")
            self.end_headers()
        elif self.path == "/not-found":
            self.send_response(404)
            self.end_headers()
        else:
            self.send_response(500)
            self.end_headers()


class TestOpNetProbe(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Ephemeral local HTTP server for HTTP HEAD tests
        cls.http_server = http.server.HTTPServer(("127.0.0.1", 0), _MockHTTPHandler)
        cls.http_port = cls.http_server.server_port
        cls.http_thread = threading.Thread(target=cls.http_server.serve_forever, daemon=True)
        cls.http_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.http_server.shutdown()
        cls.http_server.server_close()

    def _assert_envelope(self, res: dict, expected_ok: bool):
        """Assert the standard 5-key Jarvis operator envelope structure."""
        self.assertIsInstance(res, dict)
        self.assertIn("ok", res)
        self.assertIn("success", res)
        self.assertIn("data", res)
        self.assertIn("result", res)
        self.assertIn("error", res)
        self.assertEqual(res["ok"], expected_ok)
        self.assertEqual(res["success"], expected_ok)
        if expected_ok:
            self.assertIsNone(res["error"])
            self.assertEqual(res["data"], res["result"])
        else:
            self.assertIsNone(res["data"])
            self.assertIsNone(res["result"])
            self.assertIsInstance(res["error"], str)
            self.assertGreater(len(res["error"]), 0)

    # --- Contract Tests ---
    def test_01_tool_declaration_contract(self):
        tool = op_net_probe.TOOL
        self.assertEqual(tool["name"], "net_probe")
        self.assertFalse(tool["approval"], "net_probe must be read-only (approval: False)")
        self.assertTrue(callable(tool["handler"]))
        self.assertEqual(tool["input_schema"]["type"], "object")
        self.assertFalse(tool["input_schema"]["additionalProperties"])
        self.assertIn("action", tool["input_schema"]["required"])
        self.assertIn("host", tool["input_schema"]["required"])

    def test_02_schema_properties(self):
        props = op_net_probe.TOOL["input_schema"]["properties"]
        self.assertEqual(props["action"]["enum"], ["tcp_ping", "dns_lookup", "cert_inspect", "http_head"])
        self.assertIn("host", props)
        self.assertIn("port", props)
        self.assertIn("timeout", props)
        self.assertIn("timeout_seconds", props)
        self.assertIn("count", props)
        self.assertIn("allow_private", props)

    # --- Tier 1: Happy Path ---
    def test_03_tcp_ping_local_open_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            port = s.getsockname()[1]

            res = op_net_probe.net_probe({
                "action": "tcp_ping",
                "host": "127.0.0.1",
                "port": port,
                "count": 2,
                "allow_private": True,
            })
            self._assert_envelope(res, expected_ok=True)
            data = res["data"]
            self.assertTrue(data["reachable"])
            self.assertTrue(data["connected"])
            self.assertEqual(data["port"], port)
            self.assertEqual(data["packets_transmitted"], 2)
            self.assertEqual(data["packets_received"], 2)
            self.assertEqual(data["packet_loss_pct"], 0.0)
            self.assertGreaterEqual(data["latency_ms_avg"], 0.0)
            self.assertGreaterEqual(data["latency_ms"], 0.0)
            self.assertEqual(len(data["probes"]), 2)

    def test_04_tcp_ping_multi_count(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            s.listen(10)
            port = s.getsockname()[1]

            res = op_net_probe.net_probe({
                "action": "tcp_ping",
                "host": "127.0.0.1",
                "port": port,
                "count": 3,
                "timeout": 1.0,
                "allow_private": True,
            })
            self._assert_envelope(res, expected_ok=True)
            data = res["data"]
            self.assertEqual(data["count"], 3)
            self.assertEqual(len(data["probes"]), 3)
            self.assertEqual(data["loss_rate"], 0.0)
            self.assertTrue(data["min_latency_ms"] <= data["avg_latency_ms"] <= data["max_latency_ms"])

    def test_05_dns_lookup_localhost(self):
        res = op_net_probe.net_probe({
            "action": "dns_lookup",
            "host": "localhost",
            "allow_private": True,
        })
        self._assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertIn("127.0.0.1", data.get("addresses", []) or data.get("ipv4", []))
        self.assertIn("canonical_name", data)
        self.assertGreaterEqual(data["latency_ms"], 0.0)

    def test_06_dns_lookup_ptr(self):
        res = op_net_probe.net_probe({
            "action": "dns_lookup",
            "host": "127.0.0.1",
            "query_type": "PTR",
            "allow_private": True,
        })
        self._assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertEqual(data["query_type"], "PTR")
        self.assertIn("canonical_name", data)
        self.assertIsInstance(data["aliases"], list)

    def test_07_dns_lookup_mocked_records(self):
        mock_infos = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 0, 0, 0)),
        ]
        mock_cname_infos = [
            (socket.AF_UNSPEC, socket.SOCK_STREAM, 6, "example.com", ("93.184.216.34", 0)),
        ]

        def fake_getaddrinfo(host, port, *args, **kwargs):
            flags = kwargs.get("flags", 0)
            if flags == socket.AI_CANONNAME:
                return mock_cname_infos
            family = kwargs.get("family", socket.AF_UNSPEC)
            if family == socket.AF_INET:
                return [mock_infos[0]]
            if family == socket.AF_INET6:
                return [mock_infos[1]]
            return mock_infos

        with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo), \
             patch("socket.gethostbyname_ex", return_value=("example.com", ["alias.example.com"], ["93.184.216.34"])):
            res = op_net_probe.net_probe({
                "action": "dns_lookup",
                "host": "example.com",
                "allow_private": False,
            })
            self._assert_envelope(res, expected_ok=True)
            data = res["data"]
            self.assertEqual(data["canonical_name"], "example.com")
            self.assertIn("93.184.216.34", data["ipv4"])
            self.assertIn("2606:2800:220:1:248:1893:25c8:1946", data["ipv6"])
            self.assertIn("alias.example.com", data["aliases"])

    def test_08_http_head_local_server(self):
        res = op_net_probe.net_probe({
            "action": "http_head",
            "host": "127.0.0.1",
            "port": self.http_port,
            "path": "/",
            "allow_private": True,
        })
        self._assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertEqual(data["status_code"], 200)
        self.assertEqual(data["status_text"], "OK")
        self.assertEqual(data["reason"], "OK")
        self.assertTrue(data["http_version"].startswith("HTTP/"))
        self.assertEqual(data["headers"].get("X-Jarvis-Probe"), "ok")
        self.assertGreater(data["bytes_read"], 0)
        self.assertGreaterEqual(data["latency_ms"], 0.0)

    def test_09_http_head_redact_sensitive_headers(self):
        res = op_net_probe.net_probe({
            "action": "http_head",
            "host": "127.0.0.1",
            "port": self.http_port,
            "path": "/",
            "allow_private": True,
        })
        self._assert_envelope(res, expected_ok=True)
        headers = res["data"]["headers"]
        self.assertEqual(headers.get("Set-Cookie"), "[REDACTED]")
        self.assertEqual(headers.get("Authorization"), "[REDACTED]")

    def test_10_http_head_404_status(self):
        res = op_net_probe.net_probe({
            "action": "http_head",
            "host": "127.0.0.1",
            "port": self.http_port,
            "path": "/not-found",
            "allow_private": True,
        })
        self._assert_envelope(res, expected_ok=True)
        self.assertEqual(res["data"]["status_code"], 404)

    def test_11_cert_inspect_mocked_ssl(self):
        mock_cert = {
            "subject": ((("commonName", "test.jarvis.internal"),),),
            "issuer": ((("organizationName", "Jarvis CA"),),),
            "notBefore": "Jan 1 00:00:00 2026 GMT",
            "notAfter": "Jan 1 00:00:00 2027 GMT",
            "subjectAltName": (("DNS", "test.jarvis.internal"), ("DNS", "api.jarvis.internal")),
            "serialNumber": "0123456789ABCDEF",
        }
        mock_sslsock = MagicMock()
        mock_sslsock.getpeercert.return_value = mock_cert
        mock_sslsock.cipher.return_value = ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)
        mock_sslsock.version.return_value = "TLSv1.3"

        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = mock_sslsock

        mock_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with patch("ssl.create_default_context", return_value=mock_context), \
             patch("socket.getaddrinfo", return_value=mock_addrinfo), \
             patch("socket.create_connection", return_value=MagicMock()):
            res = op_net_probe.net_probe({
                "action": "cert_inspect",
                "host": "test.jarvis.internal",
                "port": 443,
                "allow_private": True,
            })
            self._assert_envelope(res, expected_ok=True)
            data = res["data"]
            self.assertEqual(data["tls_version"], "TLSv1.3")
            self.assertEqual(data["subject"].get("commonName"), "test.jarvis.internal")
            self.assertEqual(data["issuer"].get("organizationName"), "Jarvis CA")
            self.assertGreater(data["days_remaining"], 0)
            self.assertFalse(data["expired"])
            self.assertIn("test.jarvis.internal", data["subject_alt_names"])
            self.assertEqual(data["serial_number"], "0123456789ABCDEF")

    # --- Tier 2: Boundary & Error Cases ---
    def test_12_tcp_ping_connection_refused_reports_unreachable(self):
        # Guarantee closed port by binding and immediately closing socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        res = op_net_probe.net_probe({
            "action": "tcp_ping",
            "host": "127.0.0.1",
            "port": port,
            "count": 1,
            "allow_private": True,
        })
        self._assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertFalse(data["reachable"])
        self.assertFalse(data["connected"])
        self.assertEqual(data["packet_loss_pct"], 100.0)
        self.assertEqual(data["packets_transmitted"], 1)
        self.assertEqual(data["packets_received"], 0)
        self.assertIsNone(data["latency_ms"])

    def test_13_tcp_ping_timeout_reports_unreachable(self):
        with patch("socket.socket.connect", side_effect=socket.timeout("timed out")):
            res = op_net_probe.net_probe({
                "action": "tcp_ping",
                "host": "127.0.0.1",
                "port": 80,
                "timeout_seconds": 1.0,
                "count": 1,
                "allow_private": True,
            })
            self._assert_envelope(res, expected_ok=True)
            self.assertFalse(res["data"]["reachable"])
            self.assertEqual(res["data"]["packet_loss_pct"], 100.0)

    def test_14_tcp_ping_missing_port(self):
        res = op_net_probe.net_probe({
            "action": "tcp_ping",
            "host": "127.0.0.1",
            "allow_private": True,
        })
        self._assert_envelope(res, expected_ok=False)
        self.assertIn("port", res["error"].lower())

    def test_15_dns_lookup_nxdomain(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror(socket.EAI_NONAME, "Name or service not known")):
            res = op_net_probe.net_probe({
                "action": "dns_lookup",
                "host": "nonexistent.domain.invalid",
                "allow_private": True,
            })
            self._assert_envelope(res, expected_ok=False)
            self.assertIn("gaierror", res["error"])

    def test_16_dns_lookup_invalid_ptr(self):
        res = op_net_probe.net_probe({
            "action": "dns_lookup",
            "host": "not-an-ip-address",
            "query_type": "PTR",
            "allow_private": True,
        })
        self._assert_envelope(res, expected_ok=False)
        self.assertIn("valid IPv4 or IPv6", res["error"])

    def test_17_ssrf_default_rejection_of_private_ip(self):
        for private_target in ["127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254"]:
            res = op_net_probe.net_probe({
                "action": "tcp_ping",
                "host": private_target,
                "port": 80,
                # allow_private omitted -> False
            })
            self._assert_envelope(res, expected_ok=False)
            self.assertIn("SSRF", res["error"])

    def test_18_cert_inspect_non_tls_port(self):
        # Plain HTTP server returns invalid SSL header
        res = op_net_probe.net_probe({
            "action": "cert_inspect",
            "host": "127.0.0.1",
            "port": self.http_port,
            "allow_private": True,
        })
        self._assert_envelope(res, expected_ok=False)
        self.assertTrue("SSLError" in res["error"] or "error" in res["error"].lower())

    def test_19_http_head_connection_failure(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            closed_port = s.getsockname()[1]

        res = op_net_probe.net_probe({
            "action": "http_head",
            "host": "127.0.0.1",
            "port": closed_port,
            "allow_private": True,
        })
        self._assert_envelope(res, expected_ok=False)
        self.assertIn("ConnectionRefusedError", res["error"])

    def test_20_http_head_header_overflow(self):
        mock_sock = MagicMock()
        # Returns chunks without delimiter exceeding 64 KB
        mock_sock.recv.return_value = b"X-Overflow: " + (b"A" * 4096) + b"\r\n"

        with patch("socket.create_connection", return_value=mock_sock):
            res = op_net_probe.net_probe({
                "action": "http_head",
                "host": "127.0.0.1",
                "port": 80,
                "allow_private": True,
            })
            self._assert_envelope(res, expected_ok=False)
            self.assertIn("exceeded", res["error"].lower())

    def test_21_invalid_action(self):
        res = op_net_probe.net_probe({"action": "unknown_probe_action", "host": "127.0.0.1"})
        self._assert_envelope(res, expected_ok=False)
        self.assertIn("Unsupported", res["error"])

    def test_22_additional_properties_rejected(self):
        res = op_net_probe.net_probe({
            "action": "dns_lookup",
            "host": "127.0.0.1",
            "malicious_extra": 123,
            "allow_private": True,
        })
        self._assert_envelope(res, expected_ok=False)
        self.assertIn("Unexpected argument", res["error"])

    def test_23_port_boundary_validation(self):
        for invalid_port in [0, -1, 65536, 70000, True]:
            res = op_net_probe.net_probe({
                "action": "tcp_ping",
                "host": "127.0.0.1",
                "port": invalid_port,
                "allow_private": True,
            })
            self._assert_envelope(res, expected_ok=False)
            self.assertIn("port", res["error"].lower())

    def test_24_timeout_boundary_validation(self):
        for invalid_timeout in [0.0, -1.0, 15.0, True, "five"]:
            res = op_net_probe.net_probe({
                "action": "tcp_ping",
                "host": "127.0.0.1",
                "port": 80,
                "timeout": invalid_timeout,
                "allow_private": True,
            })
            self._assert_envelope(res, expected_ok=False)
            self.assertIn("timeout", res["error"].lower())

    def test_25_count_boundary_validation(self):
        for invalid_count in [0, -1, 15, True, "three"]:
            res = op_net_probe.net_probe({
                "action": "tcp_ping",
                "host": "127.0.0.1",
                "port": 80,
                "count": invalid_count,
                "allow_private": True,
            })
            self._assert_envelope(res, expected_ok=False)
            self.assertIn("count", res["error"].lower())

    def test_26_invalid_host_format(self):
        for invalid_host in ["", "   ", None, 12345]:
            res = op_net_probe.net_probe({
                "action": "tcp_ping",
                "host": invalid_host,
                "port": 80,
                "allow_private": True,
            })
            self._assert_envelope(res, expected_ok=False)
            self.assertIn("host", res["error"].lower())

    def test_27_url_formatted_host(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            port = s.getsockname()[1]

            res = op_net_probe.net_probe({
                "action": "tcp_ping",
                "host": f"http://127.0.0.1:{port}/path?query=1",
                "port": port,
                "allow_private": True,
            })
            self._assert_envelope(res, expected_ok=True)
            self.assertTrue(res["data"]["connected"])

    def test_28_http_head_crlf_injection_rejection(self):
        """Verify strict rejection of CRLF characters in http_head path."""
        crlf_payloads = [
            "/test\r\nInjected-Header: evil\r\n\r\nGET /secret HTTP/1.1",
            "/index.html\r\nEvil: True",
            "/test\nHeader: evil",
            "/test\rHeader: evil",
            "/test\x00malicious",
        ]
        for bad_path in crlf_payloads:
            res = op_net_probe.net_probe({
                "action": "http_head",
                "host": "127.0.0.1",
                "port": self.http_port,
                "path": bad_path,
                "allow_private": True,
            })
            self._assert_envelope(res, expected_ok=False)
            self.assertIn("ValueError", res["error"])
            self.assertTrue(
                "CR" in res["error"] or "LF" in res["error"] or "control" in res["error"].lower(),
                f"Expected CRLF error message, got: {res['error']}"
            )

    def test_29_http_head_slowloris_wallclock_timeout(self):
        """Verify strict wall-clock deadline enforcement during slow-trickle read loop."""
        slow_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        slow_srv.bind(("127.0.0.1", 0))
        slow_srv.listen(1)
        slow_port = slow_srv.getsockname()[1]

        def _drip():
            conn = None
            try:
                conn, _ = slow_srv.accept()
                conn.recv(1024)
                # Trickle bytes every 50ms (total 0.5s duration) without closing or delimiter
                for _ in range(10):
                    conn.sendall(b"X")
                    time.sleep(0.05)
            except Exception:
                pass
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
                try:
                    slow_srv.close()
                except Exception:
                    pass

        srv_thread = threading.Thread(target=_drip, daemon=True)
        srv_thread.start()

        # Call with tight timeout of 0.1s
        t0 = time.monotonic()
        res = op_net_probe.net_probe({
            "action": "http_head",
            "host": "127.0.0.1",
            "port": slow_port,
            "timeout": 0.1,
            "allow_private": True,
        })
        elapsed = time.monotonic() - t0
        srv_thread.join(timeout=1.0)

        self._assert_envelope(res, expected_ok=False)
        self.assertIn("TimeoutError", res["error"])
        self.assertLess(elapsed, 0.35, f"Execution hung for {elapsed:.2f}s instead of respecting 0.1s deadline!")

    def test_30_http_head_idn_and_unicode_path(self):
        """Verify IDN host punycode encoding and Unicode path URL quoting."""
        # 1. Non-ASCII Unicode path against local HTTP server
        res = op_net_probe.net_probe({
            "action": "http_head",
            "host": "127.0.0.1",
            "port": self.http_port,
            "path": "/über-uns?query=café#anchor",
            "allow_private": True,
        })
        self._assert_envelope(res, expected_ok=True)
        self.assertEqual(res["data"]["status_code"], 500)  # Mock handler returns 500 for non-root paths

        # 2. IDN internationalized domain name handling (münchen.de)
        captured_requests = []
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        def _capture_send(data):
            captured_requests.append(data)
        mock_sock.sendall.side_effect = _capture_send

        with patch("socket.create_connection", return_value=mock_sock):
            with patch("operator_modules.op_net_probe._resolve_target_ip", return_value=("127.0.0.1", socket.AF_INET, 80)):
                res_idn = op_net_probe.net_probe({
                    "action": "http_head",
                    "host": "münchen.de",
                    "path": "/kontakt/über-uns",
                    "allow_private": True,
                })
                self._assert_envelope(res_idn, expected_ok=True)
                self.assertGreater(len(captured_requests), 0)
                sent_bytes = captured_requests[0]
                self.assertIn(b"Host: xn--mnchen-3ya.de\r\n", sent_bytes)
                self.assertIn(b"HEAD /kontakt/%C3%BCber-uns HTTP/1.1\r\n", sent_bytes)


if __name__ == "__main__":
    unittest.main()
