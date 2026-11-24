"""Adversarial stress-test harness and empirical oracle verification for Jarvis operator modules."""

from __future__ import annotations

import http.server
import os
import threading
import time
import unittest
from unittest.mock import patch

import net_guard
import operator_modules.data_transform as data_transform
import operator_modules.env_inspector as env_inspector
import operator_modules.http_client as http_client


class _AdversarialServerHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress console noise

    def do_GET(self):
        if self.path == "/redirect-to-loopback":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:8080/secret")
            self.end_headers()
        elif self.path == "/redirect-to-aws-metadata":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
        elif self.path == "/redirect-to-file":
            self.send_response(302)
            self.send_header("Location", "file:///etc/passwd")
            self.end_headers()
        elif self.path == "/infinite-stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            try:
                chunk = b"X" * 65536
                for _ in range(100):
                    self.wfile.write(chunk)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
        elif self.path == "/slow-stall":
            time.sleep(2.0)
            try:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"too slow")
            except Exception:
                pass
        elif self.path == "/sensitive-headers-mixed-case":
            self.send_response(200)
            self.send_header("X-API-KEY", "secret-api-key-123")
            self.send_header("SET-COOKIE", "session=supersecret")
            self.send_header("AUTHORIZATION", "Bearer my-secret-token")
            self.send_header("X-Custom-Safe", "public-value")
            self.end_headers()
            self.wfile.write(b"headers test")
        else:
            self.send_response(404)
            self.end_headers()


class AdversarialModuleChallenges(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), _AdversarialServerHandler)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    # =========================================================================
    # 1. HTTP_CLIENT ADVERSARIAL CHALLENGES
    # =========================================================================

    def test_ssrf_ip_variations_blocked_without_allow_local(self):
        """Stress-test SSRF address classifier with various representations of loopback & private subnets."""
        suspicious_urls = [
            f"http://127.0.0.1:{self.port}/",
            f"http://127.0.0.2:{self.port}/",
            f"http://127.10.20.30:{self.port}/",
            f"http://localhost:{self.port}/",
            "http://0.0.0.0:80/",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/",
            "http://192.168.1.1/",
            "http://172.16.0.1/",
            "http://100.64.0.1/",  # Carrier-grade NAT
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[64:ff9b::127.0.0.1]/",
            # Alternate encodings
            "http://2130706433/",      # Decimal
            "http://0x7f000001/",      # Hex
            "http://0177.0.0.1/",      # Octal
            "http://127.1/",           # Short decimal
            # Credentials embedded in URL
            f"http://admin:pass@127.0.0.1:{self.port}/",
            # Unsupported schemes
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_",
            "ftp://example.com/file",
            "ldap://127.0.0.1:389/",
            "javascript:alert(1)",
        ]

        for target_url in suspicious_urls:
            res = http_client.http_client({"url": target_url, "allow_local": False})
            self.assertFalse(
                res["ok"],
                f"Security failure: URL {target_url!r} was NOT blocked! Result: {res}",
            )
            self.assertIsNotNone(res["error"])

    def test_ssrf_redirect_defense_intercepts_private_target(self):
        """Verify PinnedHTTPHandler blocks redirect when remote host redirects to loopback or metadata."""
        orig_public_ip = net_guard.public_ip

        def mock_public_ip(host):
            if host == "trusted-public-host.com":
                return "127.0.0.1"  # connect to test server
            return orig_public_ip(host)

        with patch("operator_modules.http_client._is_url_allowed", return_value=(True, "")), \
             patch("net_guard.public_ip", side_effect=mock_public_ip):

            # Test 1: Redirect to loopback 127.0.0.1:8080
            res1 = http_client.http_client({
                "url": f"http://trusted-public-host.com:{self.port}/redirect-to-loopback",
                "allow_local": False,
            })
            self.assertFalse(res1["ok"])
            self.assertIn("refusing non-public address", res1["error"])

            # Test 2: Redirect to AWS metadata 169.254.169.254
            res2 = http_client.http_client({
                "url": f"http://trusted-public-host.com:{self.port}/redirect-to-aws-metadata",
                "allow_local": False,
            })
            self.assertFalse(res2["ok"])
            self.assertIn("refusing non-public address", res2["error"])

            # Test 3: Redirect to file:///etc/passwd
            res3 = http_client.http_client({
                "url": f"http://trusted-public-host.com:{self.port}/redirect-to-file",
                "allow_local": False,
            })
            self.assertNotEqual(res3.get("data", {}).get("text"), "root:x:0:0:")

    def test_response_streaming_size_limit_enforced(self):
        """Verify that a response exceeding max_bytes is truncated and does not exceed memory limit."""
        res = http_client.http_client({
            "url": f"http://127.0.0.1:{self.port}/infinite-stream",
            "max_bytes": 2048,
            "allow_local": True,
        })
        self.assertTrue(res["ok"])
        data = res["data"]
        self.assertTrue(data["truncated"], "Expected response to be marked as truncated")
        self.assertEqual(data["bytes_read"], 2048)
        self.assertLessEqual(len(data["text"]), 2048)

    def test_max_bytes_boundary_clamping(self):
        """Verify max_bytes is strictly clamped between 1024 and 5MB."""
        res_low = http_client.http_client({
            "url": f"http://127.0.0.1:{self.port}/infinite-stream",
            "max_bytes": 50,  # Below min (1024)
            "allow_local": True,
        })
        self.assertTrue(res_low["ok"])
        self.assertEqual(res_low["data"]["bytes_read"], 1024)

    def test_timeout_bounds_and_cancellation(self):
        """Verify request timeout strictly aborts hung/slow connections."""
        t0 = time.monotonic()
        res = http_client.http_client({
            "url": f"http://127.0.0.1:{self.port}/slow-stall",
            "timeout": 1.0,
            "allow_local": True,
        })
        duration = time.monotonic() - t0
        self.assertFalse(res["ok"])
        self.assertIn("timed out", res["error"].lower())
        self.assertLess(duration, 1.8, f"Timeout took too long: {duration}s")

    def test_sensitive_header_redaction_rigor(self):
        """Verify case-insensitive header redaction for all sensitive auth/cookie tokens."""
        res = http_client.http_client({
            "url": f"http://127.0.0.1:{self.port}/sensitive-headers-mixed-case",
            "allow_local": True,
        })
        self.assertTrue(res["ok"])
        headers = {k.lower(): v for k, v in res["data"]["headers"].items()}
        self.assertEqual(headers.get("x-api-key"), "[REDACTED]")
        self.assertEqual(headers.get("set-cookie"), "[REDACTED]")
        self.assertEqual(headers.get("authorization"), "[REDACTED]")
        self.assertEqual(headers.get("x-custom-safe"), "public-value")

    def test_flaw_http_client_unhandled_crash_on_non_dict_headers(self):
        """Verify passing non-dict headers returns graceful error dict instead of AttributeError."""
        res = http_client.http_client({
            "url": f"http://127.0.0.1:{self.port}/json",
            "headers": ["Authorization: Bearer secret"],
            "allow_local": True,
        })
        self.assertFalse(res["ok"])
        self.assertIn("headers", res["error"].lower())

    # =========================================================================
    # 2. DATA_TRANSFORM ADVERSARIAL CHALLENGES
    # =========================================================================

    def test_data_transform_oversized_string_rejected(self):
        """Verify payload exceeding 5MB is rejected immediately."""
        big_payload = " " * (5 * 1024 * 1024 + 100)
        res = data_transform.data_transform({
            "action": "query",
            "data": big_payload,
            "from_format": "json",
        })
        self.assertFalse(res["ok"])
        self.assertIn("exceeds maximum allowed size", res["error"])

    def test_data_transform_malformed_inputs(self):
        """Test resilience against malformed JSON, NDJSON, CSV, and YAML."""
        res_json = data_transform.data_transform({
            "action": "query",
            "data": "{bad: json, unquoted}",
            "from_format": "json",
        })
        self.assertFalse(res_json["ok"])
        self.assertIn("Invalid JSON", res_json["error"])

        res_ndjson = data_transform.data_transform({
            "action": "convert",
            "data": '{"good": 1}\nNOT_VALID_JSON_AT_ALL\n{"good": 2}',
            "from_format": "ndjson",
            "to_format": "json",
        })
        self.assertFalse(res_ndjson["ok"])
        self.assertIn("Invalid NDJSON", res_ndjson["error"])

    def test_data_transform_path_query_edge_cases(self):
        """Test complex and adversarial dot-bracket syntax paths."""
        data = {
            "a": {
                "b": [
                    {"name": "first", "vals": [10, 20, 30]},
                    {"name": "second", "vals": []},
                ],
                "": "empty_key_val",
            },
            "null_field": None,
        }

        r1 = data_transform.data_transform({"action": "query", "data": data, "path": "null_field.subfield"})
        self.assertTrue(r1["ok"])
        self.assertIsNone(r1["data"]["result"])
        self.assertFalse(r1["data"]["found"])

        r2 = data_transform.data_transform({"action": "query", "data": data, "path": "a.b[99].name"})
        self.assertTrue(r2["ok"])
        self.assertIsNone(r2["data"]["result"])
        self.assertFalse(r2["data"]["found"])

        r3 = data_transform.data_transform({"action": "query", "data": data, "path": "a.b[invalid].name"})
        self.assertTrue(r3["ok"])
        self.assertIsNone(r3["data"]["result"])

        r4 = data_transform.data_transform({"action": "query", "data": data, "path": "x.y.z.w.v.u.t.s.r.q.p"})
        self.assertTrue(r4["ok"])
        self.assertIsNone(r4["data"]["result"])

    def test_schema_validation_type_strictness(self):
        """Verify schema validation enforces strict type boundaries (e.g. bool is not integer)."""
        schema = {
            "type": "object",
            "properties": {
                "count": {"type": "integer"},
                "rate": {"type": "number"},
                "active": {"type": "boolean"},
            },
            "required": ["count", "active"],
        }

        bad_payload = {"count": True, "rate": 1.5, "active": "not_a_bool"}
        res = data_transform.data_transform({
            "action": "validate",
            "data": bad_payload,
            "schema": schema,
        })
        self.assertTrue(res["ok"])
        self.assertFalse(res["data"]["valid"])
        self.assertGreaterEqual(res["data"]["error_count"], 2)

    def test_flaw_data_transform_unhandled_crash_on_circular_data(self):
        """Verify circular references return graceful transformation error instead of ValueError."""
        d: dict = {"a": 1}
        d["self"] = d
        res = data_transform.data_transform({"action": "convert", "data": d, "to_format": "json"})
        self.assertFalse(res["ok"])
        self.assertIn("Transformation error", res["error"])

    def test_flaw_data_transform_unhandled_crash_on_non_serializable_set(self):
        """Verify non-serializable sets return graceful transformation error instead of TypeError."""
        res = data_transform.data_transform({"action": "convert", "data": {"items": {1, 2, 3}}, "to_format": "json"})
        self.assertFalse(res["ok"])
        self.assertIn("Transformation error", res["error"])

    def test_flaw_data_transform_unhandled_crash_on_mixed_csv_rows(self):
        """Verify non-dict rows return graceful error instead of AttributeError in csv conversion."""
        res = data_transform.data_transform({"action": "convert", "data": [{"id": 1}, "invalid_string_row"], "to_format": "csv"})
        self.assertFalse(res["ok"])
        self.assertIn("objects/dicts", res["error"])

    def test_flaw_data_transform_unhandled_crash_on_deep_recursion(self):
        """Verify deep schema nesting returns valid=False without crashing with RecursionError."""
        nested: dict = {}
        curr = nested
        curr_schema: dict = {"type": "object", "properties": {}}
        schema = curr_schema
        for _ in range(1500):
            curr["a"] = {}
            curr = curr["a"]
            curr_schema["properties"]["a"] = {"type": "object", "properties": {}}
            curr_schema = curr_schema["properties"]["a"]

        res = data_transform.data_transform({"action": "validate", "data": nested, "schema": schema})
        self.assertTrue(res["ok"])
        self.assertFalse(res["data"]["valid"])

    # =========================================================================
    # 3. ENV_INSPECTOR ADVERSARIAL CHALLENGES
    # =========================================================================

    def test_env_inspector_standard_secrets_scrubbed(self):
        """Verify that standard patterns of API keys, tokens, and private keys are redacted."""
        secrets_env = {
            "OPENAI_KEY": "sk-000000000000000000000000000000",
            "ANTHROPIC_KEY": "sk-000000000000000000000000000000",
            "OPENROUTER_KEY": "sk-000000000000000000000000000000",
            "GH_TOKEN": "ghp_000000000000000000000000000000000000",
            "GITHUB_PAT": "gho_000000000000000000000000000000000000",
            "AWS_ACCESS_KEY_ID": "AKIAAAAAAAAAAAAAAAAA",
            "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "AUTH_HEADER": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M",
            "RSA_PRIV_KEY": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...",
            "OPENSSH_KEY": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC...",
            "APP_SECRET": "c1f7a2d8e4b506192837465019283746",
            "API_SECRET_KEY": "random_secret_string",
            "APP_NAME": "Jarvis",
            "ENV_MODE": "production",
            "PORT": "8080",
        }

        with patch.dict(os.environ, secrets_env, clear=True):
            res = env_inspector.env_inspector({"action": "env"})
            self.assertTrue(res["ok"])
            variables = res["data"]["variables"]

            for secret_key in [
                "OPENAI_KEY", "ANTHROPIC_KEY", "OPENROUTER_KEY", "GH_TOKEN",
                "GITHUB_PAT", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                "AUTH_HEADER", "RSA_PRIV_KEY", "OPENSSH_KEY", "APP_SECRET", "API_SECRET_KEY"
            ]:
                self.assertEqual(variables.get(secret_key), "[REDACTED]")

            self.assertEqual(variables.get("APP_NAME"), "Jarvis")
            self.assertEqual(variables.get("ENV_MODE"), "production")
            self.assertEqual(variables.get("PORT"), "8080")

    def test_flaw_env_inspector_secret_leakage_on_pass_and_db_url(self):
        """Verify env_inspector properly scrubs DB_PASS, MYSQL_PWD, DATABASE_URL, REDIS_URL, and Stripe keys."""
        test_env = {
            "DB_PASS": "my_secret_pass",
            "MYSQL_PWD": "my_mysql_pass",
            "DATABASE_URL": "postgres://user:supersecretpass@localhost:5432/mydb",
            "REDIS_URL": "redis://:mypassword@localhost:6379/0",
            "PAYMENT_GATEWAY": "sk_live_xxxx-xxxx-xxxx-xxxx",
        }

        with patch.dict(os.environ, test_env, clear=True):
            res = env_inspector.env_inspector({"action": "env"})
            variables = res["data"]["variables"]

            self.assertEqual(variables.get("DB_PASS"), "[REDACTED]")
            self.assertEqual(variables.get("MYSQL_PWD"), "[REDACTED]")
            self.assertEqual(variables.get("DATABASE_URL"), "[REDACTED]")
            self.assertEqual(variables.get("REDIS_URL"), "[REDACTED]")
            self.assertEqual(variables.get("PAYMENT_GATEWAY"), "[REDACTED]")

    def test_env_inspector_port_probe_host_restrictions(self):
        """Verify strict restriction against scanning remote hosts or injection."""
        forbidden_hosts = [
            "8.8.8.8",
            "1.1.1.1",
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "google.com",
            "127.0.0.1; ls",
            "127.0.0.2",
            "0.0.0.0",
        ]

        for host in forbidden_hosts:
            res = env_inspector.env_inspector({
                "action": "check_port",
                "port": 80,
                "host": host,
            })
            self.assertFalse(res["ok"])
            self.assertIn("Refusing", res["error"])

    def test_env_inspector_port_bounds(self):
        """Verify port boundary checks (-1, 0, 65536, 70000)."""
        invalid_ports = [-1, 0, 65536, 70000, "invalid_port", None]
        for p in invalid_ports:
            res = env_inspector.env_inspector({"action": "check_port", "port": p})
            self.assertFalse(res["ok"])

    def test_env_inspector_tools_path_traversal(self):
        """Verify directory traversal in tool names is rejected."""
        traversal_attempts = ["/bin/sh", "../../usr/bin/python", "dir\\tool", "../sh"]
        res = env_inspector.env_inspector({"action": "check_tools", "names": traversal_attempts})
        self.assertTrue(res["ok"])
        for tool in traversal_attempts:
            self.assertFalse(res["data"]["tools"][tool]["installed"])
            self.assertIn("Invalid", res["data"]["tools"][tool].get("error", ""))


if __name__ == "__main__":
    unittest.main()
