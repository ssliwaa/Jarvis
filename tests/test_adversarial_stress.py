"""Adversarial challenge and stress test suite for new operator modules.

Probes:
1. Concurrency and re-entrancy under high thread load.
2. Boundary input fuzzing (non-dict inputs, unhashable keys, malformed schemas).
3. Fallback integrity when optional dependencies (net_guard, pyyaml) are missing.
4. Error isolation to ensure no unhandled exceptions crash the service.
"""

from __future__ import annotations

import concurrent.futures
import http.server
import threading
import unittest
from unittest.mock import patch

import operator_modules.data_transform as data_transform
import operator_modules.env_inspector as env_inspector
import operator_modules.http_client as http_client


class _MockStressServer(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress logging

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "ok", "message": "concurrency test"}')


class TestAdversarialStress(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), _MockStressServer)
        cls.port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    # =========================================================================
    # 1. Concurrency & Re-Entrancy Stress Tests
    # =========================================================================

    def test_concurrent_multi_module_execution(self):
        """Stress-test concurrent invocations of all 3 modules simultaneously."""
        errors: list[str] = []

        def worker_http(idx: int):
            try:
                res = http_client.http_client({
                    "url": f"http://127.0.0.1:{self.port}",
                    "allow_local": True,
                    "params": {"idx": idx},
                })
                if not res.get("ok"):
                    errors.append(f"HTTP worker {idx} failed: {res.get('error')}")
            except Exception as exc:
                errors.append(f"HTTP worker {idx} crashed: {type(exc).__name__}: {exc}")

        def worker_data(idx: int):
            try:
                dataset = [{"id": i, "name": f"item_{i}", "val": i * 10} for i in range(20)]
                res = data_transform.data_transform({
                    "action": "filter",
                    "data": dataset,
                    "filter_expr": {"field": "id", "op": "==", "value": idx % 20},
                })
                if not res.get("ok") or len(res["data"]["results"]) != 1:
                    errors.append(f"Data worker {idx} unexpected result: {res}")
            except Exception as exc:
                errors.append(f"Data worker {idx} crashed: {type(exc).__name__}: {exc}")

        def worker_env(idx: int):
            try:
                res = env_inspector.env_inspector({"action": "system_info"})
                if not res.get("ok") or "system" not in res.get("data", {}):
                    errors.append(f"Env worker {idx} unexpected result: {res}")
            except Exception as exc:
                errors.append(f"Env worker {idx} crashed: {type(exc).__name__}: {exc}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
            futures = []
            for i in range(50):
                futures.append(pool.submit(worker_http, i))
                futures.append(pool.submit(worker_data, i))
                futures.append(pool.submit(worker_env, i))
            concurrent.futures.wait(futures)

        self.assertEqual(len(errors), 0, f"Concurrent workers encountered errors: {errors}")

    # =========================================================================
    # 2. http_client Adversarial Boundaries & Fallback Security
    # =========================================================================

    def test_http_client_malformed_headers_crash(self):
        """Verify: passing non-dict headers returns graceful error dict without crashing."""
        malformed_headers = [
            "Authorization: Bearer token",
            ["Authorization", "Bearer token"],
            12345,
            True,
        ]
        for mh in malformed_headers:
            res = http_client.http_client({
                "url": f"http://127.0.0.1:{self.port}",
                "allow_local": True,
                "headers": mh,
            })
            self.assertFalse(res["ok"])
            self.assertIn("headers", res["error"].lower())

    def test_http_client_fallback_ssrf_omits_172_subnet(self):
        """Verify: when net_guard is None, fallback SSRF check successfully blocks 172.16.0.0/12."""
        with patch.object(http_client, "net_guard", None):
            # 10.0.0.1 and 192.168.1.1 are correctly blocked
            valid_10, _ = http_client._is_url_allowed("http://10.0.0.1:80", allow_local=False)
            valid_192, _ = http_client._is_url_allowed("http://192.168.1.1:80", allow_local=False)
            self.assertFalse(valid_10)
            self.assertFalse(valid_192)

            # 172.16.0.1 and 172.31.255.255 are now correctly blocked
            valid_172_start, reason_start = http_client._is_url_allowed("http://172.16.0.1:80", allow_local=False)
            valid_172_end, reason_end = http_client._is_url_allowed("http://172.31.255.255:80", allow_local=False)
            self.assertFalse(valid_172_start)
            self.assertFalse(valid_172_end)
            self.assertIn("private subnet", reason_start)

    # =========================================================================
    # 3. data_transform Adversarial Boundaries & Serialization Crashes
    # =========================================================================

    def test_data_transform_csv_heterogeneous_crash(self):
        """Verify: CSV conversion returns graceful error on heterogeneous lists without crashing."""
        heterogeneous_data = [
            [{"name": "alice"}, 12345],
            [{"name": "alice"}, None],
            [{"name": "alice"}, "string_row"],
            [{"name": "alice"}, ["sub", "list"]],
        ]
        for d in heterogeneous_data:
            res = data_transform.data_transform({
                "action": "convert",
                "data": d,
                "to_format": "csv",
            })
            self.assertFalse(res["ok"])
            self.assertIn("objects/dicts", res["error"])

    def test_data_transform_non_serializable_conversion_crash(self):
        """Verify: converting non-JSON serializable data returns graceful error without crashing."""
        non_serializable_data = [
            {"tags": {1, 2, 3}},  # set is not JSON serializable
            b"raw_binary_bytes",   # bytes is not JSON serializable
        ]
        for d in non_serializable_data:
            res = data_transform.data_transform({
                "action": "convert",
                "data": d,
                "to_format": "json",
            })
            self.assertFalse(res["ok"])
            self.assertIn("Transformation error", res["error"])

    def test_data_transform_filter_unhashable_field_crash(self):
        """Verify: unhashable field in filter_expr handles gracefully without crashing."""
        unhashable_fields = [
            ["unhashable_list"],
            {"unhashable": "dict"},
        ]
        for field in unhashable_fields:
            res = data_transform.data_transform({
                "action": "filter",
                "data": [{"name": "alice"}],
                "filter_expr": {"field": field, "op": "==", "value": "alice"},
            })
            self.assertTrue(res["ok"])
            self.assertEqual(len(res["data"]["results"]), 0)

    def test_data_transform_validate_malformed_schema_crash(self):
        """Verify: malformed properties/required in schema return valid=False without crashing."""
        malformed_schemas = [
            {"type": "object", "properties": "not_a_dict"},
            {"type": "object", "required": 12345},
        ]
        for s in malformed_schemas:
            res = data_transform.data_transform({
                "action": "validate",
                "data": {"foo": "bar"},
                "schema": s,
            })
            self.assertTrue(res["ok"])
            self.assertFalse(res["data"]["valid"])

    def test_data_transform_yaml_missing_graceful_fallback(self):
        """Verify: data_transform returns graceful error when pyyaml is missing."""
        with patch.object(data_transform, "yaml", None):
            res_query = data_transform.data_transform({
                "action": "query",
                "data": "key: value",
                "from_format": "yaml",
            })
            self.assertFalse(res_query["ok"])
            self.assertIn("pyyaml", res_query["error"])

            res_convert = data_transform.data_transform({
                "action": "convert",
                "data": {"key": "value"},
                "to_format": "yaml",
            })
            self.assertFalse(res_convert["ok"])
            self.assertIn("pyyaml", res_convert["error"])

    # =========================================================================
    # 4. env_inspector Adversarial Boundaries & Secret Masking
    # =========================================================================

    def test_env_inspector_unhashable_names_crash(self):
        """Verify: unhashable items in names argument handle gracefully without crashing."""
        unhashable_names = [
            [{"token": "val"}],
            [["sublist"]],
        ]
        for un in unhashable_names:
            res = env_inspector.env_inspector({"action": "env", "names": un})
            self.assertTrue(res["ok"])
            self.assertEqual(res["data"]["total_count"], 0)

    def test_env_inspector_connection_uri_password_leak_blindspot(self):
        """Verify: standard database connection URIs are properly classified as sensitive."""
        is_sensitive = env_inspector._is_sensitive_env(
            "DATABASE_URL",
            "postgres://user:supersecretpassword@db.example.com:5432/app",
        )
        self.assertTrue(is_sensitive, "Database URI containing credentials must be classified as sensitive.")


if __name__ == "__main__":
    unittest.main()
