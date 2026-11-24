"""Automated test suite for operator_modules/op_local_llm_probe.py.

Tests the dispatch contract, the loopback host guardrail (SSRF perimeter:
_validate_host enforced centrally in the dispatcher for every action),
timeout clamping, per-engine probes (ollama tags/ps/version, llama-server
health/props/slots, localai v1/models) against controllable fake HTTP
responses, endpoint batch probing (malformed URLs, non-loopback rejection,
status<500 reachability, engine detection), aggregate probe_all /
check_readiness verdicts, and TCP benchmark pings with patched sockets.
100% offline: module-level _http_get_json/_tcp_ping are replaced with
in-test fakes; no real network calls are ever made.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

import operator_modules.op_local_llm_probe as lp

OLLAMA_TAGS_URL = "http://127.0.0.1:11434/api/tags"


def _ok_routes():
    """Fake HTTP route table for a fully reachable local stack."""
    return {
        OLLAMA_TAGS_URL: ({
            "models": [
                {"name": "llama3", "size": 4_000_000,
                 "modified_at": "2026-01-01",
                 "details": {"format": "gguf", "family": "llama",
                             "parameter_size": "8B",
                             "quantization_level": "Q4_0"}},
                {"name": "mistral", "size": 5_000_000,
                 "modified_at": "2026-02-01",
                 "details": {"format": "gguf", "family": "llama"}},
            ],
        }, 200, 3.5, None),
        "http://127.0.0.1:11434/api/ps": ({
            "models": [
                {"name": "llama3", "size_vram": 4_500_000,
                 "expires_at": "2026-03-01"},
            ],
        }, 200, 4.0, None),
        "http://127.0.0.1:11434/api/version": ({"version": "0.1.2"}, 200, 2.0, None),
        "http://127.0.0.1:8080/health": ({"status": "ok"}, 200, 6.0, None),
        "http://127.0.0.1:8080/props": (
            {"default_generation_settings": {"n_ctx": 4096},
             "model_path": "/models/qwen.gguf"}, 200, 5.0, None),
        "http://127.0.0.1:8080/slots": [
            {"state": 0}, {"state": 1}, {"state": 0},
        ],
        "http://127.0.0.1:8000/v1/models": (
            {"data": [{"id": "vllm-model"}]}, 200, 7.0, None),
    }


class _RouterHTTP:
    """Deterministic _http_get_json replacement with recorded calls."""

    def __init__(self, routes):
        self.routes = routes
        self.seen = []

    def __call__(self, url, timeout):
        self.seen.append((url, timeout))
        if url in self.routes:
            route = self.routes[url]
            # /slots returns a bare list response body
            if isinstance(route, list):
                return route, 200, 1.0, None
            return route
        return None, None, 0.5, "connection refused"


class TestDispatch(unittest.TestCase):
    """Handler contract: envelope and argument validation."""

    def test_rejects_non_dict_arguments(self):
        res = lp.local_llm_probe(["list"])
        self.assertFalse(res["ok"])
        self.assertIn("Arguments must be a dictionary", res["error"])

    def test_missing_or_invalid_action(self):
        res = lp.local_llm_probe({})
        self.assertFalse(res["ok"])
        self.assertIn("Invalid or missing action 'None'", res["error"])
        res2 = lp.local_llm_probe({"action": "explode"})
        self.assertFalse(res2["ok"])
        self.assertIn("Valid actions", res2["error"])

    def test_unhandled_action_falls_through(self):
        # Action is validated against VALID_ACTIONS before dispatch; an
        # unknown action can never reach the else branch, and 'explode'
        # is rejected at the action check.
        res = lp.local_llm_probe({"action": "explode"})
        self.assertFalse(res["ok"])

    def test_success_envelope_shape(self):
        router = _RouterHTTP(_ok_routes())
        with patch.object(lp, "_http_get_json", router):
            res = lp.local_llm_probe({"action": "probe_ollama"})
        self.assertEqual(set(res), {"ok", "success", "data", "result", "error"})
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"], res["result"])


class TestHostGuardrail(unittest.TestCase):
    """SSRF perimeter: non-loopback hosts are rejected for every action."""

    def test_non_loopback_host_rejected_for_engine_probes(self):
        for action in ("probe_ollama", "probe_llama_server",
                       "probe_localai", "get_model_info",
                       "probe_all", "check_readiness", "benchmark_ping"):
            with patch.object(lp, "_http_get_json", _RouterHTTP({})), \
                 patch.object(lp, "_tcp_ping", lambda h, p, t: (False, 1.0, "refused")):
                res = lp.local_llm_probe({"action": action, "host": "8.8.8.8"})
            self.assertFalse(res["ok"], msg=action)
            self.assertIn("NetworkSecurityError", res["error"], msg=action)
            self.assertIn("not permitted", res["error"], msg=action)

    def test_loopback_variants_accepted(self):
        router = _RouterHTTP(_ok_routes())
        with patch.object(lp, "_http_get_json", router):
            res = lp.local_llm_probe({"action": "probe_ollama",
                                      "host": "LOCALHOST"})
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["host"], "localhost")

    def test_probe_endpoints_validates_each_host(self):
        routes = {
            "http://127.0.0.1:9999/x": (None, 404, 12.0, "HTTP Error 404: Not Found"),
        }
        with patch.object(lp, "_http_get_json", _RouterHTTP(routes)):
            res = lp.local_llm_probe({"action": "probe_endpoints",
                                      "endpoints": [
                                          "http://127.0.0.1:9999/x",
                                          "http://192.168.0.5/api",
                                          "not a url",
                                      ]})
        eps = res["data"]["endpoints"]
        self.assertEqual(len(eps), 3)
        self.assertTrue(eps[0]["reachable"])          # 404 still < 500
        self.assertEqual(eps[0]["status_code"], 404)
        self.assertFalse(eps[1]["reachable"])
        self.assertIn("not permitted", eps[1]["error"])
        self.assertFalse(eps[2]["reachable"])
        self.assertEqual(eps[2]["error"], "Malformed endpoint URL")
        self.assertEqual(res["data"]["reachable_count"], 1)
        self.assertEqual(res["data"]["probed_count"], 3)


class TestTimeoutClamp(unittest.TestCase):
    """timeout parameter is clamped to [0.1, 30.0] seconds."""

    def test_timeout_clamped_to_bounds(self):
        router = _RouterHTTP({})
        with patch.object(lp, "_http_get_json", router):
            lp.local_llm_probe({"action": "probe_ollama", "timeout": 99})
            lp.local_llm_probe({"action": "probe_ollama", "timeout": 0.001})
        self.assertEqual([t for _, t in router.seen], [30.0, 0.1])


class TestOllamaProbe(unittest.TestCase):
    """probe_ollama: model discovery, running models, version."""

    def test_reachable_with_models(self):
        with patch.object(lp, "_http_get_json", _RouterHTTP(_ok_routes())):
            res = lp.local_llm_probe({"action": "probe_ollama"})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertTrue(data["reachable"])
        self.assertEqual(data["engine"], "ollama")
        self.assertEqual(data["version"], "0.1.2")
        self.assertEqual(data["models_count"], 2)
        self.assertEqual(data["models"][0]["name"], "llama3")
        self.assertEqual(data["models"][0]["quantization_level"], "Q4_0")
        self.assertEqual(data["models"][1]["family"], "llama")
        self.assertEqual(data["running_models_count"], 1)
        self.assertEqual(data["vram_in_use_bytes"], 4_500_000)
        self.assertEqual(data["status_code"], 200)

    def test_unreachable_reports_error(self):
        with patch.object(lp, "_http_get_json", _RouterHTTP({})):
            res = lp.local_llm_probe({"action": "probe_ollama",
                                      "port": 11501})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertFalse(data["reachable"])
        self.assertEqual(data["models_count"], 0)
        self.assertEqual(data["models"], [])
        self.assertIn("connection refused", data["error"])


class TestLlamaServerProbe(unittest.TestCase):
    """probe_llama_server: health, props, slot accounting."""

    def test_reachable_with_slots(self):
        with patch.object(lp, "_http_get_json", _RouterHTTP(_ok_routes())):
            res = lp.local_llm_probe({"action": "probe_llama_server"})
        data = res["data"]
        self.assertTrue(data["reachable"])
        self.assertEqual(data["engine"], "llama_server")
        self.assertEqual(data["server_status"], "ok")
        self.assertEqual(data["total_slots"], 3)
        self.assertEqual(data["active_slots"], 1)
        self.assertEqual(data["n_ctx"], 4096)
        self.assertEqual(data["model_path"], "/models/qwen.gguf")

    def test_unreachable_reports_error(self):
        with patch.object(lp, "_http_get_json", _RouterHTTP({})):
            res = lp.local_llm_probe({"action": "probe_llama_server",
                                      "port": 11502})
        data = res["data"]
        self.assertFalse(data["reachable"])
        self.assertIn("connection refused", data["error"])
        self.assertIsNone(data.get("total_slots"))


class TestLocalaiProbe(unittest.TestCase):
    """probe_localai: /v1/models discovery."""

    def test_reachable_lists_models(self):
        with patch.object(lp, "_http_get_json", _RouterHTTP(_ok_routes())):
            res = lp.local_llm_probe({"action": "probe_localai",
                                      "port": 8000})
        data = res["data"]
        self.assertTrue(data["reachable"])
        self.assertEqual(data["engine"], "localai")
        self.assertEqual(data["models_count"], 1)
        self.assertEqual(data["models"], ["vllm-model"])

    def test_unreachable_reports_error(self):
        with patch.object(lp, "_http_get_json", _RouterHTTP({})):
            res = lp.local_llm_probe({"action": "probe_localai",
                                      "port": 11503})
        data = res["data"]
        self.assertFalse(data["reachable"])
        self.assertEqual(data["models"], [])


class TestProbeAllAndReadiness(unittest.TestCase):
    """probe_all / check_readiness: aggregate verdicts and model tips."""

    def test_probe_all_aggregates_engines(self):
        with patch.object(lp, "_http_get_json", _RouterHTTP(_ok_routes())):
            res = lp.local_llm_probe({"action": "probe_all"})
        data = res["data"]
        self.assertTrue(data["ollama"]["reachable"])
        self.assertTrue(data["llama_server"]["reachable"])
        self.assertTrue(data["vllm"]["reachable"])
        self.assertEqual(data["vllm"]["models_count"], 1)
        self.assertTrue(data["any_service_available"])

    def test_check_readiness_ready_with_recommendation(self):
        with patch.object(lp, "_http_get_json", _RouterHTTP(_ok_routes())):
            res = lp.local_llm_probe({"action": "check_readiness"})
        data = res["data"]
        self.assertTrue(data["is_ready"])
        self.assertEqual(data["mode"], "local_inference_ready")
        self.assertIn("ollama", data["available_engines"])
        self.assertIn("llama_server", data["available_engines"])
        self.assertIn("vllm", data["available_engines"])
        self.assertEqual(data["total_local_models"], 2)
        self.assertEqual(data["recommended_model"], "llama3")
        self.assertAlmostEqual(data["best_latency_ms"], 3.5)
        self.assertIn("Local fallback ready", data["recommendation"])

    def test_check_readiness_cloud_only_when_nothing_listens(self):
        with patch.object(lp, "_http_get_json", _RouterHTTP({})):
            res = lp.local_llm_probe({"action": "check_readiness"})
        data = res["data"]
        self.assertFalse(data["is_ready"])
        self.assertEqual(data["mode"], "cloud_only_no_local_daemons")
        self.assertEqual(data["available_engines"], [])
        self.assertIsNone(data["best_latency_ms"])
        self.assertIsNone(data["recommended_model"])
        self.assertIn("fall back to cloud API", data["recommendation"])


class TestBenchmarkPing(unittest.TestCase):
    """benchmark_ping: patched TCP socket outcomes and open_ports."""

    def test_default_ports_when_port_missing(self):
        open_ports = {11434: True, 8080: False, 8000: True, 5000: False}

        def fake_tcp(host, port, timeout):
            return open_ports.get(port, False), 2.0, None

        with patch.object(lp, "_tcp_ping", fake_tcp):
            res = lp.local_llm_probe({"action": "benchmark_ping"})
        data = res["data"]
        self.assertEqual(len(data["pings"]), 4)
        self.assertEqual(data["open_ports"], [11434, 8000])
        self.assertTrue(data["pings"][0]["connected"])
        self.assertFalse(data["pings"][1]["connected"])

    def test_custom_single_port(self):
        with patch.object(lp, "_tcp_ping",
                          lambda h, p, t: (True, 1.5, None)):
            res = lp.local_llm_probe({"action": "benchmark_ping",
                                      "port": 12345})
        data = res["data"]
        self.assertEqual(len(data["pings"]), 1)
        self.assertEqual(data["pings"][0]["port"], 12345)
        self.assertEqual(data["open_ports"], [12345])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
