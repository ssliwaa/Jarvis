"""Automated test suite for operator_modules/op_llm_gateway.py.

Tests the handler contract, TokenBucket refill semantics, CircuitBreaker
state machine (CLOSED/OPEN/HALF_OPEN transitions), fallback-ladder
routing with circuit rejections and simulated provider failures,
rate-limit enforcement (RPM and TPM), metrics recording, gateway
status with p95 latency breakdown, rate-limit reconfiguration and
checks, circuit resets, and endpoint probing with mocked urllib
(no real sockets). Every test builds a fresh GatewayState instance to
isolate the module-level singleton; probe tests patch
urllib.request.urlopen with in-test fakes.
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

import operator_modules.op_llm_gateway as lg


class _FakeResp:
    """Minimal context-manager HTTP response stand-in."""

    def __init__(self, status=200, body=b"{}"):
        self.status = status
        self._body = body

    def read(self, n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class GatewayTestBase(unittest.TestCase):
    """Fresh singleton state for every test (deterministic isolation)."""

    def setUp(self):
        self.state = lg.GatewayState()
        lg.GatewayState._instance = self.state

    def tearDown(self):
        lg.GatewayState._instance = None


class TestDispatch(GatewayTestBase):
    """Handler contract: envelope, argument and action validation."""

    def test_rejects_non_dict_arguments(self):
        res = lg.llm_gateway("nope")
        self.assertFalse(res["ok"])
        self.assertIn("Arguments must be a JSON dictionary", res["error"])

    def test_rejects_disallowed_extra_keys(self):
        res = lg.llm_gateway({"action": "get_status", "rogue": 1})
        self.assertFalse(res["ok"])
        self.assertIn("Disallowed additional arguments", res["error"])
        self.assertIn("rogue", res["error"])

    def test_invalid_action(self):
        res = lg.llm_gateway({"action": "explode"})
        self.assertFalse(res["ok"])
        self.assertIn("Invalid or missing action 'explode'", res["error"])
        self.assertIn("route_request", res["error"])

    def test_success_envelope_shape(self):
        res = lg.llm_gateway({"action": "get_status"})
        self.assertEqual(set(res), {"ok", "success", "data", "result",
                                    "error"})
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"], res["result"])
        self.assertIsNone(res["error"])


class TestTokenBucket(unittest.TestCase):
    """TokenBucket: consume, capacity clamp, status accounting."""

    def test_consume_within_and_beyond_capacity(self):
        bucket = lg.TokenBucket(capacity=5, refill_rate_per_sec=0.0)
        self.assertTrue(bucket.consume(3))
        self.assertFalse(bucket.consume(5))   # only 2 left
        self.assertTrue(bucket.consume(2))

    def test_update_limits_clamps_tokens(self):
        bucket = lg.TokenBucket(capacity=100, refill_rate_per_sec=0.0)
        bucket.update_limits(capacity=10, refill_rate_per_sec=5.0)
        status = bucket.status()
        self.assertEqual(status["capacity"], 10)
        self.assertEqual(status["refill_rate_per_sec"], 5.0)
        self.assertFalse(bucket.consume(11))   # clamped to 10

    def test_status_utilization(self):
        bucket = lg.TokenBucket(capacity=100, refill_rate_per_sec=0.0)
        bucket.consume(30)
        status = bucket.status()
        self.assertEqual(status["available_tokens"], 70)
        self.assertEqual(status["utilization_pct"], 30.0)


class TestCircuitBreaker(unittest.TestCase):
    """CircuitBreaker: failure threshold, cooldown, reset."""

    def test_opens_after_threshold(self):
        cb = lg.CircuitBreaker("prov", failure_threshold=3,
                               cooldown_sec=30.0)
        self.assertEqual(cb.state, "CLOSED")
        self.assertTrue(cb.can_execute())
        cb.record_failure()
        cb.record_failure()
        self.assertEqual(cb.state, "CLOSED")
        cb.record_failure()
        self.assertEqual(cb.state, "OPEN")
        self.assertFalse(cb.can_execute())
        status = cb.status()
        self.assertEqual(status["consecutive_failures"], 3)
        self.assertEqual(status["total_failures"], 3)

    def test_zero_cooldown_transitions_to_half_open(self):
        cb = lg.CircuitBreaker("prov", failure_threshold=1,
                               cooldown_sec=0.0)
        cb.record_failure()
        self.assertEqual(cb.state, "OPEN")
        # Elapsed >= 0.0 cooldown immediately -> HALF_OPEN probe allowed
        self.assertTrue(cb.can_execute())
        self.assertEqual(cb.state, "HALF_OPEN")
        cb.record_success()
        self.assertEqual(cb.state, "CLOSED")
        self.assertEqual(cb.status()["total_successes"], 1)

    def test_explicit_reset_restores_closed(self):
        cb = lg.CircuitBreaker("prov", failure_threshold=2,
                               cooldown_sec=30.0)
        cb.record_failure()
        cb.record_failure()
        self.assertEqual(cb.state, "OPEN")
        cb.reset()
        self.assertEqual(cb.state, "CLOSED")
        self.assertEqual(cb.failure_count, 0)
        self.assertTrue(cb.can_execute())


class TestRouteRequest(GatewayTestBase):
    """route_request: ladders, fallback, circuit rejections, metrics."""

    def test_explicit_provider_routes_and_records(self):
        res = lg.llm_gateway({"action": "route_request",
                               "provider": "deepseek",
                               "estimated_tokens": 50})
        data = res["data"]
        self.assertEqual(data["status"], "routed")
        self.assertEqual(data["routed_provider"], "deepseek")
        self.assertEqual(data["tokens_allocated"], 50)
        self.assertEqual(data["attempted_providers"], ["deepseek"])
        m = self.state.metrics
        self.assertEqual(m["total_requests"], 1)
        self.assertEqual(m["successful_requests"], 1)
        self.assertEqual(m["provider_tokens"]["deepseek"], 50)
        self.assertIn(data["latency_ms"], m["latencies_ms"])

    def test_simulation_failure_falls_back_next_ladder(self):
        res = lg.llm_gateway({"action": "route_request",
                              "provider_ladder": ["a", "b"],
                              "simulate_failure": "a"})
        data = res["data"]
        self.assertEqual(data["routed_provider"], "b")
        self.assertEqual(data["attempted_providers"], ["a", "b"])
        self.assertEqual(self.state.metrics["failed_requests"], 1)
        self.assertEqual(
            self.state.circuits["a"].status()["consecutive_failures"], 1)

    def test_all_failures_raise_gateway_error(self):
        res = lg.llm_gateway({"action": "route_request",
                              "provider_ladder": ["a", "b"],
                              "simulate_failure": True})
        self.assertFalse(res["ok"])
        self.assertIn("All candidate providers", res["error"])
        self.assertIn("'a'", res["error"])
        self.assertIn("'b'", res["error"])

    def test_open_circuit_rejected_with_reason(self):
        circuit = self.state.get_circuit("vllm_local")
        for _ in range(3):
            circuit.record_failure()
        self.assertEqual(circuit.state, "OPEN")
        res = lg.llm_gateway({"action": "route_request",
                              "provider": "vllm_local"})
        self.assertFalse(res["ok"])
        self.assertIn("circuit-broken", res["error"])
        self.assertIn("Circuit breaker is OPEN", res["error"])

    def test_request_rate_limit_enforced(self):
        self.state.request_bucket = lg.TokenBucket(capacity=1,
                                                   refill_rate_per_sec=0.0)
        first = lg.llm_gateway({"action": "route_request",
                                 "provider": "deepseek"})
        self.assertTrue(first["ok"])
        second = lg.llm_gateway({"action": "route_request",
                                  "provider": "deepseek"})
        self.assertFalse(second["ok"])
        self.assertIn("Request rate limit exceeded", second["error"])

    def test_token_rate_limit_enforced(self):
        self.state.token_bucket = lg.TokenBucket(capacity=10,
                                                  refill_rate_per_sec=0.0)
        res = lg.llm_gateway({"action": "route_request",
                              "provider": "deepseek",
                              "estimated_tokens": 50})
        self.assertFalse(res["ok"])
        self.assertIn("Token rate limit exceeded", res["error"])
        self.assertIn("50 tokens", res["error"])

    def test_endpoint_probe_failure_falls_back(self):
        with patch.object(lg.urllib.request, "urlopen",
                          side_effect=urllib.error.URLError("refused")):
            res = lg.llm_gateway({"action": "route_request",
                                  "provider_ladder": ["a", "b"],
                                  "endpoint_url": "http://127.0.0.1:9/x"})
        data = res["data"]
        self.assertEqual(data["routed_provider"], "b")
        self.assertEqual(self.state.metrics["failed_requests"], 1)


class TestRecordMetrics(GatewayTestBase):
    """record_metrics: bookkeeping and circuit feedback."""

    def test_success_recording(self):
        res = lg.llm_gateway({"action": "record_metrics",
                              "provider": "anthropic",
                              "model": "claude-x",
                              "tokens": 120,
                              "latency_ms": 250.0,
                              "cost": 0.012})
        data = res["data"]
        self.assertTrue(data["recorded"])
        m = self.state.metrics
        self.assertEqual(m["total_requests"], 1)
        self.assertEqual(m["successful_requests"], 1)
        self.assertEqual(m["total_tokens"], 120)
        self.assertAlmostEqual(m["total_cost_usd"], 0.012)
        self.assertEqual(m["provider_requests"]["anthropic"], 1)
        self.assertIn(250.0, m["latencies_ms"])
        self.assertEqual(data["cumulative_requests"], 1)
        self.assertEqual(
            self.state.circuits["anthropic"].total_successes, 1)

    def test_failure_recording_updates_circuit(self):
        lg.llm_gateway({"action": "record_metrics",
                        "provider": "failprov",
                        "tokens": 10, "success": False,
                        "error_type": "timeout"})
        self.assertEqual(self.state.metrics["failed_requests"], 1)
        self.assertEqual(
            self.state.circuits["failprov"].status()["consecutive_failures"],
            1)


class TestStatusAndLimits(GatewayTestBase):
    """get_status / set_rate_limit / check_rate_limit / reset_circuit."""

    def test_fresh_status_shape(self):
        res = lg.llm_gateway({"action": "get_status"})
        data = res["data"]
        self.assertIn("uptime_seconds", data)
        self.assertIn("vllm_local", data["circuits"])
        self.assertIn("tokens", data["rate_limits"])
        self.assertIn("requests", data["rate_limits"])
        self.assertEqual(data["metrics"]["p95_latency_ms"], 0.0)
        self.assertEqual(data["metrics"]["total_requests"], 0)

    def test_status_exports_report(self):
        with tempfile.TemporaryDirectory() as td:
            target = td + "/status.json"
            res = lg.llm_gateway({"action": "get_status",
                                  "export_path": target})
            self.assertEqual(res["data"]["exported_to"], target)
            loaded = json.loads(open(target, encoding="utf-8").read())
            self.assertIn("metrics", loaded)

    def test_status_export_outside_roots_rejected(self):
        res = lg.llm_gateway({"action": "get_status",
                              "export_path": "/proc/no/no.json"})
        self.assertFalse(res["ok"])
        self.assertIn("PathSecurityError", res["error"])

    def test_set_and_check_rate_limits(self):
        res = lg.llm_gateway({"action": "set_rate_limit",
                              "rate_limit_tpm": 1000,
                              "rate_limit_rpm": 10})
        data = res["data"]
        self.assertEqual(data["updated"]["rate_limit_tpm"], 1000)
        self.assertEqual(data["updated"]["rate_limit_rpm"], 10)
        self.assertEqual(data["current_limits"]["token_bucket"]["capacity"],
                         1000)
        # Check within limits
        chk = lg.llm_gateway({"action": "check_rate_limit",
                              "estimated_tokens": 500})
        self.assertTrue(chk["data"]["allowed"])
        # Check beyond token capacity
        chk2 = lg.llm_gateway({"action": "check_rate_limit",
                               "estimated_tokens": 5000})
        self.assertFalse(chk2["data"]["allowed"])

    def test_reset_circuit_scoped_and_global(self):
        self.state.get_circuit("ollama_local").record_failure()
        self.state.get_circuit("deepseek").record_failure()
        res = lg.llm_gateway({"action": "reset_circuit",
                              "provider": "deepseek"})
        data = res["data"]
        self.assertEqual(data["reset_providers"], ["deepseek"])
        self.assertEqual(
            data["circuit_states"]["deepseek"]["consecutive_failures"], 0)
        # Other provider untouched by scoped reset
        self.assertEqual(
            self.state.circuits["ollama_local"].failure_count, 1)
        res2 = lg.llm_gateway({"action": "reset_circuit"})
        self.assertIn("vllm_local", res2["data"]["reset_providers"])
        self.assertIn("anthropic", res2["data"]["reset_providers"])


class TestProbeEndpoints(GatewayTestBase):
    """probe_endpoints: mocked urlopen scenarios (no real sockets)."""

    def test_default_and_custom_endpoints(self):
        routes = {
            "http://127.0.0.1:9000/ok": _FakeResp(200),
            "http://127.0.0.1:9000/teapot": _FakeResp(399),
        }
        with patch.object(lg.urllib.request, "urlopen",
                          side_effect=lambda req, timeout=None:
                          routes[req.full_url]):
            res = lg.llm_gateway({"action": "probe_endpoints",
                                  "endpoints": [
                                      "http://127.0.0.1:9000/ok",
                                      "http://127.0.0.1:9000/teapot"]})
        data = res["data"]
        self.assertEqual(data["endpoints_probed"], 2)
        by_url = {r["endpoint"]: r for r in data["results"]}
        self.assertTrue(by_url["http://127.0.0.1:9000/ok"]["reachable"])
        self.assertEqual(
            by_url["http://127.0.0.1:9000/ok"]["status_code"], 200)
        self.assertTrue(by_url["http://127.0.0.1:9000/teapot"]["reachable"])

    def test_http_error_counts_as_responding(self):
        def raise_teapot(req, timeout=None):
            raise urllib.error.HTTPError(req.full_url, 418,
                                         "I'm a teapot", {}, io.BytesIO(b""))
        with patch.object(lg.urllib.request, "urlopen",
                          side_effect=raise_teapot):
            res = lg.llm_gateway({"action": "probe_endpoints",
                                  "endpoint_url": "http://127.0.0.1:9/x"})
        row = res["data"]["results"][0]
        self.assertTrue(row["reachable"])   # responded, albeit error
        self.assertEqual(row["status_code"], 418)
        self.assertIn("teapot", row["error"])

    def test_connection_failure_marked_unreachable(self):
        with patch.object(lg.urllib.request, "urlopen",
                          side_effect=urllib.error.URLError("conn refused")):
            res = lg.llm_gateway({"action": "probe_endpoints",
                                  "endpoint_url": "http://127.0.0.1:9/x"})
        row = res["data"]["results"][0]
        self.assertFalse(row["reachable"])
        self.assertIsNone(row["status_code"])
        self.assertIn("conn refused", row["error"])
        self.assertGreaterEqual(row["latency_ms"], 0.0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
