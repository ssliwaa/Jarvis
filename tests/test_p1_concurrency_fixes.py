"""Multi-threaded regression tests for all 4 P1 concurrency and leak fixes."""

import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import agent_cli
import budget_guard
import evolution
import self_modify
import server
import time_travel
import workflow_miner


def _find_handler_class():
    for val in vars(server).values():
        if isinstance(val, type) and issubclass(val, BaseHTTPRequestHandler) and val is not BaseHTTPRequestHandler:
            return val
    raise RuntimeError("Could not locate HTTP handler class in server.py")


class P1ConcurrencyFixesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/tmp" if Path("/tmp").is_dir() else None)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name) / ".jarvis-tools"
        self.agents_dir = self.base / "agents"
        self.agents_dir.mkdir(parents=True, exist_ok=True)
        self.selfmod_dir = self.base / "selfmod"
        self.selfmod_dir.mkdir(parents=True, exist_ok=True)

        self.p_agents = patch.object(agent_cli, "ROOT", self.agents_dir)
        self.p_state = patch.object(evolution, "STATE", self.selfmod_dir)
        self.p_agents.start()
        self.p_state.start()
        self.addCleanup(self.p_agents.stop)
        self.addCleanup(self.p_state.stop)

    def test_p1_1_selfmod_engine_cache_lock_and_graceful_retirement(self):
        handler_cls = _find_handler_class()
        self.assertIsInstance(getattr(handler_cls, "_selfmod_cache_lock", None), type(threading.Lock()))

        created_clients = []

        def _fake_make_client(provider, key, timeout=240.0):
            cl = MagicMock()
            created_clients.append((key, cl))
            return cl

        key_box = ["key-v1"]
        app = SimpleNamespace(
            read_settings=lambda: (key_box[0], "claude-sonnet"),
            read_provider=lambda: "anthropic",
        )
        dummy_handler = SimpleNamespace(
            server=SimpleNamespace(app=app),
            _selfmod_cache_lock=handler_cls._selfmod_cache_lock,
        )

        with patch.object(server, "make_client", side_effect=_fake_make_client):
            with ThreadPoolExecutor(max_workers=6) as pool:
                engines = list(pool.map(lambda _: handler_cls._selfmod_engine(dummy_handler, need_model=True), range(12)))
            self.assertEqual(len(created_clients), 1)
            self.assertTrue(all(e is engines[0] for e in engines))

            # Rotating credentials retires v1 without closing it immediately mid-flight
            key_box[0] = "key-v2"
            eng2 = handler_cls._selfmod_engine(dummy_handler, need_model=True)
            self.assertIsNot(eng2, engines[0])
            created_clients[0][1].close.assert_not_called()

            # Once grace window (>300s) expires, next rotation closes expired retired engine
            app._selfmod_retired_engines = [(time.time() - 400.0, engines[0])]
            key_box[0] = "key-v3"
            handler_cls._selfmod_engine(dummy_handler, need_model=True)
            created_clients[0][1].close.assert_called_once()

    def test_p1_2_suggest_passes_custom_system_prompt_without_mutating_global(self):
        original_global = evolution.SUGGEST_SYSTEM

        seen_systems = []
        observed_globals = []

        class _DummyClient:
            class messages:
                @staticmethod
                def create(**kwargs):
                    seen_systems.append(kwargs.get("system"))
                    observed_globals.append(evolution.SUGGEST_SYSTEM)
                    time.sleep(0.02)
                    block = SimpleNamespace(
                        type="text",
                        text='{"suggestions": [{"file": "router.py", "instruction": "Improve", "evidence": "bench"}]}',
                    )
                    return SimpleNamespace(content=[block])

        def _worker(_):
            sm = self_modify.SelfModification(_DummyClient(), "test-model")
            return sm.suggest(limit=1)

        with patch.object(evolution.PromptLab, "get", return_value="CUSTOM_CONCURRENT_PLANNER_PROMPT"):
            with ThreadPoolExecutor(max_workers=6) as pool:
                results = list(pool.map(_worker, range(6)))

        self.assertEqual(len(results), 6)
        self.assertTrue(all(r["ok"] for r in results))
        self.assertTrue(all(s == "CUSTOM_CONCURRENT_PLANNER_PROMPT" for s in seen_systems))
        # Global constant was NEVER mutated at any point!
        self.assertTrue(all(g == original_global for g in observed_globals))
        self.assertEqual(evolution.SUGGEST_SYSTEM, original_global)

    def test_p1_3_concurrent_atomic_writes_have_zero_tmp_collisions(self):
        budget_guard.configure_limits(daily_limit_usd=100.0, monthly_limit_usd=500.0)

        def _hammer(i: int):
            workflow_miner.record_event("app.focus", target=f"win-{i}")
            time_travel.record_timepoint(session_id="conc-sess", turn_index=i, label=f"Turn {i}")
            budget_guard.record_spend(model="claude-sonnet", usd=0.05)
            return i

        with ThreadPoolExecutor(max_workers=8) as pool:
            done = list(pool.map(_hammer, range(24)))

        self.assertEqual(len(done), 24)
        self.assertEqual(len(workflow_miner.read_events(limit=100)), 24)
        self.assertEqual(len(time_travel.list_timepoints(session_id="conc-sess", limit=100)), 24)
        self.assertAlmostEqual(budget_guard.status()["spent_today_usd"], 24 * 0.05, places=3)

    def test_p1_4_paid_bucket_is_refunded_when_daily_limit_rejects(self):
        handler_cls = _find_handler_class()
        proj_root = Path(self.tmp.name) / "proj"
        proj_root.mkdir(parents=True, exist_ok=True)
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        httpd.app = SimpleNamespace(root=proj_root)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)

        fake_bucket = MagicMock()
        fake_bucket.allow.return_value = True

        with patch.object(server, "paid_endpoint", return_value="chat"), \
             patch.dict(server.PAID_BUCKETS, {"chat": fake_bucket}), \
             patch.object(server.usage_meter, "reserve_call", return_value=False):
            raw = b'{"question": "test"}'
            req = urllib.request.Request(
                f"http://127.0.0.1:{httpd.server_port}/chat",
                data=raw,
                headers={
                    "Host": f"127.0.0.1:{httpd.server_port}",
                    "Origin": f"http://127.0.0.1:{httpd.server_port}",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(raw)),
                },
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req, timeout=5)
            err = ctx.exception
            body = json.loads(err.read().decode("utf-8"))
            err.close()

        self.assertEqual(err.code, 429)
        self.assertEqual((body.get("error") or {}).get("code"), "DAILY_LIMIT")
        fake_bucket.refund.assert_called_once()


if __name__ == "__main__":
    unittest.main()
