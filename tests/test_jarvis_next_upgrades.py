"""End-to-end tests for Jarvis next-generation upgrades:
1. Wayland dictation (`wtype`/`ydotool`/`xdotool` + newline stripping)
2. Sentence-by-sentence streaming TTS chunker (<400ms, Polish abbreviations) & Barge-In
3. Hard `budget_guard` enforcement (80% auto-downgrade, 100% HTTP 429 + router shift)
4. Live SSE event bus & `GET /mission/events`
5. Deterministic `qa_gate.audit_viewer` on live repo & synthetic violations
6. Hybrid Code RAG (`FTS5 + Subword Vectors + AST Import Graph + 5-min idle eviction`)
7. Autonomous Night Shift guards & `systemd --user` timer generation
"""

import json
import os
SANDBOXED = os.environ.get("JARVIS_VERIFY_SANDBOX") == "1"
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import agent_cli
import agent_router
import budget_guard
import code_index
import event_bus
import night_shift
import qa_gate
import server
import voice_bridge
import wayland_voice

REPO_ROOT = Path(__file__).resolve().parent.parent


def _find_handler_class():
    for val in vars(server).values():
        if isinstance(val, type) and issubclass(val, BaseHTTPRequestHandler) and val is not BaseHTTPRequestHandler:
            return val
    raise RuntimeError("Could not locate HTTP handler class in server.py")


@unittest.skipIf(SANDBOXED, "needs the developer's local env (vault/Hermes/Piper/desktop); skipped in CI")
class JarvisNextUpgradesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/tmp" if Path("/tmp").is_dir() else None)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.agents_dir = self.base / "state" / ".jarvis-tools" / "agents"
        self.agents_dir.mkdir(parents=True, exist_ok=True)
        self.p_agents = patch.object(agent_cli, "ROOT", self.agents_dir)
        self.p_agents.start()
        self.addCleanup(self.p_agents.stop)

        event_bus.reset_for_tests()
        code_index.evict_idle_cache(force=True)

        self.proj_root = self.base / "proj"
        self.proj_root.mkdir(parents=True, exist_ok=True)

        handler_cls = _find_handler_class()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        self.httpd.app = SimpleNamespace(root=self.proj_root)
        self.port = self.httpd.server_port
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def _post_json(self, path: str, payload: dict | None = None, extra_headers: dict | None = None):
        raw = b"" if payload is None else json.dumps(payload).encode("utf-8")
        headers = {
            "Host": f"127.0.0.1:{self.port}",
            "Origin": f"http://127.0.0.1:{self.port}",
            "Content-Length": str(len(raw)),
        }
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if extra_headers:
            headers.update(extra_headers)
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=raw, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    def test_1_wayland_dictation_sanitizes_and_prefers_wtype_then_ydotool(self):
        clean = wayland_voice.sanitize_dictation_text("Cześć\nrm -rf /\r\x07świecie")
        self.assertEqual(clean, "Cześć rm -rf / świecie")

        with patch.dict(os.environ, {"XDG_SESSION_TYPE": "wayland", "WAYLAND_DISPLAY": "wayland-0"}, clear=False):
            with patch("shutil.which", side_effect=lambda name: "/usr/bin/wtype" if name == "wtype" else None):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = SimpleNamespace(returncode=0)
                    res = wayland_voice.type_text("Witaj\nWayland!")
        self.assertTrue(res["typed"])
        self.assertEqual(res["backend"], "wtype")
        self.assertEqual(mock_run.call_args[0][0], ["wtype", "--", "Witaj Wayland!"])

    def test_2_sentence_stream_chunker_and_barge_in_routes(self):
        chunker = wayland_voice.SentenceStreamChunker(min_chars=18)
        # Polish abbreviation "np." must NOT split prematurely
        c1 = chunker.push("Sprawdź np. moduł routera i popraw błędy. ")
        c2 = chunker.push("Druga odpowiedź jest już gotowa do odczytu!")
        tail = chunker.flush()
        all_chunks = c1 + c2 + tail
        self.assertEqual(len(all_chunks), 2)
        self.assertIn("np. moduł routera", all_chunks[0])

        status_code, body = self._post_json("/tts/chunks", {
            "text": "Pierwsze pełne zdanie do syntezatora mowy. Drugie zdanie po kropce!",
        })
        self.assertEqual(status_code, 200)
        self.assertEqual(body["count"], 2)

        b_status, b_body = self._post_json("/voice/barge-in")
        self.assertEqual(b_status, 200)
        self.assertGreater(b_body["generation"], body["generation"])

    def test_3_budget_guard_downgrade_router_shift_and_http_429_hard_cap(self):
        budget_guard.configure_limits(daily_limit_usd=1.00, monthly_limit_usd=10.00, soft_ratio=0.80)
        budget_guard.record_spend(model="claude-sonnet", usd=0.85, source="test")

        # At 85% (>=80% soft_cap): auxiliary models downgrade automatically
        sel = budget_guard.enforce_and_select_model("claude-sonnet-4-5", role="qa")
        self.assertTrue(sel["downgraded"])
        self.assertEqual(sel["model"], "claude-haiku-4-5")

        # Router shifts away from metered premium on non-architect roles
        with patch.object(agent_cli, "binary_present", return_value=True), \
             patch.object(agent_cli, "_check_running", return_value=(False, None)):
            qa_rank = agent_router.rank_agents(role="qa")
            self.assertNotEqual(qa_rank[0]["agent"], "claude")

        # Push spend over 100% hard_cap -> HTTP 429 BUDGET_EXCEEDED on paid /chat endpoint
        budget_guard.record_spend(model="claude-opus", usd=0.30, source="test")
        with self.assertRaises(budget_guard.BudgetExceededError):
            budget_guard.enforce_and_select_model("claude-sonnet-4-5")

        raw = json.dumps({"message": "hello"}).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/chat",
            data=raw,
            method="POST",
            headers={
                "Host": f"127.0.0.1:{self.port}",
                "Origin": f"http://127.0.0.1:{self.port}",
                "Content-Type": "application/json",
                "Content-Length": str(len(raw)),
            },
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        err_payload = json.loads(ctx.exception.read().decode("utf-8"))
        ctx.exception.close()
        self.assertEqual(ctx.exception.code, 429)
        self.assertEqual(err_payload["error"]["code"], "BUDGET_EXCEEDED")

    def test_4_live_sse_stream_delivers_owner_question_and_budget_events(self):
        voice_bridge.enqueue_owner_question("demo-proj", "req-sse-1", "hermes", "Czy wdrażamy SSE?", speak=False)
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/mission/events?after=0&once=1",
            headers={"Host": f"127.0.0.1:{self.port}"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertIn("text/event-stream", resp.headers.get("Content-Type", ""))
            text = resp.read().decode("utf-8")
        self.assertIn("event: owner.question", text)
        self.assertIn("req-sse-1", text)

    def test_5_qa_gate_verifies_live_jarvis_viewer_and_catches_innerhtml(self):
        live_audit = qa_gate.audit_viewer(REPO_ROOT)
        self.assertTrue(live_audit["ok"], f"Live viewer failed QA gate: {live_audit['issues']}")

        bad_proj = self.base / "bad_ui"
        (bad_proj / "viewer").mkdir(parents=True)
        (bad_proj / "viewer" / "capabilities.js").write_text("window.ok = 1;\n", encoding="utf-8")
        (bad_proj / "viewer" / "mission.js").write_text("document.body.innerHTML = 'xss';\n", encoding="utf-8")
        (bad_proj / "viewer" / "index.html").write_text(
            '<!doctype html><script src="capabilities.js"></script><script src="mission.js"></script>',
            encoding="utf-8",
        )
        bad_audit = qa_gate.audit_viewer(bad_proj)
        self.assertFalse(bad_audit["ok"])
        self.assertGreaterEqual(len(bad_audit["issues"]), 2)

    def test_6_hybrid_code_rag_ast_import_graph_and_idle_cache_eviction(self):
        repo = self.base / "rag_repo"
        repo.mkdir()
        (repo / "billing_limits.py").write_text(
            "def calculate_daily_quota_threshold(spend_usd: float) -> bool:\n    return spend_usd < 5.0\n",
            encoding="utf-8",
        )
        (repo / "api_gateway.py").write_text(
            "import billing_limits\n\ndef handle_request(cost: float):\n    return billing_limits.calculate_daily_quota_threshold(cost)\n",
            encoding="utf-8",
        )
        idx = code_index.index_directory(repo)
        self.assertTrue(idx["ok"])
        self.assertEqual(idx["indexed"], 2)

        rel = code_index.related_files("billing_limits.py", repo)
        self.assertEqual(rel["imported_by"], ["api_gateway.py"])

        hits = code_index.search_context("daily quota threshold", root_dir=repo, limit=4)
        paths = [h["path"] for h in hits]
        self.assertIn("billing_limits.py", paths)
        # 1-hop AST caller (`api_gateway.py`) is surfaced via RRF graph boost
        self.assertIn("api_gateway.py", paths)

        self.assertEqual(code_index.cache_stats()["roots_cached"], 1)
        evicted = code_index.evict_idle_cache(now=1e12)
        self.assertEqual(evicted, 1)
        self.assertEqual(code_index.cache_stats()["roots_cached"], 0)

    def test_7_night_shift_busy_agent_guard_and_systemd_timer_generation(self):
        with patch.object(night_shift, "any_agent_busy", return_value=["claude"]):
            skipped = night_shift.run_night_shift(force=False)
        self.assertTrue(skipped["skipped"])
        self.assertIn("claude", skipped["reason"])

        timer_dir = self.base / "systemd_user"
        installed = night_shift.install_user_timer(enable=False, target_dir=timer_dir)
        self.assertTrue(installed["ok"])
        self.assertTrue((timer_dir / "jarvis-night-shift.timer").is_file())
        self.assertIn("03:30:00", (timer_dir / "jarvis-night-shift.timer").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
