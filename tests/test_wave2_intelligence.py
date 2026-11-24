"""End-to-end tests for Wave-2 Jarvis intelligence upgrades:
1. Persistent SQLite FTS5 `episodic_memory` (`remember_episode`, `recall_episodes`)
2. Zero-polling auto-capture from `event_bus` (`owner.answered`, `router.circuit_tripped`)
3. Automatic episodic memory injection into `code_index.build_context_pack()`
4. Proactive `morning_briefing` (`/proc/self/status` RSS, CPU, disk, `next_actions`, TTS chunks)
5. HTTP `GET /mission/briefing` & `POST /mission/action` (`remember_episode`, `recall_episodes`)
"""

import json
import tempfile
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import agent_cli
import agent_router
import budget_guard
import code_index
import episodic_memory
import event_bus
import morning_briefing
import server
import voice_bridge


def _find_handler_class():
    for val in vars(server).values():
        if isinstance(val, type) and issubclass(val, BaseHTTPRequestHandler) and val is not BaseHTTPRequestHandler:
            return val
    raise RuntimeError("Could not locate HTTP handler class in server.py")


class Wave2IntelligenceTests(unittest.TestCase):
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

    def test_1_episodic_memory_auto_captures_owner_answers_and_feeds_context_pack(self):
        voice_bridge.enqueue_owner_question(
            "",
            "req-ep-1",
            "claude",
            "Czy używamy wtype jako głównego backendu Wayland?",
            speak=False,
        )
        voice_bridge.answer_owner_question(
            "Tak, wtype ma najwyższy priorytet pod GNOME Wayland, potem ydotool.",
            req_id="req-ep-1",
            source="web-ui",
        )

        hits = episodic_memory.recall_episodes("wtype Wayland priorytet")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["kind"], "decision")
        self.assertIn("ydotool", hits[0]["summary"])

        # Context pack built for future coding agents automatically includes recalled episode
        pack = code_index.build_context_pack("Napraw dyktowanie wtype pod Wayland", root_dir=self.proj_root)
        self.assertIn("Pamięć epizodyczna", pack)
        self.assertIn("ydotool", pack)

    def test_2_circuit_breaker_auto_records_incident_and_surfaces_in_morning_briefing(self):
        agent_router.trip_circuit("opencode", "quota_exceeded", "HTTP 429 rate limit")
        budget_guard.configure_limits(daily_limit_usd=2.00, soft_ratio=0.80)
        budget_guard.record_spend(model="claude-sonnet", usd=1.70, source="test")
        voice_bridge.enqueue_owner_question("demo", "req-mb-1", "hermes", "Potwierdzić migrację?", speak=False)

        incidents = episodic_memory.recall_episodes("opencode quota_exceeded", kind="incident")
        self.assertEqual(len(incidents), 1)

        brief = morning_briefing.generate_briefing(self.proj_root)
        self.assertTrue(brief["ok"])
        self.assertIsNotNone(brief["telemetry"]["disk_free_gb"])
        codes = [a["code"] for a in brief["next_actions"]]
        self.assertIn("ANSWER_AGENT", codes)
        self.assertIn("CIRCUIT_OPEN", codes)
        self.assertIn("BUDGET_ALERT", codes)
        self.assertGreaterEqual(len(brief["spoken_chunks"]), 2)

    def test_3_http_briefing_and_mission_episode_actions(self):
        req_get = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/mission/briefing",
            headers={"Host": f"127.0.0.1:{self.port}"},
            method="GET",
        )
        with urllib.request.urlopen(req_get, timeout=6) as resp:
            self.assertEqual(resp.status, 200)
            bdata = json.loads(resp.read().decode("utf-8"))
        self.assertTrue(bdata["ok"])
        self.assertIn("spoken_summary", bdata)

        raw = json.dumps({
            "action": "remember_episode",
            "title": "Naprawa wycieku deskryptorów bwrap",
            "summary": "Zawsze zamykaj pipe stderr po zakończeniu procesu potomnego.",
            "kind": "bugfix",
            "tags": ["bwrap", "fd_leak"],
        }).encode("utf-8")
        req_post = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/mission/action",
            data=raw,
            method="POST",
            headers={
                "Host": f"127.0.0.1:{self.port}",
                "Origin": f"http://127.0.0.1:{self.port}",
                "Content-Type": "application/json",
                "Content-Length": str(len(raw)),
            },
        )
        with urllib.request.urlopen(req_post, timeout=6) as resp:
            saved = json.loads(resp.read().decode("utf-8"))
        self.assertTrue(saved["ok"])

        raw_recall = json.dumps({
            "action": "recall_episodes",
            "query": "deskryptorów bwrap",
            "kind": "bugfix",
        }).encode("utf-8")
        req_recall = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/mission/action",
            data=raw_recall,
            method="POST",
            headers={
                "Host": f"127.0.0.1:{self.port}",
                "Origin": f"http://127.0.0.1:{self.port}",
                "Content-Type": "application/json",
                "Content-Length": str(len(raw_recall)),
            },
        )
        with urllib.request.urlopen(req_recall, timeout=6) as resp:
            recalled = json.loads(resp.read().decode("utf-8"))
        self.assertEqual(len(recalled["episodes"]), 1)
        self.assertIn("stderr", recalled["episodes"][0]["summary"])


if __name__ == "__main__":
    unittest.main()
