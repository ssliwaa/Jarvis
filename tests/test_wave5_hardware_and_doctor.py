"""End-to-end tests for Wave-5 Hardware Thermal Guardian & Self-Healing System Doctor:
1. `hardware_guard` parsing `/sys/class/hwmon` & `/proc/meminfo` + `hardware.alert` SSE event
2. `system_doctor` corrupt SQLite quarantine, `0600` permission healing & stale `.tmp-*` sweep
3. HTTP `GET /mission/doctor` & `POST /mission/action` (`run_doctor`) + updated `viewer/mission.js` QA
"""

import json
import os
SANDBOXED = os.environ.get("JARVIS_VERIFY_SANDBOX") == "1"
import stat
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import agent_cli
import event_bus
import hardware_guard
import qa_gate
import server
import system_doctor

REPO_ROOT = Path(__file__).resolve().parent.parent


def _find_handler_class():
    for val in vars(server).values():
        if isinstance(val, type) and issubclass(val, BaseHTTPRequestHandler) and val is not BaseHTTPRequestHandler:
            return val
    raise RuntimeError("Could not locate HTTP handler class in server.py")


@unittest.skipIf(SANDBOXED, "needs the developer's local env (vault/Hermes/Piper/desktop); skipped in CI")
class Wave5HardwareAndDoctorTests(unittest.TestCase):
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

    def test_1_hardware_guard_detects_thermal_spike_and_emits_sse_alert(self):
        fake_sys = self.base / "fake_sys"
        hw0 = fake_sys / "class" / "hwmon" / "hwmon0"
        hw0.mkdir(parents=True)
        (hw0 / "name").write_text("coretemp\n", encoding="utf-8")
        (hw0 / "temp1_label").write_text("Package id 0\n", encoding="utf-8")
        (hw0 / "temp1_input").write_text("91500\n", encoding="utf-8")

        fake_mem = self.base / "meminfo"
        fake_mem.write_text(
            "MemTotal:       16384000 kB\nMemAvailable:     512000 kB\nSwapTotal:       2048000 kB\nSwapFree:        1024000 kB\n",
            encoding="utf-8",
        )

        snap = hardware_guard.snapshot(sys_root=fake_sys, proc_meminfo=fake_mem)
        self.assertEqual(snap["state"], "critical")
        self.assertAlmostEqual(snap["peak_temp_c"], 91.5)
        self.assertEqual(snap["recommended_max_parallel_agents"], 1)
        self.assertFalse(snap["allow_heavy_background"])

        events = event_bus.recent(after_id=0)
        self.assertTrue(any(e["topic"] == "hardware.alert" for e in events))

    def test_2_system_doctor_heals_corrupt_sqlite_permissions_and_stale_temps(self):
        state_dir = self.agents_dir.parent
        # 1. Write corrupt SQLite header
        corrupt_db = state_dir / "semantic_cache.sqlite3"
        corrupt_db.write_bytes(b"NOT_A_VALID_SQLITE_HEADER_AT_ALL_0000")
        # 2. Permissive ledger permissions (0644)
        ledger = state_dir / "budget_ledger.json"
        ledger.write_text("{}", encoding="utf-8")
        os.chmod(ledger, 0o644)
        # 3. Stale .tmp file
        stale_tmp = state_dir / ".budget_ledger.json.tmp-stale"
        stale_tmp.write_text("partial", encoding="utf-8")
        old_ts = time.time() - 7200
        os.utime(stale_tmp, (old_ts, old_ts))

        diag = system_doctor.run_diagnostics(project_dir=self.proj_root, auto_heal=True, stale_temp_seconds=60.0)
        self.assertTrue(diag["ok"])
        self.assertFalse(corrupt_db.exists())
        self.assertTrue(any(p.name.startswith("semantic_cache.sqlite3.corrupt-") for p in state_dir.iterdir()))
        self.assertEqual(stat.S_IMODE(ledger.stat().st_mode), 0o600)
        self.assertFalse(stale_tmp.exists())
        self.assertGreaterEqual(len(diag["healed_actions"]), 3)

    def test_3_http_doctor_endpoints_and_live_viewer_qa(self):
        qa = qa_gate.audit_viewer(REPO_ROOT)
        self.assertTrue(qa["ok"], f"Updated viewer/mission.js failed QA gate: {qa['issues']}")

        req_get = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/mission/doctor",
            headers={"Host": f"127.0.0.1:{self.port}"},
            method="GET",
        )
        with urllib.request.urlopen(req_get, timeout=6) as resp:
            self.assertEqual(resp.status, 200)
            doc_get = json.loads(resp.read().decode("utf-8"))
        self.assertIn("health_score", doc_get)

        raw = json.dumps({"action": "run_doctor", "project_dir": str(self.proj_root), "auto_heal": True}).encode("utf-8")
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
            doc_post = json.loads(resp.read().decode("utf-8"))
        self.assertTrue(doc_post["ok"])
        self.assertGreaterEqual(doc_post["health_score"], 70)


if __name__ == "__main__":
    unittest.main()
