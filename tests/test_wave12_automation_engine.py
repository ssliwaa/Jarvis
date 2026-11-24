"""End-to-end tests for Wave-12 Live Cron Scheduler, Preset Routines & Reactive Rules:
1. 5-field Cron (`*/15 * * * *`, `30 8 * * 1-5`) & human schedules (`every 5m`, `daily 08:30`)
   + same-minute deduplication
2. `tick_due_jobs`, `install_preset`, Obsidian delivery (`deliver='obsidian'`), DND push suppression,
   and reactive `hardware.alert` -> `episodic_memory` auto-capture
3. HTTP `POST /mission/action` (`automation_preset`, `automation_run_now`, `automation_status`)
   + live `sync_viewer_sri(fix=True)`, `qa_gate.audit_viewer`, and `security_scanner`
"""

import json
import tempfile
import threading
import os
import unittest
SANDBOXED = os.environ.get("JARVIS_VERIFY_SANDBOX") == "1"
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import agent_cli
import automation_engine
import change_impact
import connectors_hub
import episodic_memory
import event_bus
import hardware_guard
import qa_gate
import security_scanner
import server
import wayland_voice

REPO_ROOT = Path(__file__).resolve().parent.parent


def _find_handler_class():
    for val in vars(server).values():
        if isinstance(val, type) and issubclass(val, BaseHTTPRequestHandler) and val is not BaseHTTPRequestHandler:
            return val
    raise RuntimeError("Could not locate HTTP handler class in server.py")


@unittest.skipIf(SANDBOXED, "needs the developer's local env (vault/Hermes/Piper/desktop); skipped in CI")
class Wave12AutomationEngineTests(unittest.TestCase):
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
        automation_engine._RULES_INSTALLED = False
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

    def test_1_cron_and_human_schedule_matching_with_deduplication(self):
        # Monday 2026-11-16 08:30:10 local time
        monday_830 = datetime(2026, 11, 16, 8, 30, 10)
        sunday_830 = datetime(2026, 11, 15, 8, 30, 10)

        self.assertTrue(automation_engine.matches_cron_5("30 8 * * 1-5", monday_830))
        self.assertFalse(automation_engine.matches_cron_5("30 8 * * 1-5", sunday_830))
        self.assertTrue(automation_engine.matches_cron_5("*/15 * * * *", monday_830))

        ts = monday_830.timestamp()
        job = {"enabled": True, "schedule": "weekdays 08:30", "last_run_at": 0.0}
        self.assertTrue(automation_engine.is_job_due(job, now_ts=ts))
        # Same calendar minute -> not due again!
        job["last_run_at"] = ts
        self.assertFalse(automation_engine.is_job_due(job, now_ts=ts + 25.0))

        # Interval schedule `every 5m`
        ijob = {"enabled": True, "schedule": "every 5m", "last_run_at": ts}
        self.assertFalse(automation_engine.is_job_due(ijob, now_ts=ts + 120.0))
        self.assertTrue(automation_engine.is_job_due(ijob, now_ts=ts + 305.0))

    def test_2_due_execution_obsidian_delivery_dnd_and_reactive_rules(self):
        obs_vault = self.base / "obs"
        obs_vault.mkdir(parents=True)
        connectors_hub.configure_connector("obsidian", "obsidian", {"vault_path": str(obs_vault)})

        nominal_hw = {
            "ok": True,
            "state": "nominal",
            "reasons": [],
            "peak_temp_c": 48.0,
            "sensors": [],
            "mem_total_mb": 16000.0,
            "mem_available_mb": 9000.0,
            "swap_used_mb": 0.0,
            "recommended_max_parallel_agents": 3,
            "allow_heavy_background": True,
        }
        with patch.object(hardware_guard, "snapshot", return_value=nominal_hw):
            created = automation_engine.create_automation(
                "Kontrola dysków do Obsidiana",
                "every 1m",
                action_type="storage_check",
                deliver="obsidian",
            )
            self.assertTrue(created["ok"])
            tick = automation_engine.tick_due_jobs(self.proj_root)
            self.assertEqual(tick["executed_count"], 1)

        notes = connectors_hub.execute_connector_action("obsidian_search", {"query": "Kontrola dysków"})
        self.assertEqual(notes["count"], 1)

        # DND suppresses external push channels (`telegram`)
        with patch.object(wayland_voice, "dnd_status", return_value={"active": True}):
            sup = automation_engine._deliver_summary("telegram", "Test", "Treść")
        self.assertEqual(sup, "suppressed_dnd")

        # Reactive rule captures critical `hardware.alert` into `episodic_memory`
        automation_engine.install_reactive_event_rules()
        event_bus.publish("hardware.alert", {"state": "critical", "peak_temp_c": 92.5, "mem_available_mb": 300, "reasons": ["92.5°C"]})
        incidents = episodic_memory.recall_episodes("92.5", limit=5)
        self.assertGreaterEqual(len(incidents), 1)

    def test_3_http_automation_actions_and_live_repo_gates(self):
        sri = change_impact.sync_viewer_sri(REPO_ROOT, fix=True)
        self.assertTrue(sri["ok"])
        qa = qa_gate.audit_viewer(REPO_ROOT)
        self.assertTrue(qa["ok"], f"Viewer QA failed: {qa['issues']}")
        sec = security_scanner.scan_directory(REPO_ROOT, include_tests=False)
        self.assertTrue(sec["ok"], f"Security scan findings: {sec['findings']}")

        def _post(payload: dict) -> dict:
            raw = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
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
            with urllib.request.urlopen(req, timeout=8) as resp:
                return json.loads(resp.read().decode("utf-8"))

        pres = _post({"action": "automation_preset", "preset_id": "storage_watch"})
        self.assertTrue(pres["ok"])
        jid = pres["job"]["id"]

        ran = _post({"action": "automation_run_now", "job_id": jid, "project_dir": str(self.proj_root)})
        self.assertTrue(ran["ok"])
        self.assertEqual(ran["job"]["run_count"], 1)

        st = _post({"action": "automation_status"})
        self.assertEqual(st["total_jobs"], 1)


if __name__ == "__main__":
    unittest.main()
