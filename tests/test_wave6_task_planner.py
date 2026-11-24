"""End-to-end tests for Wave-6 AST- & Hardware-Aware Multi-Agent Task Planner:
1. Disjoint file partitioning across `backend`, `frontend`, and `qa` workstreams
2. 1-hop AST `imported_by` neighbor expansion & `server.py` / `viewer/` risk warnings
3. Thermal concurrency cap (`max_parallel_agents == 1` when `warm`) & budget tier discount
4. HTTP `POST /mission/action` (`plan_task`) + `qa_gate.audit_viewer` on updated `viewer/mission.js`
"""

import json
import tempfile
import threading
import os
import unittest
SANDBOXED = os.environ.get("JARVIS_VERIFY_SANDBOX") == "1"
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import agent_cli
import budget_guard
import code_index
import episodic_memory
import hardware_guard
import qa_gate
import server
import task_planner

REPO_ROOT = Path(__file__).resolve().parent.parent


def _find_handler_class():
    for val in vars(server).values():
        if isinstance(val, type) and issubclass(val, BaseHTTPRequestHandler) and val is not BaseHTTPRequestHandler:
            return val
    raise RuntimeError("Could not locate HTTP handler class in server.py")


@unittest.skipIf(SANDBOXED, "needs the developer's local env (vault/Hermes/Piper/desktop); skipped in CI")
class Wave6TaskPlannerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/tmp" if Path("/tmp").is_dir() else None)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.agents_dir = self.base / "state" / ".jarvis-tools" / "agents"
        self.agents_dir.mkdir(parents=True, exist_ok=True)
        self.p_agents = patch.object(agent_cli, "ROOT", self.agents_dir)
        self.p_agents.start()
        self.addCleanup(self.p_agents.stop)

        code_index.evict_idle_cache(force=True)
        self.proj_root = self.base / "proj"
        (self.proj_root / "viewer").mkdir(parents=True, exist_ok=True)
        (self.proj_root / "tests").mkdir(parents=True, exist_ok=True)

        (self.proj_root / "billing_engine.py").write_text(
            "def calculate_invoice_export(items):\n    return sum(items)\n",
            encoding="utf-8",
        )
        (self.proj_root / "server.py").write_text(
            "import billing_engine\n\ndef route_invoice():\n    return billing_engine.calculate_invoice_export([1, 2])\n",
            encoding="utf-8",
        )
        (self.proj_root / "viewer" / "billing_panel.js").write_text(
            "function renderInvoiceExport() { return true; }\n",
            encoding="utf-8",
        )
        (self.proj_root / "tests" / "test_billing_export.py").write_text(
            "def test_calculate_invoice_export():\n    assert True\n",
            encoding="utf-8",
        )

        handler_cls = _find_handler_class()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        self.httpd.app = SimpleNamespace(root=self.proj_root)
        self.port = self.httpd.server_port
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def test_1_disjoint_workstreams_ast_expansion_and_thermal_budget_caps(self):
        episodic_memory.remember_episode(
            title="Eksport faktur PDF",
            summary="Używaj strumieniowego zapisu przy calculate_invoice_export.",
            kind="decision",
        )
        budget_guard.configure_limits(daily_limit_usd=1.00, soft_ratio=0.80)
        budget_guard.record_spend(model="claude-sonnet", usd=0.85, source="test")

        warm_hw = {
            "ok": True,
            "state": "warm",
            "reasons": ["wysoka temperatura czujnika (81.0°C)"],
            "peak_temp_c": 81.0,
            "sensors": [],
            "mem_total_mb": 16000.0,
            "mem_available_mb": 4000.0,
            "swap_used_mb": 0.0,
            "recommended_max_parallel_agents": 1,
            "allow_heavy_background": True,
        }
        with patch.object(hardware_guard, "snapshot", return_value=warm_hw):
            plan = task_planner.plan_goal(
                "Rozbuduj calculate_invoice_export oraz renderInvoiceExport",
                project_dir=self.proj_root,
            )

        self.assertTrue(plan["ok"])
        self.assertEqual(plan["max_parallel_agents"], 1)
        self.assertEqual(plan["budget_tier"], "economy_cloud")
        # 1-hop AST neighbor `server.py` (which imports `billing_engine`) is discovered automatically
        self.assertIn("server.py", plan["impacted_files"])
        self.assertTrue(any("server.py" in r for r in plan["risks"]))
        self.assertTrue(any("viewer/" in r for r in plan["risks"]))
        self.assertGreaterEqual(len(plan["recalled_episodes"]), 1)

        # Verify strict file disjointness across all assigned workstreams
        seen_paths: set[str] = set()
        roles = set()
        for stream in plan["assignments"]:
            roles.add(stream["role"])
            for p in stream["paths"]:
                self.assertNotIn(p, seen_paths, f"Duplicate path {p} across workstreams!")
                seen_paths.add(p)
        self.assertEqual(roles, {"backend", "frontend", "qa"})
        # With `max_parallel_agents == 1` and 2 implementation streams + 1 QA stream -> 3 sequential waves
        self.assertEqual(len(plan["waves"]), 3)
        self.assertEqual(plan["waves"][-1][0]["role"], "qa")

    def test_2_http_plan_task_action_and_live_viewer_qa(self):
        qa = qa_gate.audit_viewer(REPO_ROOT)
        self.assertTrue(qa["ok"], f"Updated viewer/mission.js failed QA gate: {qa['issues']}")

        raw = json.dumps({
            "action": "plan_task",
            "project_dir": str(self.proj_root),
            "goal": "Dodaj walidację w calculate_invoice_export",
        }).encode("utf-8")
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
        with urllib.request.urlopen(req, timeout=6) as resp:
            out = json.loads(resp.read().decode("utf-8"))
        self.assertTrue(out["ok"])
        self.assertGreaterEqual(len(out["assignments"]), 2)


if __name__ == "__main__":
    unittest.main()
