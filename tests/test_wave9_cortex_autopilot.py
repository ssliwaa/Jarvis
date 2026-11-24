"""End-to-end tests for Wave-9 XL: Jarvis Cortex Knowledge Graph & 7-Stage Autopilot:
1. `knowledge_graph` AST harvesting (modules, classes, HTTP routes, SSE pub/sub, SQLite DBs)
   + circular-import cycle detector + semantic triples + 2-hop BFS `query_subgraph`
2. `autopilot_engine` 7-stage state machine (`SPEC -> PREFLIGHT -> CONTEXT -> DISPATCH ->
   BLAST_VERIFY -> SECURITY_AND_SRI -> MEMORY_COMMIT`) + thermal preflight abort
3. Live `REPO_ROOT` Cortex build + `sync_viewer_sri(fix=True)` + `qa_gate.audit_viewer`
4. HTTP `GET /mission/graph`, `GET /mission/autopilot`, and `POST /mission/action` (`autopilot_run`)
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
import autopilot_engine
import change_impact
import code_index
import episodic_memory
import event_bus
import hardware_guard
import knowledge_graph
import qa_gate
import server

REPO_ROOT = Path(__file__).resolve().parent.parent


def _find_handler_class():
    for val in vars(server).values():
        if isinstance(val, type) and issubclass(val, BaseHTTPRequestHandler) and val is not BaseHTTPRequestHandler:
            return val
    raise RuntimeError("Could not locate HTTP handler class in server.py")


@unittest.skipIf(SANDBOXED, "needs the developer's local env (vault/Hermes/Piper/desktop); skipped in CI")
class Wave9CortexAutopilotTests(unittest.TestCase):
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
        (self.proj_root / "viewer").mkdir(parents=True, exist_ok=True)
        (self.proj_root / "tests").mkdir(parents=True, exist_ok=True)

        # Synthetic mini-project with routes, SSE pub/sub, SQLite DB, and a circular import (alpha <-> beta)
        (self.proj_root / "alpha_service.py").write_text(
            "import beta_worker\nimport event_bus\n\n"
            "DB_FILE = 'alpha_store.sqlite3'\n"
            "ROUTE = '/mission/custom-alpha'\n\n"
            "class AlphaController:\n"
            "    def emit(self):\n"
            "        event_bus.publish('alpha.ready', {'ok': True})\n",
            encoding="utf-8",
        )
        (self.proj_root / "beta_worker.py").write_text(
            "import alpha_service\nimport event_bus\n\n"
            "def register():\n"
            "    event_bus.subscribe('alpha.ready', lambda e: None)\n",
            encoding="utf-8",
        )
        (self.proj_root / "viewer" / "app.js").write_text("'use strict';\nconst x = 1;\n", encoding="utf-8")
        (self.proj_root / "viewer" / "capabilities.js").write_text("'use strict';\n", encoding="utf-8")
        (self.proj_root / "viewer" / "index.html").write_text(
            '<!doctype html><html><head></head><body>'
            '<script src="app.js"></script><script src="capabilities.js"></script>'
            '</body></html>\n',
            encoding="utf-8",
        )
        (self.proj_root / "tests" / "test_alpha.py").write_text(
            "import alpha_service\n",
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

    def test_1_cortex_graph_harvests_topology_detects_cycles_and_queries_triples(self):
        built = knowledge_graph.rebuild_code_graph(self.proj_root)
        self.assertTrue(built["ok"])
        by_kind = built["by_kind"]
        self.assertGreaterEqual(by_kind.get("module", 0), 2)
        self.assertGreaterEqual(by_kind.get("class", 0), 1)
        self.assertGreaterEqual(by_kind.get("http_route", 0), 1)
        self.assertGreaterEqual(by_kind.get("sse_topic", 0), 1)
        self.assertGreaterEqual(by_kind.get("sqlite_db", 0), 1)

        # Circular import alpha_service <-> beta_worker is caught deterministically
        cycles = built["anomalies"]["circular_imports"]
        self.assertEqual(len(cycles), 1)
        self.assertIn("alpha_service.py", cycles[0])
        self.assertIn("beta_worker.py", cycles[0])

        # Semantic domain triple + 2-hop BFS
        knowledge_graph.upsert_triple("ThinkCentre_M720q", "hosts_service", "mod:alpha_service.py")
        sub = knowledge_graph.query_subgraph("ThinkCentre_M720q", hops=2)
        node_ids = {n["id"] for n in sub["nodes"]}
        self.assertIn("mod:alpha_service.py", node_ids)
        self.assertIn("topic:alpha.ready", node_ids)

    def test_2_seven_stage_autopilot_executes_and_blocks_on_critical_thermal(self):
        nominal_hw = {
            "ok": True,
            "state": "nominal",
            "reasons": [],
            "peak_temp_c": 52.0,
            "sensors": [],
            "mem_total_mb": 16000.0,
            "mem_available_mb": 9000.0,
            "swap_used_mb": 0.0,
            "recommended_max_parallel_agents": 3,
            "allow_heavy_background": True,
        }
        with patch.object(hardware_guard, "snapshot", return_value=nominal_hw):
            res = autopilot_engine.run_autopilot(
                "Rozbuduj AlphaController i trasę /mission/custom-alpha",
                self.proj_root,
                execute_team=False,
            )

        self.assertTrue(res["ok"])
        self.assertEqual(len(res["stages"]), 7)
        stage_names = [s["stage"] for s in res["stages"]]
        self.assertEqual(stage_names, [
            "SPEC_AND_GRAPH",
            "PREFLIGHT_GUARD",
            "CONTEXT_BLUEPRINT",
            "DISPATCH_EXECUTION",
            "BLAST_RADIUS_VERIFY",
            "SECURITY_AND_SRI",
            "MEMORY_COMMIT",
        ])
        self.assertIn("# Specyfikacja Autopilota:", res["spec_markdown"])
        self.assertIn("tests/test_alpha.py", res["blast_radius"]["selected_tests"])

        # Episodic memory + SSE events recorded
        recalled = episodic_memory.recall_episodes("AlphaController", limit=5)
        self.assertGreaterEqual(len(recalled), 1)
        topics = [e["topic"] for e in event_bus.recent(after_id=0, limit=30)]
        self.assertIn("autopilot.stage", topics)
        self.assertIn("autopilot.completed", topics)

        # Critical thermal state blocks at stage 2 (`PREFLIGHT_GUARD`)
        crit_hw = {**nominal_hw, "state": "critical", "reasons": ["93.0°C"]}
        with patch.object(hardware_guard, "snapshot", return_value=crit_hw):
            blocked = autopilot_engine.run_autopilot("Test blokady termicznej", self.proj_root)
        self.assertFalse(blocked["ok"])
        self.assertEqual(blocked["status"], "blocked_preflight")
        self.assertEqual(blocked["stages"][-1]["stage"], "PREFLIGHT_GUARD")

    def test_3_live_jarvis_cortex_sri_qa_and_http_routes(self):
        # Synchronize SRI in live repo after viewer/mission.js updates & run QA gate
        sri = change_impact.sync_viewer_sri(REPO_ROOT, fix=True)
        self.assertTrue(sri["ok"])
        qa = qa_gate.audit_viewer(REPO_ROOT)
        self.assertTrue(qa["ok"], f"Live viewer QA issues: {qa['issues']}")

        live_kg = knowledge_graph.rebuild_code_graph(REPO_ROOT)
        self.assertGreater(live_kg["total_nodes"], 60)

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

        ap = _post({
            "action": "autopilot_run",
            "project_dir": str(self.proj_root),
            "goal": "Sprawdź AlphaController",
            "execute_team": False,
        })
        self.assertTrue(ap["ok"])

        req_g = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/mission/graph?q=alpha",
            headers={"Host": f"127.0.0.1:{self.port}"},
            method="GET",
        )
        with urllib.request.urlopen(req_g, timeout=6) as resp:
            g_body = json.loads(resp.read().decode("utf-8"))
        self.assertTrue(g_body["ok"])
        self.assertGreaterEqual(len(g_body["subgraph"]["nodes"]), 1)

        req_ap = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/mission/autopilot",
            headers={"Host": f"127.0.0.1:{self.port}"},
            method="GET",
        )
        with urllib.request.urlopen(req_ap, timeout=6) as resp:
            ap_body = json.loads(resp.read().decode("utf-8"))
        self.assertTrue(ap_body["ok"])
        self.assertGreaterEqual(len(ap_body["runs"]), 1)


if __name__ == "__main__":
    unittest.main()
