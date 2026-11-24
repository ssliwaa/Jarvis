"""End-to-end tests for Wave-8 AST Blast-Radius Test Selector & Viewer SRI Synchronizer:
1. 2-hop reverse-import AST blast radius (`core_math.py -> api_layer.py -> tests/test_api.py`)
2. `sync_viewer_sri` detecting & auto-healing stale `sha384-...` attributes in `viewer/index.html`
3. `system_doctor.run_diagnostics(auto_heal=True)` healing broken SRI + live `REPO_ROOT` SRI check
4. HTTP `POST /mission/action` (`blast_radius`, `sync_sri`)
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
import change_impact
import server
import system_doctor

REPO_ROOT = Path(__file__).resolve().parent.parent


def _find_handler_class():
    for val in vars(server).values():
        if isinstance(val, type) and issubclass(val, BaseHTTPRequestHandler) and val is not BaseHTTPRequestHandler:
            return val
    raise RuntimeError("Could not locate HTTP handler class in server.py")


class Wave8BlastRadiusAndSriTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/tmp" if Path("/tmp").is_dir() else None)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.agents_dir = self.base / "state" / ".jarvis-tools" / "agents"
        self.agents_dir.mkdir(parents=True, exist_ok=True)
        self.p_agents = patch.object(agent_cli, "ROOT", self.agents_dir)
        self.p_agents.start()
        self.addCleanup(self.p_agents.stop)

        self.proj_root = self.base / "proj"
        (self.proj_root / "viewer").mkdir(parents=True, exist_ok=True)
        (self.proj_root / "tests").mkdir(parents=True, exist_ok=True)

        # Build 2-hop dependency chain: core_math <- api_layer <- tests/test_api
        (self.proj_root / "core_math.py").write_text("def double(x):\n    return x * 2\n", encoding="utf-8")
        (self.proj_root / "api_layer.py").write_text("import core_math\n\ndef run():\n    return core_math.double(3)\n", encoding="utf-8")
        (self.proj_root / "unrelated_mod.py").write_text("def noop():\n    return None\n", encoding="utf-8")
        (self.proj_root / "tests" / "test_api.py").write_text("import api_layer\n", encoding="utf-8")
        (self.proj_root / "tests" / "test_unrelated.py").write_text("import unrelated_mod\n", encoding="utf-8")

        # Viewer assets with intentionally stale sha384 SRI hash
        (self.proj_root / "viewer" / "app.js").write_text("'use strict';\nconst ok = 1;\n", encoding="utf-8")
        (self.proj_root / "viewer" / "capabilities.js").write_text("'use strict';\n", encoding="utf-8")
        (self.proj_root / "viewer" / "index.html").write_text(
            '<!doctype html><html><head></head><body>'
            '<script src="app.js" integrity="sha384-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"></script>'
            '<script src="capabilities.js"></script>'
            '</body></html>\n',
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

    def test_1_two_hop_blast_radius_selects_only_impacted_tests(self):
        blast = change_impact.analyze_blast_radius(self.proj_root, changed_files=["core_math.py"])
        self.assertTrue(blast["ok"])
        self.assertIn("api_layer.py", blast["affected_modules"])
        self.assertEqual(blast["selected_tests"], ["tests/test_api.py"])
        self.assertNotIn("tests/test_unrelated.py", blast["selected_tests"])
        # Stale SRI on app.js is detected in the same pass
        self.assertFalse(blast["sri"]["ok"])
        self.assertEqual(len(blast["sri"]["mismatches"]), 1)

    def test_2_system_doctor_and_live_repo_sri_auto_sync(self):
        diag = system_doctor.run_diagnostics(project_dir=self.proj_root, auto_heal=True)
        self.assertTrue(diag["sri_ok"])
        self.assertTrue(any("SRI" in a for a in diag["healed_actions"]))

        recheck = change_impact.sync_viewer_sri(self.proj_root, fix=False)
        self.assertTrue(recheck["ok"])
        self.assertEqual(recheck["mismatches"], [])

        # Ensure live Jarvis repository has 100% synchronized SRI hashes (healing if viewer/mission.js changed)
        live_sri = change_impact.sync_viewer_sri(REPO_ROOT, fix=True)
        self.assertTrue(live_sri["ok"], f"Live viewer/index.html SRI mismatch: {live_sri}")

    def test_3_http_blast_radius_and_sync_sri_actions(self):
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
            with urllib.request.urlopen(req, timeout=6) as resp:
                return json.loads(resp.read().decode("utf-8"))

        fixed = _post({"action": "sync_sri", "project_dir": str(self.proj_root), "fix": True})
        self.assertTrue(fixed["ok"])
        self.assertEqual(fixed["updated"], 1)

        br = _post({
            "action": "blast_radius",
            "project_dir": str(self.proj_root),
            "changed_files": ["core_math.py"],
        })
        self.assertTrue(br["ok"])
        self.assertEqual(br["selected_tests"], ["tests/test_api.py"])
        self.assertTrue(br["sri"]["ok"])


if __name__ == "__main__":
    unittest.main()
