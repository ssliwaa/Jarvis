"""End-to-end tests for Wave-3 Security Gate & Mission Control UI upgrades:
1. `security_scanner` secret-leak detection (Anthropic, OpenAI, GitHub, PEM) & masking
2. `security_scanner` Python AST sink detection (`shell=True`, `os.system`, `pickle.loads`, `yaml.load`)
3. Live Jarvis repository clean scan (`0` critical/high findings) + `qa_gate` on updated `viewer/mission.js`
4. `agent_team.run_deterministic_gate()` blocking leaked secrets before review/merge
5. HTTP `POST /mission/action` (`security_scan`)
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
import agent_team
import qa_gate
import security_scanner
import server

REPO_ROOT = Path(__file__).resolve().parent.parent


def _find_handler_class():
    for val in vars(server).values():
        if isinstance(val, type) and issubclass(val, BaseHTTPRequestHandler) and val is not BaseHTTPRequestHandler:
            return val
    raise RuntimeError("Could not locate HTTP handler class in server.py")


@unittest.skipIf(SANDBOXED, "needs the developer's local env (vault/Hermes/Piper/desktop); skipped in CI")
class Wave3SecurityAndUiTests(unittest.TestCase):
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
        self.proj_root.mkdir(parents=True, exist_ok=True)

        handler_cls = _find_handler_class()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        self.httpd.app = SimpleNamespace(root=self.proj_root)
        self.port = self.httpd.server_port
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def test_1_security_scanner_catches_secrets_and_dangerous_ast_sinks(self):
        bad_dir = self.base / "bad_repo"
        bad_dir.mkdir()
        # Construct synthetic key tokens dynamically so static scanners ignore test source
        fake_ant = "sk-ant-api03-" + ("A" * 28)
        fake_gh = "ghp_" + ("B" * 34)
        (bad_dir / "leaked.py").write_text(
            f'import os, pickle, subprocess, yaml\n'
            f'API_KEY = "{fake_ant}"\n'
            f'GH_TOKEN = "{fake_gh}"\n'
            f'subprocess.run("ls -la", shell=True)\n'
            f'os.system("whoami")\n'
            f'pickle.loads(b"123")\n'
            f'yaml.load("a: 1")\n',
            encoding="utf-8",
        )
        res = security_scanner.scan_directory(bad_dir)
        self.assertFalse(res["ok"])
        kinds = {f["kind"] for f in res["findings"]}
        self.assertIn("secret_anthropic_key", kinds)
        self.assertIn("secret_github_pat", kinds)
        self.assertIn("ast_shell_true", kinds)
        self.assertIn("ast_os_system", kinds)
        self.assertIn("ast_pickle_loads", kinds)
        self.assertIn("ast_yaml_unsafe_load", kinds)
        # Ensure secret value is masked in findings output
        for f in res["findings"]:
            self.assertNotIn(fake_ant, f["detail"])

    def test_2_live_jarvis_repo_passes_security_scan_and_viewer_qa(self):
        sec = security_scanner.scan_directory(REPO_ROOT, include_tests=False)
        self.assertTrue(sec["ok"], f"Live Jarvis repo triggered security findings: {sec['findings']}")
        self.assertGreater(sec["scanned_files"], 40)

        qa = qa_gate.audit_viewer(REPO_ROOT)
        self.assertTrue(qa["ok"], f"Updated viewer/mission.js failed QA gate: {qa['issues']}")

    def test_3_agent_team_gate_blocks_secret_leak_and_http_action_scans(self):
        created = agent_team.create_project("Test bramki bezpieczeństwa", participants=["hermes"], use_worktrees=False)
        pid = created["id"]
        repo = agent_team.project_root(pid) / "repo"
        fake_oai = "sk-proj-" + ("Z" * 28)
        (repo / "app.py").write_text(f'TOKEN = "{fake_oai}"\n', encoding="utf-8")

        gate = agent_team.run_deterministic_gate(pid)
        self.assertFalse(gate["ok"])
        self.assertIn("secret_openai_key", gate["output"])

        # Clean project scans OK via HTTP POST /mission/action
        (self.proj_root / "clean.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        raw = json.dumps({"action": "security_scan", "project_dir": str(self.proj_root)}).encode("utf-8")
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
        self.assertEqual(out["findings_count"], 0)


if __name__ == "__main__":
    unittest.main()
