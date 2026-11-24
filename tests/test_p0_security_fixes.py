"""Regression tests for the 4 P0 security and UI contract fixes."""

import json
import os
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
import agent_consent
import code_index
import server


def _find_handler_class():
    for val in vars(server).values():
        if isinstance(val, type) and issubclass(val, BaseHTTPRequestHandler) and val is not BaseHTTPRequestHandler:
            return val
    raise RuntimeError("Could not locate HTTP handler class in server.py")


class P0SecurityFixesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/tmp" if Path("/tmp").is_dir() else None)
        self.addCleanup(self.tmp.cleanup)
        self.proj_root = Path(self.tmp.name) / "workspace"
        self.proj_root.mkdir(parents=True, exist_ok=True)
        (self.proj_root / "hello.py").write_text("X = 1\n", encoding="utf-8")

        self.agents_dir = Path(self.tmp.name) / "state" / ".jarvis-tools" / "agents"
        self.agents_dir.mkdir(parents=True, exist_ok=True)
        self.p_agents = patch.object(agent_cli, "ROOT", self.agents_dir)
        self.p_agents.start()
        self.addCleanup(self.p_agents.stop)

        handler_cls = _find_handler_class()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        self.httpd.app = SimpleNamespace(root=self.proj_root)
        self.port = self.httpd.server_port
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def _req(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        url = f"http://127.0.0.1:{self.port}{path}"
        headers = {
            "Host": f"127.0.0.1:{self.port}",
            "Origin": f"http://127.0.0.1:{self.port}",
            "Accept": "application/json",
        }
        data = None
        if body is not None:
            raw = json.dumps(body).encode("utf-8")
            data = raw
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(raw))
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read().decode("utf-8"))

    def test_p0_1_agents_run_rejects_missing_consent_and_accepts_valid_token(self):
        called = []
        with patch.object(agent_cli, "run", side_effect=lambda *a, **kw: called.append((a, kw))):
            # Missing consent token MUST be rejected with 403
            code, payload = self._req("POST", "/agents/run", {"agent": "claude", "task": "Fix tests"})
            self.assertEqual(code, 403)
            self.assertTrue(payload.get("consent_required"))
            self.assertEqual(called, [])

            # Valid one-time consent token succeeds with 202
            grant = agent_consent.grant_click("claude", "Fix tests")
            code_ok, payload_ok = self._req(
                "POST", "/agents/run",
                {"agent": "claude", "task": "Fix tests", "consent": grant["token"]},
            )
            self.assertEqual(code_ok, 202)
            self.assertTrue(payload_ok.get("started"))

    def test_p0_2_mission_js_uses_valid_endpoints_and_rollback_defaults_target(self):
        mission_js = (Path(__file__).resolve().parent.parent / "viewer" / "mission.js").read_text(encoding="utf-8")
        self.assertIn("'/agents/apply'", mission_js)
        self.assertIn("'/agents/team/start'", mission_js)
        self.assertNotIn("apiPost('/agents/team'", mission_js)

        targets_seen = []
        with patch("agent_review.rollback_last_checkpoint",
                   side_effect=lambda tgt, commit_hash="": (targets_seen.append(tgt) or {"ok": True, "restored_to": "abc1234"})):
            code, body = self._req("POST", "/agents/rollback", {})
        self.assertEqual(code, 200)
        self.assertEqual(targets_seen, [str(self.proj_root)])
        self.assertEqual(body.get("restored_to"), "abc1234")

    def test_p0_3_validate_safe_project_dir_blocks_etc_ssh_hermes_and_jarvis_tools(self):
        for bad in ("/etc", "~/.ssh", "~/.hermes", "~/.jarvis-tools", str(self.agents_dir)):
            with self.assertRaises(ValueError):
                code_index.validate_safe_project_dir(bad)

        # HTTP GET /agents/context?root=/etc returns 400 FORBIDDEN_PATH
        code, body = self._req("GET", "/agents/context?q=password&root=/etc")
        self.assertEqual(code, 400)
        self.assertEqual((body.get("error") or {}).get("code"), "FORBIDDEN_PATH")

        # Valid project directory succeeds
        valid = code_index.validate_safe_project_dir(self.proj_root)
        self.assertEqual(valid, self.proj_root.resolve())

    def test_p0_3b_team_workspace_under_jarvis_tools_projects_is_indexable(self):
        # The team workspace lives under ~/.jarvis-tools/projects. Treating all of
        # ~/.jarvis-tools as forbidden silently disabled the code-context pack for
        # every team prompt, while secrets next to it must stay blocked.
        fake_home = Path(self.tmp.name) / "fake-home"
        room = fake_home / ".jarvis-tools" / "projects" / "room"
        room.mkdir(parents=True)
        (room / "main.py").write_text("VALUE = 1\n", encoding="utf-8")

        with patch.dict(os.environ, {"HOME": str(fake_home)}):
            self.assertEqual(code_index.validate_safe_project_dir(room), room.resolve())
            with self.assertRaises(ValueError):
                code_index.validate_safe_project_dir(fake_home / ".jarvis-tools" / "agents")
            with self.assertRaises(ValueError):
                code_index.validate_safe_project_dir(fake_home / ".hermes")

    def test_p0_4_voice_dictate_strips_newlines_and_control_chars_before_xdotool(self):
        captured_argv = []

        def _fake_run(argv, **kwargs):
            captured_argv.append(argv)
            return SimpleNamespace(returncode=0)

        import wayland_voice
        with patch.object(wayland_voice.shutil, "which", side_effect=lambda n: "/usr/bin/xdotool" if n == "xdotool" else None), \
             patch.dict(os.environ, {"DISPLAY": ":0", "XDG_SESSION_TYPE": "x11", "WAYLAND_DISPLAY": ""}), \
             patch.object(wayland_voice.subprocess, "run", side_effect=_fake_run):
            code, body = self._req("POST", "/voice/dictate", {"text": "echo safe\nrm -rf /\r\ndone"})

        self.assertEqual(code, 200)
        self.assertTrue(body.get("typed"))
        self.assertEqual(len(captured_argv), 1)
        typed_arg = captured_argv[0][-1]
        self.assertNotIn("\n", typed_arg)
        self.assertNotIn("\r", typed_arg)
        self.assertEqual(typed_arg, "echo safe rm -rf / done")


if __name__ == "__main__":
    unittest.main()
