"""End-to-end tests for Single-Instance Port Recovery (`Errno 98`) & Auto-Reload:
1. `instance_reload.instance_status` detecting fresh vs stale `.py` source files
2. `handle_address_in_use` attaching/reloading cleanly instead of crashing with `Errno 98`
3. HTTP `GET /mission/instance` + `POST /mission/reload` Origin guard
4. JS syntax verification of `desktop/main.js` (`node --check` when Node is present)
"""

import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import instance_reload
import server

REPO_ROOT = Path(__file__).resolve().parent.parent


def _find_handler_class():
    for val in vars(server).values():
        if isinstance(val, type) and issubclass(val, BaseHTTPRequestHandler) and val is not BaseHTTPRequestHandler:
            return val
    raise RuntimeError("Could not locate HTTP handler class in server.py")


class Wave11InstanceReloadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/tmp" if Path("/tmp").is_dir() else None)
        self.addCleanup(self.tmp.cleanup)
        self.proj_root = Path(self.tmp.name) / "proj"
        self.proj_root.mkdir(parents=True, exist_ok=True)
        (self.proj_root / "mod.py").write_text("x = 1\n", encoding="utf-8")

        handler_cls = _find_handler_class()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        self.httpd.app = SimpleNamespace(root=self.proj_root)
        self.port = self.httpd.server_port
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def test_1_instance_status_detects_stale_sources_and_serves_http(self):
        old_ts = instance_reload.BOOT_TIME - 30.0
        os.utime(self.proj_root / "mod.py", (old_ts, old_ts))
        st_fresh = instance_reload.instance_status(self.proj_root)
        self.assertFalse(st_fresh["stale"])

        future_ts = instance_reload.BOOT_TIME + 10.0
        os.utime(self.proj_root / "mod.py", (future_ts, future_ts))
        st_stale = instance_reload.instance_status(self.proj_root)
        self.assertTrue(st_stale["stale"])

        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/mission/instance",
            headers={"Host": f"127.0.0.1:{self.port}"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        self.assertTrue(body["ok"])
        self.assertIn("boot_time", body)
        self.assertTrue(body["stale"])

    def test_2_address_in_use_recovery_and_reload_origin_guard(self):
        # Simulate fresh code on running test server + healthy `/health`
        old_ts = instance_reload.BOOT_TIME - 30.0
        os.utime(self.proj_root / "mod.py", (old_ts, old_ts))
        with patch.object(instance_reload, "wait_for_healthy", return_value=True):
            recovered = instance_reload.handle_address_in_use("127.0.0.1", self.port, self.proj_root)
        self.assertTrue(recovered)

        # Foreign Origin on `/mission/reload` is rejected (`403`)
        bad_req = urllib.request.Request(
            f"http://127.0.0.1:{server.PORT}/mission/reload",
            data=b"{}",
            method="POST",
            headers={"Host": f"127.0.0.1:{self.port}", "Origin": "https://evil.example"},
        )
        bad_req.full_url = f"http://127.0.0.1:{self.port}/mission/reload"
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(bad_req, timeout=5)
        self.assertEqual(ctx.exception.code, 403)

        # Valid Origin triggers `trigger_self_reload` (mocked so test runner process doesn't execv!)
        # The Origin must name the *actual* serving port: the guard compares it
        # against the Host header, not against the module constant.
        with patch.object(instance_reload, "trigger_self_reload", return_value={"ok": True, "reloading": True}) as m_rel:
            good_req = urllib.request.Request(
                f"http://127.0.0.1:{self.port}/mission/reload",
                data=b"{}",
                method="POST",
                headers={
                    "Host": f"127.0.0.1:{self.port}",
                    "Origin": f"http://127.0.0.1:{self.port}",
                    "Content-Type": "application/json",
                },
            )
            with urllib.request.urlopen(good_req, timeout=5) as resp:
                out = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(out["reloading"])
            m_rel.assert_called_once()

    def test_3_desktop_main_js_syntax_check(self):
        desktop_js = REPO_ROOT / "desktop" / "main.js"
        self.assertTrue(desktop_js.is_file())
        node_bin = shutil.which("node")
        if node_bin:
            proc = subprocess.run(
                [node_bin, "--check", str(desktop_js)],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, f"desktop/main.js syntax error: {proc.stderr}")
        time.sleep(0.01)


class AutoReloadBusyGuardTests(unittest.TestCase):
    """A reload restarts Jarvis and kills the bwrap sandboxes: never do it mid-run."""

    def setUp(self):
        lane = SimpleNamespace(snapshot=lambda: {'running': False})
        self.p_lane = patch('background_lane.get_lane', lambda: lane)
        self.p_lane.start()
        self.addCleanup(self.p_lane.stop)

    def test_a_running_single_agent_counts_as_busy(self):
        with patch('agent_cli.agent_ids', lambda: ['hermes']), \
             patch('agent_cli.live_progress', lambda aid: {'running': True}):
            self.assertTrue(instance_reload._any_agent_busy())

    def test_an_active_team_wave_counts_as_busy(self):
        with patch('agent_cli.agent_ids', lambda: []), \
             patch('agent_team.active_waves', lambda: [{'id': 'room', 'agents': ['opencode']}]):
            self.assertTrue(instance_reload._any_agent_busy())

    def test_idle_agents_do_not_block_a_reload(self):
        with patch('agent_cli.agent_ids', lambda: ['hermes']), \
             patch('agent_cli.live_progress', lambda aid: {'running': False}), \
             patch('agent_team.active_waves', lambda: []):
            self.assertFalse(instance_reload._any_agent_busy())


if __name__ == "__main__":
    unittest.main()
