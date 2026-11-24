"""Tests for P2 architecture, workspace hygiene, and browser CSRF hardening."""

import json
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
import agent_team
import code_index
import mission_routes
import server


def _find_handler_class():
    for val in vars(server).values():
        if isinstance(val, type) and issubclass(val, BaseHTTPRequestHandler) and val is not BaseHTTPRequestHandler:
            return val
    raise RuntimeError("Could not locate HTTP handler class in server.py")


class P2ArchitectureFixesTests(unittest.TestCase):
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

    def test_p2_1_seed_copy_and_code_index_exclude_artifacts_orbit_and_mcp_backups(self):
        src = self.base / "src_repo"
        (src / "src").mkdir(parents=True)
        (src / "src" / "main.py").write_text("def live_fn():\n    return 42\n", encoding="utf-8")

        for noisy in ("artifacts/agent/run1", "viewer/.orbit-backup", ".jarvis-mcp-backups"):
            ndir = src / noisy
            ndir.mkdir(parents=True, exist_ok=True)
            (ndir / "stale.py").write_text("def stale_noise_symbol():\n    return 0\n", encoding="utf-8")

        dst = self.base / "dst_repo"
        agent_team._copy_seed_tree(src, dst)
        self.assertTrue((dst / "src" / "main.py").is_file())
        self.assertFalse((dst / "artifacts").exists())
        self.assertFalse((dst / "viewer" / ".orbit-backup").exists())
        self.assertFalse((dst / ".jarvis-mcp-backups").exists())

        idx = code_index.index_directory(src)
        self.assertTrue(idx["ok"])
        self.assertEqual(idx["indexed"], 1)
        hits_stale = code_index.search_context("stale_noise_symbol", root_dir=src)
        self.assertEqual(hits_stale, [])
        hits_live = code_index.search_context("live_fn", root_dir=src)
        self.assertEqual(len(hits_live), 1)

    def test_p2_2_validate_post_origin_blocks_browser_missing_or_null_origin_but_allows_cli(self):
        raw = json.dumps({"action": "budget_config", "daily_limit_usd": 9.0}).encode("utf-8")
        url = f"http://127.0.0.1:{self.port}/mission/action"

        # 1) Browser request with Origin: null -> 403 FORBIDDEN_ORIGIN
        req_null = urllib.request.Request(
            url, data=raw, method="POST",
            headers={
                "Host": f"127.0.0.1:{self.port}",
                "Origin": "null",
                "User-Agent": "Mozilla/5.0",
                "Content-Type": "application/json",
                "Content-Length": str(len(raw)),
            },
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx1:
            urllib.request.urlopen(req_null, timeout=5)
        ctx1.exception.close()
        self.assertEqual(ctx1.exception.code, 403)

        # 2) Browser form-like POST missing Origin AND without same-origin Sec-Fetch-Site -> 403
        req_browser_no_origin = urllib.request.Request(
            url, data=raw, method="POST",
            headers={
                "Host": f"127.0.0.1:{self.port}",
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
                "Sec-Fetch-Mode": "navigate",
                "Content-Type": "application/json",
                "Content-Length": str(len(raw)),
            },
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx2:
            urllib.request.urlopen(req_browser_no_origin, timeout=5)
        ctx2.exception.close()
        self.assertEqual(ctx2.exception.code, 403)

        # 3) Local CLI / Python urllib client (no browser headers, local Host) -> 200 OK
        req_cli = urllib.request.Request(
            url, data=raw, method="POST",
            headers={
                "Host": f"127.0.0.1:{self.port}",
                "User-Agent": "Python-urllib/3.14",
                "Content-Type": "application/json",
                "Content-Length": str(len(raw)),
            },
        )
        with urllib.request.urlopen(req_cli, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            payload = json.loads(resp.read().decode("utf-8"))
        self.assertEqual(payload["daily_limit_usd"], 9.0)

    def test_p2_3_mission_routes_module_handles_get_and_post_cleanly(self):
        self.assertTrue(callable(mission_routes.get_mission))
        self.assertTrue(callable(mission_routes.post_mission))

        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/mission/status",
            headers={"Host": f"127.0.0.1:{self.port}"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            body = json.loads(resp.read().decode("utf-8"))
        self.assertTrue(body["ok"])
        self.assertIn("budget", body)
        self.assertIn("workflows", body)


if __name__ == "__main__":
    unittest.main()
