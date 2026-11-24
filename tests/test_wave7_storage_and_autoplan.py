"""End-to-end tests for Wave-7 Storage Health, Read-Only Mount Guard & Backup Retention:
1. `storage_health` classifying rotational 3.5" `HDD` vs `NVMe`, drive `hwmon` °C, and `ro` mount alerts
2. Deterministic `.jarvis-mcp-backups` pruning (`keep_latest`)
3. HTTP `POST /mission/action` (`storage_report`, `prune_backups`) + `qa_gate.audit_viewer` on `viewer/mission.js`
"""

import json
import os
SANDBOXED = os.environ.get("JARVIS_VERIFY_SANDBOX") == "1"
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
import qa_gate
import server
import storage_health

REPO_ROOT = Path(__file__).resolve().parent.parent


def _find_handler_class():
    for val in vars(server).values():
        if isinstance(val, type) and issubclass(val, BaseHTTPRequestHandler) and val is not BaseHTTPRequestHandler:
            return val
    raise RuntimeError("Could not locate HTTP handler class in server.py")


@unittest.skipIf(SANDBOXED, "needs the developer's local env (vault/Hermes/Piper/desktop); skipped in CI")
class Wave7StorageAndAutoplanTests(unittest.TestCase):
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

    def test_1_block_devices_hdd_vs_nvme_and_readonly_mount_alert(self):
        fake_block = self.base / "sys_block"
        # 1. Rotational 3.5" HDD (`sda`, 4 TB, 57°C -> triggers HDD temp warning >= 55°C)
        sda = fake_block / "sda"
        (sda / "queue").mkdir(parents=True)
        (sda / "device" / "hwmon" / "hwmon1").mkdir(parents=True)
        (sda / "size").write_text(str(8_000_000_000), encoding="utf-8")
        (sda / "queue" / "rotational").write_text("1\n", encoding="utf-8")
        (sda / "device" / "model").write_text("WD Red Plus 4TB\n", encoding="utf-8")
        (sda / "device" / "hwmon" / "hwmon1" / "temp1_input").write_text("57000\n", encoding="utf-8")

        # 2. System NVMe (`nvme0n1`, 512 GB, 42°C)
        nvme = fake_block / "nvme0n1"
        (nvme / "queue").mkdir(parents=True)
        (nvme / "device" / "hwmon0").mkdir(parents=True)
        (nvme / "size").write_text(str(1_000_000_000), encoding="utf-8")
        (nvme / "queue" / "rotational").write_text("0\n", encoding="utf-8")
        (nvme / "device" / "model").write_text("Samsung 980\n", encoding="utf-8")
        (nvme / "device" / "hwmon0" / "temp1_input").write_text("42000\n", encoding="utf-8")

        fake_mounts = self.base / "mounts"
        fake_mounts.write_text(
            "/dev/nvme0n1p2 / ext4 rw,relatime 0 0\n"
            "/dev/sda1 /mnt/hdd_dock ext4 ro,relatime,errors=remount-ro 0 0\n",
            encoding="utf-8",
        )

        snap = storage_health.inspect_storage(
            project_dir=self.proj_root,
            sys_block=fake_block,
            proc_mounts=fake_mounts,
        )
        self.assertFalse(snap["ok"])
        by_dev = {d["device"]: d for d in snap["drives"]}
        self.assertEqual(by_dev["sda"]["media"], "HDD")
        self.assertTrue(by_dev["sda"]["rotational"])
        self.assertAlmostEqual(by_dev["sda"]["temp_c"], 57.0)
        self.assertEqual(by_dev["nvme0n1"]["media"], "NVMe")
        self.assertEqual(len(snap["mounts"]["readonly_alerts"]), 1)
        self.assertTrue(any("57.0°C" in w for w in snap["warnings"]))

    def test_2_http_storage_report_backup_pruning_and_viewer_qa(self):
        qa = qa_gate.audit_viewer(REPO_ROOT)
        self.assertTrue(qa["ok"], f"Updated viewer/mission.js failed QA gate: {qa['issues']}")

        bdir = self.proj_root / ".jarvis-mcp-backups"
        bdir.mkdir(parents=True)
        now = time.time()
        for i in range(12):
            f = bdir / f"file_{i:02d}.py.bak"
            f.write_text("x = 1\n" * 50, encoding="utf-8")
            os.utime(f, (now + i, now + i))

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

        rep = _post({"action": "storage_report", "project_dir": str(self.proj_root)})
        self.assertEqual(rep["mcp_backups"]["count"], 12)

        pruned = _post({"action": "prune_backups", "project_dir": str(self.proj_root), "keep_latest": 5})
        self.assertTrue(pruned["ok"])
        self.assertEqual(pruned["removed"], 7)
        self.assertEqual(pruned["kept"], 5)
        remaining = sorted(p.name for p in bdir.glob("*.bak"))
        self.assertEqual(remaining, [f"file_{i:02d}.py.bak" for i in range(7, 12)])


if __name__ == "__main__":
    unittest.main()
