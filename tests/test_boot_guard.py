"""Boot guard restores a pending patch before systemd crash-loops."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_guard():
    spec = importlib.util.spec_from_file_location("jarvis_boot_guard",
                                                  ROOT / "scripts/boot_server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BootGuardTests(unittest.TestCase):
    def test_broken_pending_server_is_restored_before_import(self):
        guard = load_guard()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "server.py"
            backup = root / "server.py.bak"
            target.write_text("def broken(:\n", encoding="utf-8")
            backup.write_text("VALUE = 1\n", encoding="utf-8")
            pending = root / "pending-restart.json"
            pending.write_text(json.dumps({"target": str(target), "backup": str(backup)}),
                               encoding="utf-8")
            result = guard.restore_if_broken(root, pending)
            self.assertEqual(result["action"], "restored")
            self.assertEqual(target.read_text(encoding="utf-8"), "VALUE = 1\n")

    def test_healthy_pending_server_is_left_alone(self):
        guard = load_guard()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "server.py"
            backup = root / "server.py.bak"
            target.write_text("VALUE = 2\n", encoding="utf-8")
            backup.write_text("VALUE = 1\n", encoding="utf-8")
            pending = root / "pending-restart.json"
            pending.write_text(json.dumps({"target": str(target), "backup": str(backup)}),
                               encoding="utf-8")
            result = guard.restore_if_broken(root, pending)
            self.assertEqual(result["action"], "healthy")
            self.assertEqual(target.read_text(encoding="utf-8"), "VALUE = 2\n")


if __name__ == "__main__":
    unittest.main()
