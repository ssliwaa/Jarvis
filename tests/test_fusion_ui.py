"""Contract tests for embedded chat operator card and UI fusion."""
import subprocess
import unittest
from pathlib import Path

from tests.node_support import node_binary

ROOT = Path(__file__).resolve().parents[1]


class FusionUITests(unittest.TestCase):
    def test_fusion_ui_contract_in_node(self):
        node = node_binary()
        if not node:
            self.skipTest("node binary not found")
        script = ROOT / "tests/test_fusion_ui.js"
        done = subprocess.run([node, str(script)], capture_output=True, text=True, timeout=30)
        self.assertEqual(done.returncode, 0, f"test_fusion_ui.js failed:\n{done.stdout}\n{done.stderr}")


if __name__ == "__main__":
    unittest.main()
