"""Capability map contract: live manifest, no fabricated capability labels."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CapabilityMapTests(unittest.TestCase):
    def test_capability_map_is_wired_to_live_manifest(self):
        html = (ROOT / "viewer/index.html").read_text(encoding="utf-8")
        script = (ROOT / "viewer/capabilities.js").read_text(encoding="utf-8")
        for element in ("capability-overlay", "capability-toggle", "capability-grid",
                        "capability-limits", "capability-link"):
            self.assertIn(f'id="{element}"', html)
        self.assertIn("/capabilities", script)
        self.assertIn("/agent/status", script)
        self.assertIn("textContent", script)
        self.assertNotIn("innerHTML", script)


if __name__ == "__main__":
    unittest.main()
