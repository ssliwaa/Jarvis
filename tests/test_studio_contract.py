"""Static contract for the Studio UI: every P1 lane has a real control surface."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class StudioContract(unittest.TestCase):
    def test_studio_panel_covers_every_p1_lane(self):
        html = (ROOT / "viewer/index.html").read_text(encoding="utf-8")
        script = (ROOT / "viewer/studio.js").read_text(encoding="utf-8")
        for element in ("studio-panel", "studio-toggle", "studio-memory", "studio-sessions",
                        "studio-skills", "studio-research", "studio-mcp", "studio-schedules",
                        "studio-overview", "studio-system", "studio-apps", "studio-docs",
                        "studio-files", "studio-clipboard", "studio-selfmod"):
            self.assertIn(f'id="{element}"', html)
        for endpoint in ("/memory", "/sessions", "/skills", "/research", "/mcp", "/agent/schedules",
                         "/agent/schedules/run",
                         "/system", "/briefing", "/documents", "/organizer", "/checkpoints", "/apps", "/clipboard",
                         "/self/status", "/self/rules", "/self/patches", "/self/forge", "/self/heal",
                         "/self/forge/apply", "/self/heal/apply", "/self/rollback"):
            self.assertIn(endpoint, script)
        self.assertNotIn("innerHTML", script, "Studio must render with textContent, not HTML injection")
        self.assertIn("GENERAL KNOWLEDGE", (ROOT / "viewer/app.js").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
