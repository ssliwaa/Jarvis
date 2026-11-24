"""Unit tests for desktop activity tracker and operator module."""
import tempfile
import unittest
from pathlib import Path

import desktop_tracker
from operator_modules import desktop_history


class TestDesktopTracker(unittest.TestCase):

    def test_record_and_get_history(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test-desktop.db"

            _ = desktop_tracker.record_active_window(db_path=db_path)
            # rec1 may be None if running without X11 or no window, but db is initialised
            history = desktop_tracker.get_history(limit=10, db_path=db_path)
            self.assertIsInstance(history, list)

    def test_operator_module_tool(self):
        self.assertEqual(desktop_history.TOOL["name"], "desktop_history")
        res = desktop_history.desktop_history({"limit": 5})
        self.assertTrue(res["ok"])
        self.assertIn("history", res)


if __name__ == "__main__":
    unittest.main()
