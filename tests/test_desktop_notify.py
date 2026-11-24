"""Tests for operator_modules/desktop_notify.py state persistence.

The notification history is a crash-recovery artifact: a torn write must never
destroy it, and the file must never be world-readable.
"""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import operator_modules.desktop_notify as desktop_notify


class NotificationHistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "notifications.json"
        patcher = patch.object(desktop_notify, "STATE_PATH", self.state)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _entry(self, n=1):
        return {"id": f"n{n}", "title": f"title {n}", "body": "body",
                "at": 1000 + n, "expire_at": 5000 + n}

    def test_history_survives_and_reads_back(self):
        desktop_notify._record_notification(self._entry(1))
        desktop_notify._record_notification(self._entry(2))
        rows = desktop_notify._read_history()
        self.assertEqual([r["id"] for r in rows], ["n1", "n2"])

    def test_state_file_is_private(self):
        desktop_notify._record_notification(self._entry())
        mode = (self.state.stat().st_mode & 0o777)
        self.assertEqual(mode, 0o600)
        self.assertTrue(self.state.is_file())

    def test_file_is_replaced_atomically_no_temp_left_behind(self):
        desktop_notify._record_notification(self._entry(1))
        before = self.state.read_text(encoding="utf-8")
        desktop_notify._record_notification(self._entry(2))
        leftovers = [p for p in self.state.parent.iterdir()
                     if p.name.endswith(".tmp") and p.name.startswith(".notify-")]
        self.assertEqual(leftovers, [])
        # The old content is fully replaced, not appended or torn.
        self.assertNotIn(before, self.state.read_text(encoding="utf-8"))

    def test_corrupt_history_is_ignored_not_fatal(self):
        self.state.parent.mkdir(parents=True, exist_ok=True)
        self.state.write_text("[{broken json", encoding="utf-8")
        desktop_notify._record_notification(self._entry(5))
        rows = desktop_notify._read_history()
        self.assertEqual([r["id"] for r in rows], ["n5"])

    def test_capped_at_50_entries(self):
        for i in range(60):
            desktop_notify._record_notification(self._entry(i))
        rows = desktop_notify._read_history()
        self.assertLessEqual(len(rows), 50)


if __name__ == "__main__":
    unittest.main()
