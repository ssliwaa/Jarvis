"""Persistent reminders: isolated storage, no scheduler or desktop side effects."""
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from operator_modules.reminders import ReminderStore


class ReminderTests(unittest.TestCase):
    def test_create_and_reopen_with_aware_due_time(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'state'
            now = datetime(2026, 10, 27, 10, tzinfo=timezone.utc)
            store = ReminderStore(root, clock=lambda: now)
            item = store.create('Drink water', '2026-10-27T12:00:00+02:00')
            reopened = ReminderStore(root, clock=lambda: now)
            self.assertEqual(reopened.list()[0]['id'], item['id'])
            self.assertEqual(reopened.list()[0]['due_at'], '2026-10-27T10:00:00+00:00')
            self.assertEqual(reopened.list()[0]['status'], 'pending')
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertEqual((root / 'reminders.sqlite3').stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
