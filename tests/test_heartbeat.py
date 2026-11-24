"""Safety and notification behavior of the opt-in heartbeat."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from operator_modules import heartbeat


class HeartbeatTests(unittest.TestCase):
    def test_failed_schedule_notifies_once_only_after_opt_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows = [{'id': 'abc', 'name': 'Backup', 'last_status': 'error', 'last_run': 123}]
            with mock.patch.object(heartbeat, '_notify', return_value=True) as notify:
                disabled = heartbeat.check(root, rows, now=1700000000)
                self.assertEqual(disabled['status'], 'disabled')
                notify.assert_not_called()
                heartbeat.configure(root, enabled=True, quiet_start=0, quiet_end=0)
                first = heartbeat.check(root, rows, now=1700000000)
                second = heartbeat.check(root, rows, now=1700000060)
                self.assertEqual(first['delivered'], 1)
                self.assertEqual(second['delivered'], 0)
                notify.assert_called_once()

    def test_failed_delivery_is_not_recorded_as_delivered(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            heartbeat.configure(root, enabled=True, quiet_start=0, quiet_end=0)
            rows = [{'id': 'abc', 'name': 'Backup', 'last_status': 'error', 'last_run': 123}]
            with mock.patch.object(heartbeat, '_notify', side_effect=[False, True]):
                self.assertEqual(heartbeat.check(root, rows, now=1700000000)['delivered'], 0)
                self.assertEqual(heartbeat.check(root, rows, now=1700000060)['delivered'], 1)

    def test_quiet_hours_and_daily_limit_do_not_send(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            heartbeat.configure(root, enabled=True, quiet_start=0, quiet_end=24, daily_limit=1)
            rows = [{'id': 'abc', 'name': 'Backup', 'last_status': 'error', 'last_run': 123}]
            with mock.patch.object(heartbeat, '_notify', return_value=True) as notify:
                self.assertEqual(heartbeat.check(root, rows, now=1700000000)['status'], 'quiet')
                notify.assert_not_called()
            heartbeat.configure(root, enabled=True, quiet_start=0, quiet_end=0, daily_limit=1)
            with mock.patch.object(heartbeat, '_notify', return_value=True) as notify:
                self.assertEqual(heartbeat.check(root, rows, now=1700000000)['delivered'], 1)
                rows[0]['last_run'] = 456
                self.assertEqual(heartbeat.check(root, rows, now=1700000060)['status'], 'limit')
                notify.assert_called_once()

    def test_scheduler_invokes_the_same_heartbeat_without_model_jobs(self):
        from types import SimpleNamespace

        import operator_schedule
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service = SimpleNamespace(start=mock.Mock())
            scheduler = operator_schedule.Scheduler(service, path=root / 'schedules.json')
            scheduler.items = [{'id': 'abc', 'name': 'Backup', 'last_status': 'error', 'last_run': 123}]
            heartbeat.configure(root, enabled=True, quiet_start=0, quiet_end=0)
            with mock.patch.object(heartbeat, '_notify', return_value=True) as notify:
                scheduler._check_heartbeat()
                scheduler._check_heartbeat()
                notify.assert_called_once()
                service.start.assert_not_called()


if __name__ == '__main__':
    unittest.main()
