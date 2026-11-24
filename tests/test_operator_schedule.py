"""Unit contracts for the persistent Operator scheduler."""
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

import operator_schedule


class SchedulerTests(unittest.TestCase):
    def test_add_persist_remove_and_validate(self):
        started = []
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "schedules.json"
            scheduler = operator_schedule.Scheduler(
                SimpleNamespace(start=lambda task: started.append(task)), path=path)
            item = scheduler.add("printf scheduled", every_seconds=60, name="smoke", max_retries=2)
            self.assertEqual(item["name"], "smoke")
            self.assertEqual(item["max_retries"], 2)
            self.assertTrue(path.is_file())
            self.assertEqual(len(scheduler.list()), 1)
            with self.assertRaises(operator_schedule.ScheduleError):
                scheduler.add("too often", every_seconds=59)
            removed = scheduler.remove(item["id"])
            self.assertEqual(removed["removed"], item["id"])
            self.assertEqual(scheduler.list(), [])
            self.assertEqual(started, [])

    def test_existing_file_is_loaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "schedules.json"
            path.write_text('[{"id": "abc", "task": "x", "every_seconds": 60, '
                            '"next_at": 1, "enabled": true}]', encoding="utf-8")
            scheduler = operator_schedule.Scheduler(SimpleNamespace(start=lambda task: None), path=path)
            self.assertEqual(scheduler.list()[0]["id"], "abc")


    def test_failure_records_a_bounded_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "schedules.json"
            def fail(_task):
                raise RuntimeError("busy")
            scheduler = operator_schedule.Scheduler(SimpleNamespace(start=fail), path=path)
            item = scheduler.add("task", every_seconds=60, max_retries=1)
            scheduler._run_item(item)
            current = scheduler.list()[0]
            self.assertEqual(current["last_status"], "error")
            self.assertEqual(current["retry_count"], 1)
            self.assertTrue(current["last_error"].startswith("RuntimeError"))

    def test_a_long_job_does_not_push_the_cadence(self):
        # An hourly task whose run took 20 minutes must not become an 80-minute
        # task: the next slot counts from the moment that became due.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "schedules.json"
            scheduler = operator_schedule.Scheduler(SimpleNamespace(start=lambda task: None), path=path)
            item = scheduler.add("task", every_seconds=3600)
            due_slot = item["next_at"] - 1.0  # one second before the planned time
            late = dict(item, next_at=due_slot)
            time.sleep(0.001)
            scheduler._run_item(late)  # suppose the job ran 20+ minutes: now >> due_slot
            current = scheduler.list()[0]
            expected = due_slot + 3600  # still the planned slot, not completion + interval
            self.assertEqual(current["next_at"], expected)
            # a fully-missed period is skipped, never run twice
            now = time.time()
            drifted = dict(item, next_at=now - 3 * 3600)
            scheduler._run_item(drifted)
            recovered = scheduler.list()[0]["next_at"]
            self.assertGreater(recovered, now)  # advanced to a future slot
            self.assertLess(recovered, now + 3600 + 1)

    def test_manual_run_keeps_the_planned_slot(self):
        started = []
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "schedules.json"
            scheduler = operator_schedule.Scheduler(
                SimpleNamespace(start=lambda task: started.append(task)), path=path)
            item = scheduler.add("task", every_seconds=3600)
            before = item["next_at"]
            scheduler._run_item(item, manual=True)
            current = scheduler.list()[0]
            self.assertEqual(started, ["task"])
            self.assertEqual(current["last_status"], "started")
            self.assertEqual(current["next_at"], before)

    def test_run_now_queues_the_existing_item(self):
        started = []
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "schedules.json"
            scheduler = operator_schedule.Scheduler(
                SimpleNamespace(start=lambda task: started.append(task)), path=path)
            item = scheduler.add("task", every_seconds=3600)
            self.assertEqual(scheduler.run_now(item["id"]), {"ok": True, "queued": item["id"]})
            deadline = time.time() + 3
            while time.time() < deadline:
                if scheduler.list()[0]["runs"] and not scheduler._run_lock.locked():
                    break
                time.sleep(0.01)
            self.assertEqual(started, ["task"])
            self.assertEqual(scheduler.list()[0]["runs"], 1)
            with self.assertRaises(operator_schedule.ScheduleError):
                scheduler.run_now("missing")

    def test_finished_job_is_read_from_history_after_the_active_slot_clears(self):
        class FinishedService:
            def __init__(self, raises=False):
                self.raises = raises

            def start(self, _task):
                return {"id": "job1"}

            def status(self, _job_id):
                if self.raises:
                    raise RuntimeError("That agent job is no longer active.")
                return {"job": None}

            def history_rows(self):
                return [{"id": "job1", "status": "done", "error": ""}]

        with tempfile.TemporaryDirectory() as tmp:
            for raises in (False, True):
                with self.subTest(raises=raises):
                    scheduler = operator_schedule.Scheduler(
                        FinishedService(raises), path=Path(tmp) / "schedules.json")
                    started = scheduler._wait_for_job({"id": "job1"}, timeout=0.2)
                    self.assertEqual(started, ("job1", "done", ""))

    def test_a_job_missing_from_status_and_history_is_not_a_timeout(self):
        class LostService:
            def start(self, _task):
                return {"id": "job1"}

            def status(self, _job_id):
                return {"job": None}

        with tempfile.TemporaryDirectory() as tmp:
            scheduler = operator_schedule.Scheduler(
                LostService(), path=Path(tmp) / "schedules.json")
            started = scheduler._wait_for_job({"id": "job1"}, timeout=5)
            self.assertEqual(started[1], "unknown")

    def test_a_timeout_stops_the_job_before_reporting_it(self):
        class SlowService:
            def __init__(self):
                self.stopped = False

            def start(self, _task):
                return {"id": "job1"}

            def status(self, _job_id):
                return {"job": {"id": "job1", "status": "stopped" if self.stopped else "running"}}

            def stop(self, _job_id):
                self.stopped = True

        with tempfile.TemporaryDirectory() as tmp:
            service = SlowService()
            scheduler = operator_schedule.Scheduler(
                service, path=Path(tmp) / "schedules.json")
            started = scheduler._wait_for_job({"id": "job1"}, timeout=0.05)
            self.assertTrue(service.stopped)
            self.assertEqual(started[1], "stopped")

    def test_job_timeout_is_bounded(self):
        from unittest import mock
        with mock.patch.dict("os.environ", {"JARVIS_SCHEDULE_JOB_TIMEOUT": "5"}):
            self.assertEqual(operator_schedule._job_timeout(), 30)
        with mock.patch.dict("os.environ", {"JARVIS_SCHEDULE_JOB_TIMEOUT": "999999"}):
            self.assertEqual(operator_schedule._job_timeout(), 24 * 3600)
        with mock.patch.dict("os.environ", {"JARVIS_SCHEDULE_JOB_TIMEOUT": "bad"}):
            self.assertEqual(operator_schedule._job_timeout(), operator_schedule.DEFAULT_JOB_TIMEOUT)

    def test_retry_backoff_beats_the_slot_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "schedules.json"
            def fail(_task):
                raise RuntimeError("busy")
            scheduler = operator_schedule.Scheduler(SimpleNamespace(start=fail), path=path)
            item = scheduler.add("task", every_seconds=3600, max_retries=1)
            before = time.time()
            scheduler._run_item(item)
            current = scheduler.list()[0]
            self.assertEqual(current["retry_count"], 1)
            self.assertLess(current["next_at"], before + 400)  # 30 s backoff, not next slot


if __name__ == "__main__":
    unittest.main()
