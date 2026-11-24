"""Background lane: concurrent job pool lifecycle, refusal and cancellation.

Nothing here launches a real agent: a job's `runner` callable is used so the
execute path, queue limits, stop semantics and snapshot/history transitions
are exercised without spending money or spawning a sandbox.
"""
import threading
import time
import unittest
from pathlib import Path

import background_lane


def _blocking_runner(task, cancel_ev, started_hook=None):
    def run(task_text, ev):
        if started_hook:
            started_hook()
        ev.wait(10)
        return {"ok": True, "note": "ran until cancel or timeout"}
    return run


class BackgroundLaneTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.lane = background_lane.BackgroundLane(state_root=self.root, max_workers=2)

    def _wait_active(self, count, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            snap = self.lane.snapshot()
            if snap["active_count"] == count:
                return snap
            time.sleep(0.02)
        return self.lane.snapshot()

    def _wait_history(self, min_jobs, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            snap = self.lane.snapshot()
            if len(snap["recent"]) >= min_jobs:
                return snap
            time.sleep(0.02)
        return self.lane.snapshot()

    def test_start_runs_a_callable_and_records_history(self):
        res = self.lane.start("neutralne zadanie kontrolne", runner=lambda t, ev: {"ok": True})
        self.assertTrue(res["ok"])
        self.assertTrue(res["background"])
        job_id = res["job"]["id"]
        snap = self._wait_history(1)
        self.assertEqual(snap["active_count"], 0)
        row = next(r for r in snap["recent"] if r["id"] == job_id)
        self.assertEqual(row["status"], "done")
        self.assertEqual(row["percent"], 100)
        self.assertIn("Zakończono", row["stage"])

    def test_runner_error_status_is_recorded(self):
        def failing(task, ev):
            return {"ok": False, "error": "boom"}
        res = self.lane.start("zadanie z błędem", runner=failing)
        self.assertTrue(res["ok"])
        self._wait_active(0)
        snap = self._wait_history(1)
        self.assertEqual(snap["recent"][0]["status"], "error")
        self.assertIn("boom", snap["recent"][0]["error"])

    def test_empty_task_is_refused(self):
        res = self.lane.start("   ", runner=lambda t, ev: {"ok": True})
        self.assertFalse(res["ok"])
        self.assertIn("required", res["error"])

    def test_lane_full_refuses_new_jobs(self):
        started = threading.Event()
        res1 = self.lane.start("blokujące zadanie", runner=_blocking_runner("a", None, started_hook=started.set))
        self.assertTrue(res1["ok"])
        self.assertTrue(started.wait(5))
        # Lane has max_workers=2 but the second worker is also blocked: use a
        # third job to prove the refusal only past the limit.
        res2 = self.lane.start("drugie blokujące", runner=lambda t, ev: ev.wait(10) or {"ok": True})
        self.assertTrue(res2["ok"])
        res3 = self.lane.start("trzecie zadanie", runner=lambda t, ev: {"ok": True})
        self.assertFalse(res3["ok"])
        self.assertIn("full", res3["error"])
        # Stopping the first job frees a slot.
        self.assertTrue(self.lane.stop(res1["job"]["id"])["stopped"])
        snap = self._wait_history(1)
        stopped_row = next(r for r in snap["recent"] if r["id"] == res1["job"]["id"])
        self.assertEqual(stopped_row["status"], "stopped")

    def test_stop_unknown_job_reports_not_active(self):
        res = self.lane.stop("bg-nonexistent")
        self.assertFalse(res["ok"])
        self.assertIn("not active", res["error"])

    def test_snapshot_shape_and_agent_delegation_detection(self):
        res = self.lane.start("użyj claude code do naprawienia README", runner=lambda t, ev: {"ok": True})
        self.assertTrue(res["ok"])
        self.assertEqual(res["job"]["agent"], "claude")
        self.assertEqual(res["job"]["kind"], "agent:claude")
        snap = self._wait_active(0)
        for key in ("ok", "active_count", "active", "recent", "agents", "running_agents"):
            self.assertIn(key, snap)
        self.assertEqual(background_lane.detect_delegated_agent("zleć opencode refactor"), "opencode")
        self.assertEqual(background_lane.detect_delegated_agent("opentracing"), None)

    def test_concurrent_threaded_starts_respect_the_limit(self):
        # One gate job holds a slot; three threads race for the single
        # remaining worker (max_workers=2) — exactly one wins, two are refused.
        started = threading.Event()
        res0 = self.lane.start("ocupar slot 1",
                               runner=_blocking_runner("x", None, started_hook=started.set))
        self.assertTrue(res0["ok"])
        self.assertTrue(started.wait(5))
        outcomes = []
        lock = threading.Lock()

        def race(i):
            r = self.lane.start(f"racer {i}", runner=lambda t, ev: ev.wait(10) or {"ok": True})
            with lock:
                outcomes.append(r)

        threads = [threading.Thread(target=race, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()
        deadline = time.time() + 5
        while time.time() < deadline and len(outcomes) < 3:
            time.sleep(0.02)
        ok = [o for o in outcomes if o.get("ok")]
        refused = [o for o in outcomes if not o.get("ok")]
        self.assertEqual(len(ok), 1, outcomes)
        self.assertEqual(len(refused), 2, outcomes)
        for refused_job in refused:
            self.assertIn("full", refused_job.get("error", ""))
        # Cleanup: both running jobs stop and land in history as stopped.
        self.assertTrue(self.lane.stop(res0["job"]["id"])["stopped"])
        self.assertTrue(self.lane.stop(ok[0]["job"]["id"])["stopped"])
        snap = self._wait_history(2)
        self.assertEqual(snap["active_count"], 0)

    def test_history_is_capped_and_private(self):
        for i in range(60):
            self.lane.start(f"quick {i}", runner=lambda t, ev: {"ok": True})
        snap = self._wait_history(min_jobs=10)
        self.assertLessEqual(len(snap["recent"]), 10)  # snapshot shows last 10
        history_file = self.root / "background-jobs.json"
        self.assertTrue(history_file.is_file())
        mode = history_file.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)


if __name__ == "__main__":
    unittest.main()
