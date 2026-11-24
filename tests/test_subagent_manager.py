"""subagent_manager: delegation contracts, budgets and store sync — faked children.

The real AgentJob integration (spawn/wait/cancel over a live parent job) lives
in test_browser_agent.py; here the manager is exercised in isolation with an
injected fake browser_agent module, so its own contracts can be pinned:
task validation, budgets, steer/cancel/close lifecycle and status mapping.
"""
import hashlib
import os
import shutil
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import operator_tools as ops
from subagent_manager import (
    MAX_CONTEXT_CHARS,
    MAX_GOAL_CHARS,
    SUBAGENT_SYSTEM,
    SUBAGENT_TOOLS,
    SubAgentError,
    SubAgentManager,
    _ChildService,
)


def make_job_class(behavior):
    """A controllable stand-in for browser_agent.AgentJob (real locks/threads)."""

    class FakeAgentJob:
        instances = []

        def __init__(self, service, task, key, model, identifier, **kwargs):
            FakeAgentJob.instances.append(self)
            if behavior.raise_error is not None:
                error = behavior.raise_error
                behavior.raise_error = None
                raise error
            self.lock = threading.RLock()
            self.status = "queued"
            self.summary = ""
            self.error = ""
            self.usage = {"input_tokens": 12, "output_tokens": 3}
            self.steps = []
            self.service = service
            self.task = task
            self.key = key
            self.model = model
            self.identifier = identifier
            self.kwargs = kwargs
            self.steer_log = []
            self.stop_calls = 0
            self._stop = threading.Event()
            self._thread = None

        def start(self):
            self._thread = threading.Thread(target=self._body, daemon=True)
            self._thread.start()

        def _body(self):
            if behavior.stuck:
                self._stop.wait()
            else:
                time.sleep(behavior.finish_delay)
            with self.lock:
                if self.status != "stopped":
                    if behavior.outcome == "error":
                        self.status = "error"
                        self.error = behavior.error_text
                    else:
                        self.status = "done"
                        self.summary = behavior.summary_text
                        self.steps = [
                            {"tool": "read_file", "text": "notes.txt"},
                            {"tool": "web_research", "text": "r" * 300},
                        ]

        def steer(self, text):
            self.steer_log.append(text)
            return behavior.steer_accept

        def stop(self):
            self.stop_calls += 1
            with self.lock:
                self.status = "stopped"
            self._stop.set()

    return FakeAgentJob


class ManagerTestCase(unittest.TestCase):
    """One manager, one parent, one fresh fake AgentJob class per test."""

    def setUp(self):
        self.behavior = SimpleNamespace(
            outcome="done", finish_delay=0.05, stuck=False,
            raise_error=None, steer_accept=True,
            summary_text="fake research summary", error_text="child model failed",
        )
        self.job_class = make_job_class(self.behavior)
        fake_module = types.ModuleType("browser_agent")
        fake_module.AgentJob = self.job_class
        modules = patch.dict(sys.modules, {"browser_agent": fake_module})
        modules.start()
        self.addCleanup(modules.stop)
        self.parent = self.make_parent()
        self.manager = SubAgentManager(self.parent)
        self.addCleanup(self.manager.close)

    def make_parent(self, language="pl"):
        root = Path(tempfile.mkdtemp(prefix="jarvis-parent-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        return SimpleNamespace(
            id="root-1", model="parent-model", models=["parent-model", "alt-model"],
            key="secret-key", language=language, client_factory=None,
            service=SimpleNamespace(root=root, state_root=None, app=None, secret_store=None),
        )

    def spawn_stuck(self, count=1):
        self.behavior.stuck = True
        spawned = self.manager.spawn([{"goal": f"stuck goal {i}"} for i in range(count)])
        self.assertEqual(len(spawned["subagents"]), count)
        return [row["subagent_id"] for row in spawned["subagents"]]


class TaskShapeTests(ManagerTestCase):
    def test_spawn_rejects_empty_and_malformed_task_lists(self):
        for bad in (None, "a goal", 42, []):
            with self.assertRaisesRegex(SubAgentError, "at least one delegation task"):
                self.manager.spawn(bad)

    def test_spawn_rejects_non_object_task(self):
        with self.assertRaisesRegex(SubAgentError, "Task 1 must be an object"):
            self.manager.spawn([42, {"goal": "ok"}])
        with self.assertRaisesRegex(SubAgentError, "Task 2 must be an object"):
            self.manager.spawn([{"goal": "ok"}, []])

    def test_spawn_rejects_missing_or_blank_goal(self):
        for bad in ({"context": "c"}, {"goal": None}, {"goal": 42}, {"goal": "   "}):
            with self.assertRaisesRegex(SubAgentError, "goal string"):
                self.manager.spawn([bad])

    def test_spawn_rejects_unsupported_fields_and_bounds(self):
        with self.assertRaisesRegex(SubAgentError, "unsupported fields: extra1, extra2"):
            self.manager.spawn([{"goal": "g", "extra1": 1, "extra2": 2}])
        with self.assertRaisesRegex(SubAgentError, f"under {MAX_GOAL_CHARS}"):
            self.manager.spawn([{"goal": "g" * (MAX_GOAL_CHARS + 1)}])
        with self.assertRaisesRegex(SubAgentError, f"under {MAX_CONTEXT_CHARS}"):
            self.manager.spawn([{"goal": "g", "context": "c" * (MAX_CONTEXT_CHARS + 1)}])

    def test_spawn_limits_batch_size_to_max_tasks(self):
        tasks = [{"goal": f"g{i}"} for i in range(4)]
        with self.assertRaisesRegex(SubAgentError, "At most 3 tasks"):
            self.manager.spawn(tasks)

    def test_spawn_normalizes_goal_context(self):
        spawned = self.manager.spawn({"goal": "  read the readme  ", "context": None})
        row = spawned["subagents"][0]
        self.assertEqual(row["goal"], "read the readme")
        job = self.job_class.instances[-1]
        self.assertIn("GOAL:\nread the readme", job.task)
        self.assertIn("CONTEXT:\n(none supplied)", job.task)
        self.assertIn("finish tool", job.task)


class SpawnContractTests(ManagerTestCase):
    def test_spawn_returns_bounded_snapshots(self):
        spawned = self.manager.spawn([{"goal": "one"}, {"goal": "two", "context": "cx"}])
        self.assertEqual(spawned["action"], "spawn")
        self.assertEqual(len(spawned["subagents"]), 2)
        row = spawned["subagents"][0]
        self.assertTrue(row["subagent_id"].startswith("sub-"))
        self.assertEqual(row["parent_id"], "root-1")
        self.assertIn(row["status"], ("queued", "running", "done"))
        self.assertFalse(row["ready"])
        self.assertEqual(row["steering_count"], 0)
        self.assertEqual(row["usage"], {"input_tokens": 12, "output_tokens": 3})

    def test_list_counts_records(self):
        self.assertEqual(self.manager.list()["count"], 0)
        self.manager.spawn([{"goal": "one"}, {"goal": "two"}])
        listing = self.manager.list()
        self.assertEqual(listing["count"], 2)
        self.assertEqual(len(listing["subagents"]), 2)

    def test_child_toolbox_is_read_only(self):
        self.assertIsInstance(SUBAGENT_TOOLS, frozenset)
        self.assertIn("finish", SUBAGENT_TOOLS)
        self.assertIn("read_file", SUBAGENT_TOOLS)
        self.assertIn("web_research", SUBAGENT_TOOLS)
        forbidden = ("shell", "pty", "write", "delete", "mcp", "credential",
                     "clipboard", "desktop", "upload", "delegate", "skill_forge")
        for tool in SUBAGENT_TOOLS:
            for token in forbidden:
                self.assertNotIn(token, tool, f"subagent tool {tool!r} looks mutating")

    def test_child_job_gets_isolation_arguments(self):
        with patch.dict(os.environ, {"JARVIS_SUBAGENT_MODEL": "env-model"}):
            self.manager.spawn({"goal": "g"})
        job = self.job_class.instances[-1]
        self.assertEqual(job.model, "env-model")
        self.assertEqual(job.key, "secret-key")
        self.assertIsNone(job.kwargs["client_factory"])
        self.assertEqual(job.kwargs["models"], ["env-model", "parent-model", "alt-model"])
        self.assertIsNone(job.kwargs["session_token"])
        self.assertEqual(job.kwargs["subagent_depth"], 1)
        self.assertEqual(job.kwargs["allowed_tools"], SUBAGENT_TOOLS)
        self.assertTrue(job.kwargs["force_headless"])
        self.assertTrue(job.kwargs["system_override"].endswith("OUTPUT LANGUAGE: Polish only."))
        service = job.service
        self.assertTrue(service.headless)
        self.assertEqual(service.mode, "safe")

    def test_child_service_defaults_when_parent_has_no_language(self):
        parent = self.make_parent(language=None)
        manager = SubAgentManager(parent)
        self.addCleanup(manager.close)
        manager.spawn({"goal": "g"})
        job = self.job_class.instances[-1]
        self.assertEqual(job.kwargs["system_override"], SUBAGENT_SYSTEM)
        self.assertEqual(job.kwargs["max_steps"], manager.max_steps)
        self.assertEqual(job.kwargs["summary_chars"], manager.summary_chars)


class WaitResultTests(ManagerTestCase):
    def test_wait_returns_full_result_payload(self):
        spawned = self.manager.spawn({"goal": "g"})
        sub_id = spawned["subagents"][0]["subagent_id"]
        waited = self.manager.wait([sub_id], 10)
        self.assertEqual(waited["action"], "wait")
        result = waited["results"][0]
        self.assertEqual(result["status"], "done")
        self.assertTrue(result["ready"])
        self.assertEqual(result["summary"], "fake research summary")
        self.assertEqual(result["error"], "")
        self.assertEqual(result["result_hash"],
                         hashlib.sha256(b"fake research summary").hexdigest())
        self.assertEqual(result["tool_count"], 2)
        # _clip keeps the last step at 200 chars even for long step text.
        self.assertLessEqual(len(result["last_step"]), 200)
        self.assertTrue(result["last_step"].startswith("web_research:"))
        self.assertEqual(result["usage"], {"input_tokens": 12, "output_tokens": 3})
        self.assertGreaterEqual(result["running_seconds"], 0.0)

    def test_wait_without_ids_waits_for_all(self):
        self.manager.spawn([{"goal": "a"}, {"goal": "b"}])
        waited = self.manager.wait(None, 10)
        self.assertEqual(len(waited["results"]), 2)
        self.assertTrue(all(row["ready"] for row in waited["results"]))

    def test_wait_validates_the_id_list(self):
        with self.assertRaisesRegex(SubAgentError, "non-empty list"):
            self.manager.wait("sub-1")
        with self.assertRaisesRegex(SubAgentError, "non-empty list"):
            self.manager.wait([])
        with self.assertRaisesRegex(SubAgentError, "at most 20"):
            self.manager.wait(["x"] * 21)
        with self.assertRaisesRegex(SubAgentError, "No subagent has id"):
            self.manager.wait(["bogus"])

    def test_wait_maps_child_error_to_failed(self):
        self.behavior.outcome = "error"
        self.manager.spawn({"goal": "g"})
        waited = self.manager.wait(None, 10)
        result = waited["results"][0]
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["ready"])
        self.assertEqual(result["error"], "child model failed")
        self.assertEqual(result["summary"], "")

    def test_wait_timeout_clamps_to_a_minimum_poll_window(self):
        self.spawn_stuck(1)
        started = time.monotonic()
        waited = self.manager.wait(None, 0.2)
        elapsed = time.monotonic() - started
        # The 0.2 s ask is lifted to the documented 1.0 s minimum, then returns.
        self.assertGreaterEqual(elapsed, 0.9)
        self.assertLess(elapsed, 30.0)
        self.assertFalse(waited["results"][0]["ready"])

    def test_wait_rejects_a_malformed_timeout_cleanly(self):
        self.spawn_stuck(1)
        with self.assertRaisesRegex(SubAgentError, "timeout must be a number"):
            self.manager.wait(None, "soon")

    def test_result_fetches_one_subagent(self):
        spawned = self.manager.spawn({"goal": "g"})
        sub_id = spawned["subagents"][0]["subagent_id"]
        self.manager.wait([sub_id], 10)
        payload = self.manager.result(sub_id)
        self.assertEqual(payload["action"], "result")
        self.assertEqual(payload["result"]["status"], "done")
        with self.assertRaisesRegex(SubAgentError, "No subagent has that id"):
            self.manager.result("nope")


class SteerCancelTests(ManagerTestCase):
    def test_steer_forwards_trimmed_message_and_counts_it(self):
        sub_id = self.spawn_stuck(1)[0]
        payload = self.manager.steer(sub_id, "  check disk usage  ")
        self.assertTrue(payload["accepted"])
        job = self.job_class.instances[-1]
        self.assertEqual(job.steer_log, ["check disk usage"])
        self.assertEqual(self.manager.list()["subagents"][0]["steering_count"], 1)

    def test_steer_clips_the_message_to_4000_chars(self):
        sub_id = self.spawn_stuck(1)[0]
        self.manager.steer(sub_id, "x" * 5000)
        job = self.job_class.instances[-1]
        self.assertEqual(len(job.steer_log[0]), 4000)

    def test_steer_requires_text_and_a_known_child(self):
        sub_id = self.spawn_stuck(1)[0]
        for bad in ("", "   ", None):
            with self.assertRaisesRegex(SubAgentError, "Steering text is required"):
                self.manager.steer(sub_id, bad)
        with self.assertRaisesRegex(SubAgentError, "No subagent has that id"):
            self.manager.steer("bogus", "hi")

    def test_steer_reports_rejected_messages_without_counting(self):
        self.behavior.steer_accept = False
        sub_id = self.spawn_stuck(1)[0]
        payload = self.manager.steer(sub_id, "look again")
        self.assertFalse(payload["accepted"])
        self.assertEqual(self.manager.list()["subagents"][0]["steering_count"], 0)

    def test_steer_rejects_a_terminal_child(self):
        spawned = self.manager.spawn({"goal": "g"})
        sub_id = spawned["subagents"][0]["subagent_id"]
        self.manager.wait([sub_id], 10)
        with self.assertRaisesRegex(SubAgentError, "already terminal"):
            self.manager.steer(sub_id, "again please")

    def test_cancel_requests_stop_and_lands_on_cancelled(self):
        sub_id = self.spawn_stuck(1)[0]
        payload = self.manager.cancel(sub_id)
        self.assertTrue(payload["cancel_requested"])
        self.assertEqual(self.job_class.instances[-1].stop_calls, 1)
        waited = self.manager.wait([sub_id], 10)
        self.assertEqual(waited["results"][0]["status"], "cancelled")

    def test_cancel_on_terminal_child_is_a_no_op(self):
        spawned = self.manager.spawn({"goal": "g"})
        sub_id = spawned["subagents"][0]["subagent_id"]
        self.manager.wait([sub_id], 10)
        payload = self.manager.cancel(sub_id)
        self.assertTrue(payload["already_terminal"])
        self.assertEqual(self.job_class.instances[-1].stop_calls, 0)

    def test_cancel_all_stops_every_live_child(self):
        self.spawn_stuck(2)
        self.manager.cancel_all()
        for job in self.job_class.instances:
            self.assertEqual(job.stop_calls, 1)
        waited = self.manager.wait(None, 10)
        self.assertTrue(all(row["ready"] for row in waited["results"]))

    def test_failed_spawn_is_reported_not_hidden(self):
        self.behavior.raise_error = RuntimeError("boom")
        spawned = self.manager.spawn({"goal": "g"})
        row = spawned["subagents"][0]
        self.assertEqual(row["status"], "failed")
        waited = self.manager.wait(None, 5)
        self.assertEqual(waited["results"][0]["status"], "failed")
        self.assertIn("RuntimeError", waited["results"][0]["error"])
        with self.assertRaisesRegex(SubAgentError, "already terminal"):
            self.manager.steer(row["subagent_id"], "hello?")


class CloseTests(ManagerTestCase):
    def test_close_stops_children_once_and_joins(self):
        self.spawn_stuck(2)
        self.manager.close()
        self.assertTrue(self.manager.closed)
        for job in self.job_class.instances:
            self.assertEqual(job.stop_calls, 1)
        for record in self.manager.records.values():
            if record.thread is not None:
                self.assertFalse(record.thread.is_alive())
        # A closed parent never silently starts new work.
        with self.assertRaisesRegex(SubAgentError, "shutting down"):
            self.manager.spawn({"goal": "g"})
        self.manager.close()  # idempotent
        self.assertTrue(self.manager.closed)


class BudgetTests(ManagerTestCase):
    def test_active_concurrency_is_enforced(self):
        self.spawn_stuck(3)
        with self.assertRaisesRegex(SubAgentError, "Too many active subagents"):
            self.manager.spawn({"goal": "one too many"})

    def test_total_spawn_budget_is_enforced(self):
        with patch.dict(os.environ, {"JARVIS_SUBAGENT_MAX_TOTAL": "3",
                                     "JARVIS_SUBAGENT_MAX_CONCURRENT": "3"}):
            manager = SubAgentManager(self.parent)
            self.addCleanup(manager.close)
            self.behavior.stuck = True
            manager.spawn([{"goal": "a"}, {"goal": "b"}, {"goal": "c"}])
            with self.assertRaisesRegex(SubAgentError, r"budget exhausted \(3/3 used\)"):
                manager.spawn({"goal": "over"})

    def test_env_limits_are_clamped_and_fault_tolerant(self):
        cases = {
            "JARVIS_SUBAGENT_MAX_TASKS": {"50": 8, "hello": 3},
            "JARVIS_SUBAGENT_MAX_CONCURRENT": {"0": 1, "": 3},
            "JARVIS_SUBAGENT_MAX_STEPS": {"7": 7, "x": 1000},
            "JARVIS_SUBAGENT_SUMMARY_CHARS": {"10": 200, "999999": 8000},
        }
        for name, expected in cases.items():
            for raw, want in expected.items():
                with patch.dict(os.environ, {name: raw}):
                    manager = SubAgentManager(self.parent)
                    self.addCleanup(manager.close)
                    attr = name.removeprefix("JARVIS_SUBAGENT_").lower()
                    self.assertEqual(getattr(manager, attr), want, f"{name}={raw!r}")


class ChildServiceTests(unittest.TestCase):
    def test_facade_copies_parent_handles_and_stays_safe(self):
        app, secret = object(), object()
        parent_service = SimpleNamespace(root=Path("/tmp/p"), state_root=Path("/tmp/s"),
                                         app=app, secret_store=secret)
        facade = _ChildService(parent_service)
        self.assertEqual(facade.root, Path("/tmp/p"))
        self.assertEqual(facade.state_root, Path("/tmp/s"))
        self.assertIs(facade.app, app)
        self.assertIs(facade.secret_store, secret)
        self.assertTrue(facade.headless)
        self.assertEqual(facade.mode, "safe")
        self.assertIsNone(facade._record_history({}))
        self.assertIsNone(facade._job_finished(None))

    def test_facade_degrades_without_parent_attrs(self):
        facade = _ChildService(SimpleNamespace())
        self.assertEqual(facade.root, Path(ops.TOOLS))
        self.assertIsNone(facade.state_root)
        self.assertIsNone(facade.app)
        self.assertIsNone(facade.secret_store)


class SyncTests(ManagerTestCase):
    def test_active_counts_reconcile_as_children_finish(self):
        ids = self.spawn_stuck(2)
        self.assertEqual(self.manager.active_count(), 2)
        self.manager.cancel(ids[0])
        self.manager.wait([ids[0]], 10)
        self.assertEqual(self.manager.active_count(), 1)

    def test_summary_is_clipped_to_the_configured_bound(self):
        with patch.dict(os.environ, {"JARVIS_SUBAGENT_SUMMARY_CHARS": "200"}):
            manager = SubAgentManager(self.parent)
            self.addCleanup(manager.close)
            self.behavior.summary_text = "s" * 500
            manager.spawn({"goal": "g"})
            result = manager.wait(None, 10)["results"][0]
            self.assertEqual(len(result["summary"]), 200)

    def test_error_is_clipped_to_700_chars(self):
        self.behavior.outcome = "error"
        self.behavior.error_text = "e" * 900
        self.manager.spawn({"goal": "g"})
        result = self.manager.wait(None, 10)["results"][0]
        self.assertEqual(len(result["error"]), 700)


if __name__ == "__main__":
    unittest.main()
