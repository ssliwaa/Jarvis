"""Voice/text control of running Operator work: status, queue and a verified stop.

The lane must answer from the real service state and must not report a stop it
could not confirm. No model is called and no new job is started.
"""
import unittest
from types import SimpleNamespace

import server


class FakeAgent:
    """Minimal stand-in with the three methods the lane is allowed to use."""

    def __init__(self, job=None, queue=None, stop_effect=True, stop_error=None):
        self._job = job
        self._queue = list(queue or [])
        self._stop_effect = stop_effect
        self._stop_error = stop_error
        self.stopped = []

    def available(self):
        return True

    def status(self):
        return {"job": self._job, "queue": list(self._queue), "mode": "safe"}

    def stop(self, job_id):
        self.stopped.append(job_id)
        if self._stop_error is not None:
            raise RuntimeError(self._stop_error)
        if self._job and self._job.get("id") == job_id:
            if self._stop_effect:
                self._job = None
            return {"id": job_id, "status": "stopped"}
        for row in list(self._queue):
            if row.get("id") == job_id:
                self._queue.remove(row)
                return {"id": job_id, "status": "stopped", "removed_from_queue": True}
        raise RuntimeError("That agent job is no longer active.")


def handler_for(agent):
    fake = object.__new__(server.Handler)
    fake.server = SimpleNamespace(agent=agent)
    return fake


def route(control, lang="pl", subject="", confirm=0.0):
    payload = {"action": "job_control", "control": control, "lang": lang,
               "intent": "job_" + control, "confirm_seconds": confirm}
    if subject:
        payload["subject"] = subject
    return payload


class CancelAllAgent(FakeAgent):
    """Service with the atomic cancel used by 'cancel everything'."""

    def __init__(self, job=None, queue=None):
        super().__init__(job=job, queue=queue)
        self.cancelled = []

    def cancel_all(self):
        self.cancelled.append(True)
        rows = list(self._queue)
        self._queue.clear()
        job = self._job
        self._job = None
        stopped = []
        if job:
            stopped.append({"id": job.get("id"), "task": job.get("task"), "status": "stopped"})
        for row in rows:
            stopped.append({"id": row.get("id"), "task": row.get("task"), "status": "stopped",
                            "removed_from_queue": True})
        return {"ok": True, "stopped": stopped, "cleared": len(rows)}


class JobControlTests(unittest.TestCase):
    def test_status_reports_the_real_job_and_never_invents_one(self):
        agent = FakeAgent(job={"id": "abc", "status": "running", "task": "otwórz Opera GX",
                               "steps": [{"n": 1}, {"n": 2}]})
        answer = handler_for(agent).job_control_answer(route("status"))
        self.assertEqual(answer["outcome"], "done")
        self.assertIn("otwórz Opera GX", answer["answer"])
        self.assertIn("running", answer["answer"])
        self.assertIn("2", answer["answer"])

    def test_idle_operator_says_so(self):
        answer = handler_for(FakeAgent()).job_control_answer(route("status"))
        self.assertEqual(answer["outcome"], "done")
        self.assertIn("nic teraz nie robi", answer["answer"])

    def test_queue_lists_waiting_tasks_in_order(self):
        agent = FakeAgent(queue=[{"id": "q1", "task": "pierwsze"}, {"id": "q2", "task": "drugie"}])
        answer = handler_for(agent).job_control_answer(route("queue"))
        self.assertIn("pierwsze", answer["answer"])
        self.assertIn("drugie", answer["answer"])
        self.assertLess(answer["answer"].index("pierwsze"), answer["answer"].index("drugie"))

    def test_empty_queue_is_an_empty_state_not_an_error(self):
        answer = handler_for(FakeAgent()).job_control_answer(route("queue"))
        self.assertEqual(answer["outcome"], "done")
        self.assertIn("pusta", answer["answer"])

    def test_stop_is_reported_done_only_after_the_state_confirms_it(self):
        agent = FakeAgent(job={"id": "abc", "status": "running", "task": "długie"})
        answer = handler_for(agent).job_control_answer(route("stop"))
        self.assertEqual(agent.stopped, ["abc"])
        self.assertEqual(answer["outcome"], "done")
        self.assertIn("Zatrzymałem", answer["answer"])

    def test_stop_that_did_not_take_effect_is_unverified(self):
        agent = FakeAgent(job={"id": "abc", "status": "running", "task": "uparte"}, stop_effect=False)
        answer = handler_for(agent).job_control_answer(route("stop"))
        self.assertEqual(answer["outcome"], "unverified")
        self.assertIn("nadal", answer["answer"])
        self.assertNotIn("Zatrzymałem", answer["answer"])

    def test_stop_failure_never_claims_success(self):
        agent = FakeAgent(job={"id": "abc", "status": "running"}, stop_error="locked")
        answer = handler_for(agent).job_control_answer(route("stop"))
        self.assertEqual(answer["outcome"], "failed")
        self.assertIn("locked", answer["answer"])

    def test_stop_with_nothing_running_changes_nothing(self):
        agent = FakeAgent()
        answer = handler_for(agent).job_control_answer(route("stop"))
        self.assertEqual(agent.stopped, [])
        self.assertEqual(answer["outcome"], "done")
        self.assertIn("nie ma czego", answer["answer"].lower())

    def test_stop_removes_the_first_queued_task_when_idle(self):
        agent = FakeAgent(queue=[{"id": "q1", "task": "czeka"}])
        answer = handler_for(agent).job_control_answer(route("stop"))
        self.assertEqual(agent.stopped, ["q1"])
        self.assertEqual(answer["outcome"], "done")
        self.assertIn("kolejki", answer["answer"])

    def test_unavailable_operator_is_reported_without_side_effects(self):
        class Down(FakeAgent):
            def available(self):
                return False
        agent = Down()
        answer = handler_for(agent).job_control_answer(route("stop"))
        self.assertEqual(answer["outcome"], "unverified")
        self.assertEqual(agent.stopped, [])

    def test_english_route_answers_in_english(self):
        agent = FakeAgent(job={"id": "abc", "status": "running", "task": "open a page"})
        answer = handler_for(agent).job_control_answer(route("status", lang="en"))
        self.assertIn("working on", answer["answer"])

    def test_cancel_names_the_task_it_stopped(self):
        # Live: "cancel this youtube I don't want it" was answered by the general
        # lane with "this lane can't cancel anything". The local lane must cancel
        # and say which task it stopped.
        agent = FakeAgent(job={"id": "abc", "status": "running",
                               "task": "Play some music on Spotify. I have it installed."})
        answer = handler_for(agent).job_control_answer(route("stop", lang="en"))
        self.assertEqual(agent.stopped, ["abc"])
        self.assertEqual(answer["outcome"], "done")
        self.assertIn("Play some music on Spotify", answer["answer"])
        self.assertIn("The queue is empty", answer["answer"])

    def test_cancel_with_a_subject_targets_the_matching_task(self):
        agent = FakeAgent(job={"id": "abc", "status": "running", "task": "open Opera GX"},
                          queue=[{"id": "q1", "task": "Play some music on youtube"}])
        answer = handler_for(agent).job_control_answer(route("stop", lang="en", subject="youtube"))
        self.assertEqual(agent.stopped, ["q1"])
        self.assertEqual(answer["outcome"], "done")
        self.assertIn("Play some music on youtube", answer["answer"])

    def test_cancel_with_a_subject_that_is_not_running_changes_nothing(self):
        agent = FakeAgent(job={"id": "abc", "status": "running", "task": "open Opera GX"})
        answer = handler_for(agent).job_control_answer(route("stop", lang="en", subject="youtube"))
        self.assertEqual(agent.stopped, [])
        self.assertEqual(answer["outcome"], "done")
        self.assertIn("youtube", answer["answer"])

    def test_cancel_everything_stops_the_job_and_clears_the_queue(self):
        agent = CancelAllAgent(job={"id": "abc", "status": "running", "task": "music one"},
                               queue=[{"id": "q1", "task": "music two"}])
        answer = handler_for(agent).job_control_answer(route("cancel_all", lang="en"))
        self.assertEqual(agent.cancelled, [True])
        self.assertEqual(answer["outcome"], "done")
        self.assertIn("music one", answer["answer"])
        self.assertIn("music two", answer["answer"])
        self.assertEqual(agent.status()["job"], None)
        self.assertEqual(agent.status()["queue"], [])

    def test_cancel_waits_for_the_job_to_leave_before_claiming_success(self):
        # A job finishing its current step disappears a moment later; the answer
        # must wait for that instead of reporting a failure it cannot prove.
        class SlowAgent(FakeAgent):
            def __init__(self):
                super().__init__(job={"id": "abc", "status": "running", "task": "music"})
                self.polls = 0
                self.stop_requested = False

            def status(self):
                self.polls += 1
                if self.stop_requested and self.polls >= 3:
                    self._job = None
                return super().status()

            def stop(self, job_id):
                self.stopped.append(job_id)
                self.stop_requested = True
                return {"id": job_id, "status": "stopping"}

        agent = SlowAgent()
        answer = handler_for(agent).job_control_answer(route("stop", lang="en", confirm=1.0))
        self.assertEqual(answer["outcome"], "done")
        self.assertIn("I stopped the Operator task", answer["answer"])
        self.assertGreaterEqual(agent.polls, 3)


    def test_a_generic_subject_never_filters_out_the_active_job(self):
        # "przerwij to zadanie" carries subject "zadanie"; matching it against
        # the task text ("probe task") selected nothing and the stop silently
        # did nothing. The live preflight job_control check caught it.
        agent = FakeAgent(job={"id": "probe", "status": "running", "task": "probe task",
                               "steps": []})
        answer = handler_for(agent).job_control_answer(
            {"action": "job_control", "control": "stop", "lang": "pl",
             "intent": "job_stop", "subject": "zadanie"})
        self.assertEqual(agent.stopped, ["probe"])
        self.assertEqual(answer["outcome"], "done")

    def test_a_named_subject_still_narrows_the_target(self):
        agent = FakeAgent(job={"id": "probe", "status": "running",
                               "task": "odtwórz muzykę w Spotify", "steps": []})
        answer = handler_for(agent).job_control_answer(
            {"action": "job_control", "control": "stop", "lang": "pl",
             "intent": "job_stop", "subject": "muzykę"})
        self.assertEqual(agent.stopped, ["probe"])
        self.assertEqual(answer["outcome"], "done")


if __name__ == "__main__":
    unittest.main()
