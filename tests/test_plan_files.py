"""File-based plan: phases, gate, restart recovery and bounds."""
import stat
import tempfile
import unittest
from pathlib import Path

import plan_files


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def plan(self, job_id="job-1234"):
        return plan_files.PlanFiles(job_id, root=self.root)

    def test_start_writes_three_files_with_tight_permissions(self):
        plan = self.plan()
        plan.start("Book a table", ["find the number", "call", "confirm"])
        for name in ("task_plan.md", "findings.md", "progress.md"):
            path = plan.path(name)
            self.assertTrue(path.is_file(), name)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(plan.dir.stat().st_mode), 0o700)
        self.assertEqual(plan.status()["total"], 3)

    def test_start_is_a_resume_and_never_clobbers(self):
        first = self.plan()
        first.start("task", ["a"])
        first.check(0)
        second = self.plan()
        second.start("task", ["a", "b"])
        self.assertEqual(second.status()["done"], 1)
        self.assertEqual(second.status()["total"], 1)

    def test_check_marks_the_right_phase(self):
        plan = self.plan()
        plan.start("task", ["one", "two"])
        plan.check(1)
        phases = plan.phases()
        self.assertFalse(phases[0]["done"])
        self.assertTrue(phases[1]["done"])
        self.assertEqual(plan.status()["done"], 1)

    def test_gate_blocks_then_allows(self):
        plan = self.plan()
        plan.start("task", ["one", "two"])
        verdict = plan.gate()
        self.assertFalse(verdict["allow"])
        self.assertEqual(verdict["unchecked"], ["one", "two"])
        plan.check(0)
        plan.check(1)
        self.assertTrue(plan.gate()["allow"])

    def test_empty_plan_does_not_block(self):
        self.assertTrue(self.plan().gate()["allow"])

    def test_restart_reads_the_same_state(self):
        plan = self.plan()
        plan.start("task", ["one"])
        plan.check(0)
        plan.note("the number is on the site")
        plan.log("clicked submit")
        other = plan_files.PlanFiles("job-1234", root=self.root)
        self.assertTrue(other.gate()["allow"])
        self.assertIn("clicked submit", other.read_all()["progress.md"])
        self.assertIn("number is on the site", other.read_all()["findings.md"])

    def test_invalid_job_id_is_refused(self):
        for bad in ("", "../etc", "a", "x" * 80, "job/1"):
            with self.assertRaises(plan_files.PlanError):
                plan_files.PlanFiles(bad, root=self.root)

    def test_progress_is_bounded_and_single_line(self):
        plan = self.plan()
        plan.start("task", [])
        for index in range(plan_files.MAX_PROGRESS_LINES + 40):
            plan.log(f"step {index}\nsecond line\twith tab")
        text = plan.read_all()["progress.md"]
        self.assertLessEqual(len(text.splitlines()), plan_files.MAX_PROGRESS_LINES + 1)
        self.assertIn(f"step {plan_files.MAX_PROGRESS_LINES + 39}", text)
        self.assertNotIn("\t", text)
        self.assertNotIn("\nsecond line", text)
        self.assertIn(f"step {plan_files.MAX_PROGRESS_LINES + 39} second line with tab", text)

    def test_long_progress_lines_keep_the_newest_entry(self):
        plan = self.plan()
        plan.start("task", [])
        for index in range(160):
            plan.log(f"{index:03d} " + "x" * 290)
        plan.log("NEWEST-ENTRY survives the byte cap")
        path = plan.path("progress.md")
        text = path.read_text(encoding="utf-8")
        self.assertLessEqual(path.stat().st_size, plan_files.MAX_PLAN_BYTES)
        self.assertIn("NEWEST-ENTRY", text)
        self.assertNotIn("\n000 ", text)

    def test_summary_is_bounded_and_names_progress(self):
        plan = self.plan()
        plan.start("task", ["one", "two"])
        plan.check(0)
        summary = plan.summary(limit=200)
        self.assertLessEqual(len(summary), 200)
        self.assertIn("1/2", summary)
        self.assertIn("[x] one", summary)

    def test_unknown_phase_index_is_rejected(self):
        plan = self.plan()
        plan.start("task", ["one"])
        with self.assertRaises(plan_files.PlanError):
            plan.check(5)

    def test_concurrent_appends_keep_every_line(self):
        # Findings can land from the agent thread and an operator call at the
        # same time; the read-merge-write used to swallow one writer's line.
        import re
        import threading

        plan = self.plan("race-0001")
        plan.start("task", [])
        expected = {f"append-{thread_id}-{index}"
                    for thread_id in range(6) for index in range(25)}

        def append(thread_id, batch):
            for index in range(batch):
                plan._append("findings.md", f"append-{thread_id}-{index}",
                             plan_files.MAX_FINDINGS_BYTES)

        threads = [threading.Thread(target=append, args=(thread_id, 25)) for thread_id in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        body = plan.path("findings.md").read_text(encoding="utf-8")
        lines = [line for line in body.splitlines() if re.fullmatch(r"append-\d+-\d+", line)]
        self.assertEqual(len(lines), len(expected))  # nothing swallowed
        self.assertEqual(set(lines), expected)  # nothing written twice

    def test_decompose_task_categories(self):
        # Empty
        self.assertTrue(len(plan_files.decompose_task("")) >= 3)
        # Scan / code / audit
        phases = plan_files.decompose_task("przebadaj kod aplikacji")
        self.assertTrue(any("kodu" in p or "repozytorium" in p for p in phases))
        # Web development
        web_phases = plan_files.decompose_task("zbuduj stronę internetową dla kawiarni")
        self.assertTrue(any("architektur" in p or "stron" in p or "komponent" in p for p in web_phases))
        # Search
        search_phases = plan_files.decompose_task("znajdź informacje o premierach filmowych")
        self.assertTrue(any("kryteri" in p or "wyszukiwani" in p or "danych" in p for p in search_phases))
        # Organization
        org_phases = plan_files.decompose_task("uporządkuj pliki w katalogu pobrane")
        self.assertTrue(any("katalog" in p or "segregacji" in p or "plików" in p for p in org_phases))


if __name__ == "__main__":
    unittest.main()
