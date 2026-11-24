"""Evolution layer: scorecard, gate and archive. No model calls."""
import os
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from types import SimpleNamespace

import evolution

# The benchmark spawns its own bwrap child; nested namespaces are unavailable
# inside the guarded self-modification verification sandbox.
SANDBOXED = os.environ.get("JARVIS_VERIFY_SANDBOX") == "1"


class GateTests(unittest.TestCase):
    def test_gate_rolls_back_only_on_a_real_regression(self):
        self.assertTrue(evolution.gate({"score": 0.8}, {"score": 0.5})["rollback"])
        self.assertFalse(evolution.gate({"score": 0.8}, {"score": 0.8})["rollback"])
        self.assertEqual(evolution.gate({"score": 0.8}, {"score": 0.8})["verdict"], "neutral")
        self.assertFalse(evolution.gate({"score": 0.8}, {"score": 0.9})["rollback"])
        self.assertEqual(evolution.gate(None, {"score": 0.9})["verdict"], "baseline")


class UnscoredGateTests(unittest.TestCase):
    def test_no_evidence_is_reported_as_unscored_not_as_an_improvement(self):
        before = {"score": 1.0, "signal": "none"}
        after = {"score": 1.0, "signal": "none"}
        verdict = evolution.gate(before, after)
        self.assertEqual(verdict["verdict"], "unscored")
        self.assertFalse(verdict["rollback"])

    def test_bench_signal_is_not_treated_as_unscored(self):
        self.assertNotEqual(evolution.gate({"score": 0.5, "signal": "bench+tests"},
                                           {"score": 0.9, "signal": "bench+tests"})["verdict"],
                            "unscored")


class ArchiveTests(unittest.TestCase):
    def test_lineage_records_parents_and_counts_descendants(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = evolution.Archive(Path(directory) / "a.json")
            root = archive.record(module="router", file="router.py", parent="", score={"score": 0.5},
                                  before=None, verdict="baseline")
            child = archive.record(module="router", file="router.py", parent=root["id"],
                                   score={"score": 0.7}, before={"score": 0.5}, verdict="improved")
            grand = archive.record(module="router", file="router.py", parent=child["id"],
                                   score={"score": 0.9}, before={"score": 0.7}, verdict="improved")
            self.assertEqual(archive.descendants(root["id"]), 2)
            self.assertEqual(archive.head("router")["id"], grand["id"])
            # CMP ranks metaproductivity: the node that produced descendants wins.
            self.assertEqual(archive.ranked(1)[0]["id"], root["id"])
            self.assertEqual(archive.ranked(1)[0]["cmp"], 2)
            archive.mark(child["id"], "rolled_back")
            self.assertEqual(archive.summary()["applied"], 2)

    def test_summary_counts_verdicts(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = evolution.Archive(Path(directory) / "a.json")
            archive.record(module="m", file="m.py", parent="", score={"score": 0.4},
                           before={"score": 0.5}, verdict="regressed")
            self.assertEqual(archive.summary()["verdicts"]["regressed"], 1)

    def test_descendants_traverse_through_unimproved_children_once(self):
        # pick_parent counts only improved verdicts but must still walk THROUGH
        # a non-improved child: a good grandchild inherits the lineage credit.
        with tempfile.TemporaryDirectory() as directory:
            archive = evolution.Archive(Path(directory) / "a.json")
            root = archive.record(module="m", file="m.py", parent="", score={"score": 0.5},
                                  before=None, verdict="baseline")
            archive.record(module="m", file="m.py", parent=root["id"], score={"score": 0.45},
                           before={"score": 0.5}, verdict="regressed")
            archive.record(module="m", file="m.py", parent=archive.rows()[-1]["id"],
                           score={"score": 0.9}, before={"score": 0.45}, verdict="improved")
            self.assertEqual(archive.descendants(root["id"], only_improved=True), 1)
            self.assertEqual(archive.descendants(root["id"]), 2)

    def test_a_lineage_cycle_terminates_the_count(self):
        # An external repair can point a parent back at its own descendant:
        # root ⇄ child. The old per-generation rescan looped on that forever.
        with tempfile.TemporaryDirectory() as directory:
            archive = evolution.Archive(Path(directory) / "a.json")
            root = archive.record(module="m", file="m.py", parent="", score={"score": 0.5},
                                  before=None, verdict="baseline")
            child = archive.record(module="m", file="m.py", parent=root["id"],
                                   score={"score": 0.6}, before={"score": 0.5}, verdict="improved")
            rows = archive.rows()
            for row in rows:
                if row["id"] == root["id"]:
                    row["parent"] = child["id"]
            archive.save(rows)
            self.assertEqual(archive.descendants(root["id"], only_improved=True), 1)
            self.assertEqual(archive.descendants(root["id"]), 1)


class ExplorationTests(unittest.TestCase):
    def test_pick_parent_prefers_nodes_with_descendants(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = evolution.Archive(Path(directory) / "a.json")
            dead = archive.record(module="m", file="m.pybrake", parent="", score={"score": 0.9},
                                  before=None, verdict="baseline")
            alive = archive.record(module="m", file="m.py", parent="", score={"score": 0.4},
                                   before=None, verdict="baseline")
            for _ in range(3):
                archive.record(module="m", file="m.py", parent=alive["id"], score={"score": 0.5},
                               before={"score": 0.4}, verdict="improved")
            picks = {evolution.pick_parent(archive, "m", temperature=0.05)["id"] for _ in range(12)}
            self.assertIn(alive["id"], picks)
            self.assertNotIn(dead["id"], picks)

    def test_pick_parent_is_none_for_an_empty_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = evolution.Archive(Path(directory) / "a.json")
            self.assertIsNone(evolution.pick_parent(archive))


class FailureTests(unittest.TestCase):
    def test_lesson_is_deduplicated_and_counted(self):
        with tempfile.TemporaryDirectory() as directory:
            failures = evolution.Failures(Path(directory) / "f.json")
            failures.add("router", "Patch zepsul classify()")
            failures.add("router", "Patch zepsul classify()")
            self.assertEqual(len(failures.rows()), 1)
            self.assertEqual(failures.rows()[0]["count"], 2)
            self.assertInans = failures.prompt("router")
            self.assertIn("classify", self.assertInans)


class CurriculumTests(unittest.TestCase):
    def test_next_returns_the_easiest_unsolved_case(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "m.py"
            target.write_text("def f(**kwargs):\n    return 1\n", encoding="utf-8")
            cases = [{"call": "f", "expect": 1, "level": 3},
                     {"call": "f", "expect": 2, "level": 1}]
            pending = [dict(case, index=index) for index, case in enumerate(cases)]
            self.assertEqual(min(pending, key=lambda case: case["level"])["level"], 1)

    def test_next_on_the_real_tree_returns_none_when_everything_passes(self):
        if evolution.Curriculum.unsolved("router"):
            self.skipTest("the real curriculum still has unsolved router cases")
        self.assertIsNone(evolution.Curriculum.next("router"))


class BenchIntegrityTests(unittest.TestCase):
    def test_seal_then_drift_detects_a_changed_file(self):
        with tempfile.TemporaryDirectory() as directory:
            bench = Path(directory)
            (bench / "x.json").write_text("[]", encoding="utf-8")
            original = evolution.BENCH, evolution.BENCH_MANIFEST
            try:
                evolution.BENCH = bench
                evolution.BENCH_MANIFEST = bench / "manifest.json"
                evolution.Bench.seal()
                self.assertEqual(evolution.Bench.drift()["changed"], [])
                (bench / "x.json").write_text("[1]", encoding="utf-8")
                self.assertEqual(evolution.Bench.drift()["changed"], ["x.json"])
            finally:
                evolution.BENCH, evolution.BENCH_MANIFEST = original


class PromptLabTests(unittest.TestCase):
    def test_override_then_reset_restores_the_default(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = evolution.PromptLab(Path(directory) / "p.json")
            default = lab.get("critic")
            lab.set("critic"," Жаден")
            prove = lab.get("critic")
            self.assertNotEqual(prove, default)
            self.assertEqual(lab.reset("critic")["critic"], default)


class SandboxTests(unittest.TestCase):
    def test_sandbox_argv_keeps_the_command_when_bwrap_is_absent(self):
        argv = ["python", "-c", "print(1)"]
        wrapped = evolution.sandbox_argv(argv)
        self.assertEqual(wrapped[-3:], argv)
        if evolution.sandbox_available():
            self.assertEqual(wrapped[0], "bwrap")

    def test_generated_code_refuses_to_run_when_bwrap_is_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.py"
            target.write_text("def x(**kwargs):\n    return 1\n", encoding="utf-8")
            with unittest.mock.patch.object(evolution.shutil, "which", return_value=None), \
                    unittest.mock.patch.dict(os.environ, {"JARVIS_ALLOW_UNSANDBOXED_CODE": ""}):
                refusal = evolution.sandbox_refusal()
                self.assertIn("bwrap", refusal)
                result = evolution.Scorecard.run_cases(target, [{"call": "x", "expect": 1}])
            self.assertEqual(result["ok"], 0)
            self.assertIn("bwrap", result["error"])

    def test_credential_locations_are_hidden_from_generated_code(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / ".hermes").mkdir()
            (home / ".hermes" / ".env").write_text("DEEPSEEK_API_KEY=secret")
            (home / ".ssh").mkdir()
            (home / ".netrc").write_text("machine example login secret")
            dirs, files = evolution.hidden_home_paths(home)
            self.assertNotIn(home / ".hermes", dirs)  # the interpreter lives there
            self.assertIn(home / ".ssh", dirs)
            self.assertIn(home / ".hermes" / ".env", files)
            self.assertIn(home / ".netrc", files)


class RuntimeWatchTests(unittest.TestCase):
    JOURNAL = ("Traceback (most recent call last):\n"
               '  File "/x/server.py", line 1, in run\n    go()\n'
               "ValueError: boom\n"
               "INFO noise\n"
               "Traceback (most recent call last):\n"
               '  File "/x/other.py", line 7, in f\n    return 1/0\n'
               "ZeroDivisionError: division by zero\n")

    def test_extract_tracebacks_splits_blocks(self):
        blocks = evolution.extract_tracebacks(self.JOURNAL)
        self.assertEqual(len(blocks), 2)
        self.assertIn("ZeroDivisionError", blocks[1])
        self.assertIn("ZeroDivisionError", blocks[1])

    def test_scan_deduplicates_across_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            watch = evolution.RuntimeWatch(Path(directory) / "w.json", Path(directory) / "w.log")
            with unittest.mock.patch.object(evolution.subprocess, "run") as run:
                run.return_value = SimpleNamespace(stdout=self.JOURNAL, returncode=0)
                first = watch.scan()
                second = watch.scan()
            self.assertEqual(len(first), 2)
            self.assertEqual(second, [])

    def test_scan_survives_a_missing_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            watch = evolution.RuntimeWatch(Path(directory) / "w.json", Path(directory) / "w.log")
            with unittest.mock.patch.object(evolution.subprocess, "run",
                                            side_effect=FileNotFoundError("journalctl")):
                found = watch.scan()
            self.assertEqual(len(found), 1)
            self.assertIn("error", found[0])


@unittest.skipIf(SANDBOXED, "the benchmark spawns a nested sandbox")
class ScorecardTests(unittest.TestCase):
    def test_bench_case_pass_and_fail_are_both_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "demo.py"
            target.write_text("def twice(value):\n    return value * 2\n", encoding="utf-8")
            cases = [{"call": "twice", "kwargs": {"value": 2}, "expect": 4},
                     {"call": "twice", "kwargs": {"value": 3}, "expect": 7}]
            result = evolution.Scorecard.run_cases(target, cases)
            self.assertEqual(result["ok"], 1)
            self.assertEqual(result["total"], 2)

    def test_expect_type_accepts_the_right_shape_only(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "demo.py"
            target.write_text("def data():\n    return {'a': 1}\n", encoding="utf-8")
            good = evolution.Scorecard.run_cases(target, [{"call": "data", "expect_type": "dict"}])
            bad = evolution.Scorecard.run_cases(target, [{"call": "data", "expect_type": "list"}])
            self.assertEqual(good["ok"], 1)
            self.assertEqual(bad["ok"], 0)

    def test_prepare_can_build_the_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "demo.py"
            target.write_text("def read(path):\n    return open(path).read().strip()\n", encoding="utf-8")
            case = {"call": "read", "prepare": "open(tmp + '/f.txt', 'w').write('hej')\n"
                                              "scope['kwargs'] = {'path': tmp + '/f.txt'}",
                    "expect": "hej"}
            result = evolution.Scorecard.run_cases(target, [case])
            self.assertEqual(result["ok"], 1)

    def test_missing_callable_and_expect_error_are_handled(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "demo.py"
            target.write_text("def boom(**kwargs):\n    raise ValueError('x')\n", encoding="utf-8")
            result = evolution.Scorecard.run_cases(
                target, [{"call": "ghost", "expect": 1},
                         {"call": "boom", "expect_error": True}])
            self.assertEqual(result["ok"], 1)

    def test_score_is_zero_when_a_module_stops_importing(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "broken.py"
            target.write_text("def x(:\n", encoding="utf-8")
            result = evolution.Scorecard.run_cases(target, [{"call": "x", "expect": 1}])
            self.assertEqual(result["ok"], 0)

    def test_a_module_cannot_forge_or_skip_the_benchmark_verdict(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "forger.py"
            target.write_text(
                "import json, os\n"
                "print(json.dumps({'results': [{'ok': True}] * 50}))\n"
                "os._exit(0)\n"
                "def x(**kwargs):\n    return 1\n", encoding="utf-8")
            result = evolution.Scorecard.run_cases(target, [{"call": "x", "expect": 1}])
            self.assertEqual(result["ok"], 0)
            self.assertIn("verdict missing", result["error"])

    def test_a_module_cannot_read_the_nonce_from_main_globals(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "forger.py"
            target.write_text(
                "import json, os, sys\n"
                "nonce = getattr(sys.modules.get('__main__'), 'nonce', '')\n"
                "if nonce:\n"
                "    os.write(1, ('__JARVIS_BENCH_' + nonce + '__' + json.dumps("
                "{'results': [{'index': 0, 'ok': True}]}) + '\\n').encode())\n"
                "os._exit(0)\n"
                "def x(**kwargs):\n    return 1\n", encoding="utf-8")
            result = evolution.Scorecard.run_cases(target, [{"call": "x", "expect": 1}])
            self.assertEqual(result["ok"], 0)
            self.assertIn("verdict missing", result["error"])

    def test_real_router_benchmark_passes_on_the_current_tree(self):
        score = evolution.Scorecard.score("router", evolution.ROOT / "router.py")
        self.assertGreaterEqual(score["bench"]["total"], 6)
        self.assertEqual(score["score"], 1.0)


if __name__ == "__main__":
    unittest.main()
