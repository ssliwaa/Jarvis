"""Unit tests for tools_draft_bench: offline, no live API calls.

Every external seam is patched: PROJECT (tmpdir), load_deepseek_key,
make_client and self_modify.BenchDraft. The fake draft class returns
controlled case lists so each branch of main() can be verified in
isolation. No network, no real bench files, no real model key.
"""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import tools_draft_bench as tdb


def make_draft_class(plan):
    """Build a BenchDraft replacement whose draft() follows `plan`.

    `plan` maps module name -> dict with "cases" (returned untouched) or
    an Exception instance (raised). Created instances are collected on
    the class so tests can assert on wiring and call limits.
    """
    instances = []

    class FakeDraft:
        def __init__(self, client, model):
            self.client = client
            self.model = model
            self.calls = []
            instances.append(self)

        def draft(self, module, limit=6):
            self.calls.append((module, limit))
            outcome = plan[module]
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

    FakeDraft.instances = instances
    return FakeDraft


def case(call, draft_ok=True, **kwargs):
    """One drafted benchmark case as produced by BenchDraft."""
    data = {"call": call, "kwargs": dict(kwargs)}
    if draft_ok is not None:
        data["draft_ok"] = draft_ok
    return data


class TestTargets(unittest.TestCase):
    """targets(): argument handling and project globbing."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.project = Path(self.tmp.name)
        (self.project / "bench").mkdir()
        self.patches = [patch.object(tdb, "PROJECT", self.project)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def write(self, relpath):
        path = self.project / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("pass\n", encoding="utf-8")
        return path

    def test_argv_py_suffix_stripped_once(self):
        self.assertEqual(
            tdb.targets(["alpha.py", "beta", "a.py.py"]),
            ["alpha", "beta", "a.py"],
        )

    def test_argv_is_authoritative_no_filtering(self):
        # Explicit module names bypass SKIP, bench files and globbing.
        self.assertEqual(tdb.targets(["self_modify", "whatever", "_x"]),
                         ["self_modify", "whatever", "_x"])

    def test_no_argv_globs_filters_and_sorts(self):
        for name in tdb.SKIP:
            self.write(f"{name}.py")
        self.write("_hidden.py")
        self.write("benched.py")
        (self.project / "bench" / "benched.json").write_text("{}", encoding="utf-8")
        self.write("zeta.py")
        self.write("alpha.py")
        # Nested files are not picked up by the top-level glob.
        self.write("sub/deep.py")
        self.assertEqual(tdb.targets([]), ["alpha", "zeta"])

    def test_no_argv_empty_project(self):
        (self.project / "bench" / "leftover.json").write_text("{}", encoding="utf-8")
        self.assertEqual(tdb.targets([]), [])


class TestMain(unittest.TestCase):
    """main(): live seams patched, bench files land in a tmpdir."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.project = Path(self.tmp.name)
        bench = self.project / "bench"
        bench.mkdir()
        self.captured = {}

    def run_main(self, plan, argv):
        """Patch all live seams, run main(argv), return stdout text."""
        def fake_load_key():
            self.captured["key"] = "key-XYZ"
            return "key-XYZ"

        def fake_make_client(provider, key, timeout=0.0):
            self.captured["client_args"] = (provider, key, timeout)
            self.captured["client"] = object()
            return self.captured["client"]

        fake_draft_cls = make_draft_class(plan)
        fake_self_modify = SimpleNamespace(
            BenchDraft=fake_draft_cls,
            DEFAULT_MODEL="test-model",
        )
        stdout = io.StringIO()
        with patch.object(tdb, "PROJECT", self.project), \
                patch.object(tdb, "load_deepseek_key", fake_load_key), \
                patch.object(tdb, "make_client", fake_make_client), \
                patch.object(tdb, "self_modify", fake_self_modify), \
                contextlib.redirect_stdout(stdout):
            tdb.main(argv)
        self.fake_draft_cls = fake_draft_cls
        return stdout.getvalue()

    def test_wiring_provider_key_timeout_and_limit(self):
        good = [case("a1"), case("a2"), case("a3")]
        self.run_main({"mod": {"cases": good}}, ["mod"])
        self.assertEqual(self.captured["client_args"],
                         ("deepseek", "key-XYZ", 180.0))
        instance = self.fake_draft_cls.instances[0]
        self.assertIs(instance.client, self.captured["client"])
        self.assertEqual(instance.model, "test-model")
        self.assertEqual(instance.calls, [("mod", 6)])

    def test_below_min_passing_skips_module(self):
        result = {"cases": [case("a1"), case("a2"),
                            case("f1", draft_ok=False),
                            case("f2", draft_ok=False),
                            case("f3", draft_ok=False),
                            case("f4", draft_ok=False)]}
        out = self.run_main({"mod": result}, ["mod"])
        self.assertIn("- mod: 2/6 przechodzi, pomijam", out)
        self.assertFalse((self.project / "bench" / "mod.json").exists())

    def test_good_cases_persisted_without_draft_flag(self):
        result = {"cases": [case("a1"), case("a2"), case("a3")]}
        out = self.run_main({"mod": result}, ["mod"])
        self.assertIn("+ mod: 3 przypadkow (dodano 3)", out)
        path = self.project / "bench" / "mod.json"
        self.assertTrue(path.is_file())
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["module"], "mod")
        self.assertTrue(data["note"])
        self.assertEqual(len(data["cases"]), 3)
        for item in data["cases"]:
            self.assertNotIn("draft_ok", item)

    def test_failed_cases_not_persisted(self):
        result = {"cases": [case("a1"), case("f1", draft_ok=False),
                            case("a2"), case("a3")]}
        self.run_main({"mod": result}, ["mod"])
        data = json.loads(
            (self.project / "bench" / "mod.json").read_text(encoding="utf-8"))
        self.assertEqual([item["call"] for item in data["cases"]],
                         ["a1", "a2", "a3"])

    def test_merge_dedup_and_non_dict_existing_filtered(self):
        existing = {"module": "mod", "note": "old",
                    "cases": [{"call": "e1", "kwargs": {"a": 1, "b": 2}},
                              "junk-entry", 7]}
        (self.project / "bench" / "mod.json").write_text(
            json.dumps(existing), encoding="utf-8")
        result = {"cases": [
            # Same call + same kwargs (different insertion order) -> dedup.
            case("e1", a=1, b=2),
            case("e2"),
            case("e3"),
        ]}
        out = self.run_main({"mod": result}, ["mod"])
        self.assertIn("+ mod: 3 przypadkow (dodano 2)", out)
        data = json.loads(
            (self.project / "bench" / "mod.json").read_text(encoding="utf-8"))
        self.assertEqual([item["call"] for item in data["cases"]],
                         ["e1", "e2", "e3"])
        for item in data["cases"]:
            self.assertIsInstance(item, dict)

    def test_corrupt_existing_json_starts_from_empty(self):
        (self.project / "bench" / "mod.json").write_text(
            "not-json{{", encoding="utf-8")
        result = {"cases": [case("a1"), case("a2"), case("a3")]}
        out = self.run_main({"mod": result}, ["mod"])
        self.assertIn("+ mod: 3 przypadkow (dodano 3)", out)
        data = json.loads(
            (self.project / "bench" / "mod.json").read_text(encoding="utf-8"))
        self.assertEqual(len(data["cases"]), 3)

    def test_draft_exception_reported_and_loop_continues(self):
        boom = RuntimeError("boom-boom")
        ok = {"cases": [case("a1"), case("a2"), case("a3")]}
        out = self.run_main({"mod1": boom, "mod2": ok}, ["mod1", "mod2"])
        self.assertIn("- mod1: RuntimeError: boom-boom", out)
        self.assertIn("+ mod2: 3 przypadkow (dodano 3)", out)
        self.assertFalse((self.project / "bench" / "mod1.json").exists())
        self.assertTrue((self.project / "bench" / "mod2.json").exists())

    def test_main_no_argv_uses_target_globs(self):
        # main([]) derives modules from PROJECT via targets([]).
        (self.project / "alpha.py").write_text("pass\n", encoding="utf-8")
        (self.project / "beta.py").write_text("pass\n", encoding="utf-8")
        def fresh():
            return {"cases": [case("a1"), case("a2"), case("a3")]}

        # Independent dicts per module: main() pops draft_ok in place.
        plan = {"alpha": fresh(), "beta": fresh()}
        out = self.run_main(plan, [])
        self.assertIn("+ alpha: 3 przypadkow (dodano 3)", out)
        self.assertIn("+ beta: 3 przypadkow (dodano 3)", out)
        self.assertTrue((self.project / "bench" / "alpha.json").is_file())
        self.assertTrue((self.project / "bench" / "beta.json").is_file())


if __name__ == "__main__":
    unittest.main()
