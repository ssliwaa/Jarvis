"""Unit tests for scripts/lint.py: the pyflakes gate with noqa filtering.

The lint gate runs pyflakes as a child process, so `subprocess.run` is
patched everywhere here; source files for the noqa filter live in a tmp
ROOT. The module is imported as the namespace package `scripts.lint`.
"""
import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import scripts.lint as lint


class _LintCase(unittest.TestCase):
    """tmp ROOT + captured subprocess seam + captured stdout/stderr."""

    def setUp(self):
        self.tmp_obj = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp_obj.cleanup)
        self.root = Path(self.tmp_obj.name)

        patcher = mock.patch.object(lint, "ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

        self.captured = []

        def fake_run(argv, **kwargs):
            self.captured.append((list(argv), kwargs))
            return self.child_result

        patcher = mock.patch.object(lint.subprocess, "run", fake_run)
        patcher.start()
        self.addCleanup(patcher.stop)

        self.child_result = subprocess.CompletedProcess([], 0,
                                                        stdout="", stderr="")
        self.out = io.StringIO()
        self.err = io.StringIO()

    def run_main(self):
        with contextlib.redirect_stdout(self.out), \
                contextlib.redirect_stderr(self.err):
            return lint.main()

    def write(self, rel, content):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path


class TestTargets(_LintCase):
    """targets(): pattern sweep with cross-pattern dedup."""

    def test_all_patterns_collected_once(self):
        written = [self.write(rel, "x = 1\n") for rel in
                   ("top.py", "operator_modules/op_x.py", "features/f.py",
                    "tests/t.py", "scripts/s.py")]
        targets = lint.targets()
        self.assertEqual(set(targets), set(written))
        # tests/t.py matches both "*.py" and "tests/*.py" -> once.
        self.assertEqual(len(targets), len(written))
        self.assertIn(self.root / "tests" / "t.py", targets)

    def test_empty_root_returns_no_targets(self):
        self.assertEqual(lint.targets(), [])

    def test_directories_and_missing_skipped(self):
        (self.root / "operator_modules").mkdir()
        self.assertEqual(lint.targets(), [])


class TestMain(_LintCase):
    """main(): gate verdicts from the (patched) pyflakes child."""

    def test_clean_run_exits_zero(self):
        self.write("a.py", "x = 1\n")
        self.child_result = subprocess.CompletedProcess([], 0,
                                                        stdout="", stderr="")
        self.assertEqual(self.run_main(), 0)
        argv, kwargs = self.captured[0]
        self.assertEqual(argv[:3], [sys.executable, "-m", "pyflakes"])
        self.assertIn(str(self.root / "a.py"), argv)
        self.assertEqual(kwargs.get("cwd"), self.root)
        self.assertIn("lint: clean", self.out.getvalue())

    def test_child_runs_with_fail_closed_timeout(self):
        self.write("a.py", "x = 1\n")
        self.run_main()
        kwargs = self.captured[0][1]
        self.assertEqual(kwargs.get("timeout"), lint.LINT_TIMEOUT_S)
        self.assertGreater(lint.LINT_TIMEOUT_S, 0)

    def test_pyflakes_timeout_gates_red_not_hang(self):
        self.write("a.py", "x = 1\n")

        def hang(argv, **kwargs):
            self.captured.append((list(argv), kwargs))
            raise subprocess.TimeoutExpired(argv, lint.LINT_TIMEOUT_S)

        with mock.patch.object(lint.subprocess, "run", hang):
            code = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("timed out", self.err.getvalue())
        self.assertIn("pyflakes", self.err.getvalue())

    def test_missing_targets_gate_red_without_spawning(self):
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.captured, [])
        self.assertIn("no Python files", self.err.getvalue())

    def test_finding_fails_and_echoes(self):
        target = self.write("bad.py", "import os\n")
        self.child_result = subprocess.CompletedProcess(
            [], 1, stdout=f"{target}:1:1: 'os' imported but unused\n",
            stderr="")
        self.assertEqual(self.run_main(), 1)
        self.assertIn("'os' imported but unused", self.out.getvalue())
        self.assertIn("1 issue(s)", self.err.getvalue())

    def test_noqa_line_filtered_from_real_source(self):
        target = self.write("probe.py", "import os  # noqa: F401\n")
        self.child_result = subprocess.CompletedProcess(
            [], 1, stdout=f"{target}:1:1: 'os' imported but unused\n",
            stderr="")
        # The finding points at a source line carrying `# noqa`, so the
        # deliberate availability probe must not fail the gate.
        self.assertEqual(self.run_main(), 0)
        self.assertIn("lint: clean", self.out.getvalue())

    def test_noqa_not_found_when_vanished_source(self):
        target = self.root / "ghost.py"
        self.child_result = subprocess.CompletedProcess(
            [], 1, stdout=f"{target}:1:1: 'os' imported but unused\n",
            stderr="")
        # The referenced file does not exist -> OSError -> line kept.
        self.assertEqual(self.run_main(), 1)

    def test_unparseable_output_line_kept_verbatim(self):
        self.write("a.py", "x = 1\n")
        self.child_result = subprocess.CompletedProcess(
            [], 0, stdout="pyflakes exploded mysteriously\n", stderr="")
        self.assertEqual(self.run_main(), 1)
        self.assertIn("pyflakes exploded mysteriously", self.out.getvalue())

    def test_stderr_findings_also_counted(self):
        target = self.write("a.py", "x = 1\n")
        self.child_result = subprocess.CompletedProcess(
            [], 1, stdout="", stderr=f"{target}:1:1: unused variable\n")
        self.assertEqual(self.run_main(), 1)
        self.assertIn("unused variable", self.out.getvalue())

    def test_multiple_lines_reported_with_count(self):
        target = self.write("a.py", "import os\nimport sys\n")
        self.child_result = subprocess.CompletedProcess(
            [], 1,
            stdout=f"{target}:1:1: 'os' unused\n{target}:2:1: 'sys' unused\n",
            stderr="")
        self.assertEqual(self.run_main(), 1)
        self.assertIn("2 issue(s)", self.err.getvalue())


if __name__ == "__main__":
    unittest.main()
