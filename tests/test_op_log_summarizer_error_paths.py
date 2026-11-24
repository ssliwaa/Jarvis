"""ERROR-path coverage tests for operator_modules/op_log_summarizer.py.

Second wave of the sys.settrace audit, module four: log intelligence
(cluster_errors, detect_spikes, triage_stacktrace, mask_pii) with 16
raise sites and 6 never executed - all in the shared input loader.
The suite mirrors the op_secret_scanner one because the loaders share
the same guard family: path hygiene, existence checks, the size
ceiling, non-string inline text, and the read-failure wrapper.
"""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import operator_modules.op_log_summarizer as ls


class LogSummarizerCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def call(self, **kwargs):
        return ls.log_summarizer(kwargs)

    def bad(self, fragment, **kwargs):
        result = self.call(**kwargs)
        self.assertFalse(result["ok"], msg=str(result.get("error")))
        self.assertIn(fragment, result["error"])
        return result


class PathGuardTests(LogSummarizerCase):
    def test_empty_path_is_rejected_by_the_validator(self):
        with self.assertRaises(ValueError) as ctx:
            ls._validate_and_resolve_path("")
        self.assertIn("non-empty string", str(ctx.exception))

    def test_empty_path_via_dispatcher_scans_empty_content(self):
        # Characterization: the `path or source_path or log_path` chain
        # swallows an empty string, so the dispatcher treats it as empty
        # input instead of rejecting the path.
        result = self.call(action="cluster_errors", path="")
        self.assertTrue(result["ok"], msg=str(result.get("error")))

    def test_missing_log_file(self):
        self.bad("File not found",
                 action="cluster_errors",
                 path=str(self.tmp / "absent.log"))

    def test_directory_input_is_refused(self):
        subdir = self.tmp / "logs"
        subdir.mkdir()
        self.bad("is not a regular file.",
                 action="cluster_errors", path=str(subdir))

    def test_input_size_ceiling(self):
        bulky = self.tmp / "bulky.log"
        bulky.write_text("z" * 1024, encoding="utf-8")
        with patch.object(ls, "MAX_LOG_BYTES", 8):
            self.bad("exceeds maximum allowed size",
                     action="cluster_errors", path=str(bulky))

    def test_unreadable_file_reports_summarizer_error(self):
        locked = self.tmp / "locked.log"
        locked.write_text("2026-11-24 ERROR something broke\n",
                          encoding="utf-8")
        os.chmod(locked, 0)
        self.addCleanup(os.chmod, locked, 0o600)
        result = self.bad("Failed to read file",
                          action="cluster_errors", path=str(locked))
        self.assertIn("LogSummarizerError", result["error"])


class TextGuardTests(LogSummarizerCase):
    def test_non_string_inline_text_is_refused(self):
        self.bad("'text' must be a string.",
                 action="cluster_errors", text=12345)

    def test_inline_cluster_for_contrast(self):
        result = self.call(
            action="cluster_errors",
            text="2026-11-24 ERROR db connection refused\n"
                 "2026-11-24 ERROR db connection refused\n"
                 "2026-11-24 WARN cache warm\n")
        self.assertTrue(result["ok"], msg=str(result.get("error")))
        data = result.get("data") or result
        self.assertIn("clusters", data if isinstance(data, dict) else {})


if __name__ == "__main__":
    unittest.main()
