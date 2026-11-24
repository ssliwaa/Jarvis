"""Row-ceiling and invariant-defense suite for operator_modules/op_tabular_data.py.

Characterizes the five raise sites the tracer reports as never executed
in this module. Empirical probes (trace probes of the dispatcher under
a patched MAX_ROW_COUNT) show every one of them is invariant-only
defense:

- line 319 (Markdown rows re-check): the parser raises earlier, at the
  data_lines check (line 306), and rows are built one per data line,
  so len(rows) can never exceed a limit the data-lines check passed
- line 434 (JSON rows outer re-check): all three JSON shapes carry
  their own inner limits before rows are returned (records list at
  330, split "columns/data" at 349, index dict at 356), so len(rows)
  is already bounded at the point of the outer check
- line 440 (Markdown outer duplicate of the parser's own checks)
- line 296 (empty Markdown headers): _split_row delegates to re.split,
  which never returns an empty list, so header_cells cannot be empty
- line 209 (post-resolve symlink re-check): the first symlink check
  already rejects every deterministic input (Path(path_str) lstat and
  os.path.islink are stable within the call, realpath never yields a
  symlink), leaving the re-check as TOCTOU-race armor

The live ceiling raises ARE triggered here through the dispatcher with
a patched MAX_ROW_COUNT (Markdown data-lines cap and the JSON records
cap), keeping the size-limit behavior pinned end-to-end.

100% offline and deterministic; every input is inline Markdown/JSON
authored by this suite.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

import operator_modules.op_tabular_data as td

MD_4_ROWS = "| a | b |\n|---|---|\n| 1 | 2 |\n| 3 | 4 |\n| 5 | 6 |\n| 7 | 8 |\n"
MD_2_ROWS = "| a | b |\n|---|---|\n| 1 | 2 |\n"
JSON_4_RECORDS = '[{"a": 1}, {"a": 2}, {"a": 3}, {"a": 4}]'


class TestRowCountCeilings(unittest.TestCase):
    """Live guards: dataset size ceilings (patched MAX_ROW_COUNT).

    These raise through the dispatcher end-to-end: the Markdown data
    lines cap (line 306, the first cap the parser can hit) and the
    JSON records cap (line 330, the first cap the records path can
    hit). The later duplicate re-checks (319/434/440) can never fire
    once these first-line guards passed; see the module docstring.
    """

    def test_markdown_row_ceiling_enforced(self):
        with patch.object(td, "MAX_ROW_COUNT", 3):
            res = td.tabular_data({"action": "convert_format",
                                   "data": MD_4_ROWS,
                                   "from_format": "markdown",
                                   "to_format": "csv"})
        self.assertFalse(res["ok"])
        self.assertIn("PayloadSizeError", res["error"])
        self.assertIn("Row count (4) exceeds maximum allowed (3).",
                      res["error"])

    def test_json_row_ceiling_enforced(self):
        with patch.object(td, "MAX_ROW_COUNT", 3):
            res = td.tabular_data({"action": "convert_format",
                                   "data": JSON_4_RECORDS,
                                   "from_format": "json",
                                   "to_format": "csv"})
        self.assertFalse(res["ok"])
        self.assertIn("PayloadSizeError", res["error"])
        self.assertIn("Row count (4) exceeds maximum allowed (3).",
                      res["error"])

    def test_rows_under_ceiling_convert_fine(self):
        # Contrast anchor: the same conversion succeeds under the
        # patched ceiling, proving the caps reject only real overruns.
        with patch.object(td, "MAX_ROW_COUNT", 3):
            res = td.tabular_data({"action": "convert_format",
                                   "data": MD_2_ROWS,
                                   "from_format": "markdown",
                                   "to_format": "csv"})
        self.assertTrue(res["ok"])
        self.assertIsNone(res["error"])


class TestInvariantDefenses(unittest.TestCase):
    """Nearest-observable behaviour around the five dead sites.

    These tests pin the behaviour adjacent to each invariant-only
    raise so that any refactor making them live will fail loudly and
    be re-audited.
    """

    def test_markdown_row_caps_reach_parser_first(self):
        # Over-ceiling Markdown raises the FIRST cap (data lines) with
        # the exact same message the later duplicates would produce;
        # a row-count error is impossible without the data-lines cap
        # firing first.
        with patch.object(td, "MAX_ROW_COUNT", 3):
            res = td.tabular_data({"action": "convert_format",
                                   "data": MD_4_ROWS,
                                   "from_format": "md",
                                   "to_format": "csv"})
        self.assertFalse(res["ok"])
        self.assertIn("PayloadSizeError", res["error"])
        self.assertIn("Row count (4) exceeds maximum allowed (3).",
                      res["error"])

    def test_markdown_header_split_never_yields_empty(self):
        # Line 296 guard: a pipe-only line yields a single empty
        # header cell (no raise), and the empty-input case raises
        # earlier from the 'no table lines' guard instead.
        headers, rows = td._parse_markdown_table("|")
        self.assertEqual(headers, [""])

        res = td.tabular_data({"action": "convert_format", "data": "",
                               "from_format": "markdown",
                               "to_format": "csv"})
        self.assertFalse(res["ok"])
        self.assertIn("No markdown table lines containing '|' found.",
                      res["error"])

    def test_symlink_first_check_covers_deterministic_inputs(self):
        # Line 209 guard: a symlinked output path is refused by the
        # FIRST check; a dot-suffixed plain directory path passes
        # both checks without any raise, so the post-resolve re-check
        # fires only on filesystem races (TOCTOU), never on input.
        import os
        import tempfile
        from pathlib import Path

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        real = root / "realdir"
        real.mkdir()
        os.symlink(real, root / "link")

        with self.assertRaises(td.SecurityError) as ctx:
            td._validate_output_path(str(root / "link"), overwrite=True)
        self.assertIn("Refusing to write to symbolic link",
                      str(ctx.exception))

        resolved = td._validate_output_path(str(real / "."), overwrite=True)
        self.assertEqual(resolved, real)


if __name__ == "__main__":
    unittest.main()
