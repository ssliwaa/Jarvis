"""ERROR-path coverage tests for operator_modules/op_tabular_data.py.

Second module from the sys.settrace audit (CF methodology): the module
has 39 raise sites and the existing suites only ever execute 10. This
suite drives the remaining reachable branches through the public
``tabular_data`` dispatcher plus two direct helper probes: input/output
path hygiene (null bytes, traversal, sensitive names, extensions and
path parts), size ceilings, markdown/JSON/CSV parse failures, format
validation, and the atomic write cleanup turn.

Five raise lines are verified dead by structure and stay untested: the
markdown "failed to parse headers" branch (``_split_row`` always yields
at least one cell), the duplicated markdown and JSON dispatcher-level
row-count checks (the in-parser checks fire first with the same
thresholds), and the second symlink refusal in ``_validate_output_path``
- it is a TOCTOU race guard whose predicate repeats the first check, so
in single-threaded offline runs the first check always fires first.
The renderer's JSON-format guard is dead through the public dispatcher
(the handler's accepted tuple is a subset of the renderer's names) and
is exercised directly as a helper boundary instead.
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import operator_modules.op_tabular_data as op_tab


class TabularErrorCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def call(self, **kwargs):
        result = op_tab.tabular_data(kwargs)
        self.assertIsInstance(result, dict)
        self.assertIn("ok", result)
        self.assertIn("error", result)
        return result

    def bad(self, fragment, **kwargs):
        result = self.call(**kwargs)
        self.assertFalse(result["ok"], msg=str(result.get("error")))
        self.assertIn(fragment, result["error"])
        return result

    def mkfile(self, name, content="a,b\n1,2\n"):
        target = self.tmp / name
        target.write_text(content, encoding="utf-8")
        return target


class InputPathGuards(TabularErrorCase):
    def test_empty_path_is_rejected(self):
        # The dispatcher's `path or source_path` chain swallows an empty
        # string, so the guard is characterized directly plus via the
        # dispatcher outcome.
        with self.assertRaises(ValueError):
            op_tab._validate_input_path("")
        self.bad("Either 'data' (inline string) or 'path'",
                 action="convert_format", path="")

    def test_missing_input_file(self):
        self.bad("Input file not found",
                 action="convert_format",
                 path=str(self.tmp / "nope.csv"))

    def test_directory_as_input(self):
        self.bad("not a regular file",
                 action="convert_format", path=str(self.tmp))

    def test_oversize_input_file(self):
        big = self.mkfile("big.csv", "abcdefgh" * 4)
        with patch.object(op_tab, "MAX_INPUT_BYTES", 8):
            self.bad("exceeds limit",
                     action="convert_format", path=str(big))

    def test_sensitive_path_part_is_blocked(self):
        secret_dir = self.tmp / ".ssh"
        secret_dir.mkdir()
        secret = secret_dir / "known_hosts"
        secret.write_text("csv,data\n1,2\n", encoding="utf-8")
        self.bad("sensitive path '.ssh' is blocked",
                 action="convert_format", path=str(secret))

    def test_sensitive_extension_is_blocked(self):
        cert = self.mkfile("cert.pem", "not really a key")
        self.bad("sensitive file extension '.pem' is blocked",
                 action="convert_format", path=str(cert))


class OutputPathGuards(TabularErrorCase):
    def test_null_byte_in_output_path(self):
        self.bad("Null byte in output path",
                 action="convert_format", data="a,b\n1,2\n",
                 output_path=str(self.tmp / "out\x00.csv"))

    def test_traversal_in_output_path(self):
        self.bad("traversal '..' detected in output path",
                 action="convert_format", data="a,b\n1,2\n",
                 output_path="/tmp/../etc/escape.csv")

    def test_output_outside_allowed_roots(self):
        self.bad("resolves outside ALLOWED_ROOTS",
                 action="convert_format", data="a,b\n1,2\n",
                 output_path="/etc/jarvis_should_not_write.csv")

    def test_output_to_symlink_refused(self):
        real = self.mkfile("real.csv")
        link = self.tmp / "link.csv"
        link.symlink_to(real)
        self.bad("Refusing to write to symbolic link",
                 action="convert_format", data="a,b\n1,2\n",
                 output_path=str(link))

    def test_empty_output_path_helper_is_direct_guard(self):
        with self.assertRaises(ValueError):
            op_tab._validate_output_path("")

    def test_atomic_write_helper_refuses_symlinks(self):
        real = self.mkfile("real.csv")
        link = self.tmp / "link.csv"
        link.symlink_to(real)
        with self.assertRaises(op_tab.SecurityError):
            op_tab._atomic_write_file(link, "a,b\n")

    def test_oversize_output_payload(self):
        # Input (8 bytes) passes the lowered ceiling; the JSON rendering
        # is much larger, so the atomic writer's payload check fires.
        with patch.object(op_tab, "MAX_INPUT_BYTES", 8):
            self.bad("Output payload size",
                     action="convert_format", data="a,b\n1,2\n",
                     to_format="json", output_path=str(self.tmp / "out.json"))

    def test_replace_failure_cleans_temp_file(self):
        # overwrite=True lets an existing DIRECTORY target past the
        # existence check; os.replace then fails and the atomic writer
        # must clean up its temp sibling before re-raising.
        dest = self.tmp / "already_a_dir"
        dest.mkdir()
        result = self.call(action="convert_format", data="a,b\n1,2\n",
                           output_path=str(dest), overwrite=True)
        self.assertFalse(result["ok"])
        leftovers = [p for p in self.tmp.iterdir()
                     if p.name.endswith(".tmp")]
        self.assertEqual(leftovers, [])


class DataInputGuards(TabularErrorCase):
    def test_non_string_data(self):
        self.bad("'data' parameter must be a string",
                 action="convert_format", data=42)

    def test_neither_data_nor_path(self):
        self.bad("Either 'data' (inline string) or 'path'",
                 action="convert_format")


class MarkdownGuards(TabularErrorCase):
    def test_no_pipe_lines(self):
        self.bad("No markdown table lines containing '|'",
                 action="convert_format", data="plain prose without pipes",
                 from_format="markdown")

    def test_row_count_ceiling(self):
        table = "| a | b |\n|---|---|\n" + "| 1 | 2 |\n" * 5
        with patch.object(op_tab, "MAX_ROW_COUNT", 4):
            self.bad("Row count (5) exceeds maximum",
                     action="convert_format", data=table,
                     from_format="markdown")


class JsonGuards(TabularErrorCase):
    def test_records_row_count_ceiling(self):
        records = json.dumps([{"a": i} for i in range(5)])
        with patch.object(op_tab, "MAX_ROW_COUNT", 4):
            self.bad("Row count (5) exceeds maximum",
                     action="convert_format", data=records,
                     from_format="json")

    def test_index_orientation_row_count_ceiling(self):
        index = json.dumps({f"k{i}": {"a": i} for i in range(5)})
        with patch.object(op_tab, "MAX_ROW_COUNT", 4):
            self.bad("Row count (5) exceeds maximum",
                     action="convert_format", data=index,
                     from_format="json")

    def test_split_orientation_row_count_ceiling(self):
        split = json.dumps({"columns": ["a"], "data": [[i] for i in range(5)]})
        with patch.object(op_tab, "MAX_ROW_COUNT", 4):
            self.bad("Row count (5) exceeds maximum",
                     action="convert_format", data=split,
                     from_format="json")

    def test_list_of_lists_row_count_ceiling(self):
        # The list-of-lists JSON branch has no in-parser row check, so
        # this exercises the dispatcher-level ceiling in _parse_table.
        rows = json.dumps([[i] for i in range(5)])
        with patch.object(op_tab, "MAX_ROW_COUNT", 4):
            self.bad("Row count (5) exceeds maximum",
                     action="convert_format", data=rows,
                     from_format="json")

    def test_unrecognized_json_shape(self):
        self.bad("Unrecognized JSON tabular format",
                 action="convert_format", data=json.dumps([42]),
                 from_format="json")

    def test_invalid_json_text(self):
        self.bad("Failed to parse JSON tabular data",
                 action="convert_format", data="{definitely not json",
                 from_format="json")


class CsvGuards(TabularErrorCase):
    def test_row_count_ceiling(self):
        text = "a,b\n" + "1,2\n" * 5
        with patch.object(op_tab, "MAX_ROW_COUNT", 4):
            self.bad("Row count (6) exceeds maximum",
                     action="convert_format", data=text, from_format="csv")


class FormatGuards(TabularErrorCase):
    def test_unsupported_source_format(self):
        self.bad("Unsupported format 'parquet'",
                 action="convert_format", data="a,b\n", from_format="parquet")

    def test_unsupported_json_render_helper_guard(self):
        # Unreachable through the dispatcher (the handler's json tuple is
        # a subset of the renderer's accepted names, typos fall through to
        # "Unsupported target format"), so the renderer's own guard is
        # characterized directly as a helper boundary.
        with self.assertRaises(op_tab.FormatError):
            op_tab._render_json([], [], "json_matrix")

    def test_unsupported_target(self):
        self.bad("Unsupported target format 'xml'",
                 action="convert_format", data="a,b\n1,2\n",
                 to_format="xml")


if __name__ == "__main__":
    unittest.main()
