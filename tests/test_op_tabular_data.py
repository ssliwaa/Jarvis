"""Automated unit test suite for operator_modules/op_tabular_data.py.

Verifies:
1. Tool registration contract, input_schema (additionalProperties: False), and approval=False.
2. Standard 5-key return envelope (ok, success, data, result, error).
3. Feature 17: convert_format (CSV, TSV, JSON records/split/index, Markdown tables).
4. Feature 18: sniff_dialect (delimiter, quotechar, escapechar, header detection, single-column fallback).
5. Feature 19: profile_columns (type inference, null counts, distinct counts, min/max).
6. Feature 20: to_markdown (clean GFM tables, pipe escaping, alignment, truncation).
7. Path confinement to ALLOWED_ROOTS, sensitive path blocking, and input size limits.
8. Integration with ToolRegistry dynamic discovery.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

import operator_modules.op_tabular_data as op_tabular_data
from tool_registry import ToolRegistry


class TestOpTabularData(unittest.TestCase):
    def setUp(self):
        # Create isolated temporary directory inside /tmp (part of ALLOWED_ROOTS)
        self.temp_dir = tempfile.TemporaryDirectory(dir="/tmp")
        self.root = Path(self.temp_dir.name).resolve()

        # Build sample CSV file
        self.csv_path = self.root / "sample.csv"
        self.csv_content = (
            "id,name,score,active,joined\n"
            "1,Alice,95.5,true,2023-01-15\n"
            "2,Bob,82.0,false,2023-02-20\n"
            "3,Charlie,,true,2023-03-10\n"
            "4,Diana,99.9,true,2023-04-05\n"
        )
        self.csv_path.write_text(self.csv_content, encoding="utf-8")

        # Build sample TSV file
        self.tsv_path = self.root / "sample.tsv"
        self.tsv_content = "colA\tcolB\tcolC\n10\tfoo\ttrue\n20\tbar\tfalse\n"
        self.tsv_path.write_text(self.tsv_content, encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def _assert_envelope(self, res: dict, expected_ok: bool):
        """Assert the standard 5-key Jarvis operator envelope structure."""
        self.assertIsInstance(res, dict)
        self.assertIn("ok", res)
        self.assertIn("success", res)
        self.assertIn("data", res)
        self.assertIn("result", res)
        self.assertIn("error", res)
        self.assertEqual(res["ok"], expected_ok)
        self.assertEqual(res["success"], expected_ok)
        if expected_ok:
            self.assertIsNone(res["error"])
            self.assertEqual(res["data"], res["result"])
        else:
            self.assertIsNone(res["data"])
            self.assertIsNone(res["result"])
            self.assertIsInstance(res["error"], str)
            self.assertGreater(len(res["error"]), 0)

    # =========================================================================
    # Contract & Schema Conformance Tests
    # =========================================================================

    def test_01_tool_declaration_contract(self):
        tool = op_tabular_data.TOOL
        self.assertEqual(tool["name"], "tabular_data")
        self.assertFalse(tool["approval"], "tabular_data is an analytical operator and must have approval=False")
        self.assertTrue(callable(tool["handler"]))
        self.assertEqual(tool["input_schema"]["type"], "object")
        self.assertFalse(tool["input_schema"]["additionalProperties"])
        self.assertIn("action", tool["input_schema"]["required"])

    def test_02_schema_actions_enum(self):
        actions = op_tabular_data.TOOL["input_schema"]["properties"]["action"]["enum"]
        expected = ["convert_format", "sniff_dialect", "profile_columns", "to_markdown"]
        for exp in expected:
            self.assertIn(exp, actions)

    def test_03_envelope_on_invalid_action(self):
        res = op_tabular_data.tabular_data({"action": "invalid_action"})
        self._assert_envelope(res, False)
        self.assertIn("ValueError", res["error"])

    def test_04_unknown_argument_rejected(self):
        res = op_tabular_data.tabular_data({"action": "sniff_dialect", "data": "a,b\n1,2", "malicious_arg": 123})
        self._assert_envelope(res, False)
        self.assertIn("Unexpected argument", res["error"])

    def test_05_missing_action(self):
        res = op_tabular_data.tabular_data({})
        self._assert_envelope(res, False)
        self.assertIn("ValueError", res["error"])

    # =========================================================================
    # Feature 17: convert_format Tests
    # =========================================================================

    def test_10_csv_to_json_records(self):
        res = op_tabular_data.tabular_data({
            "action": "convert_format",
            "data": "name,age\nAlice,30\nBob,25",
            "from_format": "csv",
            "to_format": "json",
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertEqual(data["format"], "json")
        self.assertEqual(data["row_count"], 2)
        parsed = json.loads(data["output"])
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["name"], "Alice")
        self.assertEqual(parsed[0]["age"], "30")

    def test_11_csv_to_json_split(self):
        res = op_tabular_data.tabular_data({
            "action": "convert_format",
            "data": "x,y\n1,2\n3,4",
            "from_format": "csv",
            "to_format": "json_split",
        })
        self._assert_envelope(res, True)
        parsed = json.loads(res["data"]["output"])
        self.assertEqual(parsed["columns"], ["x", "y"])
        self.assertEqual(parsed["data"], [["1", "2"], ["3", "4"]])

    def test_12_csv_to_json_index(self):
        res = op_tabular_data.tabular_data({
            "action": "convert_format",
            "data": "k,v\na,10\nb,20",
            "from_format": "csv",
            "to_format": "json_index",
        })
        self._assert_envelope(res, True)
        parsed = json.loads(res["data"]["output"])
        self.assertIn("0", parsed)
        self.assertEqual(parsed["0"]["k"], "a")

    def test_13_json_to_csv(self):
        json_input = json.dumps([{"a": 1, "b": 2}, {"a": 3, "b": 4}])
        res = op_tabular_data.tabular_data({
            "action": "convert_format",
            "data": json_input,
            "from_format": "json",
            "to_format": "csv",
        })
        self._assert_envelope(res, True)
        lines = res["data"]["output"].strip().splitlines()
        self.assertEqual(lines[0], "a,b")
        self.assertEqual(lines[1], "1,2")
        self.assertEqual(lines[2], "3,4")

    def test_14_csv_to_tsv(self):
        res = op_tabular_data.tabular_data({
            "action": "convert_format",
            "data": "col1,col2\nval1,val2",
            "from_format": "csv",
            "to_format": "tsv",
        })
        self._assert_envelope(res, True)
        lines = res["data"]["output"].strip().splitlines()
        self.assertEqual(lines[0], "col1\tcol2")
        self.assertEqual(lines[1], "val1\tval2")

    def test_15_tsv_to_csv(self):
        res = op_tabular_data.tabular_data({
            "action": "convert_format",
            "path": str(self.tsv_path),
            "from_format": "tsv",
            "to_format": "csv",
        })
        self._assert_envelope(res, True)
        lines = res["data"]["output"].strip().splitlines()
        self.assertEqual(lines[0], "colA,colB,colC")
        self.assertEqual(lines[1], "10,foo,true")

    def test_16_markdown_to_csv(self):
        md = "| name | city |\n| --- | --- |\n| Paris | France |\n| Tokyo | Japan |\n"
        res = op_tabular_data.tabular_data({
            "action": "convert_format",
            "data": md,
            "from_format": "markdown",
            "to_format": "csv",
        })
        self._assert_envelope(res, True)
        lines = res["data"]["output"].strip().splitlines()
        self.assertEqual(lines[0], "name,city")
        self.assertEqual(lines[1], "Paris,France")
        self.assertEqual(lines[2], "Tokyo,Japan")

    def test_17_file_output_atomic(self):
        out_file = self.root / "converted.json"
        res = op_tabular_data.tabular_data({
            "action": "convert_format",
            "path": str(self.csv_path),
            "output_path": str(out_file),
            "to_format": "json",
        })
        self._assert_envelope(res, True)
        self.assertTrue(out_file.exists())
        self.assertEqual(res["data"]["written_to"], str(out_file))
        # Verify 0o600 file permissions
        mode = stat.S_IMODE(out_file.stat().st_mode)
        self.assertEqual(mode, 0o600)

    def test_18_utf8_bom_handling(self):
        bom_csv = "\ufeffcol1,col2\nval1,val2"
        res = op_tabular_data.tabular_data({
            "action": "convert_format",
            "data": bom_csv,
            "to_format": "json",
        })
        self._assert_envelope(res, True)
        parsed = json.loads(res["data"]["output"])
        self.assertIn("col1", parsed[0])
        self.assertNotIn("\ufeffcol1", parsed[0])

    # =========================================================================
    # Feature 18: sniff_dialect Tests
    # =========================================================================

    def test_30_sniff_comma_csv(self):
        res = op_tabular_data.tabular_data({
            "action": "sniff_dialect",
            "path": str(self.csv_path),
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertEqual(data["delimiter"], ",")
        self.assertEqual(data["quotechar"], '"')
        self.assertTrue(data["has_header"])
        self.assertEqual(data["column_count"], 5)
        self.assertIn("name", data["columns"])

    def test_31_sniff_tsv(self):
        res = op_tabular_data.tabular_data({
            "action": "sniff_dialect",
            "path": str(self.tsv_path),
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["delimiter"], "\t")
        self.assertTrue(res["data"]["has_header"])

    def test_32_sniff_semicolon(self):
        semi = "a;b;c\n1;2;3\n4;5;6"
        res = op_tabular_data.tabular_data({
            "action": "sniff_dialect",
            "data": semi,
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["delimiter"], ";")

    def test_33_sniff_pipe(self):
        pipe_data = "header1|header2\nval1|val2\nval3|val4\n"
        res = op_tabular_data.tabular_data({
            "action": "sniff_dialect",
            "data": pipe_data,
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["delimiter"], "|")

    def test_34_sniff_empty_fails(self):
        res = op_tabular_data.tabular_data({
            "action": "sniff_dialect",
            "data": "   ",
        })
        self._assert_envelope(res, False)
        self.assertIn("FormatError", res["error"])

    def test_35_sniff_single_column_fallback(self):
        single_col = "numbers\n10\n20\n30\n"
        res = op_tabular_data.tabular_data({
            "action": "sniff_dialect",
            "data": single_col,
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["delimiter"], ",")
        self.assertEqual(res["data"]["column_count"], 1)
        self.assertEqual(res["data"]["columns"], ["numbers"])

    # =========================================================================
    # Feature 19: profile_columns Tests
    # =========================================================================

    def test_40_profile_types_and_metrics(self):
        res = op_tabular_data.tabular_data({
            "action": "profile_columns",
            "path": str(self.csv_path),
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertEqual(data["row_count"], 4)
        self.assertEqual(data["column_count"], 5)

        cols = {c["name"]: c for c in data["columns"]}
        # id: integer
        self.assertEqual(cols["id"]["inferred_type"], "integer")
        self.assertEqual(cols["id"]["min_value"], 1)
        self.assertEqual(cols["id"]["max_value"], 4)
        self.assertTrue(cols["id"]["is_unique"])

        # score: float with 1 null
        self.assertEqual(cols["score"]["inferred_type"], "float")
        self.assertEqual(cols["score"]["null_count"], 1)
        self.assertEqual(cols["score"]["null_percentage"], 25.0)
        self.assertAlmostEqual(cols["score"]["min_value"], 82.0)
        self.assertAlmostEqual(cols["score"]["max_value"], 99.9)

        # active: boolean
        self.assertEqual(cols["active"]["inferred_type"], "boolean")

        # joined: date
        self.assertEqual(cols["joined"]["inferred_type"], "date")
        self.assertEqual(cols["joined"]["min_value"], "2023-01-15")
        self.assertEqual(cols["joined"]["max_value"], "2023-04-05")

    def test_41_profile_distinct_count(self):
        sample = "cat,val\nA,1\nA,2\nB,3\nB,4"
        res = op_tabular_data.tabular_data({
            "action": "profile_columns",
            "data": sample,
        })
        self._assert_envelope(res, True)
        cols = {c["name"]: c for c in res["data"]["columns"]}
        self.assertEqual(cols["cat"]["distinct_count"], 2)
        self.assertFalse(cols["cat"]["is_unique"])
        self.assertEqual(len(cols["cat"]["sample_values"]), 2)

    def test_42_profile_all_nulls(self):
        sample = "col1,col2\n,\n,"
        res = op_tabular_data.tabular_data({
            "action": "profile_columns",
            "data": sample,
        })
        self._assert_envelope(res, True)
        cols = {c["name"]: c for c in res["data"]["columns"]}
        self.assertEqual(cols["col1"]["inferred_type"], "null")
        self.assertEqual(cols["col1"]["null_count"], 2)

    # =========================================================================
    # Feature 20: to_markdown Tests
    # =========================================================================

    def test_50_markdown_table_formatting(self):
        res = op_tabular_data.tabular_data({
            "action": "to_markdown",
            "data": "name,age,country\nAlice,30,USA\nBob,25,UK",
        })
        self._assert_envelope(res, True)
        md = res["data"]["markdown"]
        lines = md.strip().splitlines()
        self.assertEqual(len(lines), 4)  # header, delimiter, 2 rows
        self.assertTrue(lines[0].startswith("|") and lines[0].endswith("|"))
        self.assertIn("name", lines[0])
        self.assertIn("---", lines[1])

    def test_51_markdown_pipe_escaping(self):
        res = op_tabular_data.tabular_data({
            "action": "to_markdown",
            "data": "title,formula\nLogic,A|B\nMath,1|2",
        })
        self._assert_envelope(res, True)
        md = res["data"]["markdown"]
        self.assertIn(r"A\|B", md)
        self.assertIn(r"1\|2", md)

    def test_52_markdown_newline_conversion(self):
        res = op_tabular_data.tabular_data({
            "action": "to_markdown",
            "data": "id,notes\n1,\"Line 1\nLine 2\"",
        })
        self._assert_envelope(res, True)
        md = res["data"]["markdown"]
        self.assertIn("Line 1<br>Line 2", md)

    def test_53_markdown_alignments(self):
        res = op_tabular_data.tabular_data({
            "action": "to_markdown",
            "data": "left_col,center_col,right_col\n1,2,3",
            "alignments": {"left_col": "left", "center_col": "center", "right_col": "right"},
        })
        self._assert_envelope(res, True)
        md = res["data"]["markdown"]
        delims = md.splitlines()[1]
        self.assertIn(":-", delims)
        self.assertIn("-:", delims)

    def test_54_markdown_max_rows_truncation(self):
        rows = ["id,val"] + [f"{i},{i*10}" for i in range(10)]
        data = "\n".join(rows)
        res = op_tabular_data.tabular_data({
            "action": "to_markdown",
            "data": data,
            "max_rows": 3,
        })
        self._assert_envelope(res, True)
        md = res["data"]["markdown"]
        self.assertIn("more rows truncated", md)
        self.assertTrue(res["data"]["truncated"])
        lines = [line for line in md.splitlines() if line.startswith("|")]
        self.assertEqual(len(lines), 5)  # header, delimiter, 3 rows

    def test_55_markdown_max_col_width(self):
        res = op_tabular_data.tabular_data({
            "action": "to_markdown",
            "data": "id,long_text\n1,abcdefghijklmnopqrstuvwxyz",
            "max_col_width": 10,
        })
        self._assert_envelope(res, True)
        md = res["data"]["markdown"]
        self.assertIn("...", md)

    # =========================================================================
    # Security Perimeter & Path Confinement Tests
    # =========================================================================

    def test_60_confinement_outside_allowed_roots(self):
        res = op_tabular_data.tabular_data({
            "action": "sniff_dialect",
            "path": "/etc/passwd",
        })
        self._assert_envelope(res, False)
        self.assertIn("SecurityError", res["error"])

    def test_61_path_traversal_rejection(self):
        res = op_tabular_data.tabular_data({
            "action": "profile_columns",
            "path": str(self.root / ".." / ".." / "etc" / "passwd"),
        })
        self._assert_envelope(res, False)
        self.assertIn("SecurityError", res["error"])

    def test_62_null_byte_rejection(self):
        res = op_tabular_data.tabular_data({
            "action": "convert_format",
            "path": str(self.root / "file\0.csv"),
        })
        self._assert_envelope(res, False)
        self.assertIn("SecurityError", res["error"])

    def test_63_sensitive_file_blocking(self):
        env_file = self.root / ".env"
        env_file.write_text("API_KEY=secret\n", encoding="utf-8")
        res = op_tabular_data.tabular_data({
            "action": "convert_format",
            "path": str(env_file),
        })
        self._assert_envelope(res, False)
        self.assertIn("SecurityError", res["error"])

    def test_64_overwrite_protection(self):
        existing = self.root / "existing.csv"
        existing.write_text("old data", encoding="utf-8")
        res = op_tabular_data.tabular_data({
            "action": "convert_format",
            "data": "a,b\n1,2",
            "output_path": str(existing),
            "to_format": "csv",
            "overwrite": False,
        })
        self._assert_envelope(res, False)
        self.assertIn("FileExistsError", res["error"])

    def test_65_payload_size_limit(self):
        huge_data = "a,b\n" + ("x,y\n" * 3000000)  # > 10 MB
        res = op_tabular_data.tabular_data({
            "action": "convert_format",
            "data": huge_data,
        })
        self._assert_envelope(res, False)
        self.assertIn("PayloadSizeError", res["error"])

    def test_66_symlink_output_path_rejected(self):
        """Verify that writing to a symbolic link output_path is strictly rejected with SecurityError."""
        target_file = self.root / "target.csv"
        target_file.write_text("IMMUTABLE_CONTENT", encoding="utf-8")
        symlink_file = self.root / "symlink_output.csv"
        os.symlink(str(target_file), str(symlink_file))

        # Attempt to write to symlink with overwrite=True
        res = op_tabular_data.tabular_data({
            "action": "convert_format",
            "data": "id,val\n1,evil",
            "output_path": str(symlink_file),
            "to_format": "csv",
            "overwrite": True,
        })
        self._assert_envelope(res, False)
        self.assertIn("SecurityError", res["error"])
        self.assertIn("symbolic link", res["error"].lower())
        self.assertEqual(target_file.read_text(encoding="utf-8"), "IMMUTABLE_CONTENT")

        # Also test dangling symlink
        dangling_file = self.root / "dangling_link.csv"
        os.symlink(str(self.root / "nonexistent.csv"), str(dangling_file))
        res_dangling = op_tabular_data.tabular_data({
            "action": "convert_format",
            "data": "id,val\n1,evil",
            "output_path": str(dangling_file),
            "to_format": "csv",
            "overwrite": True,
        })
        self._assert_envelope(res_dangling, False)
        self.assertIn("SecurityError", res_dangling["error"])
        self.assertIn("symbolic link", res_dangling["error"].lower())

    def test_67_csv_with_quoted_tabs_auto_detection(self):
        """Verify that CSV with embedded tabs inside quoted fields is correctly detected as CSV, not TSV."""
        csv_data = 'name,notes\nitem1,"tab\thidden\thunt"\nitem2,"more\ttabs"\n'
        res = op_tabular_data.tabular_data({
            "action": "convert_format",
            "data": csv_data,
            "from_format": "auto",
            "to_format": "json",
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["columns"], ["name", "notes"])
        self.assertEqual(res["data"]["row_count"], 2)
        parsed = json.loads(res["data"]["output"])
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["name"], "item1")
        self.assertEqual(parsed[0]["notes"], "tab\thidden\thunt")
        self.assertEqual(parsed[1]["name"], "item2")
        self.assertEqual(parsed[1]["notes"], "more\ttabs")

    def test_68_max_row_count_exceeded_json(self):
        """Verify that JSON input exceeding MAX_ROW_COUNT (50,000) raises PayloadSizeError."""
        json_data = json.dumps([{"x": i} for i in range(50005)])
        res = op_tabular_data.tabular_data({
            "action": "convert_format",
            "data": json_data,
            "from_format": "json",
            "to_format": "csv",
        })
        self._assert_envelope(res, False)
        self.assertIn("PayloadSizeError", res["error"])
        self.assertIn("exceeds maximum allowed", res["error"])

    def test_69_max_row_count_exceeded_markdown(self):
        """Verify that Markdown input exceeding MAX_ROW_COUNT (50,000) raises PayloadSizeError."""
        md_lines = ["| col1 | col2 |", "| --- | --- |"]
        md_lines.extend(f"| {i} | val |" for i in range(50005))
        md_data = "\n".join(md_lines)
        res = op_tabular_data.tabular_data({
            "action": "convert_format",
            "data": md_data,
            "from_format": "markdown",
            "to_format": "json",
        })
        self._assert_envelope(res, False)
        self.assertIn("PayloadSizeError", res["error"])
        self.assertIn("exceeds maximum allowed", res["error"])

    # =========================================================================
    # ToolRegistry Integration Tests
    # =========================================================================

    def test_70_tool_registry_discovery(self):
        registry = ToolRegistry()
        self.assertIn("tabular_data", registry.tools)
        tool = registry.tools["tabular_data"]
        decl = tool.declaration()
        self.assertEqual(decl["name"], "tabular_data")
        self.assertFalse(tool.approval)

        # Run invocation through registry
        res = registry.run("tabular_data", {
            "action": "convert_format",
            "data": "col1,col2\n1,2",
            "to_format": "json",
        })
        self._assert_envelope(res, True)


if __name__ == "__main__":
    unittest.main()
