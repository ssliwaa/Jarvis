"""Tests for operator_modules/data_transform.py (Structured Data Transformation)."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

import operator_modules.data_transform as data_transform


class TestDataTransform(unittest.TestCase):
    def test_tool_declaration_contract(self):
        tool = data_transform.TOOL
        self.assertEqual(tool["name"], "data_transform")
        self.assertFalse(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        self.assertEqual(tool["input_schema"]["type"], "object")
        self.assertFalse(tool["input_schema"]["additionalProperties"])

    def test_query_nested_path(self):
        sample = {
            "users": [
                {"id": 1, "profile": {"name": "Alice", "city": "Warsaw"}},
                {"id": 2, "profile": {"name": "Bob", "city": "Krakow"}},
            ],
            "total": 2,
        }
        res = data_transform.data_transform({
            "action": "query",
            "data": sample,
            "path": "users[0].profile.name",
        })
        self.assertTrue(res["ok"])
        self.assertTrue(res["success"])
        self.assertEqual(res["data"]["result"], "Alice")
        self.assertEqual(res["result"], res["data"])

    def test_query_missing_path(self):
        sample = {"users": [{"name": "Alice"}]}
        res = data_transform.data_transform({
            "action": "query",
            "data": sample,
            "path": "users[5].name",
        })
        self.assertTrue(res["ok"])
        self.assertIsNone(res["data"]["result"])
        self.assertFalse(res["data"]["found"])

    def test_query_empty_path(self):
        sample = {"users": [1, 2, 3]}
        res = data_transform.data_transform({
            "action": "query",
            "data": sample,
            "path": "",
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["result"], sample)

    def test_convert_json_to_csv(self):
        items = [
            {"id": "1", "name": "CPU", "temp": "45"},
            {"id": "2", "name": "RAM", "temp": "38"},
        ]
        res = data_transform.data_transform({
            "action": "convert",
            "data": items,
            "to_format": "csv",
        })
        self.assertTrue(res["ok"])
        csv_text = res["data"]["result"]
        self.assertIn("id,name,temp", csv_text)
        self.assertIn("CPU", csv_text)
        self.assertEqual(res["data"]["row_count"], 2)

    def test_convert_csv_to_json(self):
        raw_csv = "id,name\n10,Widget\n20,Gadget\n"
        res = data_transform.data_transform({
            "action": "convert",
            "data": raw_csv,
            "from_format": "csv",
            "to_format": "json",
        })
        self.assertTrue(res["ok"])
        parsed = json.loads(res["data"]["result"])
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["name"], "Widget")

    def test_convert_json_to_ndjson(self):
        items = [{"id": 1, "status": "active"}, {"id": 2, "status": "idle"}]
        res = data_transform.data_transform({
            "action": "convert",
            "data": items,
            "to_format": "ndjson",
        })
        self.assertTrue(res["ok"])
        lines = res["data"]["result"].splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0])["id"], 1)

    def test_convert_ndjson_to_json(self):
        raw_ndjson = '{"id": 1}\n{"id": 2}\n'
        res = data_transform.data_transform({
            "action": "convert",
            "data": raw_ndjson,
            "from_format": "ndjson",
            "to_format": "json",
        })
        self.assertTrue(res["ok"])
        parsed = json.loads(res["data"]["result"])
        self.assertEqual(len(parsed), 2)

    def test_convert_csv_invalid_input(self):
        res = data_transform.data_transform({
            "action": "convert",
            "data": [1, 2, 3],
            "to_format": "csv",
        })
        self.assertFalse(res["ok"])
        self.assertIn("array of objects", res["error"])

    def test_validate_schema_success_and_failure(self):
        schema = {
            "type": "object",
            "required": ["username", "age"],
            "properties": {
                "username": {"type": "string"},
                "age": {"type": "integer"},
            },
        }
        # Success case
        res1 = data_transform.data_transform({
            "action": "validate",
            "data": {"username": "admin", "age": 30},
            "schema": schema,
        })
        self.assertTrue(res1["ok"])
        self.assertTrue(res1["data"]["valid"])
        self.assertEqual(res1["data"]["error_count"], 0)

        # Failure case (missing age and invalid username type)
        res2 = data_transform.data_transform({
            "action": "validate",
            "data": {"username": 123},
            "schema": schema,
        })
        self.assertTrue(res2["ok"])
        self.assertFalse(res2["data"]["valid"])
        self.assertGreaterEqual(res2["data"]["error_count"], 1)

    def test_summarize_array_and_object(self):
        res_arr = data_transform.data_transform({
            "action": "summarize",
            "data": [{"a": 1, "b": 2}, {"a": 3, "b": 4}],
        })
        self.assertTrue(res_arr["ok"])
        self.assertEqual(res_arr["data"]["type"], "array")
        self.assertEqual(res_arr["data"]["item_count"], 2)

        res_obj = data_transform.data_transform({
            "action": "summarize",
            "data": {"key1": "val1", "key2": "val2"},
        })
        self.assertTrue(res_obj["ok"])
        self.assertEqual(res_obj["data"]["type"], "object")
        self.assertEqual(res_obj["data"]["key_count"], 2)

    def test_filter_predicate(self):
        items = [
            {"name": "test1.py", "lines": 50},
            {"name": "test2.py", "lines": 150},
            {"name": "test3.py", "lines": 20},
        ]
        res = data_transform.data_transform({
            "action": "filter",
            "data": items,
            "filter_expr": {"field": "lines", "op": ">", "value": 40},
        })
        self.assertTrue(res["ok"])
        results = res["data"]["results"]
        self.assertEqual(len(results), 2)
        names = {item["name"] for item in results}
        self.assertEqual(names, {"test1.py", "test2.py"})

    def test_filter_predicate_contains(self):
        items = [
            {"file": "main.py"},
            {"file": "test_app.py"},
            {"file": "readme.md"},
        ]
        res = data_transform.data_transform({
            "action": "filter",
            "data": items,
            "filter_expr": {"field": "file", "op": "contains", "value": "test"},
        })
        self.assertTrue(res["ok"])
        self.assertEqual(len(res["data"]["results"]), 1)
        self.assertEqual(res["data"]["results"][0]["file"], "test_app.py")

    def test_filter_limit(self):
        items = [{"id": i} for i in range(10)]
        res = data_transform.data_transform({
            "action": "filter",
            "data": items,
            "filter_expr": {"field": "id", "op": ">=", "value": 0},
            "limit": 3,
        })
        self.assertTrue(res["ok"])
        self.assertEqual(len(res["data"]["results"]), 3)
        self.assertTrue(res["data"]["truncated"])
        self.assertEqual(res["data"]["matched_count"], 10)

    def test_optional_yaml_fallback_when_missing(self):
        with patch.object(data_transform, "yaml", None):
            res = data_transform.data_transform({
                "action": "convert",
                "data": {"key": "val"},
                "to_format": "yaml",
            })
            self.assertFalse(res["ok"])
            self.assertIn("pyyaml", res["error"].lower())

    def test_missing_data_error(self):
        res = data_transform.data_transform({})
        self.assertFalse(res["ok"])
        self.assertIn("required", res["error"])

    def test_unsupported_action(self):
        res = data_transform.data_transform({
            "action": "nonexistent_action",
            "data": [1, 2, 3],
        })
        self.assertFalse(res["ok"])
        self.assertIn("Unsupported action", res["error"])

    def test_convert_json_circular_data_error(self):
        d: dict = {"a": 1}
        d["self"] = d
        res = data_transform.data_transform({"action": "convert", "data": d, "to_format": "json"})
        self.assertFalse(res["ok"])
        self.assertIn("Transformation error", res["error"])

    def test_convert_json_non_serializable_error(self):
        res = data_transform.data_transform({"action": "convert", "data": {"items": {1, 2}}, "to_format": "json"})
        self.assertFalse(res["ok"])
        self.assertIn("Transformation error", res["error"])

    def test_convert_csv_heterogeneous_rows_error(self):
        res = data_transform.data_transform({
            "action": "convert",
            "data": [{"name": "alice"}, 123],
            "to_format": "csv",
        })
        self.assertFalse(res["ok"])
        self.assertIn("objects/dicts", res["error"])

    def test_filter_unhashable_field_gracefully_handled(self):
        res = data_transform.data_transform({
            "action": "filter",
            "data": [{"name": "alice"}],
            "filter_expr": {"field": ["unhashable_list"], "op": "==", "value": 1},
        })
        self.assertTrue(res["ok"])
        self.assertEqual(len(res["data"]["results"]), 0)

    def test_validate_malformed_schema_gracefully_handled(self):
        res1 = data_transform.data_transform({
            "action": "validate",
            "data": {"a": 1},
            "schema": {"type": "object", "properties": "invalid"},
        })
        self.assertTrue(res1["ok"])
        self.assertFalse(res1["data"]["valid"])

        res2 = data_transform.data_transform({
            "action": "validate",
            "data": {"a": 1},
            "schema": {"type": "object", "required": 123},
        })
        self.assertTrue(res2["ok"])
        self.assertFalse(res2["data"]["valid"])


if __name__ == "__main__":
    unittest.main()
