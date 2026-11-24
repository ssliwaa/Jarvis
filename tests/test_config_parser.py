"""Comprehensive test suite for operator_modules/config_parser.py."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import operator_modules.config_parser as config_parser


class TestConfigParser(unittest.TestCase):
    def test_tool_contract(self):
        tool = config_parser.TOOL
        self.assertEqual(tool["name"], "config_parser")
        self.assertFalse(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        self.assertEqual(tool["input_schema"]["type"], "object")
        self.assertFalse(tool["input_schema"]["additionalProperties"])
        self.assertIn("action", tool["input_schema"]["required"])

    def test_ini_parsing_standard_and_unsectioned(self):
        ini_content = """
[server]
host = 127.0.0.1
port = 8080

[database]
name = jarvis_db
timeout = 30
"""
        res = config_parser.config_parser({
            "action": "parse",
            "format": "ini",
            "text": ini_content,
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["config"]["server"]["host"], "127.0.0.1")
        self.assertEqual(res["data"]["config"]["server"]["port"], "8080")
        self.assertEqual(res["data"]["config"]["database"]["name"], "jarvis_db")

        # Unsectioned INI
        unsectioned = "key1 = val1\nkey2 = val2"
        res2 = config_parser.config_parser({
            "action": "parse",
            "format": "ini",
            "text": unsectioned,
        })
        self.assertTrue(res2["ok"])
        self.assertEqual(res2["data"]["config"]["DEFAULT"]["key1"], "val1")

    def test_ini_interpolation_recursion_bomb_safety(self):
        # Cyclical recursive expansion bomb that would freeze standard configparser
        bomb = """
[malicious]
a = %(b)s
b = %(a)s
c = %(c)s
"""
        res = config_parser.config_parser({
            "action": "parse",
            "format": "ini",
            "text": bomb,
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["config"]["malicious"]["a"], "%(b)s")
        self.assertEqual(res["data"]["config"]["malicious"]["b"], "%(a)s")

    def test_dotenv_lexical_parsing(self):
        dotenv_content = """
# This is a comment
export APP_ENV=production
DATABASE_URL="postgres://user:pass@localhost:5432/app\\nwith\\nescapes"
PORT=3000 # inline comment
DEBUG='false'
EMPTY=
"""
        res = config_parser.config_parser({
            "action": "parse",
            "format": "dotenv",
            "text": dotenv_content,
        })
        self.assertTrue(res["ok"])
        cfg = res["data"]["config"]
        self.assertEqual(cfg["APP_ENV"], "production")
        self.assertEqual(cfg["PORT"], "3000")
        self.assertEqual(cfg["DEBUG"], "false")
        self.assertEqual(cfg["EMPTY"], "")
        self.assertIn("postgres://user:pass@localhost:5432/app\nwith\nescapes", cfg["DATABASE_URL"])

    def test_properties_parsing(self):
        prop_content = """
# Properties comment
! Another comment
server.host = 192.168.1.1
server.port : 8000
greeting\\ message = Hello\\
 World!
unicode.test = \\u0048\\u0065\\u006c\\u006c\\u006f
"""
        res = config_parser.config_parser({
            "action": "parse",
            "format": "properties",
            "text": prop_content,
        })
        self.assertTrue(res["ok"])
        cfg = res["data"]["config"]
        self.assertEqual(cfg["server.host"], "192.168.1.1")
        self.assertEqual(cfg["server.port"], "8000")
        self.assertEqual(cfg["greeting message"], "Hello World!")
        self.assertEqual(cfg["unicode.test"], "Hello")

    def test_get_value_action(self):
        ini_content = """
[app]
theme = dark
api_key = secret123
"""
        # Specific section
        res1 = config_parser.config_parser({
            "action": "get_value",
            "format": "ini",
            "text": ini_content,
            "section": "app",
            "key": "theme",
        })
        self.assertTrue(res1["ok"])
        self.assertTrue(res1["data"]["found"])
        self.assertEqual(res1["data"]["value"], "dark")

        # Global search without section
        res2 = config_parser.config_parser({
            "action": "get_value",
            "format": "ini",
            "text": ini_content,
            "key": "api_key",
        })
        self.assertTrue(res2["ok"])
        self.assertTrue(res2["data"]["found"])
        self.assertEqual(res2["data"]["value"], "secret123")

        # Not found key
        res3 = config_parser.config_parser({
            "action": "get_value",
            "format": "ini",
            "text": ini_content,
            "key": "missing_key",
        })
        self.assertTrue(res3["ok"])
        self.assertFalse(res3["data"]["found"])
        self.assertIsNone(res3["data"]["value"])

    def test_format_action(self):
        ini_text = "[service]\nname = jarvis\nworkers = 4\n"
        res = config_parser.config_parser({
            "action": "format",
            "format": "dotenv",
            "text": ini_text,
        })
        self.assertTrue(res["ok"])
        formatted = res["data"]["formatted"]
        self.assertIn('name="jarvis"', formatted)
        self.assertIn('workers="4"', formatted)

    def test_validate_action(self):
        dotenv_content = "HOST=localhost\nPORT=8080\n"
        res_valid = config_parser.config_parser({
            "action": "validate",
            "format": "dotenv",
            "text": dotenv_content,
            "required_keys": ["HOST", "PORT"],
        })
        self.assertTrue(res_valid["ok"])
        self.assertTrue(res_valid["data"]["valid"])
        self.assertEqual(res_valid["data"]["missing_keys"], [])

        res_invalid = config_parser.config_parser({
            "action": "validate",
            "format": "dotenv",
            "text": dotenv_content,
            "required_keys": ["HOST", "PORT", "SECRET_KEY"],
        })
        self.assertTrue(res_invalid["ok"])
        self.assertFalse(res_invalid["data"]["valid"])
        self.assertEqual(res_invalid["data"]["missing_keys"], ["SECRET_KEY"])

    def test_load_from_path_and_sensitive_target_blocking(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sample_file = Path(tmpdir) / "app.ini"
            sample_file.write_text("[section]\nfoo = bar\n", encoding="utf-8")

            res = config_parser.config_parser({
                "action": "parse",
                "format": "ini",
                "path": str(sample_file),
            })
            self.assertTrue(res["ok"])
            self.assertEqual(res["data"]["config"]["section"]["foo"], "bar")

        # Test sensitive target blocking
        sensitive_path = Path.home() / ".ssh" / "config"
        res_blocked = config_parser.config_parser({
            "action": "parse",
            "format": "ini",
            "path": str(sensitive_path),
        })
        self.assertFalse(res_blocked["ok"])
        self.assertIn("protected credential target", res_blocked["error"].lower())

    def test_payload_limit_enforced(self):
        oversized = "a = 1\n" * 100_000
        res = config_parser.config_parser({
            "action": "parse",
            "format": "ini",
            "text": oversized,
        })
        self.assertFalse(res["ok"])
        self.assertIn("exceeds maximum size", res["error"])


if __name__ == "__main__":
    unittest.main()
