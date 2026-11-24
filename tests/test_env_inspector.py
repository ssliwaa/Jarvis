"""Tests for operator_modules/env_inspector.py (Safe Environment Inspector)."""

from __future__ import annotations

import os
import socket
import unittest
from unittest.mock import patch

import operator_modules.env_inspector as env_inspector


class TestEnvInspector(unittest.TestCase):
    def test_tool_declaration_contract(self):
        tool = env_inspector.TOOL
        self.assertEqual(tool["name"], "env_inspector")
        self.assertFalse(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        self.assertEqual(tool["input_schema"]["type"], "object")
        self.assertFalse(tool["input_schema"]["additionalProperties"])

    def test_env_inspection_with_secret_redaction(self):
        mock_env = {
            "SAFE_PATH": "/usr/local/bin",
            "APP_ENV": "development",
            "OPENAI_API_KEY": "sk-proj-abc123456789",
            "DB_PASSWORD": "supersecretpassword",
            "AUTH_TOKEN": "Bearer xyz987",
        }
        with patch.dict(os.environ, mock_env, clear=True):
            res = env_inspector.env_inspector({"action": "env"})
            self.assertTrue(res["ok"])
            self.assertTrue(res["success"])
            variables = res["data"]["variables"]
            self.assertEqual(variables["SAFE_PATH"], "/usr/local/bin")
            self.assertEqual(variables["APP_ENV"], "development")
            self.assertEqual(variables["OPENAI_API_KEY"], "[REDACTED]")
            self.assertEqual(variables["DB_PASSWORD"], "[REDACTED]")
            self.assertEqual(variables["AUTH_TOKEN"], "[REDACTED]")
            self.assertEqual(res["data"]["redacted_count"], 3)
            self.assertEqual(res["result"], res["data"])

    def test_env_prefix_and_names_filter(self):
        mock_env = {
            "JARVIS_MODE": "test",
            "JARVIS_PORT": "9000",
            "OTHER_VAR": "value",
        }
        with patch.dict(os.environ, mock_env, clear=True):
            res_prefix = env_inspector.env_inspector({"action": "env", "prefix": "JARVIS_"})
            self.assertTrue(res_prefix["ok"])
            self.assertEqual(set(res_prefix["data"]["variables"].keys()), {"JARVIS_MODE", "JARVIS_PORT"})

            res_names = env_inspector.env_inspector({"action": "env", "names": ["OTHER_VAR"]})
            self.assertTrue(res_names["ok"])
            self.assertEqual(list(res_names["data"]["variables"].keys()), ["OTHER_VAR"])

    def test_check_tools_which(self):
        res = env_inspector.env_inspector({
            "action": "check_tools",
            "names": ["python3", "nonexistent_fake_tool_xyz"],
        })
        self.assertTrue(res["ok"])
        tools = res["data"]["tools"]
        self.assertTrue(tools["python3"]["installed"])
        self.assertIsNotNone(tools["python3"]["path"])
        self.assertFalse(tools["nonexistent_fake_tool_xyz"]["installed"])
        self.assertIsNone(tools["nonexistent_fake_tool_xyz"]["path"])

    def test_check_tools_path_traversal_prevention(self):
        res = env_inspector.env_inspector({
            "action": "check_tools",
            "names": ["../../bin/sh", "/bin/ls"],
        })
        self.assertTrue(res["ok"])
        tools = res["data"]["tools"]
        for tool_name in ["../../bin/sh", "/bin/ls"]:
            self.assertFalse(tools[tool_name]["installed"])
            self.assertIn("Invalid", tools[tool_name]["error"])

    def test_check_port_loopback_listener(self):
        # Bind a temporary loopback socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            port = s.getsockname()[1]

            res = env_inspector.env_inspector({
                "action": "check_port",
                "port": port,
                "host": "127.0.0.1",
            })
            self.assertTrue(res["ok"])
            self.assertTrue(res["data"]["listening"])
            self.assertEqual(res["data"]["port"], port)
            self.assertEqual(res["data"]["status"], "open / listening")

    def test_check_port_closed_port(self):
        # Find an unused port by binding and immediately closing
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        res = env_inspector.env_inspector({
            "action": "check_port",
            "port": port,
            "host": "127.0.0.1",
        })
        self.assertTrue(res["ok"])
        self.assertFalse(res["data"]["listening"])
        self.assertEqual(res["data"]["status"], "closed / not responding")

    def test_check_port_refuses_remote_host(self):
        res = env_inspector.env_inspector({
            "action": "check_port",
            "port": 80,
            "host": "8.8.8.8",
        })
        self.assertFalse(res["ok"])
        self.assertIn("Refusing", res["error"])

    def test_check_port_invalid_port(self):
        res1 = env_inspector.env_inspector({"action": "check_port", "port": 0})
        self.assertFalse(res1["ok"])

        res2 = env_inspector.env_inspector({"action": "check_port", "port": 70000})
        self.assertFalse(res2["ok"])

        res3 = env_inspector.env_inspector({"action": "check_port"})
        self.assertFalse(res3["ok"])

    def test_system_info(self):
        res = env_inspector.env_inspector({"action": "system_info"})
        self.assertTrue(res["ok"])
        data = res["data"]
        self.assertIn("platform", data)
        self.assertIn("python_version", data)
        self.assertIn("machine", data)
        self.assertIn("python_executable", data)

    def test_unsupported_action(self):
        res = env_inspector.env_inspector({"action": "nonexistent_action"})
        self.assertFalse(res["ok"])
        self.assertIn("Unsupported action", res["error"])

    def test_env_names_unhashable_items_handled(self):
        res = env_inspector.env_inspector({
            "action": "env",
            "names": [{"token": "val"}, ["sublist"]],
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["total_count"], 0)

    def test_expanded_sensitive_credentials_scrubbed(self):
        test_env = {
            "DB_PASS": "my_secret_pass",
            "MYSQL_PWD": "my_mysql_pass",
            "DATABASE_URL": "postgres://user:supersecretpass@localhost:5432/mydb",
            "REDIS_URL": "redis://:mypassword@localhost:6379/0",
            "PAYMENT_GATEWAY": "sk_live_xxxx-xxxx-xxxx-xxxx",
            "TEST_STRIPE": "sk_test_xxxx-xxxx-xxxx-xxxx",
            "NOTIFICATION_WEBHOOK": "https://hooks.slack.com/services/T00/B00/X00",
        }
        with patch.dict(os.environ, test_env, clear=True):
            res = env_inspector.env_inspector({"action": "env"})
            self.assertTrue(res["ok"])
            variables = res["data"]["variables"]
            for k in test_env:
                self.assertEqual(variables.get(k), "[REDACTED]", f"Key {k} was not redacted")


if __name__ == "__main__":
    unittest.main()
