"""Minimal MCP stdio contract test with a local fake server."""
import json
import tempfile
import textwrap
import unittest
from pathlib import Path

import mcp_client


class MCPTests(unittest.TestCase):
    def test_mcp_child_does_not_inherit_provider_secrets(self):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            process = mcp_client.MCPProcess("x", "true", [], cwd=tmp)
            self.assertNotIn("DEEPSEEK_API_KEY", process.env)
            os.environ["DEEPSEEK_API_KEY"] = "test-secret"
            try:
                process = mcp_client.MCPProcess("x", "true", [], cwd=tmp)
                self.assertNotIn("DEEPSEEK_API_KEY", process.env)
            finally:
                del os.environ["DEEPSEEK_API_KEY"]

    def test_status_and_tool_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "server.py"
            script.write_text(textwrap.dedent("""
                import json, sys
                for line in sys.stdin:
                    msg = json.loads(line)
                    method = msg.get("method")
                    if method == "initialize":
                        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"],
                                          "result": {"serverInfo": {"name": "fake"}}}), flush=True)
                    elif method == "tools/list":
                        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"],
                                          "result": {"tools": [{"name": "echo", "description": "Echo",
                                                                "inputSchema": {"type": "object"}}]}}), flush=True)
                    elif method == "tools/call":
                        args = msg.get("params", {}).get("arguments", {})
                        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"],
                                          "result": {"content": [{"type": "text", "text": args.get("text", "")}]}}), flush=True)
            """), encoding="utf-8")
            config = root / "mcp.json"
            config.write_text(json.dumps({"servers": [{"name": "fake", "command": "python3", "args": [str(script)]}]}),
                              encoding="utf-8")
            manager = mcp_client.MCPManager(config)
            self.assertEqual(manager.status()[0]["name"], "fake")
            tools = manager.tools()
            self.assertEqual(tools[0]["name"], "echo")
            result = manager.call("fake", "echo", {"text": "hello"})
            self.assertEqual(result["result"]["content"][0]["text"], "hello")
            manager.close()


if __name__ == "__main__":
    unittest.main()
