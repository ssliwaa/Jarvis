"""Automated unit test suite for Milestone 3 Domain 3 Operator Modules:
- operator_modules/op_repo_mapper.py
- operator_modules/op_mcp_bridge.py
- operator_modules/op_code_review.py
- operator_modules/op_local_llm_probe.py
- operator_modules/op_plan_sandbox.py

Verifies:
1. Tool registration contracts (TOOL schema, additionalProperties: False, approval flags).
2. Standard 5-key return envelope (ok, success, data, result, error) across success and error paths.
3. Codebase AST mapping, symbol hierarchy, reference graphs, and token-budgeted outlines.
4. MCP manifest export, schema inspection, stdio JSON-RPC 2.0 frames, and tool execution.
5. Unified diff parsing, security risk detection (eval, shell injection, secrets), and file hygiene.
6. Local LLM health discovery, REST probing, TCP benchmark pinging, and offline readiness checks.
7. Multi-stage transactional plan sandboxing, search/replace edits, diffing, atomic commits, and rollbacks.
8. Filesystem sandboxing within ALLOWED_ROOTS, sensitive path blocking, and network loopback confinement.
"""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

import operator_modules.op_code_review as op_code_review
import operator_modules.op_local_llm_probe as op_local_llm_probe
import operator_modules.op_mcp_bridge as op_mcp_bridge
import operator_modules.op_plan_sandbox as op_plan_sandbox
import operator_modules.op_repo_mapper as op_repo_mapper


class BaseDomain3TestCase(unittest.TestCase):
    def _assert_envelope(self, res: dict, expected_ok: bool) -> None:
        """Assert standard 5-key Jarvis operator envelope structure."""
        self.assertIsInstance(res, dict, "Result must be a dictionary")
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


class TestOpRepoMapper(BaseDomain3TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(dir="/tmp")
        self.sample_dir = Path(self.temp_dir.name)
        # Create sample python files
        self.file_a = self.sample_dir / "service_a.py"
        self.file_a.write_text(
            '"""Service A Module."""\n\n'
            'import os\n\n'
            'class BaseService:\n'
            '    """Base service class."""\n'
            '    def run(self, flag: bool = True) -> str:\n'
            '        return "base"\n\n'
            'class WorkerService(BaseService):\n'
            '    def execute(self, task_name: str) -> None:\n'
            '        self.run()\n'
            '        helper_func(task_name)\n\n'
            'def helper_func(name: str) -> str:\n'
            '    """Helper utility."""\n'
            '    return f"hello {name}"\n',
            encoding="utf-8",
        )

        self.file_b = self.sample_dir / "main.py"
        self.file_b.write_text(
            'from service_a import WorkerService, helper_func\n\n'
            'def main() -> None:\n'
            '    w = WorkerService()\n'
            '    w.execute("daily")\n'
            '    helper_func("test")\n',
            encoding="utf-8",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_tool_contract(self):
        """Verify TOOL registration contract for repo_mapper."""
        tool = op_repo_mapper.TOOL
        self.assertEqual(tool["name"], "repo_mapper")
        self.assertFalse(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        schema = tool["input_schema"]
        self.assertEqual(schema["type"], "object")
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("action", schema["required"])

    def test_map_tree_success(self):
        """Test generating directory tree."""
        res = op_repo_mapper.repo_mapper({
            "action": "map_tree",
            "directory": str(self.sample_dir),
            "max_depth": 2,
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertEqual(data["total_files"], 2)
        self.assertGreaterEqual(data["total_size_bytes"], 100)
        self.assertEqual(len(data["tree"]["children"]), 2)

    def test_extract_symbols_success(self):
        """Test extracting AST symbols from Python file."""
        res = op_repo_mapper.repo_mapper({
            "action": "extract_symbols",
            "path": str(self.file_a),
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertEqual(len(data["classes"]), 2)
        class_names = [c["name"] for c in data["classes"]]
        self.assertIn("BaseService", class_names)
        self.assertIn("WorkerService", class_names)
        func_names = [f["name"] for f in data["functions"]]
        self.assertIn("helper_func", func_names)
        self.assertIn("os", data["imports"])

    def test_find_symbol_success(self):
        """Test locating symbol definitions across files."""
        res = op_repo_mapper.repo_mapper({
            "action": "find_symbol",
            "directory": str(self.sample_dir),
            "symbol_name": "WorkerService",
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertEqual(data["matches_count"], 1)
        self.assertEqual(data["matches"][0]["type"], "class")
        self.assertEqual(data["matches"][0]["name"], "WorkerService")
        self.assertIn("BaseService", data["matches"][0]["bases"])

    def test_get_call_hierarchy(self):
        """Test analyzing callers and callees."""
        res = op_repo_mapper.repo_mapper({
            "action": "get_call_hierarchy",
            "directory": str(self.sample_dir),
            "symbol_name": "helper_func",
        })
        self._assert_envelope(res, True)
        data = res["data"]
        callers = [c["caller"] for c in data["callers"]]
        self.assertIn("main", callers)

    def test_find_references(self):
        """Test finding code reference sites."""
        res = op_repo_mapper.repo_mapper({
            "action": "find_references",
            "directory": str(self.sample_dir),
            "symbol_query": "helper_func",
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertGreaterEqual(data["total_references"], 2)

    def test_build_repo_map_within_budget(self):
        """Test generating compact Markdown repo map within token budget."""
        res = op_repo_mapper.repo_mapper({
            "action": "build_repo_map",
            "directory": str(self.sample_dir),
            "token_budget": 512,
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertEqual(data["files_included"], 2)
        self.assertIn("# Repository Map", data["repo_map_markdown"])
        self.assertIn("BaseService", data["repo_map_markdown"])

    def test_security_allowed_roots_rejection(self):
        """Test that paths outside ALLOWED_ROOTS are strictly rejected."""
        res = op_repo_mapper.repo_mapper({
            "action": "map_tree",
            "directory": "/etc",
        })
        self._assert_envelope(res, False)
        self.assertIn("outside ALLOWED_ROOTS", res["error"])

    def test_security_sensitive_path_rejection(self):
        """Test that access to sensitive directories like .ssh is blocked."""
        sensitive_dir = Path.home() / ".ssh"
        res = op_repo_mapper.repo_mapper({
            "action": "map_tree",
            "directory": str(sensitive_dir),
        })
        self._assert_envelope(res, False)
        self.assertIn("restricted", res["error"])

    def test_invalid_action(self):
        """Test error handling for unknown actions."""
        res = op_repo_mapper.repo_mapper({"action": "unknown_action"})
        self._assert_envelope(res, False)
        self.assertIn("Invalid or missing action", res["error"])


class TestOpMCPBridge(BaseDomain3TestCase):
    def test_tool_contract(self):
        """Verify TOOL registration contract for mcp_bridge."""
        tool = op_mcp_bridge.TOOL
        self.assertEqual(tool["name"], "mcp_bridge")
        self.assertFalse(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        schema = tool["input_schema"]
        self.assertEqual(schema["type"], "object")
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("action", schema["required"])

    def test_export_manifest(self):
        """Test exporting standard MCP tools/list manifest."""
        res = op_mcp_bridge.mcp_bridge({"action": "export_manifest"})
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertEqual(data["protocolVersion"], "2024-11-05")
        self.assertGreater(data["count"], 0)
        tool_names = [t["name"] for t in data["tools"]]
        self.assertIn("repo_mapper", tool_names)
        self.assertIn("mcp_bridge", tool_names)

    def test_inspect_tool(self):
        """Test inspecting a specific tool schema."""
        res = op_mcp_bridge.mcp_bridge({
            "action": "inspect_tool",
            "tool_name": "repo_mapper",
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertEqual(data["name"], "repo_mapper")
        self.assertIn("action", data["property_names"])
        self.assertIn("action", data["required_fields"])

    def test_invoke_mcp_tool_success(self):
        """Test invoking a tool and receiving standard MCP content envelope."""
        res = op_mcp_bridge.mcp_bridge({
            "action": "invoke_mcp_tool",
            "tool_name": "repo_mapper",
            "arguments": {
                "action": "map_tree",
                "directory": "/tmp",
                "max_depth": 1,
            },
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertIn("content", data)
        self.assertFalse(data["isError"])
        self.assertEqual(data["content"][0]["type"], "text")
        raw_res = data["raw_response"]
        self.assertTrue(raw_res["ok"])

    def test_invoke_mcp_tool_nonexistent(self):
        """Test invoking non-existent tool returns error envelope."""
        res = op_mcp_bridge.mcp_bridge({
            "action": "invoke_mcp_tool",
            "tool_name": "non_existent_tool_xyz",
            "arguments": {},
        })
        self._assert_envelope(res, False)
        self.assertIn("not found in registry", res["error"])

    def test_validate_rpc_success(self):
        """Test validating valid JSON-RPC 2.0 frames."""
        valid_payload = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {},
        })
        res = op_mcp_bridge.mcp_bridge({
            "action": "validate_rpc",
            "rpc_payload": valid_payload,
        })
        self._assert_envelope(res, True)
        self.assertTrue(res["data"]["is_valid"])
        self.assertEqual(res["data"]["method"], "tools/list")

    def test_validate_rpc_malformed(self):
        """Test validating invalid JSON-RPC 2.0 frames."""
        invalid_payload = json.dumps({
            "jsonrpc": "1.0",
            "id": 1,
            "method": "test",
        })
        res = op_mcp_bridge.mcp_bridge({
            "action": "validate_rpc",
            "rpc_payload": invalid_payload,
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["is_valid"])
        self.assertEqual(res["data"]["error_code"], -32600)

    def test_handle_rpc_ping_and_init(self):
        """Test JSON-RPC handling for ping and initialize methods."""
        # Ping
        ping_res = op_mcp_bridge.mcp_bridge({
            "action": "handle_rpc",
            "rpc_payload": json.dumps({"jsonrpc": "2.0", "id": 10, "method": "ping"}),
        })
        self._assert_envelope(ping_res, True)
        self.assertEqual(ping_res["data"]["id"], 10)
        self.assertEqual(ping_res["data"]["result"], {})

        # Initialize
        init_res = op_mcp_bridge.mcp_bridge({
            "action": "handle_rpc",
            "rpc_payload": json.dumps({"jsonrpc": "2.0", "id": 11, "method": "initialize"}),
        })
        self._assert_envelope(init_res, True)
        self.assertEqual(init_res["data"]["result"]["serverInfo"]["name"], "jarvis-operator-mcp-server")


class TestOpCodeReview(BaseDomain3TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(dir="/tmp")
        self.sample_file = Path(self.temp_dir.name) / "code.py"
        self.sample_file.write_text(
            '"""Sample module."""\n\n'
            'def compute(val: int) -> int:\n'
            '    """Compute result."""\n'
            '    return val * 2\n',
            encoding="utf-8",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_tool_contract(self):
        """Verify TOOL registration contract for code_review."""
        tool = op_code_review.TOOL
        self.assertEqual(tool["name"], "code_review")
        self.assertFalse(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        schema = tool["input_schema"]
        self.assertEqual(schema["type"], "object")
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("action", schema["required"])

    def test_review_diff_clean(self):
        """Test reviewing clean unified diff produces high score and APPROVE recommendation."""
        diff = (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,3 +1,5 @@\n"
            "+def add_numbers(a: int, b: int) -> int:\n"
            "+    return a + b\n"
        )
        res = op_code_review.code_review({
            "action": "review_diff",
            "diff_text": diff,
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertEqual(data["review_score"], 100)
        self.assertEqual(data["recommendation"], "APPROVE")
        self.assertEqual(data["critical_issues"], 0)

    def test_review_diff_vulnerabilities(self):
        """Test reviewing diff with severe security anti-patterns flags critical issues."""
        diff = (
            "diff --git a/vuln.py b/vuln.py\n"
            "--- a/vuln.py\n"
            "+++ b/vuln.py\n"
            "@@ -1,5 +1,9 @@\n"
            "+import os\n"
            "+os.system('rm -rf /')\n"
            "+eval(user_input)\n"
            "+subprocess.run(cmd, shell=True)\n"
            "+api_key = 'AKIAAAAAAAAAAAAAAAAA'\n"
        )
        res = op_code_review.code_review({
            "action": "review_diff",
            "diff_text": diff,
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertGreaterEqual(data["critical_issues"], 3)
        self.assertEqual(data["recommendation"], "REQUEST_CHANGES")
        self.assertLess(data["review_score"], 70)

    def test_review_diff_code_smells(self):
        """Test reviewing diff with debugging and wildcard imports flags warnings."""
        diff = (
            "diff --git a/smell.py b/smell.py\n"
            "--- a/smell.py\n"
            "+++ b/smell.py\n"
            "@@ -1,3 +1,5 @@\n"
            "+breakpoint()\n"
            "+from math import *\n"
            "+print('debug output')\n"
        )
        res = op_code_review.code_review({
            "action": "review_diff",
            "diff_text": diff,
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertGreater(data["warnings"], 0)
        self.assertGreater(data["info"], 0)

    def test_scan_security_risks(self):
        """Test dedicated security scan on file."""
        vuln_file = Path(self.temp_dir.name) / "vuln.py"
        vuln_file.write_text("import pickle\nobj = pickle.loads(b'data')\n", encoding="utf-8")
        res = op_code_review.code_review({
            "action": "scan_security_risks",
            "path": str(vuln_file),
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertFalse(data["is_safe"])
        self.assertEqual(data["critical_count"], 1)
        self.assertEqual(data["findings"][0]["cwe"], "CWE-502")

    def test_check_file_hygiene(self):
        """Test evaluating file hygiene."""
        res = op_code_review.code_review({
            "action": "check_file_hygiene",
            "path": str(self.sample_file),
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertTrue(data["syntax_valid"])
        self.assertGreaterEqual(data["hygiene_score"], 90)

    def test_generate_changelog(self):
        """Test generating changelog from diff."""
        diff = (
            "diff --git a/auth.py b/auth.py\n"
            "--- a/auth.py\n"
            "+++ b/auth.py\n"
            "@@ -1,2 +1,3 @@\n"
            "+# Security hardening fix\n"
        )
        res = op_code_review.code_review({
            "action": "generate_changelog",
            "diff_text": diff,
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertIn("# Release Changelog", data["changelog_markdown"])
        self.assertGreater(data["total_entries"], 0)

    def test_verify_patch(self):
        """Test dry-run patch verification."""
        patch = (
            "--- a/code.py\n"
            "+++ b/code.py\n"
            "@@ -2,2 +2,3 @@\n"
            "+# added comment\n"
        )
        res = op_code_review.code_review({
            "action": "verify_patch",
            "path": str(self.sample_file),
            "patch_text": patch,
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertTrue(data["applies_cleanly"])

    def test_security_allowed_roots_rejection(self):
        """Test file hygiene on outside paths is rejected."""
        res = op_code_review.code_review({
            "action": "check_file_hygiene",
            "path": "/etc/passwd",
        })
        self._assert_envelope(res, False)
        self.assertIn("outside ALLOWED_ROOTS", res["error"])


class TestOpLocalLLMProbe(BaseDomain3TestCase):
    def test_tool_contract(self):
        """Verify TOOL registration contract for local_llm_probe."""
        tool = op_local_llm_probe.TOOL
        self.assertEqual(tool["name"], "local_llm_probe")
        self.assertFalse(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        schema = tool["input_schema"]
        self.assertEqual(schema["type"], "object")
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("action", schema["required"])

    def test_check_readiness(self):
        """Test checking offline local inference readiness."""
        res = op_local_llm_probe.local_llm_probe({
            "action": "check_readiness",
            "timeout": 0.2,
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertIn("is_ready", data)
        self.assertIn("mode", data)
        self.assertIn("recommendation", data)

    def test_benchmark_ping(self):
        """Test TCP socket connect latency testing."""
        res = op_local_llm_probe.local_llm_probe({
            "action": "benchmark_ping",
            "port": 9999,
            "timeout": 0.1,
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertEqual(len(data["pings"]), 1)
        self.assertFalse(data["pings"][0]["connected"])
        self.assertGreater(data["pings"][0]["latency_ms"], 0)

    def test_probe_endpoints_graceful_offline(self):
        """Test probing list of endpoints handles offline ports cleanly without crashing."""
        res = op_local_llm_probe.local_llm_probe({
            "action": "probe_endpoints",
            "endpoints": [
                "http://127.0.0.1:11434/api/tags",
                "http://127.0.0.1:8080/health",
            ],
            "timeout": 0.2,
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertEqual(data["probed_count"], 2)

    def test_probe_ollama_offline(self):
        """Test probing offline Ollama port returns structured failure without error envelope."""
        res = op_local_llm_probe.local_llm_probe({
            "action": "probe_ollama",
            "port": 19999,
            "timeout": 0.1,
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertFalse(data["reachable"])
        self.assertEqual(data["engine"], "ollama")

    def test_probe_llama_server_offline(self):
        """Test probing offline llama_server port returns structured failure."""
        res = op_local_llm_probe.local_llm_probe({
            "action": "probe_llama_server",
            "port": 19998,
            "timeout": 0.1,
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertFalse(data["reachable"])
        self.assertEqual(data["engine"], "llama_server")

    def test_probe_localai_offline(self):
        """Test probing offline LocalAI port returns structured failure."""
        res = op_local_llm_probe.local_llm_probe({
            "action": "probe_localai",
            "port": 19997,
            "timeout": 0.1,
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertFalse(data["reachable"])
        self.assertEqual(data["engine"], "localai")

    def test_probe_all(self):
        """Test probing all default ports in one action."""
        res = op_local_llm_probe.local_llm_probe({
            "action": "probe_all",
            "timeout": 0.1,
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertIn("ollama", data)
        self.assertIn("llama_server", data)
        self.assertIn("vllm", data)

    def test_security_non_loopback_rejected(self):
        """Test that probing non-loopback addresses raises security error."""
        res = op_local_llm_probe.local_llm_probe({
            "action": "benchmark_ping",
            "host": "8.8.8.8",
        })
        self._assert_envelope(res, False)
        self.assertIn("strictly restricted to local loopback", res["error"])


class TestOpPlanSandbox(BaseDomain3TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(dir="/tmp")
        self.sample_file = Path(self.temp_dir.name) / "service.py"
        self.sample_file.write_text("API_VERSION = 'v1'\nDEBUG = True\n", encoding="utf-8")
        self.stage_id = f"test_stage_{int(time.time() * 1000)}"

    def tearDown(self):
        self.temp_dir.cleanup()
        # Clean up sandbox session if any
        op_plan_sandbox.plan_sandbox({
            "action": "rollback_stage",
            "stage_id": self.stage_id,
        })

    def test_tool_contract(self):
        """Verify TOOL registration contract for plan_sandbox."""
        tool = op_plan_sandbox.TOOL
        self.assertEqual(tool["name"], "plan_sandbox")
        self.assertTrue(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        schema = tool["input_schema"]
        self.assertEqual(schema["type"], "object")
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("action", schema["required"])

    def test_create_stage_and_stage_file(self):
        """Test creating sandbox and staging a file."""
        c_res = op_plan_sandbox.plan_sandbox({
            "action": "create_stage",
            "stage_id": self.stage_id,
        })
        self._assert_envelope(c_res, True)
        self.assertEqual(c_res["data"]["status"], "ACTIVE")

        s_res = op_plan_sandbox.plan_sandbox({
            "action": "stage_file",
            "stage_id": self.stage_id,
            "file_path": str(self.sample_file),
        })
        self._assert_envelope(s_res, True)
        self.assertEqual(s_res["data"]["staged_files_count"], 1)

    def test_apply_edit_content(self):
        """Test whole content replacement inside sandbox does not alter live file."""
        op_plan_sandbox.plan_sandbox({"action": "create_stage", "stage_id": self.stage_id})
        op_plan_sandbox.plan_sandbox({"action": "stage_file", "stage_id": self.stage_id, "file_path": str(self.sample_file)})

        e_res = op_plan_sandbox.plan_sandbox({
            "action": "apply_edit",
            "stage_id": self.stage_id,
            "file_path": str(self.sample_file),
            "content": "API_VERSION = 'v2'\nDEBUG = False\n",
        })
        self._assert_envelope(e_res, True)
        self.assertTrue(e_res["data"]["is_modified"])

        # Verify live file on disk is UNTOUCHED
        live_content = self.sample_file.read_text(encoding="utf-8")
        self.assertEqual(live_content, "API_VERSION = 'v1'\nDEBUG = True\n")

    def test_apply_edit_search_replace(self):
        """Test search and replace modification inside sandbox."""
        op_plan_sandbox.plan_sandbox({"action": "create_stage", "stage_id": self.stage_id})
        op_plan_sandbox.plan_sandbox({"action": "stage_file", "stage_id": self.stage_id, "file_path": str(self.sample_file)})

        e_res = op_plan_sandbox.plan_sandbox({
            "action": "apply_edit",
            "stage_id": self.stage_id,
            "file_path": str(self.sample_file),
            "search_block": "DEBUG = True",
            "replace_block": "DEBUG = False",
        })
        self._assert_envelope(e_res, True)
        self.assertTrue(e_res["data"]["is_modified"])

    def test_diff_stage(self):
        """Test computing unified diff between live file and sandboxed copy."""
        op_plan_sandbox.plan_sandbox({"action": "create_stage", "stage_id": self.stage_id})
        op_plan_sandbox.plan_sandbox({"action": "stage_file", "stage_id": self.stage_id, "file_path": str(self.sample_file)})
        op_plan_sandbox.plan_sandbox({
            "action": "apply_edit",
            "stage_id": self.stage_id,
            "file_path": str(self.sample_file),
            "search_block": "v1",
            "replace_block": "v2",
        })

        d_res = op_plan_sandbox.plan_sandbox({
            "action": "diff_stage",
            "stage_id": self.stage_id,
        })
        self._assert_envelope(d_res, True)
        data = d_res["data"]
        self.assertEqual(data["modified_files_count"], 1)
        self.assertEqual(data["total_additions"], 1)
        self.assertEqual(data["total_deletions"], 1)
        self.assertIn("-API_VERSION = 'v1'", data["unified_diff"])
        self.assertIn("+API_VERSION = 'v2'", data["unified_diff"])

    def test_commit_stage(self):
        """Test committing staged changes atomically updates disk file and creates backup."""
        op_plan_sandbox.plan_sandbox({"action": "create_stage", "stage_id": self.stage_id})
        op_plan_sandbox.plan_sandbox({"action": "stage_file", "stage_id": self.stage_id, "file_path": str(self.sample_file)})
        op_plan_sandbox.plan_sandbox({
            "action": "apply_edit",
            "stage_id": self.stage_id,
            "file_path": str(self.sample_file),
            "content": "COMMITTED = True\n",
        })

        c_res = op_plan_sandbox.plan_sandbox({
            "action": "commit_stage",
            "stage_id": self.stage_id,
        })
        self._assert_envelope(c_res, True)
        self.assertEqual(c_res["data"]["status"], "COMMITTED")

        # Live file must now be updated
        self.assertEqual(self.sample_file.read_text(encoding="utf-8"), "COMMITTED = True\n")
        # Backup must exist
        backup_file = self.sample_file.with_suffix(f"{self.sample_file.suffix}.bak_{self.stage_id}")
        self.assertTrue(backup_file.exists())
        self.assertEqual(backup_file.read_text(encoding="utf-8"), "API_VERSION = 'v1'\nDEBUG = True\n")
        backup_file.unlink()

    def test_rollback_stage(self):
        """Test rolling back stage wipes sandbox cleanly."""
        op_plan_sandbox.plan_sandbox({"action": "create_stage", "stage_id": self.stage_id})
        op_plan_sandbox.plan_sandbox({"action": "stage_file", "stage_id": self.stage_id, "file_path": str(self.sample_file)})

        r_res = op_plan_sandbox.plan_sandbox({
            "action": "rollback_stage",
            "stage_id": self.stage_id,
        })
        self._assert_envelope(r_res, True)
        self.assertEqual(r_res["data"]["status"], "ROLLED_BACK")

    def test_list_sandboxes(self):
        """Test listing existing sandboxes."""
        op_plan_sandbox.plan_sandbox({"action": "create_stage", "stage_id": self.stage_id})
        l_res = op_plan_sandbox.plan_sandbox({"action": "list_sandboxes"})
        self._assert_envelope(l_res, True)
        self.assertGreaterEqual(l_res["data"]["total_sandboxes"], 1)

    def test_security_allowed_roots_rejection(self):
        """Test staging file outside ALLOWED_ROOTS is blocked."""
        op_plan_sandbox.plan_sandbox({"action": "create_stage", "stage_id": self.stage_id})
        res = op_plan_sandbox.plan_sandbox({
            "action": "stage_file",
            "stage_id": self.stage_id,
            "file_path": "/etc/hosts",
        })
        self._assert_envelope(res, False)
        self.assertIn("outside ALLOWED_ROOTS", res["error"])

    def test_security_sensitive_path_rejection(self):
        """Test staging sensitive credential file is blocked."""
        op_plan_sandbox.plan_sandbox({"action": "create_stage", "stage_id": self.stage_id})
        res = op_plan_sandbox.plan_sandbox({
            "action": "stage_file",
            "stage_id": self.stage_id,
            "file_path": str(Path.home() / ".bashrc"),
        })
        self._assert_envelope(res, False)
        self.assertIn("restricted", res["error"])


if __name__ == "__main__":
    unittest.main()
