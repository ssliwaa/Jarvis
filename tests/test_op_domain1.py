"""Automated unit test suite for Milestone 1 Domain 1 Operator Modules:
- operator_modules/op_state_graph.py
- operator_modules/op_code_action_sandbox.py
- operator_modules/op_contract_validator.py
- operator_modules/op_a11y_tree_indexer.py

Verifies:
1. Tool registration contracts (TOOL schema, additionalProperties: False, approval flags).
2. Standard 5-key return envelope (ok, success, data, result, error) across success and error paths.
3. Cyclic graph execution, conditional branching, time-travel checkpointing, and rollbacks.
4. Safe AST code-as-action evaluation, step capping, timeout guards, and security enforcement.
5. JSON schema validation, envelope conformance verification, and operator module compliance auditing.
6. Accessibility tree parsing, coordinate tag indexing, token reduction, and selector queries.
7. Path confinement to ALLOWED_ROOTS and sensitive directory access blocking.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

import operator_modules.op_a11y_tree_indexer as op_a11y_tree_indexer
import operator_modules.op_code_action_sandbox as op_code_action_sandbox
import operator_modules.op_contract_validator as op_contract_validator
import operator_modules.op_state_graph as op_state_graph
from tool_registry import ToolRegistry


class BaseDomain1TestCase(unittest.TestCase):
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


class TestOpStateGraph(BaseDomain1TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(dir="/tmp")
        self.db_path = str(Path(self.temp_dir.name) / "test_graph.sqlite3")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_tool_contract(self):
        """Verify TOOL registration contract for state_graph."""
        tool = op_state_graph.TOOL
        self.assertEqual(tool["name"], "state_graph")
        self.assertFalse(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        schema = tool["input_schema"]
        self.assertEqual(schema["type"], "object")
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("action", schema["required"])

    def test_create_graph_and_get_state(self):
        """Test initializing a state graph and reading its initial state."""
        res = op_state_graph.state_graph({
            "action": "create_graph",
            "graph_id": "flow_1",
            "initial_state": {"counter": 0, "status": "init"},
            "node_name": "START",
            "db_path": self.db_path,
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertEqual(data["graph_id"], "flow_1")
        self.assertEqual(data["current_node"], "START")
        self.assertEqual(data["current_step"], 0)
        self.assertEqual(data["state"]["counter"], 0)

        # Retrieve state
        state_res = op_state_graph.state_graph({
            "action": "get_state",
            "graph_id": "flow_1",
            "db_path": self.db_path,
        })
        self._assert_envelope(state_res, True)
        self.assertEqual(state_res["data"]["current_node"], "START")
        self.assertEqual(state_res["data"]["state"]["status"], "init")

    def test_step_and_conditional_edges(self):
        """Test adding nodes, conditional edges, and stepping through graph."""
        # 1. Init
        op_state_graph.state_graph({
            "action": "create_graph",
            "graph_id": "approval_flow",
            "initial_state": {"score": 85},
            "node_name": "review",
            "db_path": self.db_path,
        })

        # 2. Add nodes and edges
        op_state_graph.state_graph({
            "action": "add_edge",
            "graph_id": "approval_flow",
            "node_name": "review",
            "target_node": "approved",
            "condition": {"field": "score", "op": ">=", "value": 80},
            "db_path": self.db_path,
        })
        op_state_graph.state_graph({
            "action": "add_edge",
            "graph_id": "approval_flow",
            "node_name": "review",
            "target_node": "rejected",
            "condition": {"field": "score", "op": "<", "value": 80},
            "db_path": self.db_path,
        })
        op_state_graph.state_graph({
            "action": "add_edge",
            "graph_id": "approval_flow",
            "node_name": "approved",
            "target_node": "END",
            "db_path": self.db_path,
        })

        # 3. Step from 'review' -> should transition to 'approved' because score >= 80
        step1 = op_state_graph.state_graph({
            "action": "step",
            "graph_id": "approval_flow",
            "db_path": self.db_path,
        })
        self._assert_envelope(step1, True)
        self.assertEqual(step1["data"]["previous_node"], "review")
        self.assertEqual(step1["data"]["current_node"], "approved")
        self.assertEqual(step1["data"]["current_step"], 1)
        self.assertFalse(step1["data"]["is_terminal"])

        # 4. Step from 'approved' -> should transition to 'END'
        step2 = op_state_graph.state_graph({
            "action": "step",
            "graph_id": "approval_flow",
            "db_path": self.db_path,
        })
        self._assert_envelope(step2, True)
        self.assertEqual(step2["data"]["current_node"], "END")
        self.assertEqual(step2["data"]["status"], "completed")
        self.assertTrue(step2["data"]["is_terminal"])

    def test_run_graph_to_completion(self):
        """Test running a multi-step workflow until completion."""
        op_state_graph.state_graph({
            "action": "create_graph",
            "graph_id": "pipeline",
            "initial_state": {"processed": False},
            "node_name": "fetch",
            "db_path": self.db_path,
        })
        op_state_graph.state_graph({
            "action": "add_edge",
            "graph_id": "pipeline",
            "node_name": "fetch",
            "target_node": "transform",
            "db_path": self.db_path,
        })
        op_state_graph.state_graph({
            "action": "add_edge",
            "graph_id": "pipeline",
            "node_name": "transform",
            "target_node": "END",
            "db_path": self.db_path,
        })

        run_res = op_state_graph.state_graph({
            "action": "run_graph",
            "graph_id": "pipeline",
            "state_delta": {"processed": True},
            "max_steps": 10,
            "db_path": self.db_path,
        })
        self._assert_envelope(run_res, True)
        self.assertEqual(run_res["data"]["current_node"], "END")
        self.assertEqual(run_res["data"]["status"], "completed")
        self.assertEqual(run_res["data"]["steps_executed"], 2)
        self.assertTrue(run_res["data"]["state"]["processed"])

    def test_time_travel_checkpoint_and_rollback(self):
        """Test durable SQLite checkpoints and rollback (time-travel)."""
        op_state_graph.state_graph({
            "action": "create_graph",
            "graph_id": "time_travel_graph",
            "initial_state": {"version": 1},
            "node_name": "v1",
            "db_path": self.db_path,
        })

        # Step 1: version 2
        op_state_graph.state_graph({
            "action": "step",
            "graph_id": "time_travel_graph",
            "node_name": "v2",
            "state_delta": {"version": 2},
            "db_path": self.db_path,
        })

        # Step 2: version 3
        op_state_graph.state_graph({
            "action": "step",
            "graph_id": "time_travel_graph",
            "node_name": "v3",
            "state_delta": {"version": 3},
            "db_path": self.db_path,
        })

        # Check list of checkpoints
        list_res = op_state_graph.state_graph({
            "action": "list_checkpoints",
            "graph_id": "time_travel_graph",
            "db_path": self.db_path,
        })
        self._assert_envelope(list_res, True)
        self.assertGreaterEqual(list_res["data"]["count"], 3)

        # Rollback to step 1
        rb_res = op_state_graph.state_graph({
            "action": "rollback",
            "graph_id": "time_travel_graph",
            "checkpoint_id": "1",
            "db_path": self.db_path,
        })
        self._assert_envelope(rb_res, True)
        self.assertEqual(rb_res["data"]["current_node"], "v2")
        self.assertEqual(rb_res["data"]["state"]["version"], 2)

        # Verify state matches rollback point
        state_res = op_state_graph.state_graph({
            "action": "get_state",
            "graph_id": "time_travel_graph",
            "db_path": self.db_path,
        })
        self._assert_envelope(state_res, True)
        self.assertEqual(state_res["data"]["current_node"], "v2")
        self.assertEqual(state_res["data"]["state"]["version"], 2)

    def test_db_path_security_violations(self):
        """Verify that db_path outside ALLOWED_ROOTS or in sensitive locations is rejected."""
        # Outside ALLOWED_ROOTS (/etc)
        res_outside = op_state_graph.state_graph({
            "action": "create_graph",
            "graph_id": "sec_test",
            "db_path": "/etc/jarvis_evil.db",
        })
        self._assert_envelope(res_outside, False)
        self.assertIn("PathSecurityError", res_outside["error"])

        # Sensitive path (~/.ssh)
        res_sensitive = op_state_graph.state_graph({
            "action": "create_graph",
            "graph_id": "sec_test",
            "db_path": str(Path.home() / ".ssh" / "test.db"),
        })
        self._assert_envelope(res_sensitive, False)
        self.assertIn("SensitivePathError", res_sensitive["error"])


class TestOpCodeActionSandbox(BaseDomain1TestCase):
    def test_tool_contract(self):
        """Verify TOOL registration contract for code_action_sandbox."""
        tool = op_code_action_sandbox.TOOL
        self.assertEqual(tool["name"], "code_action_sandbox")
        self.assertFalse(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        schema = tool["input_schema"]
        self.assertEqual(schema["type"], "object")
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("action", schema["required"])

    def test_get_limits(self):
        """Verify get_limits returns limits and lists."""
        res = op_code_action_sandbox.code_action_sandbox({"action": "get_limits"})
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertIn("default_timeout_seconds", data)
        self.assertIn("max_steps_cap", data)
        self.assertIn("math", data["allowed_modules"])
        self.assertIn("open", data["forbidden_builtins"])

    def test_analyze_safety_clean_and_malicious(self):
        """Verify analyze_safety distinguishes clean code from attacks."""
        # Clean code
        clean_code = "import math\nval = math.sqrt(16.0)\nitems = [x * 2 for x in range(5)]"
        res_clean = op_code_action_sandbox.code_action_sandbox({
            "action": "analyze_safety",
            "code": clean_code,
        })
        self._assert_envelope(res_clean, True)
        self.assertTrue(res_clean["data"]["safe"])
        self.assertEqual(len(res_clean["data"]["violations"]), 0)

        # Forbidden import
        bad_import = "import os\nos.system('echo bad')"
        res_bad_import = op_code_action_sandbox.code_action_sandbox({
            "action": "analyze_safety",
            "code": bad_import,
        })
        self._assert_envelope(res_bad_import, True)
        self.assertFalse(res_bad_import["data"]["safe"])
        self.assertTrue(any("os" in v for v in res_bad_import["data"]["violations"]))

        # Dunder introspection
        bad_dunder = "x = ().__class__.__subclasses__()"
        res_bad_dunder = op_code_action_sandbox.code_action_sandbox({
            "action": "analyze_safety",
            "code": bad_dunder,
        })
        self._assert_envelope(res_bad_dunder, True)
        self.assertFalse(res_bad_dunder["data"]["safe"])
        self.assertTrue(any("__class__" in v or "__subclasses__" in v for v in res_bad_dunder["data"]["violations"]))

    def test_execute_data_manipulation_and_math(self):
        """Verify code execution with comprehensions, math, and variable assignments."""
        code = """
import math

numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
evens_squared = [n * n for n in numbers if n % 2 == 0]
total = sum(evens_squared)
mean = total / len(evens_squared)
hypot = math.sqrt(3**2 + 4**2)
"""
        res = op_code_action_sandbox.code_action_sandbox({
            "action": "execute_code",
            "code": code,
        })
        self._assert_envelope(res, True)
        scope = res["data"]["final_scope"]
        self.assertEqual(scope["evens_squared"], [4, 16, 36, 64, 100])
        self.assertEqual(scope["total"], 220)
        self.assertEqual(scope["mean"], 44.0)
        self.assertEqual(scope["hypot"], 5.0)
        self.assertGreater(res["data"]["executed_steps"], 20)

    def test_execute_functions_and_loops(self):
        """Verify defining custom functions and executing loops inside sandbox."""
        code = """
def fibonacci(n):
    if n <= 1:
        return n
    a, b = 0, 1
    for _ in range(2, n + 1):
        a, b = b, a + b
    return b

results = [fibonacci(i) for i in range(8)]
print("Fibonacci sequence:", results)
"""
        res = op_code_action_sandbox.code_action_sandbox({
            "action": "execute_code",
            "code": code,
        })
        self._assert_envelope(res, True)
        scope = res["data"]["final_scope"]
        self.assertEqual(scope["results"], [0, 1, 1, 2, 3, 5, 8, 13])
        self.assertIn("Fibonacci sequence: [0, 1, 1, 2, 3, 5, 8, 13]", res["data"]["stdout"])

    def test_execute_step_limit_exceeded(self):
        """Verify infinite loop or excessive instructions trigger step limit exception."""
        code = """
count = 0
while True:
    count += 1
"""
        res = op_code_action_sandbox.code_action_sandbox({
            "action": "execute_code",
            "code": code,
            "max_steps": 200,
        })
        self._assert_envelope(res, False)
        self.assertIn("SandboxStepLimitExceeded", res["error"])

    def test_execute_security_violations_blocked(self):
        """Verify that malicious attempts are blocked at execution time."""
        res = op_code_action_sandbox.code_action_sandbox({
            "action": "execute_code",
            "code": "import subprocess\nsubprocess.run(['ls'])",
        })
        self._assert_envelope(res, False)
        self.assertIn("SecurityViolation", res["error"])


class TestOpContractValidator(BaseDomain1TestCase):
    def test_tool_contract(self):
        """Verify TOOL registration contract for contract_validator."""
        tool = op_contract_validator.TOOL
        self.assertEqual(tool["name"], "contract_validator")
        self.assertFalse(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        schema = tool["input_schema"]
        self.assertEqual(schema["type"], "object")
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("action", schema["required"])

    def test_validate_envelope_success_and_error(self):
        """Verify envelope validation conforms to 5-key specification."""
        # Valid success
        valid_success = {"ok": True, "success": True, "data": {"a": 1}, "result": {"a": 1}, "error": None}
        res1 = op_contract_validator.contract_validator({
            "action": "validate_envelope",
            "payload": valid_success,
        })
        self._assert_envelope(res1, True)
        self.assertTrue(res1["data"]["valid"])
        self.assertEqual(len(res1["data"]["errors"]), 0)

        # Valid error
        valid_error = {"ok": False, "success": False, "data": None, "result": None, "error": "OperationFailed: timeout"}
        res2 = op_contract_validator.contract_validator({
            "action": "validate_envelope",
            "payload": valid_error,
        })
        self._assert_envelope(res2, True)
        self.assertTrue(res2["data"]["valid"])

        # Invalid envelope (missing keys, mismatch)
        invalid_env = {"ok": True, "success": False, "data": 123}
        res3 = op_contract_validator.contract_validator({
            "action": "validate_envelope",
            "payload": invalid_env,
        })
        self._assert_envelope(res3, True)
        self.assertFalse(res3["data"]["valid"])
        self.assertGreater(len(res3["data"]["errors"]), 0)

    def test_validate_schema_features(self):
        """Verify JSON schema validation: types, required, enum, bounds, additionalProperties."""
        schema = {
            "type": "object",
            "required": ["username", "role", "age"],
            "properties": {
                "username": {"type": "string", "minLength": 3, "pattern": r"^[a-zA-Z0-9_]+$"},
                "role": {"type": "string", "enum": ["admin", "developer", "guest"]},
                "age": {"type": "integer", "minimum": 18, "maximum": 120},
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "additionalProperties": False,
        }

        # Valid payload
        valid_payload = {
            "username": "coder_42",
            "role": "developer",
            "age": 28,
            "tags": ["python", "ai"],
        }
        res_valid = op_contract_validator.contract_validator({
            "action": "validate_schema",
            "payload": valid_payload,
            "schema": schema,
        })
        self._assert_envelope(res_valid, True)
        self.assertTrue(res_valid["data"]["valid"])

        # Invalid payload (unknown property, invalid enum, out of bounds)
        invalid_payload = {
            "username": "a",  # too short
            "role": "superman",  # not in enum
            "age": 12,  # < 18
            "hacker_field": True,  # additional property forbidden
        }
        res_invalid = op_contract_validator.contract_validator({
            "action": "validate_schema",
            "payload": invalid_payload,
            "schema": schema,
        })
        self._assert_envelope(res_invalid, True)
        self.assertFalse(res_invalid["data"]["valid"])
        errs = res_invalid["data"]["errors"]
        self.assertTrue(any("minLength" in e for e in errs))
        self.assertTrue(any("EnumViolation" in e for e in errs))
        self.assertTrue(any("minimum" in e for e in errs))
        self.assertTrue(any("AdditionalPropertyForbidden" in e for e in errs))

    def test_audit_operator_modules(self):
        """Verify auditing compliance across Domain 1 modules."""
        for mod in ["op_state_graph", "op_code_action_sandbox", "op_contract_validator", "op_a11y_tree_indexer"]:
            res = op_contract_validator.contract_validator({
                "action": "audit_operator_module",
                "module_name": mod,
            })
            self._assert_envelope(res, True)
            self.assertTrue(res["data"]["compliant"], f"Module {mod} failed audit: {res['data']['issues']}")
            self.assertTrue(res["data"]["checks"]["has_additional_properties_false"])
            self.assertTrue(res["data"]["checks"]["error_envelope_compliant"])


class TestOpA11yTreeIndexer(BaseDomain1TestCase):
    def setUp(self):
        self.sample_html = """
        <!DOCTYPE html>
        <html>
        <head><title>Test App</title></head>
        <body>
            <header>
                <h1>Jarvis Control Dashboard</h1>
                <p>Manage system nodes and pipelines.</p>
            </header>
            <main>
                <form id="action-form">
                    <label for="query-input">Search Query:</label>
                    <input type="text" id="query-input" name="query" placeholder="Type command..." />

                    <label for="filter-mode">Mode:</label>
                    <select id="filter-mode" name="mode">
                        <option value="auto">Automatic</option>
                        <option value="manual">Manual</option>
                    </select>

                    <input type="checkbox" id="chk-sync" name="sync" checked />
                    <input type="hidden" name="token" value="secret_csrf_123" />

                    <button type="submit" id="btn-submit" class="btn btn-primary">Execute Plan</button>
                    <button type="button" id="btn-cancel" class="btn btn-secondary">Cancel</button>
                </form>
                <div style="display: none;">
                    <button id="hidden-btn">Should not appear</button>
                </div>
                <div aria-hidden="true">
                    <a href="/hidden">Aria hidden link</a>
                </div>
                <footer>
                    <a href="/docs" id="link-docs">Documentation</a>
                </footer>
            </main>
        </body>
        </html>
        """

    def test_tool_contract(self):
        """Verify TOOL registration contract for a11y_tree_indexer."""
        tool = op_a11y_tree_indexer.TOOL
        self.assertEqual(tool["name"], "a11y_tree_indexer")
        self.assertFalse(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        schema = tool["input_schema"]
        self.assertEqual(schema["type"], "object")
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("action", schema["required"])

    def test_index_html_coordinate_tags_and_token_reduction(self):
        """Verify sequential coordinate tags, token reduction, and compact tree formatting."""
        res = op_a11y_tree_indexer.a11y_tree_indexer({
            "action": "index_html",
            "html_content": self.sample_html,
            "include_text_snippets": True,
        })
        self._assert_envelope(res, True)
        data = res["data"]
        self.assertGreater(data["total_tags_parsed"], 10)
        self.assertGreaterEqual(data["interactive_count"], 6)
        self.assertGreater(data["token_reduction_percent"], 0.0)

        compact_tree = data["compact_tree"]
        self.assertIn("# Jarvis Control Dashboard", compact_tree)
        self.assertIn("[1]", compact_tree)
        self.assertIn("Execute Plan", compact_tree)
        # Ensure hidden elements are filtered out
        self.assertNotIn("Should not appear", compact_tree)
        self.assertNotIn("Aria hidden link", compact_tree)

    def test_extract_interactive_elements(self):
        """Verify extracting only interactive elements with normalized metadata."""
        res = op_a11y_tree_indexer.a11y_tree_indexer({
            "action": "extract_interactive",
            "html_content": self.sample_html,
        })
        self._assert_envelope(res, True)
        elements = res["data"]["interactive_elements"]
        self.assertIsInstance(elements, list)
        tag_types = [el["tag"] for el in elements]
        self.assertIn("button", tag_types)
        self.assertIn("input", tag_types)
        self.assertIn("select", tag_types)
        self.assertIn("a", tag_types)

        btn_submit = next(el for el in elements if el.get("id") == "btn-submit")
        self.assertEqual(btn_submit["text"], "Execute Plan")
        self.assertEqual(btn_submit["type"], "submit")
        self.assertIn("btn-primary", btn_submit["classes"])

    def test_query_elements(self):
        """Verify querying elements by ID, class, and attribute selectors."""
        # Query by ID
        res_id = op_a11y_tree_indexer.a11y_tree_indexer({
            "action": "query_elements",
            "html_content": self.sample_html,
            "selector": "#btn-cancel",
        })
        self._assert_envelope(res_id, True)
        self.assertEqual(res_id["data"]["match_count"], 1)
        self.assertEqual(res_id["data"]["matches"][0]["id"], "btn-cancel")

        # Query by attribute
        res_attr = op_a11y_tree_indexer.a11y_tree_indexer({
            "action": "query_elements",
            "html_content": self.sample_html,
            "selector": "[type=checkbox]",
        })
        self._assert_envelope(res_attr, True)
        self.assertEqual(res_attr["data"]["match_count"], 1)
        self.assertEqual(res_attr["data"]["matches"][0]["id"], "chk-sync")

        # Query by text substring
        res_text = op_a11y_tree_indexer.a11y_tree_indexer({
            "action": "query_elements",
            "html_content": self.sample_html,
            "selector": "Documentation",
        })
        self._assert_envelope(res_text, True)
        self.assertEqual(res_text["data"]["match_count"], 1)
        self.assertEqual(res_text["data"]["matches"][0]["href"], "/docs")

    def test_file_path_sandboxing(self):
        """Verify local HTML file reading and path confinement within ALLOWED_ROOTS."""
        with tempfile.NamedTemporaryFile("w", suffix=".html", dir="/tmp", delete=False) as f:
            f.write("<html><body><button id='tmp-btn'>OK</button></body></html>")
            tmp_path = f.name

        try:
            # Valid file in /tmp
            res = op_a11y_tree_indexer.a11y_tree_indexer({
                "action": "extract_interactive",
                "file_path": tmp_path,
            })
            self._assert_envelope(res, True)
            self.assertEqual(res["data"]["interactive_count"], 1)

            # Security: outside ALLOWED_ROOTS (/etc/passwd)
            res_outside = op_a11y_tree_indexer.a11y_tree_indexer({
                "action": "index_html",
                "file_path": "/etc/passwd",
            })
            self._assert_envelope(res_outside, False)
            self.assertIn("PathSecurityError", res_outside["error"])

            # Security: sensitive directory (~/.ssh)
            res_sensitive = op_a11y_tree_indexer.a11y_tree_indexer({
                "action": "index_html",
                "file_path": str(Path.home() / ".ssh" / "id_rsa"),
            })
            self._assert_envelope(res_sensitive, False)
            self.assertIn("SensitivePathError", res_sensitive["error"])
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


class TestToolRegistryIntegration(BaseDomain1TestCase):
    def test_tool_registry_discovers_domain1_modules(self):
        """Verify that ToolRegistry dynamically discovers all 4 Domain 1 operator modules."""
        tr = ToolRegistry()
        for expected_tool in ["state_graph", "code_action_sandbox", "contract_validator", "a11y_tree_indexer"]:
            self.assertTrue(tr.has(expected_tool), f"ToolRegistry failed to discover '{expected_tool}'")
            tool_obj = tr.get(expected_tool)
            self.assertIsNotNone(tool_obj)
            self.assertFalse(tool_obj.approval)
            decl = tool_obj.declaration()
            self.assertEqual(decl["name"], expected_tool)
            self.assertIn("input_schema", decl)
            self.assertFalse(decl["input_schema"]["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
