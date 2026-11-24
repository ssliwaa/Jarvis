"""Automated test suite for operator_modules/op_code_action_sandbox.py.

Tests the dispatch contract, get_limits metadata, AST safety analysis
(forbidden imports, builtin calls, dunder/private attribute blocking,
allowed_modules whitelisting), executed semantics of the SafeAST
interpreter (arithmetic, assignment, print capture, for loops, user
functions, lambdas, comprehensions, initial_scope seeding), sandbox
enforcement at execution time, step-limit and serialization behaviour.
100% offline and deterministic: every snippet is authored by this
suite (no untrusted code), execution paths are bounded by design
(step caps verified empirically to terminate).
"""

from __future__ import annotations

import unittest

import operator_modules.op_code_action_sandbox as cs


class TestDispatch(unittest.TestCase):
    """Handler contract and get_limits metadata."""

    def test_rejects_non_dict_arguments(self):
        res = cs.code_action_sandbox("nope")
        self.assertFalse(res["ok"])
        self.assertIn("Arguments must be a dictionary", res["error"])

    def test_rejects_unknown_argument(self):
        res = cs.code_action_sandbox({"action": "get_limits",
                                       "rogue": 1})
        self.assertFalse(res["ok"])
        self.assertIn("Unknown argument 'rogue'", res["error"])

    def test_invalid_action(self):
        res = cs.code_action_sandbox({"action": "detonate"})
        self.assertFalse(res["ok"])
        self.assertIn("Invalid or unsupported action 'detonate'",
                      res["error"])

    def test_get_limits_metadata(self):
        res = cs.code_action_sandbox({"action": "get_limits"})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertEqual(data["max_timeout_seconds"], 30.0)
        self.assertEqual(data["default_max_steps"], 5000)
        self.assertIn("math", data["allowed_modules"])
        self.assertIn("urllib.parse", data["allowed_modules"])
        self.assertIn("open", data["forbidden_builtins"])
        self.assertIn("__class__", data["forbidden_attributes"])

    def test_envelope_shape_on_success(self):
        res = cs.code_action_sandbox({"action": "analyze_safety",
                                      "code": "x = 1"})
        self.assertEqual(set(res), {"ok", "success", "data", "result",
                                    "error"})
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"], res["result"])
        self.assertIsNone(res["error"])


class TestAnalyzeSafety(unittest.TestCase):
    """analyze_safety: static AST violation reporting."""

    def test_safe_code_summary(self):
        res = cs.code_action_sandbox({"action": "analyze_safety",
                                      "code": "import math\n"
                                              "y = math.sqrt(16) + 1\n"
                                              "for i in range(3):\n"
                                              "    y += i"})
        data = res["data"]
        self.assertTrue(data["safe"])
        self.assertEqual(data["violations"], [])
        self.assertEqual(data["analysis"]["imports"], ["math"])
        self.assertTrue(data["analysis"]["has_loops"])
        self.assertIn("sqrt", data["analysis"]["functions_called"])
        self.assertGreater(data["analysis"]["node_count"], 5)

    def test_forbidden_import_violation(self):
        res = cs.code_action_sandbox({"action": "analyze_safety",
                                      "code": "import os"})
        data = res["data"]
        self.assertFalse(data["safe"])
        self.assertTrue(any("Import of module 'os'" in v
                            for v in data["violations"]))

    def test_forbidden_builtin_and_dunder(self):
        res = cs.code_action_sandbox({
            "action": "analyze_safety",
            "code": "f = open('/etc/passwd')\n"
                    "k = x.__class__\n"
                    "g = __import__('os')",
        })
        data = res["data"]
        self.assertFalse(data["safe"])
        joined = " ".join(data["violations"])
        self.assertIn("forbidden builtin 'open'", joined)
        self.assertIn("'__class__'", joined)
        self.assertIn("forbidden builtin '__import__'", joined)

    def test_private_attribute_blocked(self):
        res = cs.code_action_sandbox({"action": "analyze_safety",
                                      "code": "v = obj._private"})
        data = res["data"]
        self.assertFalse(data["safe"])
        self.assertTrue(any("_private" in v for v in data["violations"]))

    def test_allowed_modules_whitelist_extends(self):
        res = cs.code_action_sandbox({"action": "analyze_safety",
                                      "code": "import os",
                                      "allowed_modules": ["os"]})
        self.assertTrue(res["data"]["safe"])
        # Explicit module end not required to be safe
        res2 = cs.code_action_sandbox({"action": "analyze_safety",
                                       "code": "import os"})
        self.assertFalse(res2["data"]["safe"])

    def test_syntax_error_reported(self):
        res = cs.code_action_sandbox({"action": "analyze_safety",
                                      "code": "def broken("})
        self.assertFalse(res["ok"])
        self.assertIn("SyntaxError", res["error"])
        self.assertIn("line", res["error"])

    def test_code_param_required(self):
        res = cs.code_action_sandbox({"action": "analyze_safety"})
        self.assertFalse(res["ok"])
        self.assertIn("'code' must be a non-empty string", res["error"])

    def test_allowed_modules_type_validated(self):
        res = cs.code_action_sandbox({"action": "analyze_safety",
                                      "code": "x = 1",
                                      "allowed_modules": "os"})
        self.assertFalse(res["ok"])
        self.assertIn("must be a list of strings", res["error"])


class TestExecuteCode(unittest.TestCase):
    """execute_code: interpreter semantics for authored snippets."""

    def test_arithmetic_assignment_and_result(self):
        res = cs.code_action_sandbox({"action": "execute_code",
                                      "code": "x = 2 + 3 * 4\nx"})
        data = res["data"]
        self.assertEqual(data["result"], 14)
        self.assertEqual(data["final_scope"], {"x": 14})
        self.assertGreater(data["executed_steps"], 0)
        self.assertEqual(data["stdout"], "")
        self.assertGreaterEqual(data["duration_ms"], 0.0)

    def test_print_captured_to_stdout(self):
        res = cs.code_action_sandbox({"action": "execute_code",
                                      "code": "print('hello', 42)"})
        self.assertEqual(res["data"]["stdout"], "hello 42\n")

    def test_for_loop_accumulates_scope(self):
        code = ("total = 0\n"
                "for i in range(5):\n"
                "    total += i\n"
                "total")
        res = cs.code_action_sandbox({"action": "execute_code",
                                      "code": code})
        data = res["data"]
        self.assertEqual(data["result"], 10)
        self.assertEqual(data["final_scope"]["total"], 10)
        self.assertEqual(data["final_scope"]["i"], 4)

    def test_user_function_definition_and_call(self):
        code = ("def add(a, b):\n"
                "    return a + b\n"
                "add(2, 3)")
        res = cs.code_action_sandbox({"action": "execute_code",
                                      "code": code})
        self.assertEqual(res["data"]["result"], 5)

    def test_conditional_logic(self):
        code = ("n = 7\n"
                "if n % 2 == 0:\n"
                "    label = 'even'\n"
                "else:\n"
                "    label = 'odd'\n"
                "label")
        res = cs.code_action_sandbox({"action": "execute_code",
                                      "code": code})
        self.assertEqual(res["data"]["result"], "odd")

    def test_lambda_and_comprehensions(self):
        code = ("double = lambda v: v * 2\n"
                "squares = [x*x for x in range(4)]\n"
                "pairs = {k: double(k) for k in [3, 4]}\n"
                "pairs")
        res = cs.code_action_sandbox({"action": "execute_code",
                                      "code": code})
        data = res["data"]
        self.assertEqual(res["data"]["result"], {3: 6, 4: 8})
        self.assertEqual(data["final_scope"]["squares"],
                         [0, 1, 4, 9])

    def test_initial_scope_seeds_variables(self):
        res = cs.code_action_sandbox({"action": "execute_code",
                                      "code": "n = scope_val * 2\nn",
                                      "initial_scope": {"scope_val": 21}})
        data = res["data"]
        self.assertEqual(data["result"], 42)
        self.assertEqual(data["final_scope"],
                         {"scope_val": 21, "n": 42})

    def test_top_level_return_is_controlled_error(self):
        # Observed sandbox behaviour: a bare top-level return raises the
        # internal ReturnSignal which surfaces as a controlled envelope
        # error (the snippet was never valid module-level code).
        res = cs.code_action_sandbox({"action": "execute_code",
                                      "code": "return 5"})
        self.assertFalse(res["ok"])
        self.assertIn("ReturnSignal", res["error"])


class TestSandboxEnforcement(unittest.TestCase):
    """Execution-time security and resource guards."""

    def test_unsafe_code_never_executes(self):
        res = cs.code_action_sandbox({"action": "execute_code",
                                      "code": "import os\nos.getcwd()"})
        self.assertFalse(res["ok"])
        self.assertIn("SandboxSecurityViolation", res["error"])
        self.assertIn("Import of module 'os'", res["error"])

    def test_execution_of_dunder_import_blocked(self):
        res = cs.code_action_sandbox({"action": "execute_code",
                                      "code": "m = __import__('os')"})
        self.assertFalse(res["ok"])
        self.assertIn("SandboxSecurityViolation", res["error"])

    def test_step_limit_terminates_infinite_loop(self):
        res = cs.code_action_sandbox({"action": "execute_code",
                                      "code": "while True:\n    pass",
                                      "max_steps": 10})
        self.assertFalse(res["ok"])
        self.assertIn("SandboxStepLimitExceeded", res["error"])

    def test_initial_scope_type_validated(self):
        res = cs.code_action_sandbox({"action": "execute_code",
                                      "code": "x = 1",
                                      "initial_scope": "not-a-dict"})
        self.assertFalse(res["ok"])
        self.assertIn("'initial_scope' must be a dictionary",
                      res["error"])

    def test_unserializable_result_falls_back_to_repr(self):
        # Import json (safe list) and build an object json cannot encode:
        # a set is not JSON-serializable by default.
        res = cs.code_action_sandbox({"action": "execute_code",
                                      "code": "s = {1, 2}\ns"})
        data = res["data"]
        self.assertTrue(res["ok"])
        self.assertEqual(data["result"], repr({1, 2}))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
