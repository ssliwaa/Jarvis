"""Automated error-path suite for operator_modules/op_code_action_sandbox.py.

Completes raise coverage for the SafeAST interpreter and its dispatcher.
Three layers are exercised:

1. Dispatcher-driven runtime failures (execute_code action): every
   snippet passes the static _analyze_ast_safety pre-check, then trips
   a defense raise inside the interpreter (stdout overflow, wall-clock
   timeout, unsupported operators/statements, forbidden function names,
   unpack errors, loop control signals).
2. Interpreter defense-in-depth raises that the dispatcher pre-check
   pre-empts at analyze time (forbidden name references/assignments,
   private attribute access/assignment): the pre-check AST walk flags
   those symbols before execution, so these raises cannot be reached
   through code_action_sandbox with *any* parseable source. They are
   verified by driving SafeASTInterpreter directly, because the class
   is importable on its own and remains the last line of defense.
3. Forged-AST operator nodes: the operator maps already cover every
   unary and comparison operator class that ast.parse can produce
   (asserted by mapping-completeness tests), so the "unsupported
   operator" raises only fire for hand-built AST nodes with a
   mismatched operator class -- the realistic analogue of a malformed
   tree reaching the evaluator.

100% offline and deterministic: all snippets are authored by this suite,
every execution is bounded by timeout/step caps verified empirically.
"""

from __future__ import annotations

import ast
import unittest

import operator_modules.op_code_action_sandbox as cs


class TestDispatcherRuntimeRaises(unittest.TestCase):
    """Runtime raise sites reached through code_action_sandbox(execute_code)."""

    def _run(self, code: str, **extra: object) -> dict:
        args: dict = {"action": "execute_code", "code": code}
        args.update(extra)
        return cs.code_action_sandbox(args)

    def test_stdout_buffer_overflow_triggers_runtime_error(self):
        res = self._run("print('A' * 1100000)\nprint('B')")
        self.assertFalse(res["ok"])
        self.assertFalse(res["success"])
        self.assertIn("RuntimeError", res["error"])
        self.assertIn("Stdout buffer overflow (> 1MB)", res["error"])

    def test_wall_clock_timeout_terminates_execution(self):
        # 4000 iterations of sum(range(50000)) need far more than the
        # 0.1s clamped minimum timeout, so SandboxTimeoutError always
        # fires long before the 50000-step cap is reached.
        res = self._run(
            "for i in range(4000):\n    s = sum(range(50000))",
            timeout_seconds=0.1,
            max_steps=50000,
        )
        self.assertFalse(res["ok"])
        self.assertIn("SandboxTimeoutError", res["error"])
        self.assertIn("ExecutionTimeout", res["error"])
        self.assertIn("0.10s", res["error"])

    def test_augassign_matmult_rejected(self):
        res = self._run("x = 2\nx @= 3")
        self.assertFalse(res["ok"])
        self.assertIn("NotImplementedError", res["error"])
        self.assertIn("Unsupported AugAssign operator", res["error"])

    def test_for_over_non_iterable_raises_typeerror(self):
        res = self._run("for i in 42:\n    pass")
        self.assertFalse(res["ok"])
        self.assertIn("TypeError", res["error"])
        self.assertIn("'int' object is not iterable", res["error"])

    def test_function_def_forbidden_name_rejected(self):
        # The FunctionDef name field is not an ast.Name node, so the
        # static pre-check cannot see it; the interpreter raise is the
        # only guard.
        res = self._run("def open():\n    pass")
        self.assertFalse(res["ok"])
        self.assertIn("SandboxSecurityViolation", res["error"])
        self.assertIn("Cannot define function with forbidden name 'open'",
                      res["error"])

    def test_break_signal_completes_loop_ok(self):
        res = self._run("for i in range(3):\n    break")
        self.assertTrue(res["ok"])
        self.assertTrue(res["success"])
        self.assertIsNone(res["error"])
        self.assertEqual(res["data"]["final_scope"]["i"], 0)

    def test_continue_signal_completes_loop_ok(self):
        res = self._run("for i in range(3):\n    continue")
        self.assertTrue(res["ok"])
        self.assertIsNone(res["error"])
        self.assertEqual(res["data"]["final_scope"]["i"], 2)

    def test_classdef_statement_rejected(self):
        res = self._run("class Foo:\n    pass")
        self.assertFalse(res["ok"])
        self.assertIn("NotImplementedError", res["error"])
        self.assertIn("Unsupported statement type: ClassDef", res["error"])

    def test_undefined_name_raises_nameerror(self):
        res = self._run("undefined_thing")
        self.assertFalse(res["ok"])
        self.assertIn("NameError", res["error"])
        self.assertIn("Name 'undefined_thing' is not defined in sandbox scope",
                      res["error"])

    def test_binop_matmult_rejected(self):
        res = self._run("2 @ 3")
        self.assertFalse(res["ok"])
        self.assertIn("NotImplementedError", res["error"])
        self.assertIn("Unsupported BinOp", res["error"])
        self.assertIn("ast.MatMult", res["error"])

    def test_generator_expression_rejected(self):
        res = self._run("y = (i * 2 for i in range(3))")
        self.assertFalse(res["ok"])
        self.assertIn("NotImplementedError", res["error"])
        self.assertIn("Unsupported expression type: GeneratorExp",
                      res["error"])

    def test_unpack_non_iterable_raises_typeerror(self):
        res = self._run("a, b = 42")
        self.assertFalse(res["ok"])
        self.assertIn("TypeError", res["error"])
        self.assertIn("Cannot unpack non-iterable 'int' object",
                      res["error"])

    def test_unpack_arity_mismatch_raises_valueerror(self):
        res = self._run("a, b = [1, 2, 3]")
        self.assertFalse(res["ok"])
        self.assertIn("ValueError", res["error"])
        self.assertIn("Need 2 values to unpack, got 3", res["error"])

    def test_starred_assignment_target_rejected(self):
        res = self._run("a, *b = [1, 2]")
        self.assertFalse(res["ok"])
        self.assertIn("NotImplementedError", res["error"])
        self.assertIn("Unsupported assignment target: Starred",
                      res["error"])

    def test_execute_code_error_envelope_shape(self):
        res = self._run("2 @ 3")
        self.assertEqual(set(res), {"ok", "success", "data", "result",
                                    "error"})
        self.assertFalse(res["ok"])
        self.assertFalse(res["success"])
        self.assertIsNone(res["data"])
        self.assertIsNone(res["result"])
        self.assertIsInstance(res["error"], str)


class TestInterpreterDefenseInDepth(unittest.TestCase):
    """Raises pre-empted by the dispatcher pre-check, verified directly.

    The static _analyze_ast_safety walk flags any ast.Name or
    ast.Attribute node that holds a forbidden/private symbol, so no
    parseable source can reach these interpreter raises through the
    dispatcher. SafeASTInterpreter is validated on its own because it
    is the execution-time backstop for non-dispatcher callers.
    """

    def _run_snippet(self, code: str,
                     initial_scope: dict | None = None) -> None:
        interp = cs.SafeASTInterpreter(initial_scope=initial_scope)
        interp.eval(ast.parse(code))

    def test_interpreter_rejects_forbidden_name_reference(self):
        with self.assertRaises(cs.SandboxSecurityViolation) as ctx:
            self._run_snippet("eval")
        self.assertIn("Reference to forbidden name 'eval'",
                      str(ctx.exception))

    def test_interpreter_rejects_private_attribute_access(self):
        with self.assertRaises(cs.SandboxSecurityViolation) as ctx:
            self._run_snippet("obj._secret",
                              initial_scope={"obj": object()})
        self.assertIn("Access to private attribute '_secret' is forbidden.",
                      str(ctx.exception))

    def test_interpreter_rejects_forbidden_name_assignment(self):
        with self.assertRaises(cs.SandboxSecurityViolation) as ctx:
            self._run_snippet("open = 1")
        self.assertIn("Cannot assign to forbidden name 'open'",
                      str(ctx.exception))

    def test_interpreter_rejects_forbidden_attribute_assignment(self):
        with self.assertRaises(cs.SandboxSecurityViolation) as ctx:
            self._run_snippet("obj._hidden = 1",
                              initial_scope={"obj": object()})
        self.assertIn("Cannot assign to forbidden attribute '_hidden'",
                      str(ctx.exception))


class TestForgedOperatorNodes(unittest.TestCase):
    """Unsupported-operator raises driven by hand-built AST nodes.

    The operator maps cover every unary/comparison class that
    ast.parse can emit (see TestOperatorMapCompleteness), so these
    raises fire only when a malformed tree with a mismatched operator
    class reaches the evaluator -- the analogue of a future Python
    operator or a non-parse source constructing nodes by hand.
    """

    def test_forged_unary_op_node_rejected(self):
        forged = ast.Module(
            body=[ast.Expr(value=ast.UnaryOp(op=ast.MatMult(),
                                             operand=ast.Constant(value=1)))],
            type_ignores=[],
        )
        interp = cs.SafeASTInterpreter()
        with self.assertRaises(NotImplementedError) as ctx:
            interp.eval(forged)
        self.assertIn("Unsupported UnaryOp", str(ctx.exception))
        self.assertIn("ast.MatMult", str(ctx.exception))

    def test_forged_comparison_op_node_rejected(self):
        forged = ast.Module(
            body=[ast.Expr(value=ast.Compare(
                left=ast.Constant(value=1),
                ops=[ast.MatMult()],
                comparators=[ast.Constant(value=2)],
            ))],
            type_ignores=[],
        )
        interp = cs.SafeASTInterpreter()
        with self.assertRaises(NotImplementedError) as ctx:
            interp.eval(forged)
        self.assertIn("Unsupported comparison operator",
                      str(ctx.exception))
        self.assertIn("ast.MatMult", str(ctx.exception))


class TestOperatorMapCompleteness(unittest.TestCase):
    """Pin the operator tables against the AST class hierarchy.

    If a Python upgrade introduces a new operator node, ast.parse will
    start emitting it and these assertions fail loudly, pointing at the
    interpreter map that needs a new entry (instead of the sandbox
    silently rejecting all code using that operator).
    """

    def test_unary_op_map_covers_all_ast_unaryops(self):
        covered = {op for op in cs.SafeASTInterpreter.UNARY_OPS}
        missing = {c for c in ast.unaryop.__subclasses__() if c not in covered}
        self.assertEqual(missing, set(),
                         f"UNARY_OPS missing ast classes: {missing}")

    def test_compare_op_map_covers_all_ast_cmpops(self):
        covered = {op for op in cs.SafeASTInterpreter.COMPARE_OPS}
        missing = {c for c in ast.cmpop.__subclasses__() if c not in covered}
        self.assertEqual(missing, set(),
                         f"COMPARE_OPS missing ast classes: {missing}")

    def test_binop_map_covers_all_ast_operators_except_matmult(self):
        covered = {op for op in cs.SafeASTInterpreter.BIN_OPS}
        ast_operators = set(ast.operator.__subclasses__())
        self.assertEqual(covered | {ast.MatMult}, ast_operators,
                         "BIN_OPS must cover every ast.operator class "
                         "except the deliberately rejected ast.MatMult")


if __name__ == "__main__":
    unittest.main()
