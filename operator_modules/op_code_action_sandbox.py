"""Zero-dependency safe AST code-as-action execution sandbox inspired by smolagents, OpenHands, and E2B.

Executes data manipulation, transformations, mathematical operations, and filtering scripts
via a safe AST visitor without eval/exec, with instruction-bounded stepping, timeout guards,
and strict import/introspection whitelisting. Exclusively uses the Python standard library.
"""

from __future__ import annotations

import ast
import collections
import copy
import datetime
import decimal
import fractions
import hashlib
import io
import itertools
import json
import math
import operator
import random
import re
import string
import time
import urllib.parse
from pathlib import Path
from typing import Any

# Security perimeter: Allowed root directories
HOME = Path.home().resolve()
ALLOWED_ROOTS: tuple[Path, ...] = (
    HOME,
    Path("/tmp").resolve(),
    Path("/mnt").resolve(),
    Path("/media").resolve(),
)

SAFE_MODULES: dict[str, Any] = {
    "math": math,
    "json": json,
    "re": re,
    "datetime": datetime,
    "random": random,
    "collections": collections,
    "itertools": itertools,
    "string": string,
    "hashlib": hashlib,
    "copy": copy,
    "decimal": decimal,
    "fractions": fractions,
    "urllib.parse": urllib.parse,
}

FORBIDDEN_NAMES: frozenset[str] = frozenset({
    "open",
    "eval",
    "exec",
    "compile",
    "getattr",
    "setattr",
    "delattr",
    "__import__",
    "globals",
    "locals",
    "vars",
    "dir",
    "breakpoint",
    "exit",
    "quit",
    "help",
    "input",
    "memoryview",
})

FORBIDDEN_ATTRIBUTES: frozenset[str] = frozenset({
    "__class__",
    "__subclasses__",
    "__bases__",
    "__base__",
    "__mro__",
    "__globals__",
    "__code__",
    "__builtins__",
    "__dict__",
    "__closure__",
    "__qualname__",
    "__module__",
    "__annotations__",
    "__func__",
    "__self__",
    "gi_frame",
    "gi_code",
    "cr_frame",
    "cr_code",
    "f_locals",
    "f_globals",
    "f_builtins",
    "f_code",
})

VALID_ACTIONS: frozenset[str] = frozenset({
    "execute_code",
    "analyze_safety",
    "get_limits",
})

KNOWN_ARGUMENTS: frozenset[str] = frozenset({
    "action",
    "code",
    "initial_scope",
    "timeout_seconds",
    "max_memory_mb",
    "max_steps",
    "allowed_modules",
})


class SandboxSecurityViolation(Exception):
    """Raised when code violates sandbox security constraints."""


class SandboxStepLimitExceeded(Exception):
    """Raised when code exceeds maximum AST instruction steps."""


class SandboxTimeoutError(Exception):
    """Raised when code execution exceeds wall-clock timeout."""


class ControlFlowSignal(Exception):
    """Base class for AST control flow signals."""


class ReturnSignal(ControlFlowSignal):
    def __init__(self, value: Any):
        self.value = value


class BreakSignal(ControlFlowSignal):
    pass


class ContinueSignal(ControlFlowSignal):
    pass


def _envelope_success(data: Any) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator success envelope."""
    return {"ok": True, "success": True, "data": data, "result": data, "error": None}


def _envelope_error(error: str | Exception) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator error envelope."""
    if isinstance(error, Exception):
        msg = f"{type(error).__name__}: {error}"
    else:
        msg = str(error)
    return {"ok": False, "success": False, "data": None, "result": None, "error": msg}


def _analyze_ast_safety(tree: ast.AST, allowed_module_names: set[str]) -> tuple[bool, list[str], dict[str, Any]]:
    """Inspect AST for unauthorized imports, dunder access, and forbidden builtins."""
    violations: list[str] = []
    imports_found: list[str] = []
    function_calls: set[str] = set()
    node_count = 0
    has_loops = False
    has_functions = False

    for node in ast.walk(tree):
        node_count += 1
        if isinstance(node, (ast.For, ast.While)):
            has_loops = True
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            has_functions = True

        if isinstance(node, ast.Import):
            for alias in node.names:
                mod_root = alias.name.split(".")[0]
                imports_found.append(alias.name)
                if alias.name not in allowed_module_names and mod_root not in allowed_module_names:
                    violations.append(f"SecurityViolation: Import of module '{alias.name}' is forbidden.")
        elif isinstance(node, ast.ImportFrom):
            mod_name = node.module or ""
            mod_root = mod_name.split(".")[0]
            imports_found.append(mod_name)
            if mod_name not in allowed_module_names and mod_root not in allowed_module_names:
                violations.append(f"SecurityViolation: Import from module '{mod_name}' is forbidden.")
        elif isinstance(node, ast.Attribute):
            attr = node.attr
            if attr in FORBIDDEN_ATTRIBUTES or attr.startswith("__") or (attr.startswith("_") and attr != "_"):
                violations.append(f"SecurityViolation: Access to private or dunder attribute '{attr}' is forbidden.")
        elif isinstance(node, ast.Name):
            if node.id in FORBIDDEN_NAMES or (node.id.startswith("__") and node.id != "_"):
                violations.append(f"SecurityViolation: Reference to forbidden builtin '{node.id}'.")
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                function_calls.add(node.func.id)
                if node.func.id in FORBIDDEN_NAMES:
                    violations.append(f"SecurityViolation: Call to forbidden builtin '{node.func.id}'.")
            elif isinstance(node.func, ast.Attribute):
                function_calls.add(node.func.attr)
                if node.func.attr in FORBIDDEN_ATTRIBUTES:
                    violations.append(f"SecurityViolation: Call to forbidden attribute '{node.func.attr}'.")

    summary = {
        "node_count": node_count,
        "imports": imports_found,
        "functions_called": sorted(function_calls),
        "has_loops": has_loops,
        "has_functions": has_functions,
    }
    return len(violations) == 0, violations, summary


class SafeASTInterpreter:
    """Bounded, safe AST evaluator for Python expressions and control structures."""

    BIN_OPS = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv,
        ast.Mod: operator.mod,
        ast.Pow: operator.pow,
        ast.BitOr: operator.or_,
        ast.BitAnd: operator.and_,
        ast.BitXor: operator.xor,
        ast.LShift: operator.lshift,
        ast.RShift: operator.rshift,
    }

    UNARY_OPS = {
        ast.UAdd: operator.pos,
        ast.USub: operator.neg,
        ast.Not: operator.not_,
        ast.Invert: operator.inv,
    }

    COMPARE_OPS = {
        ast.Eq: operator.eq,
        ast.NotEq: operator.ne,
        ast.Lt: operator.lt,
        ast.LtE: operator.le,
        ast.Gt: operator.gt,
        ast.GtE: operator.ge,
        ast.Is: operator.is_,
        ast.IsNot: operator.is_not,
        ast.In: lambda a, b: a in b,
        ast.NotIn: lambda a, b: a not in b,
    }

    def __init__(
        self,
        initial_scope: dict[str, Any] | None = None,
        max_steps: int = 5000,
        timeout_seconds: float = 5.0,
        extra_modules: dict[str, Any] | None = None,
    ):
        self.max_steps = max_steps
        self.timeout_seconds = timeout_seconds
        self.steps = 0
        self.start_time = time.perf_counter()
        self.stdout_buffer = io.StringIO()

        # Build safe builtins
        safe_builtins: dict[str, Any] = {
            "abs": abs,
            "all": all,
            "any": any,
            "bin": bin,
            "bool": bool,
            "dict": dict,
            "enumerate": enumerate,
            "filter": filter,
            "float": float,
            "format": format,
            "frozenset": frozenset,
            "hex": hex,
            "int": int,
            "isinstance": isinstance,
            "len": len,
            "list": list,
            "map": map,
            "max": max,
            "min": min,
            "oct": oct,
            "ord": ord,
            "chr": chr,
            "pow": pow,
            "print": self._safe_print,
            "range": range,
            "reversed": reversed,
            "round": round,
            "set": set,
            "sorted": sorted,
            "str": str,
            "sum": sum,
            "tuple": tuple,
            "zip": zip,
        }

        self.scope: dict[str, Any] = dict(safe_builtins)
        # Ingest safe modules
        self.scope.update(SAFE_MODULES)
        if extra_modules:
            self.scope.update(extra_modules)

        if initial_scope:
            for k, v in initial_scope.items():
                if not k.startswith("_") and k not in FORBIDDEN_NAMES:
                    self.scope[k] = v

    def _safe_print(self, *args: Any, sep: str = " ", end: str = "\n") -> None:
        text = sep.join(str(a) for a in args) + end
        if self.stdout_buffer.tell() > 1_000_000:
            raise RuntimeError("Stdout buffer overflow (> 1MB)")
        self.stdout_buffer.write(text)

    def _tick(self) -> None:
        self.steps += 1
        if self.steps > self.max_steps:
            raise SandboxStepLimitExceeded(
                f"ExecutionStepLimitExceeded: Exceeded maximum allowed instructions ({self.max_steps} steps)."
            )
        if (self.steps % 50 == 0) and (time.perf_counter() - self.start_time > self.timeout_seconds):
            raise SandboxTimeoutError(
                f"ExecutionTimeout: Exceeded maximum wall-clock timeout ({self.timeout_seconds:.2f}s)."
            )

    def eval(self, tree: ast.AST) -> Any:
        last_val = None
        if isinstance(tree, ast.Module):
            for stmt in tree.body:
                last_val = self._eval_stmt(stmt, self.scope)
            return last_val
        elif isinstance(tree, ast.Expression):
            return self._eval_expr(tree.body, self.scope)
        else:
            return self._eval_stmt(tree, self.scope)

    def _eval_stmt(self, node: ast.AST, env: dict[str, Any]) -> Any:
        self._tick()

        if isinstance(node, ast.Expr):
            return self._eval_expr(node.value, env)

        elif isinstance(node, ast.Assign):
            val = self._eval_expr(node.value, env)
            for target in node.targets:
                self._assign_target(target, val, env)
            return val

        elif isinstance(node, ast.AugAssign):
            curr = self._eval_expr(node.target, env)
            val = self._eval_expr(node.value, env)
            op_fn = self.BIN_OPS.get(type(node.op))
            if not op_fn:
                raise NotImplementedError(f"Unsupported AugAssign operator {type(node.op)}")
            new_val = op_fn(curr, val)
            self._assign_target(node.target, new_val, env)
            return new_val

        elif isinstance(node, ast.If):
            test_val = self._eval_expr(node.test, env)
            if test_val:
                res = None
                for s in node.body:
                    res = self._eval_stmt(s, env)
                return res
            else:
                res = None
                for s in node.orelse:
                    res = self._eval_stmt(s, env)
                return res

        elif isinstance(node, ast.While):
            res = None
            while self._eval_expr(node.test, env):
                self._tick()
                try:
                    for s in node.body:
                        res = self._eval_stmt(s, env)
                except BreakSignal:
                    break
                except ContinueSignal:
                    continue
            else:
                for s in node.orelse:
                    res = self._eval_stmt(s, env)
            return res

        elif isinstance(node, ast.For):
            iter_obj = self._eval_expr(node.iter, env)
            res = None
            try:
                iterator = iter(iter_obj)
            except TypeError:
                raise TypeError(f"'{type(iter_obj).__name__}' object is not iterable")

            for item in iterator:
                self._tick()
                self._assign_target(node.target, item, env)
                try:
                    for s in node.body:
                        res = self._eval_stmt(s, env)
                except BreakSignal:
                    break
                except ContinueSignal:
                    continue
            else:
                for s in node.orelse:
                    res = self._eval_stmt(s, env)
            return res

        elif isinstance(node, ast.Import):
            for alias in node.names:
                mod_name = alias.name
                if mod_name in SAFE_MODULES:
                    env[alias.asname or mod_name] = SAFE_MODULES[mod_name]
                else:
                    root = mod_name.split(".")[0]
                    if root in SAFE_MODULES:
                        env[alias.asname or mod_name] = SAFE_MODULES[root]
            return None

        elif isinstance(node, ast.ImportFrom):
            mod_name = node.module or ""
            if mod_name in SAFE_MODULES:
                target_mod = SAFE_MODULES[mod_name]
                for alias in node.names:
                    val = getattr(target_mod, alias.name, None)
                    env[alias.asname or alias.name] = val
            return None

        elif isinstance(node, ast.FunctionDef):
            fn_name = node.name
            if (fn_name.startswith("__") or (fn_name.startswith("_") and fn_name != "_")) or fn_name in FORBIDDEN_NAMES:
                raise SandboxSecurityViolation(f"Cannot define function with forbidden name '{fn_name}'")

            def user_fn(*args: Any, **kwargs: Any) -> Any:
                self._tick()
                fn_env = dict(env)
                # Map positional args
                arg_names = [a.arg for a in node.args.args]
                for idx, a_name in enumerate(arg_names):
                    if idx < len(args):
                        fn_env[a_name] = args[idx]
                    elif a_name in kwargs:
                        fn_env[a_name] = kwargs[a_name]

                # Vararg (*args)
                if node.args.vararg:
                    fn_env[node.args.vararg.arg] = tuple(args[len(arg_names):])

                # Kwarg (**kwargs)
                if node.args.kwarg:
                    remaining_kwargs = {k: v for k, v in kwargs.items() if k not in arg_names}
                    fn_env[node.args.kwarg.arg] = remaining_kwargs

                try:
                    ret_val = None
                    for s in node.body:
                        ret_val = self._eval_stmt(s, fn_env)
                    return ret_val
                except ReturnSignal as sig:
                    return sig.value

            env[fn_name] = user_fn
            return user_fn

        elif isinstance(node, ast.Return):
            val = self._eval_expr(node.value, env) if node.value else None
            raise ReturnSignal(val)

        elif isinstance(node, ast.Break):
            raise BreakSignal()

        elif isinstance(node, ast.Continue):
            raise ContinueSignal()

        elif isinstance(node, ast.Pass):
            return None

        else:
            raise NotImplementedError(f"Unsupported statement type: {type(node).__name__}")

    def _eval_expr(self, node: ast.AST, env: dict[str, Any]) -> Any:
        self._tick()

        if isinstance(node, ast.Constant):
            return node.value

        elif isinstance(node, ast.Name):
            name = node.id
            if name in FORBIDDEN_NAMES or name.startswith("__") or (name.startswith("_") and name != "_"):
                raise SandboxSecurityViolation(f"Reference to forbidden name '{name}'")
            if name in env:
                return env[name]
            raise NameError(f"Name '{name}' is not defined in sandbox scope")

        elif isinstance(node, ast.UnaryOp):
            val = self._eval_expr(node.operand, env)
            op_fn = self.UNARY_OPS.get(type(node.op))
            if not op_fn:
                raise NotImplementedError(f"Unsupported UnaryOp {type(node.op)}")
            return op_fn(val)

        elif isinstance(node, ast.BinOp):
            left = self._eval_expr(node.left, env)
            right = self._eval_expr(node.right, env)
            op_fn = self.BIN_OPS.get(type(node.op))
            if not op_fn:
                raise NotImplementedError(f"Unsupported BinOp {type(node.op)}")
            return op_fn(left, right)

        elif isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                res = True
                for val_node in node.values:
                    res = self._eval_expr(val_node, env)
                    if not res:
                        return res
                return res
            elif isinstance(node.op, ast.Or):
                res = False
                for val_node in node.values:
                    res = self._eval_expr(val_node, env)
                    if res:
                        return res
                return res

        elif isinstance(node, ast.Compare):
            left = self._eval_expr(node.left, env)
            for op, comparator in zip(node.ops, node.comparators):
                right = self._eval_expr(comparator, env)
                op_fn = self.COMPARE_OPS.get(type(op))
                if not op_fn:
                    raise NotImplementedError(f"Unsupported comparison operator {type(op)}")
                if not op_fn(left, right):
                    return False
                left = right
            return True

        elif isinstance(node, ast.IfExp):
            cond = self._eval_expr(node.test, env)
            return self._eval_expr(node.body, env) if cond else self._eval_expr(node.orelse, env)

        elif isinstance(node, ast.List):
            return [self._eval_expr(elt, env) for elt in node.elts]

        elif isinstance(node, ast.Tuple):
            return tuple(self._eval_expr(elt, env) for elt in node.elts)

        elif isinstance(node, ast.Set):
            return {self._eval_expr(elt, env) for elt in node.elts}

        elif isinstance(node, ast.Dict):
            return {
                self._eval_expr(k, env): self._eval_expr(v, env)
                for k, v in zip(node.keys, node.values)
                if k is not None
            }

        elif isinstance(node, ast.Subscript):
            val = self._eval_expr(node.value, env)
            slice_val = self._eval_slice(node.slice, env)
            return val[slice_val]

        elif isinstance(node, ast.Attribute):
            obj = self._eval_expr(node.value, env)
            attr = node.attr
            if (attr.startswith("__") or (attr.startswith("_") and attr != "_")) or attr in FORBIDDEN_ATTRIBUTES:
                raise SandboxSecurityViolation(f"Access to private attribute '{attr}' is forbidden.")
            return getattr(obj, attr)

        elif isinstance(node, ast.Call):
            func = self._eval_expr(node.func, env)
            args = [self._eval_expr(arg, env) for arg in node.args]
            kwargs = {kw.arg: self._eval_expr(kw.value, env) for kw in node.keywords if kw.arg}
            return func(*args, **kwargs)

        elif isinstance(node, ast.ListComp):
            return self._eval_comp(node.elt, node.generators, env, list)

        elif isinstance(node, ast.SetComp):
            return self._eval_comp(node.elt, node.generators, env, set)

        elif isinstance(node, ast.DictComp):
            result_dict: dict[Any, Any] = {}
            self._eval_dict_comp(node.key, node.value, node.generators, 0, env, result_dict)
            return result_dict

        elif isinstance(node, ast.JoinedStr):
            parts = []
            for val in node.values:
                parts.append(str(self._eval_expr(val, env)))
            return "".join(parts)

        elif isinstance(node, ast.FormattedValue):
            val = self._eval_expr(node.value, env)
            return val

        elif isinstance(node, ast.Lambda):
            def lambda_fn(*args: Any, **kwargs: Any) -> Any:
                self._tick()
                lam_env = dict(env)
                arg_names = [a.arg for a in node.args.args]
                for idx, a_name in enumerate(arg_names):
                    if idx < len(args):
                        lam_env[a_name] = args[idx]
                    elif a_name in kwargs:
                        lam_env[a_name] = kwargs[a_name]
                return self._eval_expr(node.body, lam_env)
            return lambda_fn

        else:
            raise NotImplementedError(f"Unsupported expression type: {type(node).__name__}")

    def _eval_slice(self, slice_node: ast.AST, env: dict[str, Any]) -> Any:
        if isinstance(slice_node, ast.Slice):
            lower = self._eval_expr(slice_node.lower, env) if slice_node.lower else None
            upper = self._eval_expr(slice_node.upper, env) if slice_node.upper else None
            step = self._eval_expr(slice_node.step, env) if slice_node.step else None
            return slice(lower, upper, step)
        return self._eval_expr(slice_node, env)

    def _assign_target(self, target: ast.AST, value: Any, env: dict[str, Any]) -> None:
        if isinstance(target, ast.Name):
            name = target.id
            if (name.startswith("__") or (name.startswith("_") and name != "_")) or name in FORBIDDEN_NAMES:
                raise SandboxSecurityViolation(f"Cannot assign to forbidden name '{name}'")
            env[name] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            try:
                seq = list(value)
            except TypeError:
                raise TypeError(f"Cannot unpack non-iterable '{type(value).__name__}' object")
            if len(seq) != len(target.elts):
                raise ValueError(f"Need {len(target.elts)} values to unpack, got {len(seq)}")
            for sub_target, sub_val in zip(target.elts, seq):
                self._assign_target(sub_target, sub_val, env)
        elif isinstance(target, ast.Subscript):
            container = self._eval_expr(target.value, env)
            slice_idx = self._eval_slice(target.slice, env)
            container[slice_idx] = value
        elif isinstance(target, ast.Attribute):
            obj = self._eval_expr(target.value, env)
            attr = target.attr
            if attr.startswith("_") or attr in FORBIDDEN_ATTRIBUTES:
                raise SandboxSecurityViolation(f"Cannot assign to forbidden attribute '{attr}'")
            setattr(obj, attr, value)
        else:
            raise NotImplementedError(f"Unsupported assignment target: {type(target).__name__}")

    def _eval_comp(self, elt_node: ast.AST, generators: list[ast.comprehension], env: dict[str, Any], container_cls: Any) -> Any:
        result = []
        self._eval_comp_step(elt_node, generators, 0, env, result)
        return container_cls(result)

    def _eval_comp_step(self, elt_node: ast.AST, generators: list[ast.comprehension], gen_idx: int, env: dict[str, Any], acc: list[Any]) -> None:
        if gen_idx >= len(generators):
            acc.append(self._eval_expr(elt_node, env))
            return

        gen = generators[gen_idx]
        iter_obj = self._eval_expr(gen.iter, env)
        for item in iter_obj:
            self._tick()
            child_env = dict(env)
            self._assign_target(gen.target, item, child_env)
            match = True
            for if_node in gen.ifs:
                if not self._eval_expr(if_node, child_env):
                    match = False
                    break
            if match:
                self._eval_comp_step(elt_node, generators, gen_idx + 1, child_env, acc)

    def _eval_dict_comp(self, key_node: ast.AST, val_node: ast.AST, generators: list[ast.comprehension], gen_idx: int, env: dict[str, Any], acc: dict[Any, Any]) -> None:
        if gen_idx >= len(generators):
            k = self._eval_expr(key_node, env)
            v = self._eval_expr(val_node, env)
            acc[k] = v
            return

        gen = generators[gen_idx]
        iter_obj = self._eval_expr(gen.iter, env)
        for item in iter_obj:
            self._tick()
            child_env = dict(env)
            self._assign_target(gen.target, item, child_env)
            match = True
            for if_node in gen.ifs:
                if not self._eval_expr(if_node, child_env):
                    match = False
                    break
            if match:
                self._eval_dict_comp(key_node, val_node, generators, gen_idx + 1, child_env, acc)


def _serialize_scope(scope: dict[str, Any]) -> dict[str, Any]:
    """Filter and serialize scope variables into JSON-safe representations."""
    out: dict[str, Any] = {}
    for k, v in scope.items():
        if k in SAFE_MODULES or k.startswith("_") or callable(v):
            continue
        try:
            json.dumps(v)
            out[k] = v
        except (TypeError, ValueError):
            out[k] = repr(v)
    return out


def code_action_sandbox(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute code action sandbox operations."""
    if not isinstance(arguments, dict):
        return _envelope_error(ValueError("Arguments must be a dictionary."))

    for key in arguments:
        if key not in KNOWN_ARGUMENTS:
            return _envelope_error(ValueError(f"Unknown argument '{key}' or schema violation"))

    action = arguments.get("action")
    if not action or not isinstance(action, str):
        return _envelope_error(ValueError("Missing required parameter 'action'"))

    if action not in VALID_ACTIONS:
        return _envelope_error(ValueError(f"Invalid or unsupported action '{action}'"))

    if action == "get_limits":
        return _envelope_success({
            "default_timeout_seconds": 5.0,
            "max_timeout_seconds": 30.0,
            "default_max_steps": 5000,
            "max_steps_cap": 50000,
            "max_memory_mb": 128,
            "allowed_modules": sorted(list(SAFE_MODULES.keys())),
            "forbidden_builtins": sorted(list(FORBIDDEN_NAMES)),
            "forbidden_attributes": sorted(list(FORBIDDEN_ATTRIBUTES)),
        })

    code = arguments.get("code")
    if not isinstance(code, str) or not code.strip():
        return _envelope_error(ValueError("Parameter 'code' must be a non-empty string."))

    allowed_user_modules = arguments.get("allowed_modules") or []
    if not isinstance(allowed_user_modules, list):
        return _envelope_error(ValueError("Parameter 'allowed_modules' must be a list of strings."))

    allowed_module_set = set(SAFE_MODULES.keys()) | set(allowed_user_modules)

    try:
        parsed_tree = ast.parse(code)
    except SyntaxError as syn_err:
        return _envelope_error(f"SyntaxError: {syn_err.msg} (line {syn_err.lineno})")

    is_safe, violations, ast_summary = _analyze_ast_safety(parsed_tree, allowed_module_set)

    if action == "analyze_safety":
        return _envelope_success({
            "safe": is_safe,
            "violations": violations,
            "analysis": ast_summary,
        })

    elif action == "execute_code":
        if not is_safe:
            return _envelope_error(SandboxSecurityViolation(violations[0]))

        timeout_sec = float(arguments.get("timeout_seconds", 5.0))
        timeout_sec = max(0.1, min(30.0, timeout_sec))

        max_steps = int(arguments.get("max_steps", 5000))
        max_steps = max(10, min(50000, max_steps))

        initial_scope = arguments.get("initial_scope") or {}
        if not isinstance(initial_scope, dict):
            return _envelope_error(ValueError("Parameter 'initial_scope' must be a dictionary."))

        start_time = time.perf_counter()
        try:
            interpreter = SafeASTInterpreter(
                initial_scope=initial_scope,
                max_steps=max_steps,
                timeout_seconds=timeout_sec,
            )
            result = interpreter.eval(parsed_tree)
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            safe_scope = _serialize_scope(interpreter.scope)

            # Check if result itself is serializable
            try:
                json.dumps(result)
                clean_result = result
            except (TypeError, ValueError):
                clean_result = repr(result)

            return _envelope_success({
                "result": clean_result,
                "final_scope": safe_scope,
                "executed_steps": interpreter.steps,
                "stdout": interpreter.stdout_buffer.getvalue(),
                "duration_ms": round(duration_ms, 3),
            })
        except Exception as exc:
            return _envelope_error(exc)

    return _envelope_error(ValueError(f"Unhandled action '{action}'"))


TOOL = {
    "name": "code_action_sandbox",
    "description": (
        "Zero-dependency safe AST-based Python code runner inspired by smolagents, OpenHands, and E2B. "
        "Executes batch data transformations, filtering, and mathematical expressions via safe AST visitor "
        "without eval/exec or external dependencies. Enforces instruction-step caps, timeout guards, and strict whitelist sandboxing."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["execute_code", "analyze_safety", "get_limits"],
                "description": "Sandbox operation to perform.",
            },
            "code": {
                "type": "string",
                "description": "Python code snippet to analyze or execute.",
            },
            "initial_scope": {
                "type": "object",
                "description": "Initial variable dictionary provided to execution scope.",
            },
            "timeout_seconds": {
                "type": "number",
                "minimum": 0.1,
                "maximum": 30.0,
                "description": "Wall-clock timeout in seconds (default: 5.0).",
            },
            "max_memory_mb": {
                "type": "integer",
                "minimum": 16,
                "maximum": 512,
                "description": "Virtual memory ceiling in megabytes (default: 128 MB).",
            },
            "max_steps": {
                "type": "integer",
                "minimum": 10,
                "maximum": 50000,
                "description": "Maximum number of AST execution steps before timeout (default: 5000).",
            },
            "allowed_modules": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional list of additional allowed standard library modules.",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": code_action_sandbox,
    "approval": False,
}
