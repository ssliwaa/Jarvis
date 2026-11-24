"""Adversarial stress and security test suite for Jarvis external modules.

Challenges sqlite_ops, git_ops, code_ast, and tool_registry under hostile inputs,
injection payloads, path traversal, sensitive credential commits, oversized inputs,
and SystemExit / BaseException crash vectors.
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import operator_modules.code_ast as code_ast
import operator_modules.git_ops as git_ops
import operator_modules.sqlite_ops as sqlite_ops
import tool_registry


class AdversarialSqliteOpsTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.db_path = self.root / "adversarial.db"

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, secret TEXT)")
        cur.execute("INSERT INTO users VALUES (1, 'alice', 'topsecret123')")
        cur.execute("INSERT INTO users VALUES (2, 'bob', 'hunter2')")
        conn.commit()
        conn.close()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_sql_injection_multiple_statements(self):
        vectors = [
            "SELECT * FROM users; DROP TABLE users;",
            "SELECT 1; VACUUM;",
            "SELECT name FROM users; INSERT INTO users VALUES (3, 'evil', 'pw');",
            "SELECT * FROM users; --\nDROP TABLE users;",
        ]
        for query in vectors:
            res = sqlite_ops.sqlite_ops({"action": "query", "path": str(self.db_path), "query": query})
            self.assertFalse(res["ok"], f"Expected rejection for multi-statement query: {query}")
            self.assertTrue(
                "multiple" in res["error"].lower() or "forbidden" in res["error"].lower(),
                f"Unexpected error message: {res['error']}",
            )

        # Confirm users table was not dropped
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM users")
        self.assertEqual(cur.fetchone()[0], 2)
        conn.close()

    def test_rejection_of_ddl_and_write_queries(self):
        write_queries = [
            "DROP TABLE users",
            "CREATE TABLE evil_table (x TEXT)",
            "INSERT INTO users VALUES (99, 'hacked', 'pwned')",
            "UPDATE users SET secret = 'pwned'",
            "DELETE FROM users WHERE 1=1",
            "ALTER TABLE users ADD COLUMN compromised INT",
            "REPLACE INTO users VALUES (1, 'pwn', 'pwn')",
            "VACUUM",
            "REINDEX",
            "ATTACH DATABASE '/tmp/evil.db' AS evil",
            "DETACH DATABASE evil",
        ]
        for query in write_queries:
            res = sqlite_ops.sqlite_ops({"action": "query", "path": str(self.db_path), "query": query})
            self.assertFalse(res["ok"], f"Write query was not rejected: {query}")
            self.assertIn("forbidden", res["error"].lower())

    def test_rejection_of_dangerous_pragmas_and_extensions(self):
        forbidden_pragmas = [
            "PRAGMA query_only = OFF",
            "PRAGMA writable_schema = 1",
            "PRAGMA schema_version = 0",
            "PRAGMA journal_mode = WAL",
            "PRAGMA foreign_keys = OFF",
        ]
        for pragma in forbidden_pragmas:
            res = sqlite_ops.sqlite_ops({"action": "query", "path": str(self.db_path), "query": pragma})
            self.assertFalse(res["ok"], f"Dangerous pragma was not rejected: {pragma}")

        # Extension loading attempt
        ext_query = "SELECT load_extension('nonexistent.so')"
        res = sqlite_ops.sqlite_ops({"action": "query", "path": str(self.db_path), "query": ext_query})
        self.assertFalse(res["ok"])
        self.assertIn("failed", res["error"].lower())

    def test_path_traversal_and_sensitive_file_blocking(self):
        # Parent directory traversal
        res = sqlite_ops.sqlite_ops({"action": "list_tables", "path": "../../../etc/passwd"})
        self.assertFalse(res["ok"])
        self.assertIn("parent-directory", res["error"].lower())

        # Sensitive SSH key
        res = sqlite_ops.sqlite_ops({"action": "list_tables", "path": str(Path.home() / ".ssh" / "id_rsa")})
        self.assertFalse(res["ok"])

        # Sensitive secrets.json
        res = sqlite_ops.sqlite_ops({"action": "list_tables", "path": str(Path.home() / ".jarvis-tools" / "secrets.json")})
        self.assertFalse(res["ok"])

    def test_malformed_and_corrupt_database(self):
        corrupt_file = self.root / "corrupt.db"
        corrupt_file.write_bytes(b"THIS IS NOT A SQLITE DATABASE BINARY GARBAGE\x00\xff\xfe\x01\x02")

        res = sqlite_ops.sqlite_ops({"action": "list_tables", "path": str(corrupt_file)})
        self.assertFalse(res["ok"])
        self.assertTrue(
            "not a database" in res["error"].lower() or "could not open" in res["error"].lower(),
            f"Unexpected error: {res['error']}",
        )

    def test_boundary_limits_and_invalid_arguments(self):
        # Non-integer limit
        res = sqlite_ops.sqlite_ops({
            "action": "query",
            "path": str(self.db_path),
            "query": "SELECT * FROM users",
            "limit": "invalid_limit",
        })
        self.assertFalse(res["ok"])
        self.assertIn("integer", res["error"].lower())

        # Massive limit is clamped to 500
        res = sqlite_ops.sqlite_ops({
            "action": "query",
            "path": str(self.db_path),
            "query": "SELECT * FROM users",
            "limit": 999999,
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["result"]["limit"], 500)

        # Negative limit is clamped to 1
        res = sqlite_ops.sqlite_ops({
            "action": "query",
            "path": str(self.db_path),
            "query": "SELECT * FROM users",
            "limit": -50,
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["result"]["limit"], 1)

        # Empty query
        res = sqlite_ops.sqlite_ops({"action": "query", "path": str(self.db_path), "query": "   "})
        self.assertFalse(res["ok"])

        # Comment-only query
        res = sqlite_ops.sqlite_ops({"action": "query", "path": str(self.db_path), "query": "-- just a comment"})
        self.assertFalse(res["ok"])

    def test_sql_cte_and_subquery_write_attempts(self):
        cte_queries = [
            "WITH evil AS (DELETE FROM users RETURNING *) SELECT * FROM evil",
            "WITH evil AS (UPDATE users SET secret='pwned' RETURNING *) SELECT * FROM evil",
            "WITH evil AS (INSERT INTO users VALUES (5, 'x', 'x') RETURNING *) SELECT * FROM evil",
        ]
        for query in cte_queries:
            res = sqlite_ops.sqlite_ops({"action": "query", "path": str(self.db_path), "query": query})
            self.assertFalse(res["ok"], f"CTE write query was not rejected: {query}")
            self.assertIn("forbidden", res["error"].lower())

    def test_transaction_statements_rejected(self):
        tx_statements = [
            "BEGIN TRANSACTION",
            "COMMIT",
            "ROLLBACK",
            "SAVEPOINT sp1",
            "RELEASE sp1",
        ]
        for stmt in tx_statements:
            res = sqlite_ops.sqlite_ops({"action": "query", "path": str(self.db_path), "query": stmt})
            self.assertFalse(res["ok"], f"Transaction statement was not rejected: {stmt}")
            self.assertTrue(
                "disallowed statement type" in res["error"].lower()
                or "forbidden" in res["error"].lower(),
                f"Unexpected error: {res['error']}",
            )

    def test_describe_table_injection_attempts(self):
        malicious_tables = [
            "users; DROP TABLE users;",
            "users' OR '1'='1",
            "users--",
            "sqlite_master",
        ]
        for tbl in malicious_tables:
            res = sqlite_ops.sqlite_ops({"action": "describe_table", "path": str(self.db_path), "table": tbl})
            self.assertFalse(res["ok"], f"Describe table did not reject malicious input: {tbl}")
            self.assertTrue(
                "invalid table name format" in res["error"].lower()
                or "not found" in res["error"].lower(),
                f"Unexpected error: {res['error']}",
            )

    def test_string_literal_semicolon_behavior(self):
        # Even a semicolon within a string literal is conservatively rejected to prevent multi-statement smuggling
        query = "SELECT 'semi;colon' FROM users"
        res = sqlite_ops.sqlite_ops({"action": "query", "path": str(self.db_path), "query": query})
        self.assertFalse(res["ok"])
        self.assertIn("multiple sql statements", res["error"].lower())


class AdversarialGitOpsTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.repo_dir = Path(self.tmpdir.name) / "test_repo"
        self.repo_dir.mkdir()

        # Initialize real git repository
        subprocess.run(["git", "init", "-b", "main"], cwd=self.repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Tester"], cwd=self.repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=self.repo_dir, check=True, capture_output=True)

        # Initial commit
        (self.repo_dir / "README.md").write_text("# Test Repo\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=self.repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=self.repo_dir, check=True, capture_output=True)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_hook_isolation(self):
        # Create a malicious pre-commit hook that drops an indicator file
        hooks_dir = self.repo_dir / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        hook_marker = self.repo_dir / "hook_executed.txt"
        hook_script = hooks_dir / "pre-commit"
        hook_script.write_text(f"#!/bin/sh\ntouch '{hook_marker}'\nexit 1\n", encoding="utf-8")
        hook_script.chmod(0o755)

        # Try to commit via git_ops
        (self.repo_dir / "safe_file.txt").write_text("safe content\n", encoding="utf-8")
        res = git_ops.git_ops({
            "action": "commit",
            "repo_path": str(self.repo_dir),
            "message": "Hook bypass test",
            "files": ["safe_file.txt"],
        })
        self.assertTrue(res["ok"], f"Commit failed: {res}")
        # The hook must NOT have been executed because core.hooksPath=/dev/null is enforced
        self.assertFalse(hook_marker.exists(), "MALICIOUS HOOK WAS EXECUTED! Hook isolation failed.")

    def test_command_injection_and_argument_sanitization(self):
        # Try command injection via repo_path
        res = git_ops.git_ops({"action": "status", "repo_path": "; touch /tmp/pwned_repo"})
        self.assertFalse(res["ok"])
        self.assertFalse(Path("/tmp/pwned_repo").exists())

        # Try option injection via revision in log
        res = git_ops.git_ops({
            "action": "log",
            "repo_path": str(self.repo_dir),
            "revision": "--output=/tmp/pwned_log",
        })
        self.assertFalse(res["ok"])
        self.assertIn("invalid revision", res["error"].lower())
        self.assertFalse(Path("/tmp/pwned_log").exists())

        # Try option injection via branch name
        res = git_ops.git_ops({
            "action": "branch",
            "repo_path": str(self.repo_dir),
            "branch_action": "create",
            "branch_name": "-d main",
        })
        self.assertFalse(res["ok"])
        self.assertIn("invalid branch name", res["error"].lower())

        # Try option injection via diff path
        res = git_ops.git_ops({
            "action": "diff",
            "repo_path": str(self.repo_dir),
            "path": "--output=/tmp/pwned_diff",
        })
        self.assertFalse(res["ok"])
        self.assertIn("invalid path", res["error"].lower())
        self.assertFalse(Path("/tmp/pwned_diff").exists())

    def test_sensitive_file_staging_and_commit_blocking(self):
        sensitive_files = [
            ".env",
            ".env.local",
            ".env.production",
            "secrets.json",
            "id_rsa",
            "id_ed25519",
            "credentials.json",
            "server.key",
            "cert.pem",
        ]
        for sfile in sensitive_files:
            target = self.repo_dir / sfile
            target.write_text("SECRET_KEY=123456\n", encoding="utf-8")

            # 1. Attempt to stage and commit via files param
            res = git_ops.git_ops({
                "action": "commit",
                "repo_path": str(self.repo_dir),
                "message": f"Accidental commit of {sfile}",
                "files": [sfile],
            })
            self.assertFalse(res["ok"], f"Sensitive file {sfile} was not blocked in files parameter!")
            self.assertIn("sensitive", res["error"].lower())

            # 2. Pre-stage using external git add and verify commit still refuses
            subprocess.run(["git", "add", sfile], cwd=self.repo_dir, check=True, capture_output=True)
            res2 = git_ops.git_ops({
                "action": "commit",
                "repo_path": str(self.repo_dir),
                "message": f"Commit pre-staged {sfile}",
            })
            self.assertFalse(res2["ok"], f"Pre-staged sensitive file {sfile} was not blocked from committing!")
            self.assertIn("sensitive", res2["error"].lower())

            # Unstage for next test
            subprocess.run(["git", "reset", "HEAD", sfile], cwd=self.repo_dir, check=True, capture_output=True)
            target.unlink()

    def test_non_git_and_nonexistent_directories(self):
        non_git = Path(self.tmpdir.name) / "outside_git_dir"
        non_git.mkdir()
        res = git_ops.git_ops({"action": "status", "repo_path": str(non_git)})
        self.assertFalse(res["ok"])
        self.assertIn("not a valid git repository", res["error"].lower())

        res2 = git_ops.git_ops({"action": "status", "repo_path": str(self.repo_dir / "does_not_exist")})
        self.assertFalse(res2["ok"])
        self.assertIn("does not exist", res2["error"].lower())

    def test_nested_sensitive_files_commit_blocked(self):
        nested_dirs = [
            ("config", ".env"),
            ("sub/dir", "secrets.json"),
            ("ssh_keys", "id_rsa"),
            ("certs", "server.key"),
            ("tls", "cert.pem"),
        ]
        for parent, filename in nested_dirs:
            full_parent = self.repo_dir / parent
            full_parent.mkdir(parents=True, exist_ok=True)
            fpath = full_parent / filename
            fpath.write_text("TOP_SECRET_CREDENTIAL\n", encoding="utf-8")
            rel_str = f"{parent}/{filename}"

            res = git_ops.git_ops({
                "action": "commit",
                "repo_path": str(self.repo_dir),
                "message": f"Trying to commit nested {rel_str}",
                "files": [rel_str],
            })
            self.assertFalse(res["ok"], f"Nested sensitive file was not blocked: {rel_str}")
            self.assertIn("sensitive", res["error"].lower())
            fpath.unlink()

    def test_commit_message_with_dash_args(self):
        # Even if commit message looks like an option (e.g. '--amend' or '-m'), it must be treated as message text
        sample_file = self.repo_dir / "sample_dash.txt"
        sample_file.write_text("content\n", encoding="utf-8")
        res = git_ops.git_ops({
            "action": "commit",
            "repo_path": str(self.repo_dir),
            "message": "--amend",
            "files": ["sample_dash.txt"],
        })
        self.assertTrue(res["ok"], f"Commit failed with dash message: {res}")
        self.assertEqual(res["result"]["message"], "--amend")

    def test_diff_and_show_options_injection(self):
        # Attempt option injection via path parameter in diff and show
        for act in ["diff", "show"]:
            res = git_ops.git_ops({
                "action": act,
                "repo_path": str(self.repo_dir),
                "path": "--no-index",
            })
            self.assertFalse(res["ok"], f"Option injection succeeded for {act}: {res}")
            self.assertIn("invalid path", res["error"].lower())


class AdversarialCodeAstTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_zero_code_execution_guarantee(self):
        pwn_marker = self.root / "ast_pwned.txt"
        malicious_code = f"""
import os
os.system("touch '{pwn_marker}'")
raise RuntimeError("Execution bomb exploded!")
"""
        # Test all actions against the malicious code string
        actions = ["outline", "check_syntax", "inspect_imports"]
        for act in actions:
            res = code_ast.code_ast({"action": act, "code": malicious_code})
            self.assertTrue(res["ok"], f"Action {act} failed to parse: {res}")
            # Ensure code was NOT executed
            self.assertFalse(pwn_marker.exists(), f"CODE WAS EXECUTED during {act}! AST isolation failed.")

    def test_malformed_syntax_containment(self):
        bad_syntax = "def broken_func(a, b, : None\n  return ?"
        res_check = code_ast.code_ast({"action": "check_syntax", "code": bad_syntax})
        self.assertTrue(res_check["ok"])
        self.assertFalse(res_check["result"]["valid"])
        self.assertIn("error", res_check["result"])

        res_outline = code_ast.code_ast({"action": "outline", "code": bad_syntax})
        self.assertFalse(res_outline["ok"])
        self.assertIn("syntaxerror", res_outline["error"].lower())

    def test_deep_nesting_and_recursion_limit(self):
        # 1000 nested brackets
        deep_brackets = "(" * 1000 + "1" + ")" * 1000
        res = code_ast.code_ast({"action": "check_syntax", "code": deep_brackets})
        # Should either cleanly parse, return invalid syntax, or catch RecursionError cleanly without crashing
        self.assertIn("ok", res)

    def test_oversized_input_capping(self):
        # 350,000 bytes is allowed
        allowed_code = "# " + "A" * (350_000 - 2)
        self.assertEqual(len(allowed_code.encode("utf-8")), 350_000)
        res_allowed = code_ast.code_ast({"action": "check_syntax", "code": allowed_code})
        self.assertTrue(res_allowed["ok"])

        # 350,001 bytes must be rejected
        blocked_code = "# " + "A" * (350_001 - 2)
        self.assertEqual(len(blocked_code.encode("utf-8")), 350_001)
        res_blocked = code_ast.code_ast({"action": "check_syntax", "code": blocked_code})
        self.assertFalse(res_blocked["ok"])
        self.assertIn("exceeds maximum limit", res_blocked["error"].lower())

        # Check file size limit as well
        large_file = self.root / "large.py"
        large_file.write_bytes(b"#" + b"B" * 350_005)
        res_file = code_ast.code_ast({"action": "outline", "path": str(large_file)})
        self.assertFalse(res_file["ok"])
        self.assertIn("exceeds maximum limit", res_file["error"].lower())

    def test_binary_file_with_invalid_utf8(self):
        bin_file = self.root / "binary.bin"
        bin_file.write_bytes(b"\x00\xff\xfe\xca\xfe\xba\xbe" * 100)
        res = code_ast.code_ast({"action": "outline", "path": str(bin_file)})
        # Should gracefully report syntax error or decode issue, without crashing
        self.assertFalse(res["ok"])
        self.assertTrue("syntaxerror" in res["error"].lower() or "failed" in res["error"].lower())

    def test_modern_python_syntax_parsing(self):
        modern_code = """
import os, sys
from . import sibling
from ..parent import grandparent

def my_decorator(fn):
    return fn

@my_decorator
async def async_worker(a: int, /, b: str = "default", *args, key: bool = True, **kwargs):
    \"\"\"Docstring for async worker.\"\"\"
    if (val := a * 2) > 10:
        match val:
            case 20:
                return f"exact {val}"
            case _:
                return "other"
    return str(val)

class BaseClass:
    pass

class DerivedClass(BaseClass):
    @classmethod
    def create(cls):
        return cls()
"""
        # Test outline
        res_outline = code_ast.code_ast({"action": "outline", "code": modern_code})
        self.assertTrue(res_outline["ok"], f"Outline failed: {res_outline}")
        funcs = {f["name"]: f for f in res_outline["result"]["functions"]}
        self.assertIn("async_worker", funcs)
        self.assertTrue(funcs["async_worker"]["is_async"])
        self.assertIn("/", funcs["async_worker"]["args"])
        self.assertIn("*args", funcs["async_worker"]["args"])
        self.assertIn("**kwargs", funcs["async_worker"]["args"])

        # Test check_syntax
        res_syntax = code_ast.code_ast({"action": "check_syntax", "code": modern_code})
        self.assertTrue(res_syntax["ok"])
        self.assertTrue(res_syntax["result"]["valid"])

        # Test inspect_imports
        res_imports = code_ast.code_ast({"action": "inspect_imports", "code": modern_code})
        self.assertTrue(res_imports["ok"])
        self.assertIn("os", res_imports["result"]["modules"])
        self.assertIn("sys", res_imports["result"]["modules"])


class AdversarialToolRegistryTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.mod_dir = Path(self.tmpdir.name) / "test_modules"
        self.mod_dir.mkdir()
        self.state_file = Path(self.tmpdir.name) / "test_state.json"
        self.reg = tool_registry.ToolRegistry(directory=self.mod_dir, state_path=self.state_file)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_run_catches_system_exit(self):
        # Create a tool whose handler calls sys.exit
        def evil_exit_handler(args, ctx=None):
            sys.exit("Intentional test kill")

        evil_tool = tool_registry.ModuleTool(
            name="evil_exit",
            description="Exits the process",
            schema={"type": "object", "properties": {}},
            handler=evil_exit_handler,
            path=Path("/tmp/evil.py"),
            approval=False,
        )
        self.reg.tools["evil_exit"] = evil_tool

        with self.assertRaises(tool_registry.ToolRegistryError) as ctx:
            self.reg.run("evil_exit", {})

        self.assertIn("SystemExit", str(ctx.exception))
        self.assertIn("Intentional test kill", str(ctx.exception))

    def test_run_catches_system_exit_code_1(self):
        def exit_code_handler(args, ctx=None):
            raise SystemExit(1)

        exit_tool = tool_registry.ModuleTool(
            name="exit_code",
            description="Exits with code 1",
            schema={"type": "object", "properties": {}},
            handler=exit_code_handler,
            path=Path("/tmp/exit_code.py"),
            approval=False,
        )
        self.reg.tools["exit_code"] = exit_tool

        with self.assertRaises(tool_registry.ToolRegistryError) as ctx:
            self.reg.run("exit_code", {})

        self.assertIn("SystemExit: 1", str(ctx.exception))

    def test_run_catches_custom_base_exception(self):
        def base_exc_handler(args, ctx=None):
            raise GeneratorExit("generator exit test")

        gen_tool = tool_registry.ModuleTool(
            name="gen_exit",
            description="Raises GeneratorExit",
            schema={"type": "object", "properties": {}},
            handler=base_exc_handler,
            path=Path("/tmp/gen.py"),
            approval=False,
        )
        self.reg.tools["gen_exit"] = gen_tool

        with self.assertRaises(tool_registry.ToolRegistryError) as ctx:
            self.reg.run("gen_exit", {})

        self.assertIn("generator exit test", str(ctx.exception))

    def test_reload_containment_of_failing_module(self):
        # Module that crashes at top level during import
        crash_mod = self.mod_dir / "crash_mod.py"
        crash_mod.write_text("raise SystemExit('Top-level module crash!')\n", encoding="utf-8")

        # Reload should survive and catch the exception into self.errors
        loaded_count = self.reg.reload()
        self.assertEqual(loaded_count, 0)
        self.assertEqual(len(self.reg.errors), 1)
        self.assertIn("SystemExit", self.reg.errors[0])
        self.assertIn("Top-level module crash!", self.reg.errors[0])

    def test_keyboard_interrupt_propagation(self):
        # KeyboardInterrupt must NOT be swallowed by ToolRegistry; it must propagate
        def ctrl_c_handler(args, ctx=None):
            raise KeyboardInterrupt()

        tool = tool_registry.ModuleTool(
            name="ctrl_c",
            description="Simulates SIGINT",
            schema={"type": "object", "properties": {}},
            handler=ctrl_c_handler,
            path=Path("/tmp/ctrl_c.py"),
            approval=False,
        )
        self.reg.tools["ctrl_c"] = tool

        with self.assertRaises(KeyboardInterrupt):
            self.reg.run("ctrl_c", {})

    def test_disabled_tool_rejection(self):
        def dummy_handler(args, ctx=None):
            return {"ok": True}

        tool = tool_registry.ModuleTool(
            name="dummy_mod",
            description="Dummy module",
            schema={"type": "object", "properties": {}},
            handler=dummy_handler,
            path=Path("/tmp/dummy.py"),
            approval=False,
        )
        self.reg.tools["dummy_mod"] = tool

        # First run succeeds (registry.run completes the output to the
        # standardized envelope of PROJECT.md, additively).
        out = self.reg.run("dummy_mod", {})
        self.assertEqual(set(out), {"ok", "success", "data", "result", "error"})
        self.assertTrue(out["ok"] and out["success"])
        self.assertIsNone(out["error"] or out["data"] or out["result"])

        # Disable tool and verify rejection
        self.reg.set_enabled("dummy_mod", False)
        with self.assertRaises(tool_registry.ToolRegistryError) as ctx:
            self.reg.run("dummy_mod", {})
        self.assertIn("is disabled", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
