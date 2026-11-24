"""Adversarial Stress, Concurrency, and Lifecycle Challenge Test Suite.

Author: empirical challenger (challenger_jarvis_2)
Purpose: Stress-test dynamic discovery lifecycle, registry reload fault tolerance,
         concurrent execution of sqlite_ops and code_ast, resource leaks (FDs,
         connections, subprocesses), and extensive edge case matrices.
"""

from __future__ import annotations

import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import operator_modules.code_ast as code_ast
import operator_modules.git_ops as git_ops
import operator_modules.sqlite_ops as sqlite_ops
import tool_registry


def _get_open_fd_count() -> int:
    """Return count of open file descriptors for the current process on Linux."""
    try:
        fd_dir = Path("/proc/self/fd")
        if fd_dir.exists():
            return len(list(fd_dir.iterdir()))
    except (OSError, PermissionError):
        pass
    return -1


class TestLifecycleAndReload(unittest.TestCase):
    """Stress-test dynamic discovery, state persistence, and reload fault tolerance."""

    def test_dynamic_discovery_without_modifying_core(self):
        """ToolRegistry dynamically discovers sqlite_ops, git_ops, and code_ast."""
        reg = tool_registry.ToolRegistry()
        self.assertTrue(reg.has("sqlite_ops"), "sqlite_ops not found in registry")
        self.assertTrue(reg.has("git_ops"), "git_ops not found in registry")
        self.assertTrue(reg.has("code_ast"), "code_ast not found in registry")

        # Verify contracts and schemas
        sqlite_tool = reg.get("sqlite_ops")
        self.assertIsNotNone(sqlite_tool)
        self.assertFalse(sqlite_tool.approval)
        self.assertEqual(sqlite_tool.schema["type"], "object")

        git_tool = reg.get("git_ops")
        self.assertIsNotNone(git_tool)
        self.assertTrue(git_tool.approval)

        code_tool = reg.get("code_ast")
        self.assertIsNotNone(code_tool)
        self.assertFalse(code_tool.approval)

    def test_enable_disable_lifecycle_and_state_persistence(self):
        """Verify disabling/re-enabling modules persists across registry instances."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "operator-modules.json"
            reg1 = tool_registry.ToolRegistry(state_path=state_file)

            # Initially enabled
            self.assertIn("sqlite_ops", [t["name"] for t in reg1.declarations()])

            # Disable sqlite_ops
            reg1.set_enabled("sqlite_ops", False)
            self.assertNotIn("sqlite_ops", [t["name"] for t in reg1.declarations()])
            with self.assertRaises(tool_registry.ToolRegistryError) as ctx:
                reg1.run("sqlite_ops", {"path": "dummy.db"})
            self.assertIn("disabled", str(ctx.exception).lower())

            # Verify persisted file
            self.assertTrue(state_file.exists())
            content = state_file.read_text(encoding="utf-8")
            self.assertIn("sqlite_ops", content)

            # Re-instantiate ToolRegistry to simulate server restart
            reg2 = tool_registry.ToolRegistry(state_path=state_file)
            self.assertNotIn("sqlite_ops", [t["name"] for t in reg2.declarations()])
            with self.assertRaises(tool_registry.ToolRegistryError):
                reg2.run("sqlite_ops", {"path": "dummy.db"})

            # Re-enable sqlite_ops
            reg2.set_enabled("sqlite_ops", True)
            self.assertIn("sqlite_ops", [t["name"] for t in reg2.declarations()])

            # Verify persistence after re-enabling
            reg3 = tool_registry.ToolRegistry(state_path=state_file)
            self.assertIn("sqlite_ops", [t["name"] for t in reg3.declarations()])

    def test_reload_fault_tolerance_with_corrupted_and_hostile_modules(self):
        """Verify reload() survives syntax errors, import crashes, SystemExit, and bad schemas."""
        with tempfile.TemporaryDirectory() as tmpdir:
            modules_dir = Path(tmpdir) / "operator_modules"
            modules_dir.mkdir(parents=True, exist_ok=True)
            state_file = Path(tmpdir) / "state.json"

            # 1. Valid module
            (modules_dir / "valid_tool.py").write_text(
                'def run(args, context=None):\n'
                '    return {"ok": True, "val": args.get("val", 0) * 2}\n'
                'TOOL = {"name": "valid_tool", "description": "Valid Tool",\n'
                '        "input_schema": {"type": "object", "properties": {"val": {"type": "integer"}}},\n'
                '        "handler": run, "approval": False}\n',
                encoding="utf-8",
            )

            # 2. Module with SyntaxError
            (modules_dir / "corrupted_syntax.py").write_text(
                "def bad_syntax(::: this is invalid syntax :::",
                encoding="utf-8",
            )

            # 3. Module with runtime exception at import (ZeroDivisionError)
            (modules_dir / "zero_div.py").write_text(
                "X = 1 / 0\n",
                encoding="utf-8",
            )

            # 4. Module attempting SystemExit at import
            (modules_dir / "system_exit.py").write_text(
                "import sys\nsys.exit(99)\n",
                encoding="utf-8",
            )

            # 5. Module with missing TOOL dict
            (modules_dir / "missing_tool.py").write_text(
                "def foo(): pass\n",
                encoding="utf-8",
            )

            # 6. Module with invalid tool name (illegal characters)
            (modules_dir / "bad_name.py").write_text(
                'def run(args): return {"ok": True}\n'
                'TOOL = {"name": "invalid-name-with-dashes", "description": "Bad name",\n'
                '        "input_schema": {"type": "object"}, "handler": run}\n',
                encoding="utf-8",
            )

            # 7. Module with uncallable handler
            (modules_dir / "bad_handler.py").write_text(
                'TOOL = {"name": "bad_handler", "description": "Uncallable handler",\n'
                '        "input_schema": {"type": "object"}, "handler": "not_callable"}\n',
                encoding="utf-8",
            )

            # 8. Copy real sqlite_ops, git_ops, and code_ast into this directory
            real_modules = Path(__file__).resolve().parents[1] / "operator_modules"
            shutil.copy(real_modules / "sqlite_ops.py", modules_dir / "sqlite_ops.py")
            shutil.copy(real_modules / "git_ops.py", modules_dir / "git_ops.py")
            shutil.copy(real_modules / "code_ast.py", modules_dir / "code_ast.py")

            # Initialize registry and reload
            reg = tool_registry.ToolRegistry(directory=modules_dir, state_path=state_file)

            # Verify reload survived and collected errors for bad modules
            self.assertGreaterEqual(len(reg.errors), 6)
            self.assertTrue(any("corrupted_syntax.py" in e for e in reg.errors))
            self.assertTrue(any("zero_div.py" in e for e in reg.errors))
            self.assertTrue(any("system_exit.py" in e for e in reg.errors))
            self.assertTrue(any("missing_tool.py" in e for e in reg.errors))
            self.assertTrue(any("bad_name.py" in e for e in reg.errors))
            self.assertTrue(any("bad_handler.py" in e for e in reg.errors))

            # Verify all legitimate modules loaded and work properly despite the broken ones
            self.assertTrue(reg.has("valid_tool"))
            self.assertTrue(reg.has("sqlite_ops"))
            self.assertTrue(reg.has("git_ops"))
            self.assertTrue(reg.has("code_ast"))

            res = reg.run("valid_tool", {"val": 21})
            # Registry.run completes every handler output to the 5-key
            # envelope (PROJECT.md); the legacy task keys survive as payload.
            self.assertTrue(res["ok"] and res["success"])
            self.assertIsNone(res["error"])
            self.assertEqual(res["data"], {"val": 42})
            self.assertEqual(res["result"], {"val": 42})


class TestConcurrencyAndResourceLeaks(unittest.TestCase):
    """Stress-test concurrent read execution on WAL SQLite, concurrent AST parsing, and resource cleanup."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)

        # Setup SQLite database with WAL mode and 500 rows
        self.db_path = self.root / "concurrency_wal.db"
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, category TEXT, payload TEXT, num REAL)")
        categories = ["alpha", "beta", "gamma", "delta", "epsilon"]
        conn.executemany(
            "INSERT INTO records (category, payload, num) VALUES (?, ?, ?)",
            [(categories[i % 5], f"data_{i}_{'X' * 50}", i * 1.5) for i in range(500)],
        )
        conn.commit()
        conn.close()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_concurrent_sqlite_ops_reads_with_wal_and_background_writer(self):
        """Execute 40 concurrent threads performing 1,000 queries while a writer writes to WAL."""
        stop_writer = threading.Event()
        writer_errors: list[Exception] = []

        def writer_loop():
            # Writer thread writes to the database in WAL mode
            try:
                w_conn = sqlite3.connect(self.db_path, timeout=10.0)
                counter = 10000
                while not stop_writer.is_set():
                    w_conn.execute(
                        "INSERT INTO records (category, payload, num) VALUES ('bg', ?, ?)",
                        (f"bg_write_{counter}", float(counter)),
                    )
                    w_conn.commit()
                    counter += 1
                    time.sleep(0.005)
                w_conn.close()
            except Exception as exc:  # noqa: BLE001
                writer_errors.append(exc)

        writer_thread = threading.Thread(target=writer_loop, daemon=True)
        writer_thread.start()

        def reader_task(task_id: int):
            # Mix actions: list_tables, describe_table, query, explain
            actions = ["list_tables", "describe_table", "query", "explain"]
            action = actions[task_id % len(actions)]

            if action == "list_tables":
                return sqlite_ops.sqlite_ops({"action": "list_tables", "path": str(self.db_path)})
            elif action == "describe_table":
                return sqlite_ops.sqlite_ops({
                    "action": "describe_table",
                    "path": str(self.db_path),
                    "table": "records",
                })
            elif action == "query":
                return sqlite_ops.sqlite_ops({
                    "action": "query",
                    "path": str(self.db_path),
                    "query": "SELECT category, count(*), avg(num) FROM records GROUP BY category ORDER BY avg(num) DESC",
                    "limit": 50,
                })
            else:
                return sqlite_ops.sqlite_ops({
                    "action": "explain",
                    "path": str(self.db_path),
                    "query": "SELECT * FROM records WHERE category = 'alpha'",
                })

        num_queries = 200
        concurrency = 20
        results = []

        try:
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                futures = [executor.submit(reader_task, i) for i in range(num_queries)]
                for future in as_completed(futures):
                    results.append(future.result())
        finally:
            stop_writer.set()
            writer_thread.join(timeout=2.0)

        self.assertEqual(len(writer_errors), 0, f"Background writer encountered errors: {writer_errors}")
        self.assertEqual(len(results), num_queries)
        failed_results = [r for r in results if not r.get("ok")]
        self.assertEqual(len(failed_results), 0, f"Concurrent sqlite_ops failed on {len(failed_results)} queries: {failed_results[:3]}")

    def test_concurrent_code_ast_parsing(self):
        """Execute 20 concurrent threads parsing code and outlining symbols."""
        complex_code = """
import os
import sys
from typing import Generic, TypeVar, Optional, List

T = TypeVar('T')

class Container(Generic[T]):
    \"\"\"Generic container.\"\"\"
    def __init__(self, value: T):
        self.value = value

    @property
    def item(self) -> T:
        return self.value

    async def async_process(self, transform) -> Optional[T]:
        \"\"\"Async transformation.\"\"\"
        if transform:
            return transform(self.value)
        return None

def compute_all(items: List[int]) -> int:
    \"\"\"Compute sum.\"\"\"
    total = 0
    for x in items:
        total += x
    return total
"""

        def parse_task(idx: int):
            action = ["outline", "check_syntax", "inspect_imports"][idx % 3]
            return code_ast.code_ast({"action": action, "code": complex_code})

        num_tasks = 150
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = [executor.submit(parse_task, i) for i in range(num_tasks)]
            results = [f.result() for f in as_completed(futures)]

        self.assertEqual(len(results), num_tasks)
        for r in results:
            self.assertTrue(r["ok"])

    def test_resource_leaks_fd_and_connections(self):
        """Repeatedly run sqlite_ops, code_ast, and git_ops to verify FDs are not leaked."""
        initial_fds = _get_open_fd_count()
        if initial_fds < 0:
            self.skipTest("FD counting via /proc/self/fd not supported on this platform")

        # 1. Stress sqlite_ops queries
        for _ in range(100):
            res = sqlite_ops.sqlite_ops({
                "action": "query",
                "path": str(self.db_path),
                "query": "SELECT id, category FROM records LIMIT 10",
            })
            self.assertTrue(res["ok"])

        # 2. Stress code_ast on file
        test_py = self.root / "probe.py"
        test_py.write_text("class Probe:\n    def ping(self): return 1\n", encoding="utf-8")
        for _ in range(100):
            res = code_ast.code_ast({"action": "outline", "path": str(test_py)})
            self.assertTrue(res["ok"])

        # 3. Check FD count
        final_fds = _get_open_fd_count()
        # FD count should not grow by more than a reasonable tolerance (e.g. 5)
        fd_growth = final_fds - initial_fds
        self.assertLessEqual(fd_growth, 5, f"Open file descriptors leaked! Grew from {initial_fds} to {final_fds} (+{fd_growth})")


class TestEdgeCaseMatrix(unittest.TestCase):
    """Stress-test edge cases in SQLite, Git, and Python AST parsing."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    # --- SQLite Edge Cases ---

    def test_sqlite_completely_empty_file(self):
        """Verify behavior on a 0-byte file (SQLite treats as valid empty DB)."""
        empty_db = self.root / "empty.db"
        empty_db.touch()
        res = sqlite_ops.sqlite_ops({"action": "list_tables", "path": str(empty_db)})
        # SQLite gracefully treats 0-byte file as empty database with 0 tables
        self.assertTrue(res["ok"])
        self.assertEqual(res["result"]["count"], 0)
        self.assertEqual(res["result"]["tables"], [])

    def test_sqlite_corrupted_non_sqlite_file(self):
        """Verify behavior on a file containing corrupted non-SQLite data."""
        bad_db = self.root / "corrupted.db"
        bad_db.write_text("NOT A SQLITE DATABASE", encoding="utf-8")
        res = sqlite_ops.sqlite_ops({"action": "list_tables", "path": str(bad_db)})
        self.assertFalse(res["ok"])
        self.assertIn("file is not a database", res["error"].lower())

    def test_sqlite_empty_database_no_tables(self):
        """Verify behavior on a valid SQLite database with 0 tables."""
        db_path = self.root / "no_tables.db"
        conn = sqlite3.connect(db_path)
        conn.commit()
        conn.close()

        res = sqlite_ops.sqlite_ops({"action": "list_tables", "path": str(db_path)})
        self.assertTrue(res["ok"])
        self.assertEqual(res["result"]["count"], 0)
        self.assertEqual(res["result"]["tables"], [])

    def test_sqlite_table_with_zero_rows(self):
        """Verify querying an empty table."""
        db_path = self.root / "zero_rows.db"
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)")
        conn.commit()
        conn.close()

        res = sqlite_ops.sqlite_ops({
            "action": "query",
            "path": str(db_path),
            "query": "SELECT * FROM items",
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["result"]["row_count"], 0)
        self.assertEqual(res["result"]["rows"], [])
        self.assertEqual(res["result"]["columns"], ["id", "label"])

    def test_sqlite_null_values_and_unicode_data(self):
        """Verify handling of NULL values, empty strings, emojis, and special chars in data."""
        db_path = self.root / "nulls_and_unicode.db"
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE special (id INTEGER PRIMARY KEY, val1 TEXT, val2 REAL, val3 BLOB)")
        conn.execute("INSERT INTO special VALUES (1, NULL, NULL, NULL)")
        conn.execute("INSERT INTO special VALUES (2, '🚀 UTF-8 ĄĘĆ ŻÓŁĆ 🌟', 3.14159, X'01020304')")
        conn.execute("INSERT INTO special VALUES (3, '', 0.0, X'')")
        conn.commit()
        conn.close()

        res = sqlite_ops.sqlite_ops({
            "action": "query",
            "path": str(db_path),
            "query": "SELECT * FROM special ORDER BY id ASC",
        })
        self.assertTrue(res["ok"])
        rows = res["result"]["rows"]
        self.assertEqual(len(rows), 3)

        # Row 1 NULLs
        self.assertIsNone(rows[0]["val1"])
        self.assertIsNone(rows[0]["val2"])
        self.assertIsNone(rows[0]["val3"])

        # Row 2 Unicode
        self.assertEqual(rows[1]["val1"], "🚀 UTF-8 ĄĘĆ ŻÓŁĆ 🌟")
        self.assertAlmostEqual(rows[1]["val2"], 3.14159)

        # Row 3 Empty string
        self.assertEqual(rows[2]["val1"], "")

    def test_sqlite_special_character_and_keyword_column_names(self):
        """Verify columns named with SQL keywords and special characters."""
        db_path = self.root / "weird_cols.db"
        conn = sqlite3.connect(db_path)
        conn.execute('CREATE TABLE weird ("select" TEXT, "from" TEXT, "order by" INTEGER, "col with space" REAL)')
        conn.execute('INSERT INTO weird VALUES (\'val_select\', \'val_from\', 42, 99.9)')
        conn.commit()
        conn.close()

        res = sqlite_ops.sqlite_ops({
            "action": "query",
            "path": str(db_path),
            "query": 'SELECT "select", "from", "order by", "col with space" FROM weird',
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["result"]["row_count"], 1)
        row = res["result"]["rows"][0]
        self.assertEqual(row["select"], "val_select")
        self.assertEqual(row["from"], "val_from")
        self.assertEqual(row["order by"], 42)
        self.assertEqual(row["col with space"], 99.9)

    def test_sqlite_recursive_cte(self):
        """Verify complex WITH RECURSIVE queries execute safely."""
        db_path = self.root / "cte.db"
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE dummy (x INT)")
        conn.commit()
        conn.close()

        cte_query = """
        WITH RECURSIVE cnt(x) AS (
            SELECT 1
            UNION ALL
            SELECT x + 1 FROM cnt WHERE x < 10
        )
        SELECT x, x * x AS square FROM cnt
        """
        res = sqlite_ops.sqlite_ops({"action": "query", "path": str(db_path), "query": cte_query})
        self.assertTrue(res["ok"])
        self.assertEqual(res["result"]["row_count"], 10)
        self.assertEqual(res["result"]["rows"][-1]["square"], 100)

    # --- Git Ops Edge Cases ---

    def test_git_empty_repository_without_commits(self):
        """Verify git_ops behavior on an empty repository without any commits."""
        empty_repo = self.root / "empty_repo"
        empty_repo.mkdir()
        subprocess.run(["git", "init"], cwd=empty_repo, capture_output=True, check=True)

        # 1. status on repo with no commits
        res_status = git_ops.git_ops({"action": "status", "repo_path": str(empty_repo)})
        self.assertTrue(res_status["ok"])
        self.assertTrue(res_status["result"]["clean"])

        # 2. log on repo with no commits (should return clean error, not unhandled crash)
        res_log = git_ops.git_ops({"action": "log", "repo_path": str(empty_repo)})
        self.assertFalse(res_log["ok"])
        self.assertIn("git log failed", res_log["error"])

        # 3. branch list on repo with no commits
        res_branch = git_ops.git_ops({"action": "branch", "branch_action": "list", "repo_path": str(empty_repo)})
        self.assertTrue(res_branch["ok"])
        self.assertEqual(res_branch["result"]["count"], 0)

    def test_git_detached_head_state(self):
        """Verify git_ops status, branch, and log in detached HEAD state."""
        repo = self.root / "detached_repo"
        repo.mkdir()
        subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.name", "Tester"], cwd=repo, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.email", "tester@example.com"], cwd=repo, capture_output=True, check=True)

        # Commit 1
        (repo / "file1.txt").write_text("commit 1", encoding="utf-8")
        subprocess.run(["git", "add", "file1.txt"], cwd=repo, capture_output=True, check=True)
        subprocess.run(["git", "commit", "-m", "First commit"], cwd=repo, capture_output=True, check=True)
        first_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()

        # Commit 2
        (repo / "file2.txt").write_text("commit 2", encoding="utf-8")
        subprocess.run(["git", "add", "file2.txt"], cwd=repo, capture_output=True, check=True)
        subprocess.run(["git", "commit", "-m", "Second commit"], cwd=repo, capture_output=True, check=True)

        # Detach HEAD to first_commit
        subprocess.run(["git", "checkout", first_commit], cwd=repo, capture_output=True, check=True)

        # Verify status handles detached HEAD
        res_status = git_ops.git_ops({"action": "status", "repo_path": str(repo)})
        self.assertTrue(res_status["ok"])
        self.assertTrue(res_status["result"]["clean"])
        self.assertIn("HEAD", res_status["result"]["branch"])

        # Verify branch list handles detached HEAD
        res_branch = git_ops.git_ops({"action": "branch", "branch_action": "list", "repo_path": str(repo)})
        self.assertTrue(res_branch["ok"])
        self.assertGreaterEqual(res_branch["result"]["count"], 1)

        # Verify log shows correct history from detached commit
        res_log = git_ops.git_ops({"action": "log", "repo_path": str(repo)})
        self.assertTrue(res_log["ok"])
        self.assertEqual(res_log["result"]["count"], 1)
        self.assertEqual(res_log["result"]["commits"][0]["hash"], first_commit)

    def test_git_merge_conflict_state(self):
        """Verify git_ops status and diff when repository is in merge conflict state."""
        repo = self.root / "conflict_repo"
        repo.mkdir()
        subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.name", "Tester"], cwd=repo, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.email", "tester@example.com"], cwd=repo, capture_output=True, check=True)

        # Base commit
        doc = repo / "doc.txt"
        doc.write_text("base line\n", encoding="utf-8")
        subprocess.run(["git", "add", "doc.txt"], cwd=repo, capture_output=True, check=True)
        subprocess.run(["git", "commit", "-m", "Base commit"], cwd=repo, capture_output=True, check=True)

        # Branch A
        subprocess.run(["git", "checkout", "-b", "branch-a"], cwd=repo, capture_output=True, check=True)
        doc.write_text("branch A change\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "Change in A"], cwd=repo, capture_output=True, check=True)

        # Branch B
        subprocess.run(["git", "checkout", "master" if subprocess.run(["git", "rev-parse", "--verify", "master"], cwd=repo, capture_output=True).returncode == 0 else "main"], cwd=repo, capture_output=True, check=True)
        subprocess.run(["git", "checkout", "-b", "branch-b"], cwd=repo, capture_output=True, check=True)
        doc.write_text("branch B conflicting change\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "Change in B"], cwd=repo, capture_output=True, check=True)

        # Attempt merge to trigger conflict
        subprocess.run(["git", "merge", "branch-a"], cwd=repo, capture_output=True)

        # Check git_ops status
        res_status = git_ops.git_ops({"action": "status", "repo_path": str(repo)})
        self.assertTrue(res_status["ok"])
        self.assertFalse(res_status["result"]["clean"])
        # Unmerged files appear in unstaged/staged
        unmerged_paths = [f["path"] for f in res_status["result"]["unstaged"]] + [f["path"] for f in res_status["result"]["staged"]]
        self.assertIn("doc.txt", unmerged_paths)

        # Check git_ops diff
        res_diff = git_ops.git_ops({"action": "diff", "repo_path": str(repo)})
        self.assertTrue(res_diff["ok"])
        self.assertIn("<<<<<<<", res_diff["result"]["diff"])

    # --- Python AST Edge Cases ---

    def test_ast_walrus_operator(self):
        """Verify AST outlines and syntax-checks Python walrus operator :=."""
        code = """
def process_data(data):
    if (n := len(data)) > 5:
        return f"Long: {n}"
    return "Short"
"""
        res_syntax = code_ast.code_ast({"action": "check_syntax", "code": code})
        self.assertTrue(res_syntax["ok"])
        self.assertTrue(res_syntax["result"]["valid"])

        res_outline = code_ast.code_ast({"action": "outline", "code": code})
        self.assertTrue(res_outline["ok"])
        self.assertEqual(len(res_outline["result"]["functions"]), 1)
        self.assertEqual(res_outline["result"]["functions"][0]["name"], "process_data")

    def test_ast_match_case_pattern_matching(self):
        """Verify AST parsing of PEP 634 match-case statements."""
        code = """
def route_event(event):
    match event:
        case {"type": "click", "x": x, "y": y}:
            return f"Clicked at {x},{y}"
        case {"type": "keypress", "key": key}:
            return f"Key {key}"
        case _:
            return "Unknown"
"""
        res_syntax = code_ast.code_ast({"action": "check_syntax", "code": code})
        self.assertTrue(res_syntax["ok"])
        self.assertTrue(res_syntax["result"]["valid"])

        res_outline = code_ast.code_ast({"action": "outline", "code": code})
        self.assertTrue(res_outline["ok"])
        self.assertEqual(len(res_outline["result"]["functions"]), 1)
        self.assertEqual(res_outline["result"]["functions"][0]["name"], "route_event")

    def test_ast_pep695_type_parameters(self):
        """Verify AST parsing of PEP 695 type parameter syntax (Python 3.12+)."""
        code = """
type Coordinate[T] = tuple[T, T]

class GenericStack[T]:
    \"\"\"A stack of T items.\"\"\"
    def __init__(self):
        self._items: list[T] = []

    def push(self, item: T) -> None:
        self._items.append(item)

def identity_func[T](val: T) -> T:
    return val
"""
        res_syntax = code_ast.code_ast({"action": "check_syntax", "code": code})
        self.assertTrue(res_syntax["ok"])
        self.assertTrue(res_syntax["result"]["valid"])

        res_outline = code_ast.code_ast({"action": "outline", "code": code})
        self.assertTrue(res_outline["ok"])
        self.assertEqual(len(res_outline["result"]["classes"]), 1)
        self.assertEqual(res_outline["result"]["classes"][0]["name"], "GenericStack")
        self.assertEqual(res_outline["result"]["classes"][0]["method_count"], 2)
        self.assertEqual(len(res_outline["result"]["functions"]), 1)
        self.assertEqual(res_outline["result"]["functions"][0]["name"], "identity_func")

    def test_ast_unicode_identifiers_and_empty_code(self):
        """Verify AST parsing with unicode identifiers and whitespace/empty code."""
        # 1. Unicode function and class names
        code = """
class Żółw:
    def idź_naprzód(self, dystans: int) -> str:
        return f"Idę {dystans}m"
"""
        res = code_ast.code_ast({"action": "outline", "code": code})
        self.assertTrue(res["ok"])
        self.assertEqual(res["result"]["classes"][0]["name"], "Żółw")
        self.assertEqual(res["result"]["classes"][0]["methods"][0]["name"], "idź_naprzód")

        # 2. Empty code string
        empty_res = code_ast.code_ast({"action": "outline", "code": ""})
        self.assertTrue(empty_res["ok"])
        self.assertEqual(empty_res["result"]["class_count"], 0)
        self.assertEqual(empty_res["result"]["function_count"], 0)

    def test_sqlite_params_and_explain_missing_table(self):
        """Verify explain on missing table and complex parameter binding."""
        db_path = self.root / "params.db"
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE types_test (id INT, f REAL, s TEXT, b BLOB, n TEXT)")
        conn.execute("INSERT INTO types_test VALUES (1, 2.5, 'text', X'FF00AA', NULL)")
        conn.commit()
        conn.close()

        # Query with mixed params
        res = sqlite_ops.sqlite_ops({
            "action": "query",
            "path": str(db_path),
            "query": "SELECT * FROM types_test WHERE id = ? AND f > ? AND s = ?",
            "params": [1, 2.0, "text"],
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["result"]["row_count"], 1)

        # Explain on nonexistent table
        res_exp = sqlite_ops.sqlite_ops({
            "action": "explain",
            "path": str(db_path),
            "query": "SELECT * FROM missing_table_xyz",
        })
        self.assertFalse(res_exp["ok"])
        self.assertIn("no such table", res_exp["error"].lower())

    def test_git_empty_files_and_missing_diff_path(self):
        """Verify git_ops handles commit with no changes and diff with non-existent path."""
        repo = self.root / "edge_repo"
        repo.mkdir()
        subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.name", "Tester"], cwd=repo, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.email", "tester@example.com"], cwd=repo, capture_output=True, check=True)

        (repo / "file.txt").write_text("hello", encoding="utf-8")
        subprocess.run(["git", "add", "file.txt"], cwd=repo, capture_output=True, check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo, capture_output=True, check=True)

        # Commit with no staged changes
        res_commit = git_ops.git_ops({
            "action": "commit",
            "repo_path": str(repo),
            "message": "Empty commit attempt",
            "files": [],
        })
        self.assertFalse(res_commit["ok"])
        self.assertIn("no changes staged", res_commit["error"].lower())

        # Diff on non-existent file
        res_diff = git_ops.git_ops({
            "action": "diff",
            "repo_path": str(repo),
            "path": "does_not_exist.txt",
        })
        self.assertTrue(res_diff["ok"])
        self.assertEqual(res_diff["result"]["diff"], "")

    def test_ast_complex_syntax_constructs(self):
        """Verify AST outlines nested functions, lambdas, decorators with calls, and relative imports."""
        code = """
\"\"\"Complex module.\"\"\"
from . import local_mod
from ..parent.pkg import helper as h
from typing import Callable

X = Y = Z = 42

@router.get("/items", tags=["api"])
@auth.require("admin", level=2)
async def api_handler(req: dict) -> dict:
    \"\"\"Handler doc.\"\"\"
    compute = lambda a, b: a + b
    def inner_helper(val):
        return val * 2
    return {"res": inner_helper(compute(1, 2))}
"""
        res = code_ast.code_ast({"action": "outline", "code": code})
        self.assertTrue(res["ok"])
        result = res["result"]
        self.assertEqual(result["function_count"], 1)
        self.assertIn("X", result["top_level_vars"])
        self.assertIn("Y", result["top_level_vars"])
        self.assertIn("Z", result["top_level_vars"])

        func = result["functions"][0]
        self.assertEqual(func["name"], "api_handler")
        self.assertTrue(func["is_async"])
        self.assertEqual(len(func["decorators"]), 2)
        self.assertIn("@router.get(...)", func["decorators"][0])
        self.assertIn("@auth.require(...)", func["decorators"][1])

        # Imports inspection
        res_imp = code_ast.code_ast({"action": "inspect_imports", "code": code})
        self.assertTrue(res_imp["ok"])
        imp_types = {imp["type"] for imp in res_imp["result"]["imports"]}
        self.assertIn("from_import", imp_types)


if __name__ == "__main__":
    unittest.main()

