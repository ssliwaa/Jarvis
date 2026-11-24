"""Tests for operator_modules/sqlite_ops.py (Safe SQLite Inspector)."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

import operator_modules.sqlite_ops as sqlite_ops


class TestSqliteOps(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.db_path = self.root / "test_data.db"

        # Create a test database with sample tables and rows
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "CREATE TABLE users ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "username TEXT NOT NULL UNIQUE, "
            "email TEXT, "
            "active INTEGER DEFAULT 1)"
        )
        cur.execute(
            "CREATE TABLE posts ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "user_id INTEGER, "
            "title TEXT NOT NULL, "
            "FOREIGN KEY(user_id) REFERENCES users(id))"
        )
        cur.execute("CREATE INDEX idx_posts_user ON posts(user_id)")
        cur.execute("CREATE VIEW active_users AS SELECT id, username FROM users WHERE active = 1")

        # Insert 10 sample users
        for i in range(1, 11):
            cur.execute("INSERT INTO users (username, email) VALUES (?, ?)", (f"user_{i}", f"user_{i}@example.com"))
        cur.execute("INSERT INTO posts (user_id, title) VALUES (1, 'First Post')")
        conn.commit()
        conn.close()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_tool_declaration_contract(self):
        tool = sqlite_ops.TOOL
        self.assertEqual(tool["name"], "sqlite_ops")
        self.assertFalse(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        self.assertEqual(tool["input_schema"]["type"], "object")
        self.assertFalse(tool["input_schema"]["additionalProperties"])

    def test_list_tables(self):
        res = sqlite_ops.sqlite_ops({"action": "list_tables", "path": str(self.db_path)})
        self.assertTrue(res["ok"])
        tables = res["result"]["tables"]
        names = {t["name"] for t in tables}
        self.assertIn("users", names)
        self.assertIn("posts", names)
        self.assertIn("active_users", names)
        self.assertGreaterEqual(res["result"]["count"], 3)

    def test_describe_table(self):
        res = sqlite_ops.sqlite_ops({"action": "describe_table", "path": str(self.db_path), "table": "users"})
        self.assertTrue(res["ok"])
        cols = {c["name"]: c for c in res["result"]["columns"]}
        self.assertIn("username", cols)
        self.assertEqual(cols["username"]["type"], "TEXT")
        self.assertTrue(cols["username"]["notnull"])
        self.assertTrue(cols["id"]["pk"])

        # Check posts foreign keys and indexes
        post_res = sqlite_ops.sqlite_ops({"action": "describe_table", "path": str(self.db_path), "table": "posts"})
        self.assertTrue(post_res["ok"])
        fks = post_res["result"]["foreign_keys"]
        self.assertEqual(len(fks), 1)
        self.assertEqual(fks[0]["table"], "users")
        self.assertEqual(fks[0]["from"], "user_id")

    def test_describe_nonexistent_table(self):
        res = sqlite_ops.sqlite_ops({"action": "describe_table", "path": str(self.db_path), "table": "nonexistent"})
        self.assertFalse(res["ok"])
        self.assertIn("not found", res["error"])

    def test_query_select_rows(self):
        res = sqlite_ops.sqlite_ops({
            "action": "query",
            "path": str(self.db_path),
            "query": "SELECT id, username FROM users ORDER BY id ASC",
            "limit": 5,
        })
        self.assertTrue(res["ok"])
        rows = res["result"]["rows"]
        self.assertEqual(len(rows), 5)
        self.assertEqual(rows[0]["username"], "user_1")
        self.assertTrue(res["result"]["truncated"])
        self.assertEqual(res["result"]["columns"], ["id", "username"])

    def test_query_parameterized(self):
        res = sqlite_ops.sqlite_ops({
            "action": "query",
            "path": str(self.db_path),
            "query": "SELECT username FROM users WHERE username = ?",
            "params": ["user_3"],
        })
        self.assertTrue(res["ok"])
        self.assertEqual(len(res["result"]["rows"]), 1)
        self.assertEqual(res["result"]["rows"][0]["username"], "user_3")

    def test_explain_query_plan(self):
        res = sqlite_ops.sqlite_ops({
            "action": "explain",
            "path": str(self.db_path),
            "query": "SELECT * FROM posts WHERE user_id = 1",
        })
        self.assertTrue(res["ok"])
        self.assertIn("plan", res["result"])
        self.assertGreater(len(res["result"]["plan"]), 0)

    def test_rejection_of_write_and_ddl_statements(self):
        dangerous_queries = [
            "DROP TABLE users",
            "INSERT INTO users (username) VALUES ('hacker')",
            "UPDATE users SET active = 0",
            "DELETE FROM users WHERE id = 1",
            "ALTER TABLE users ADD COLUMN compromised TEXT",
            "CREATE TABLE evil (x INT)",
            "REPLACE INTO users (id, username) VALUES (1, 'replaced')",
            "VACUUM",
            "ATTACH DATABASE '/etc/shadow' AS evil",
            "DETACH DATABASE evil",
        ]
        for query in dangerous_queries:
            res = sqlite_ops.sqlite_ops({
                "action": "query",
                "path": str(self.db_path),
                "query": query,
            })
            self.assertFalse(res["ok"], f"Expected query {query!r} to be rejected, but got: {res}")
            self.assertIn("forbidden", res["error"].lower())

    def test_rejection_of_multiple_statements(self):
        multi_query = "SELECT * FROM users; SELECT * FROM posts"
        res = sqlite_ops.sqlite_ops({
            "action": "query",
            "path": str(self.db_path),
            "query": multi_query,
        })
        self.assertFalse(res["ok"])
        self.assertIn("multiple", res["error"].lower())

    def test_rejection_of_sensitive_paths(self):
        sensitive_target = Path.home() / ".ssh" / "id_rsa"
        res = sqlite_ops.sqlite_ops({
            "action": "list_tables",
            "path": str(sensitive_target),
        })
        self.assertFalse(res["ok"])
        self.assertTrue(
            "refused" in res["error"].lower()
            or "does not exist" in res["error"].lower()
            or "sensitive" in res["error"].lower()
        )

    def test_nonexistent_database_path(self):
        res = sqlite_ops.sqlite_ops({
            "action": "list_tables",
            "path": str(self.root / "does_not_exist.db"),
        })
        self.assertFalse(res["ok"])
        self.assertIn("does not exist", res["error"].lower())


if __name__ == "__main__":
    unittest.main()
