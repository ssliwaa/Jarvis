"""SQLite online backups and artifact retention."""
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

import maintenance


class MaintenanceTests(unittest.TestCase):
    def test_backup_copies_a_live_wal_database(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            source = state / "sessions.db"
            connection = sqlite3.connect(str(source))
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("CREATE TABLE t(x)")
            connection.execute("INSERT INTO t VALUES (1)")
            connection.commit()
            result = maintenance.backup_databases(state, keep=3)
            connection.close()
            self.assertTrue(result["ok"])
            backup = next(Path(result["dir"]).glob("sessions.db"))
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
            check = sqlite3.connect(str(backup))
            self.assertEqual(check.execute("SELECT x FROM t").fetchone()[0], 1)
            check.close()

    def test_old_artifact_entries_are_pruned_when_enabled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "artifacts" / "evidence"
            evidence.mkdir(parents=True)
            for index in range(5):
                path = evidence / f"job-{index}"
                path.mkdir()
                old = time.time() - 30 * 86400
                path.touch()
                os.utime(path, (old, old))
            result = maintenance.prune_artifacts(root, keep=1, days=7)
            self.assertGreaterEqual(result["removed"], 1)
            self.assertLessEqual(len(list(evidence.iterdir())), 2)

    def test_tool_storage_prunes_old_files_but_protects_undo_stack_and_db_backups(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            backups = state / "backups"
            backups.mkdir(parents=True)
            db_dir = backups / "db-20260101-000000"
            db_dir.mkdir()
            old = time.time() - 30 * 86400
            os.utime(db_dir, (old, old))
            protected_backup = backups / "100-protected-note.md"
            protected_backup.write_text("keep me", encoding="utf-8")
            os.utime(protected_backup, (old, old))
            (state / "undo.json").write_text(
                json.dumps([{"kind": "write", "backup": str(protected_backup)}]),
                encoding="utf-8",
            )
            for index in range(5):
                item = backups / f"{index}-old.txt"
                item.write_text("old", encoding="utf-8")
                os.utime(item, (old, old))
            result = maintenance.prune_tool_storage(state, keep=1, days=7)
            self.assertGreaterEqual(result["removed"], 3)
            self.assertTrue(db_dir.is_dir())
            self.assertTrue(protected_backup.is_file())


if __name__ == "__main__":
    unittest.main()
