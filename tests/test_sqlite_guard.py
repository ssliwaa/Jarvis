"""sqlite_guard: corruption detection, sidecar quarantine and private permissions.

This suite pins the SQLite quarantine helpers: is_corruption() matching by
token scan of the exception text ('not a database', 'malformed', 'corrupt',
'encrypted', 'eof', case-insensitively, and therefore catching even plain
ValueErrors mentioning 'malformed' while leaving write-lock contention
'database is locked' untouched), quarantine_database() moving the main file
plus its -wal/-shm/-journal sidecars to timestamped .corrupt-<pid>-<ns>
names while leaving unrelated neighbours alone and tolerating a missing
source with a best-effort return value, secure_database() applying 0600 to
the database and whichever sidecars exist plus 0700 for the parent,
secure_state_root() creating the root owner-only and re-hardening the
private subdirectories and *.db* files (with directories outside the
private list left as they are), and connect_private() documenting that
sqlite3.connect is lazy — a garbage file connects fine and only fails at
first use — while the actual corruption path (a DatabaseError raised at
connect time) quarantines the corrupt original, recreates a fresh usable
database at the same path and leaves the original bytes in the .corrupt
copy, and non-corruption errors like lock contention are re-raised.

All assertions were pinned empirically before writing.
"""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import sqlite_guard


class TempBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="sgt_")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)


class TestIsCorruption(unittest.TestCase):
    def test_token_matrix(self):
        corrupted = (
            sqlite3.DatabaseError("file is not a database"),
            sqlite3.OperationalError("database disk image is malformed"),
            sqlite3.OperationalError("file is encrypted or is not a database"),
            sqlite3.DatabaseError("unexpected eof whilst reading"),
            ValueError("something about MALFORMED input"),
        )
        for error in corrupted:
            self.assertTrue(sqlite_guard.is_corruption(error), str(error))
        # lock contention is NOT corruption — retry is the right response
        locked = sqlite3.OperationalError("database is locked")
        self.assertFalse(sqlite_guard.is_corruption(locked))
        self.assertFalse(sqlite_guard.is_corruption(
            sqlite3.DatabaseError("no such table: users")))

    def test_matching_is_case_insensitive(self):
        self.assertTrue(sqlite_guard.is_corruption(
            sqlite3.DatabaseError("FILE IS NOT A DATABASE")))


class TestQuarantine(TempBase):
    def test_moves_database_and_all_sidecars_together(self):
        db = self.tmp / "app.db"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE t(x)")
        conn.commit()
        conn.close()
        for suffix, content in (("-wal", b"W"), ("-shm", b"S"), ("-journal", b"J")):
            (self.tmp / f"app.db{suffix}").write_bytes(content)
        (self.tmp / "app.db-other").write_bytes(b"X")  # not a managed sidecar

        corrupt = sqlite_guard.quarantine_database(db, "test")
        self.assertTrue(".corrupt-" in corrupt.name)
        self.assertTrue(corrupt.exists())                    # original bytes moved here
        self.assertFalse(db.exists())                        # gone from the live path
        for suffix in ("-wal", "-shm", "-journal"):
            self.assertTrue(corrupt.with_name(corrupt.name + suffix).exists())
        self.assertTrue((self.tmp / "app.db-other").exists())  # neighbours untouched

    def test_missing_database_is_tolerated(self):
        missing = self.tmp / "ghost.db"
        returned = sqlite_guard.quarantine_database(missing)
        self.assertTrue(returned.name.startswith("ghost.db.corrupt-"))
        self.assertFalse(returned.exists())  # rename failed, best-effort


class TestSecure(TempBase):
    def test_secure_database_locks_files_and_parent(self):
        db = self.tmp / "private.db"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE t(x)")
        conn.commit()
        conn.close()
        (self.tmp / "private.db-wal").write_bytes(b"W")
        sqlite_guard.secure_database(db)
        self.assertEqual(db.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.tmp / "private.db-wal").stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.tmp.stat().st_mode & 0o777, 0o700)

    def test_secure_state_root_hardens_private_dirs_and_db_files(self):
        root = self.tmp / "jroot"
        for name in ("backups", "documents", "selfmod"):
            (root / name).mkdir(parents=True)
        (root / "public").mkdir()          # not in the private list
        (root / "x.db").write_bytes(b"db")
        (root / "x.db-wal").write_bytes(b"wal")
        (root / "plain.txt").write_bytes(b"text")

        sqlite_guard.secure_state_root(root)
        self.assertEqual(root.stat().st_mode & 0o777, 0o700)
        for name in ("backups", "documents", "selfmod"):
            self.assertEqual((root / name).stat().st_mode & 0o777, 0o700)
        self.assertNotEqual((root / "public").stat().st_mode & 0o777, 0o700)
        self.assertEqual((root / "x.db").stat().st_mode & 0o777, 0o600)
        self.assertEqual((root / "x.db-wal").stat().st_mode & 0o777, 0o600)
        self.assertNotEqual((root / "plain.txt").stat().st_mode & 0o777, 0o600)
        # missing private dirs are simply skipped, not created
        self.assertFalse((root / "plans").exists())


class TestConnectPrivate(TempBase):
    def test_lazy_connect_on_garbage_and_0600(self):
        garbage = self.tmp / "garbage.db"
        garbage.write_bytes(b"garbage-garbage")
        connection = sqlite_guard.connect_private(garbage)
        # sqlite3.connect is lazy: a corrupt file opens fine and only the
        # first statement use fails — documented limitation of the guard
        with self.assertRaises(sqlite3.DatabaseError):
            connection.execute("CREATE TABLE t(x)")
        connection.close()
        self.assertEqual(garbage.stat().st_mode & 0o777, 0o600)
        self.assertFalse(any(".corrupt-" in p.name for p in self.tmp.iterdir()))

    def test_corruption_at_connect_quarantines_and_recreates(self):
        target = self.tmp / "looks_bad.db"
        target.write_bytes(b"pretend corrupt payload")
        real_connect = sqlite3.connect
        calls = []

        def flaky_connect(*args, **kwargs):
            calls.append(1)
            if len(calls) == 1:
                raise sqlite3.DatabaseError("file is not a database")
            return real_connect(*args, **kwargs)

        with patch.object(sqlite3, "connect", flaky_connect):
            connection = sqlite_guard.connect_private(target)
        self.assertEqual(len(calls), 2)                      # quarantined, retried
        self.assertTrue(target.exists())                     # fresh db recreated
        connection.execute("CREATE TABLE q(x)")              # immediately usable
        connection.close()
        quarantined = [p for p in self.tmp.iterdir() if ".corrupt-" in p.name]
        self.assertEqual(len(quarantined), 1)
        self.assertTrue(quarantined[0].name.startswith("looks_bad.db.corrupt-"))
        self.assertEqual(quarantined[0].read_bytes(), b"pretend corrupt payload")
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_non_corruption_errors_are_reraised(self):
        locked = sqlite3.OperationalError("database is locked")
        with patch.object(sqlite3, "connect", side_effect=locked):
            with self.assertRaises(sqlite3.OperationalError) as ctx:
                sqlite_guard.connect_private(self.tmp / "busy.db")
        self.assertEqual(str(ctx.exception), "database is locked")
        # nothing quarantined for a mere lock contention
        self.assertFalse(any(".corrupt-" in p.name for p in self.tmp.iterdir()))


if __name__ == "__main__":
    unittest.main()
