"""Automated test suite for undo_center.py (persistent undo stack).

Tests push/status bookkeeping (max depth, newest-first entry order),
write undo (backup restore, removal of freshly-created files, refusal
when no backup exists), delete undo (trash move-back, missing trash),
entry re-validation (allowed-roots perimeter, sensitive targets,
storage-root containment, symlink refusal), corrupt stack quarantine,
clear, and error cases. 100% isolated: every test constructs
UndoCenter with explicit paths inside its own TemporaryDirectory; no
global ~/.jarvis-tools state is touched.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import undo_center as uc


class UndoTestBase(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        td = Path(self._td.name)
        self.td = td
        self.center = uc.UndoCenter(path=td / "state" / "undo.json",
                                    backups=td / "backups",
                                    trash=td / "trash")

    def tearDown(self):
        self._td.cleanup()

    def _file(self, rel: str, content: str) -> Path:
        p = self.td / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p


class TestPushAndStatus(UndoTestBase):
    """push/status bookkeeping and MAX_DEPTH trimming."""

    def test_push_returns_row_and_status_counts(self):
        target = self._file("work/a.txt", "x")
        row = self.center.push("write", str(target),
                               backup=None, existed=True,
                               label="edit a")
        self.assertEqual(row["kind"], "write")
        self.assertEqual(row["path"], str(target))
        self.assertEqual(row["label"], "edit a")
        self.assertIn("at", row)
        status = self.center.status()
        self.assertEqual(status["count"], 1)
        self.assertTrue(status["can_undo"])
        self.assertEqual(status["entries"][0]["label"], "edit a")

    def test_status_newest_first(self):
        t1 = self._file("work/one.txt", "1")
        t2 = self._file("work/two.txt", "2")
        self.center.push("write", str(t1), existed=True, label="first")
        self.center.push("write", str(t2), existed=True, label="second")
        entries = self.center.status()["entries"]
        self.assertEqual([e["label"] for e in entries],
                         ["second", "first"])

    def test_max_depth_trims_oldest(self):
        target = self._file("work/bulk.txt", "x")
        for i in range(25):
            self.center.push("write", str(target), existed=True,
                             label=f"step-{i}")
        status = self.center.status()
        # The stack file itself is trimmed to MAX_DEPTH on every write,
        # so both count and entries cap at 20 (oldest steps dropped).
        self.assertEqual(status["count"], uc.MAX_DEPTH)
        self.assertEqual(len(status["entries"]), uc.MAX_DEPTH)
        self.assertEqual(status["entries"][0]["label"], "step-24")
        self.assertEqual(status["entries"][-1]["label"], "step-5")

    def test_label_is_truncated(self):
        target = self._file("work/label.txt", "x")
        row = self.center.push("write", str(target), existed=True,
                               label="z" * 300)
        self.assertEqual(len(row["label"]), 200)

    def test_unsupported_kind_rejected(self):
        with self.assertRaises(uc.UndoError) as ctx:
            self.center.push("move", "/tmp/x", existed=True)
        self.assertIn("Unsupported undo kind", str(ctx.exception))


class TestUndoWrite(UndoTestBase):
    """uno_last for write entries: restore / remove / refuse."""

    def test_write_undo_restores_backup_content(self):
        target = self._file("work/doc.txt", "new content")
        backup = self._file("backups/doc.bak", "old content")
        self.center.push("write", str(target), backup=str(backup),
                         existed=True, label="overwrite doc")
        result = self.center.undo_last()
        self.assertTrue(result["ok"])
        self.assertEqual(result["undone"]["kind"], "write")
        self.assertEqual(result["remaining"], 0)
        self.assertEqual(target.read_text(encoding="utf-8"),
                         "old content")

    def test_write_undo_removes_created_file(self):
        target = self._file("work/created.txt", "fresh")
        # No backup: the file did not exist before the write
        self.center.push("write", str(target), existed=False)
        result = self.center.undo_last()
        self.assertTrue(result["ok"])
        self.assertFalse(target.exists())

    def test_write_without_backup_and_existed_refuses(self):
        target = self._file("work/precious.txt", "data")
        self.center.push("write", str(target), existed=True)
        with self.assertRaises(uc.UndoError) as ctx:
            self.center.undo_last()
        self.assertIn("no backup", str(ctx.exception))

    def test_undo_on_empty_stack_raises(self):
        with self.assertRaises(uc.UndoError) as ctx:
            self.center.undo_last()
        self.assertIn("nothing to undo", str(ctx.exception))


class TestUndoDelete(UndoTestBase):
    """undo_last for delete entries: trash move-back."""

    def test_delete_undo_moves_trash_back(self):
        target = self.td / "work" / "victim.txt"   # deleted earlier
        trash = self._file("trash/victim.txt", "rescued data")
        self.center.push("delete", str(target), trash=str(trash),
                         existed=True, label="rm victim")
        result = self.center.undo_last()
        self.assertTrue(result["ok"])
        self.assertTrue(target.exists())
        self.assertFalse(trash.exists())
        self.assertEqual(target.read_text(encoding="utf-8"),
                         "rescued data")

    def test_delete_with_missing_trash_refuses(self):
        target = self.td / "work" / "vanished.txt"
        self.center.push("delete", str(target),
                         trash=str(self.td / "trash" / "missing.txt"),
                         existed=True)
        with self.assertRaises(uc.UndoError) as ctx:
            self.center.undo_last()
        self.assertIn("trash copy is missing", str(ctx.exception))


class TestEntryRevalidation(UndoTestBase):
    """Stack entries are model-writable: every path gets revalidated."""

    def test_entry_path_outside_allowed_roots_refused(self):
        # Craft a hostile stack file directly (as a model could)
        stack = self.td / "state" / "undo.json"
        stack.parent.mkdir(parents=True, exist_ok=True)
        stack.write_text(json.dumps([{
            "kind": "write", "path": "/proc/escape/target.txt",
            "backup": None, "existed": False,
        }]), encoding="utf-8")
        with self.assertRaises(uc.UndoError) as ctx:
            self.center.undo_last()
        self.assertIn("path is not allowed", str(ctx.exception))

    def test_entry_sensitive_path_refused(self):
        stack = self.td / "state" / "undo.json"
        stack.parent.mkdir(parents=True, exist_ok=True)
        stack.write_text(json.dumps([{
            "kind": "write",
            "path": str(self.td / "work" / ".ssh" / "config"),
            "backup": None, "existed": True,
        }]), encoding="utf-8")
        with self.assertRaises(uc.UndoError) as ctx:
            self.center.undo_last()
        self.assertIn("protected path", str(ctx.exception))

    def test_backup_outside_backup_root_refused(self):
        target = self._file("work/doc.txt", "data")
        stray = self._file("stray/doc.bak", "outside backups dir")
        self.center.push("write", str(target), backup=str(stray),
                         existed=True)
        with self.assertRaises(uc.UndoError) as ctx:
            self.center.undo_last()
        self.assertIn("outside its own storage", str(ctx.exception))

    def test_trash_outside_trash_root_refused(self):
        target = self.td / "work" / "gone.txt"
        stray = self._file("stray/gone.txt", "outside trash dir")
        self.center.push("delete", str(target), trash=str(stray),
                         existed=True)
        with self.assertRaises(uc.UndoError) as ctx:
            self.center.undo_last()
        self.assertIn("outside its own storage", str(ctx.exception))

    def test_symlink_target_refused(self):
        real = self._file("work/real.txt", "real")
        link = self.td / "work" / "link.txt"
        link.symlink_to(real)
        self.center.push("write", str(link), existed=True)
        with self.assertRaises(uc.UndoError) as ctx:
            self.center.undo_last()
        self.assertIn("symlink", str(ctx.exception))

    def test_unknown_entry_kind_refused(self):
        stack = self.td / "state" / "undo.json"
        stack.parent.mkdir(parents=True, exist_ok=True)
        stack.write_text(json.dumps([{
            "kind": "mystery", "path": str(self.td / "work" / "x.txt"),
        }]), encoding="utf-8")
        with self.assertRaises(uc.UndoError) as ctx:
            self.center.undo_last()
        self.assertIn("Unknown undo entry", str(ctx.exception))


class TestCorruptStack(UndoTestBase):
    """Unparseable stack is quarantined, not silently discarded."""

    def test_corrupt_stack_preserved_and_emptied(self):
        self._file("state/undo.json", "{not valid json")
        self.center.push("write", str(self.td / "work" / "new.txt"),
                         existed=False, label="after corrupt")
        self.assertEqual(self.center.status()["count"], 1)
        quarantined = list((self.td / "state").glob("undo.json.corrupt-*"))
        self.assertEqual(len(quarantined), 1)
        self.assertIn(b"not valid json",
                      quarantined[0].read_bytes())

    def test_status_on_corrupt_stack_is_empty(self):
        self._file("state/undo.json", "][ broken")
        status = self.center.status()
        self.assertEqual(status["count"], 0)
        self.assertFalse(status["can_undo"])
        self.assertEqual(status["entries"], [])


class TestClear(UndoTestBase):
    """clear empties the persistent stack."""

    def test_clear_wipes_entries(self):
        target = self._file("work/c.txt", "x")
        self.center.push("write", str(target), existed=False)
        self.assertEqual(self.center.status()["count"], 1)
        self.center.clear()
        status = self.center.status()
        self.assertEqual(status["count"], 0)
        self.assertFalse(status["can_undo"])
        with self.assertRaises(uc.UndoError):
            self.center.undo_last()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
