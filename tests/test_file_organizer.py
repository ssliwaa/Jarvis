"""Organizer scans duplicates and quarantines without deleting."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import file_organizer


class OrganizerTests(unittest.TestCase):
    def test_scan_duplicates_and_quarantine_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.txt").write_text("same bytes", encoding="utf-8")
            (root / "b.txt").write_text("same bytes", encoding="utf-8")
            (root / "empty").mkdir()
            with_original = file_organizer.TRASH
            file_organizer.TRASH = root / "trash"
            file_organizer.MANIFEST = root / "manifest.json"
            try:
                result = file_organizer.scan(root)
                self.assertEqual(result["files"], 2)
                self.assertEqual(len(result["duplicates"]), 1)
                self.assertEqual(result["empty_dirs"], [str(root / "empty")])
                moved = file_organizer.trash([str(root / "b.txt")], confirm=True)
                self.assertTrue(moved["ok"])
                self.assertFalse((root / "b.txt").exists())
                restored = file_organizer.restore(moved["batch"], confirm=True)
                self.assertTrue(restored["ok"])
                self.assertTrue((root / "b.txt").exists())
            finally:
                file_organizer.TRASH = with_original
                file_organizer.MANIFEST = file_organizer.TOOLS / "organizer-manifest.json"

    def test_outside_root_is_refused(self):
        with self.assertRaises(file_organizer.OrganizerError):
            file_organizer.scan("/etc")

    def test_batch_name_cannot_escape_the_archive(self):
        for batch in ("..", "../other", "/tmp", "a/b", "bad\0name"):
            with self.subTest(batch=batch):
                with self.assertRaises(file_organizer.OrganizerError):
                    file_organizer.restore(batch, confirm=True)
                with self.assertRaises(file_organizer.OrganizerError):
                    file_organizer.restore_archive(batch, confirm=True)

    def test_trash_does_not_report_a_failed_move_as_moved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "keep.txt"
            source.write_text("still here", encoding="utf-8")
            with mock.patch.object(file_organizer, "TRASH", root / "trash"), \
                    mock.patch.object(file_organizer, "MANIFEST", root / "manifest.json"), \
                    mock.patch.object(file_organizer.shutil, "move", side_effect=OSError("busy")):
                result = file_organizer.trash([str(source)], confirm=True)
            self.assertFalse(result["ok"])
            self.assertEqual(result["moved"], [])
            self.assertEqual(len(result["errors"]), 1)
            self.assertTrue(source.exists())


if __name__ == "__main__":
    unittest.main()
