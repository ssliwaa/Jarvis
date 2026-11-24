"""atomic_io: the crash-safety primitive every state writer builds on.

Shared by operator_tools, plan_files, operator_schedule, vault_health,
diff_patch and the op_* tier. These tests pin the contract: visibility of
intermediate states, refused symlink targets, private modes, backup
retention and failure cleanup.
"""
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import atomic_io


class AtomicWriteBytesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_write_creates_private_file_and_missing_parent(self):
        target = self.root / "deep" / "nested" / "state.json"
        backup = atomic_io.atomic_write_text(target, "hello")
        self.assertIsNone(backup)
        self.assertEqual(target.read_text(encoding="utf-8"), "hello")
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        # dir_mode=0o700 default tightened the fresh chain
        self.assertEqual((target.parent.stat().st_mode & 0o777), 0o700)

    def test_dir_mode_none_leaves_existing_directory_permissions(self):
        shared_dir = self.root / "shared"
        shared_dir.mkdir(mode=0o755)
        target = shared_dir / "out.json"
        atomic_io.atomic_write_text(target, "x", dir_mode=None)
        self.assertEqual(shared_dir.stat().st_mode & 0o777, 0o755)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_plain_text_and_json_wrappers_share_the_contract(self):
        target = self.root / "j.json"
        atomic_io.atomic_write_json(target, {"a": 1}, ensure_ascii=False)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertIn('"a": 1', target.read_text(encoding="utf-8"))

    def test_symlink_target_is_refused(self):
        real_file = self.root / "real.txt"
        real_file.write_text("secret", encoding="utf-8")
        link = self.root / "link.txt"
        os.symlink(real_file, link)
        with self.assertRaises(OSError):
            atomic_io.atomic_write_bytes(link, b"data")
        # The pointed-at file must never have been touched.
        self.assertEqual(real_file.read_text(encoding="utf-8"), "secret")
        self.assertEqual(set(p.name for p in self.root.iterdir()),
                         {"real.txt", "link.txt"})

    def test_backup_dir_keeps_the_previous_generation_private(self):
        bdir = self.root / "backups"
        target = self.root / "state.json"
        atomic_io.atomic_write_text(target, "v1")
        backup_path = atomic_io.atomic_write_text(target, "v2", backup_dir=bdir)
        self.assertIsNotNone(backup_path)
        self.assertTrue(backup_path.is_file())
        self.assertIn("v1", backup_path.read_text(encoding="utf-8"))
        self.assertEqual(target.read_text(encoding="utf-8"), "v2")
        self.assertEqual(backup_path.stat().st_mode & 0o777, 0o600)

    def test_failed_replace_cleans_the_temp_and_keeps_the_original(self):
        target = self.root / "state.json"
        atomic_io.atomic_write_text(target, "original")
        with patch("atomic_io.os.replace", side_effect=OSError("boom")):
            with self.assertRaises(OSError):
                atomic_io.atomic_write_text(target, "torn write")
        self.assertEqual(target.read_text(encoding="utf-8"), "original")
        leftovers = [p for p in self.root.iterdir() if p.name.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_concurrent_writers_leave_a_single_consistent_file(self):
        target = self.root / "counter.json"
        barrier = threading.Barrier(8)

        def writer(i):
            barrier.wait()
            atomic_io.atomic_write_text(target, f"writer-{i}")

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        content = target.read_text(encoding="utf-8")
        self.assertTrue(content.startswith("writer-"))
        # Exactly one whole value, never a torn interleave.
        self.assertIn(content, {f"writer-{i}" for i in range(8)})


if __name__ == "__main__":
    unittest.main()
