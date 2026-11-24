"""Unit tests for the storage guard and retention enforcement."""
import tempfile
import unittest
from pathlib import Path

import storage_guard


class TestStorageGuard(unittest.TestCase):

    def test_get_storage_status(self):
        status = storage_guard.get_storage_status()
        self.assertTrue(status["ok"])
        self.assertGreater(status["total_gb"], 0)
        self.assertGreaterEqual(status["free_gb"], 0)
        self.assertIsInstance(status["warning"], bool)
        self.assertIsInstance(status["critical"], bool)

    def test_enforce_retention_temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            trash = tmppath / "trash"
            trash.mkdir()
            # Create a 2MB dummy file
            dummy = trash / "dummy.tmp"
            dummy.write_bytes(b"X" * (2 * 1024 * 1024))

            # Set limit to 1MB, so it must prune
            result = storage_guard.enforce_retention(state_root=tmppath, max_storage_mb=1.0)
            self.assertTrue(result["ok"])
            self.assertGreater(result["pruned_bytes"], 0)
            self.assertEqual(result["pruned_files"], 1)
            self.assertFalse(dummy.exists())


if __name__ == "__main__":
    unittest.main()
