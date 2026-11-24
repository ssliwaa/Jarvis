"""Unit tests for the knowledge vault watcher."""
import tempfile
import unittest
from pathlib import Path

import vault_watcher


class TestVaultWatcher(unittest.TestCase):

    def test_rebuild_now_with_mock_vault(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            vault = tmppath / "notes"
            vault.mkdir()
            (vault / "note1.md").write_text("# Note 1\nSome test content.", encoding="utf-8")
            (vault / "note2.md").write_text("# Note 2\nLink to [[note1]].", encoding="utf-8")
            output_file = tmppath / "graph-data.js"

            result = vault_watcher.rebuild_now(vault_dir=vault, output=output_file)
            self.assertTrue(result["ok"])
            self.assertEqual(result["notes"], 2)
            self.assertEqual(result["links"], 1)
            self.assertTrue(output_file.is_file())
            content = output_file.read_text(encoding="utf-8")
            self.assertIn("const GRAPH =", content)

    def test_status(self):
        st = vault_watcher.status()
        self.assertIn("running", st)
        self.assertIn("vault", st)
        self.assertIn("rebuild_count", st)


if __name__ == "__main__":
    unittest.main()
