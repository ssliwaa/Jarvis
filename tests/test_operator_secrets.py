"""operator_secrets CLI: prompt-only values, list and remove."""
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import operator_secrets
import operator_tools as ops


class CliTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.store = ops.SecretStore(Path(folder.name) / "secrets.json")
        patcher = mock.patch.object(operator_secrets, "SecretStore", lambda: self.store)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_cli(self, argv, secrets):
        out = io.StringIO()
        with mock.patch("sys.argv", ["operator_secrets.py", *argv]), \
                mock.patch.object(operator_secrets.getpass, "getpass", side_effect=secrets):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = operator_secrets.main()
        return code, out.getvalue()

    def test_set_stores_a_password_without_printing_it(self):
        code, out = self.run_cli(["set", "github"], ["s3cret-value"])
        self.assertEqual(code, 0)
        self.assertNotIn("s3cret-value", out)
        self.assertIn("github", out)
        names = {item["name"]: item["type"] for item in self.store.names()}
        self.assertEqual(names.get("github"), "password")

    def test_set_totp_stores_a_seed(self):
        code, out = self.run_cli(["set-totp", "bank"], ["JBSWY3DPEHPK3PXP"])
        self.assertEqual(code, 0)
        self.assertNotIn("JBSWY3DPEHPK3PXP", out)
        names = {item["name"]: item["type"] for item in self.store.names()}
        self.assertEqual(names.get("bank"), "totp")

    def test_empty_input_saves_nothing(self):
        code, _ = self.run_cli(["set", "empty"], [""])
        self.assertEqual(code, 1)
        self.assertEqual(self.store.names(), [])

    def test_list_shows_name_and_type(self):
        self.run_cli(["set", "github"], ["value"])
        code, out = self.run_cli(["list"], [])
        self.assertEqual(code, 0)
        self.assertIn("github\tpassword", out)

    def test_remove_deletes_the_entry(self):
        self.run_cli(["set", "github"], ["value"])
        code, out = self.run_cli(["remove", "github"], [])
        self.assertEqual(code, 0)
        self.assertIn("Removed github", out)
        self.assertEqual(self.store.names(), [])


if __name__ == "__main__":
    unittest.main()
