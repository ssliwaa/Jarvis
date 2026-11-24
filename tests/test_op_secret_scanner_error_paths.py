"""ERROR-path coverage tests for operator_modules/op_secret_scanner.py.

Second wave of the sys.settrace audit. A security module - entropy and
pattern secret scanning, PEM audits, CSPRNG tokens, PBKDF2/Scrypt key
derivation and HMAC - had 20 raise sites with only half ever executed.

All guards here run offline against a per-test tmp tree: path hygiene
(empty string handled through both the direct validator and the
dispatcher's or-chain), directory inputs, the input size ceiling with a
lowered module constant, unreadable files through a real chmod 000 lock,
non-string inline text, and the crypto operation grammar (unknown token
type, missing and non-string passwords, hmac_generate without key or
message, unknown operation).
"""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import operator_modules.op_secret_scanner as ss


class SecretScannerCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def call(self, **kwargs):
        return ss.secret_scanner(kwargs)

    def bad(self, fragment, **kwargs):
        result = self.call(**kwargs)
        self.assertFalse(result["ok"], msg=str(result.get("error")))
        self.assertIn(fragment, result["error"])
        return result


class PathGuardTests(SecretScannerCase):
    def test_empty_path_is_rejected_by_the_validator(self):
        with self.assertRaises(ValueError) as ctx:
            ss._validate_and_resolve_path("")
        self.assertIn("non-empty string", str(ctx.exception))

    def test_empty_path_via_dispatcher_scans_empty_content(self):
        # Characterization: the `path or source_path` chain swallows an
        # empty string, so the dispatcher treats it as empty input instead
        # of rejecting the path.
        result = self.call(action="scan_entropy", path="")
        self.assertTrue(result["ok"], msg=str(result.get("error")))

    def test_directory_input_is_refused(self):
        subdir = self.tmp / "payloads"
        subdir.mkdir()
        result = self.bad("is not a regular file.",
                          action="scan_entropy", path=str(subdir))
        self.assertIn(str(subdir), result["error"])

    def test_input_size_ceiling(self):
        bulky = self.tmp / "bulky.txt"
        bulky.write_text("z" * 1024, encoding="utf-8")
        with patch.object(ss, "MAX_INPUT_BYTES", 8):
            self.bad("exceeds maximum allowed size",
                     action="scan_entropy", path=str(bulky))

    def test_unreadable_file_reports_scanner_error(self):
        locked = self.tmp / "locked.txt"
        locked.write_text("SECRET=1", encoding="utf-8")
        os.chmod(locked, 0)
        self.addCleanup(os.chmod, locked, 0o600)
        result = self.bad("Failed to read file",
                          action="scan_entropy", path=str(locked))
        self.assertIn("SecretScannerError", result["error"])


class TextGuardTests(SecretScannerCase):
    def test_non_string_inline_text_is_refused(self):
        self.bad("'text' must be a string.",
                 action="scan_entropy", text=12345)


class CryptoGrammarTests(SecretScannerCase):
    def test_unknown_token_type(self):
        self.bad("Unsupported token_type 'matrix'.",
                 action="crypto_utils", operation="generate_token",
                 token_type="matrix")

    def test_missing_password_for_key_derivation(self):
        self.bad("'password' is required for key derivation.",
                 action="crypto_utils", operation="derive_key")

    def test_non_string_password_for_key_derivation(self):
        self.bad("'password' must be a string.",
                 action="crypto_utils", operation="derive_key",
                 password=12345)

    def test_hmac_generate_requires_key_and_message(self):
        self.bad("'key' and 'message' are required for hmac_generate.",
                 action="crypto_utils", operation="hmac_generate")
        self.bad("'key' and 'message' are required for hmac_generate.",
                 action="crypto_utils", operation="hmac_generate",
                 key="only-key")

    def test_unknown_operation(self):
        self.bad("Unknown crypto operation 'frobnicate'.",
                 action="crypto_utils", operation="frobnicate")

    def test_happy_hmac_generate_for_contrast(self):
        result = self.call(action="crypto_utils",
                           operation="hmac_generate",
                           key="k", message="m")
        self.assertTrue(result["ok"], msg=str(result.get("error")))
        self.assertIn("hmac_hex", result["data"])
        self.assertEqual(len(result["data"]["hmac_hex"]), 64)


if __name__ == "__main__":
    unittest.main()
