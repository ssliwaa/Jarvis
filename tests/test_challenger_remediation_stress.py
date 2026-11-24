"""Adversarial stress-testing suite for remediated operator modules.

Specifically covers:
1. operator_modules.config_parser:
   - Unauthorized host paths (/etc/passwd, /etc/shadow, /proc/version, /sys/kernel) across all 4 actions.
   - Directory traversal sequences (../, nested ..).
   - Symlinks created in allowed roots pointing to restricted targets.
   - Protected credential targets inside allowed roots (.ssh, .aws, secrets.json, .env).
   - Legitimate INI, Dotenv, and Properties files inside allowed roots across all 4 actions.
   - Boundary limits (oversized files, non-existent files, directory targets).
2. operator_modules.id_generator:
   - Empty alphabet ("") rejection with ok=False and error message.
   - Single character alphabet ("A", "AA", "AAAA") rejection.
   - Control and non-printable characters (\\x00, \\n, \\t, \\x1b, \\x7f) rejection.
   - Non-string alphabet rejection (int, list, dict).
   - Omitted and None alphabet using default nanoid alphabet.
   - Minimal 2-character valid alphabets (binary, hex, unicode).
   - Extreme lengths and counts clamping and validation.
   - Full coverage across all actions (uuid4, uuid5, token_hex, token_urlsafe, nanoid, validate, batch).
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

import operator_modules.config_parser as cp
import operator_modules.id_generator as ig


class TestConfigParserAdversarialRemediation(unittest.TestCase):
    """Adversarial challenge for config_parser path confinement and file resolution."""

    @classmethod
    def setUpClass(cls):
        cls.test_dir = Path(tempfile.mkdtemp(prefix="jarvis_cfg_test_"))

        # Create valid legitimate configuration files
        cls.valid_ini = cls.test_dir / "valid.ini"
        cls.valid_ini.write_text("[database]\nhost = 127.0.0.1\nport = 5432\nenabled = true\n")

        # Dotenv file (named .dotenv to avoid Jarvis's global .env credential block)
        cls.valid_env = cls.test_dir / "valid.dotenv"
        cls.valid_env.write_text("APP_ENV=production\nAPP_PORT=8080\nDEBUG=false\n")

        cls.valid_prop = cls.test_dir / "valid.properties"
        cls.valid_prop.write_text("server.host=0.0.0.0\nserver.port=9000\napp.name=JarvisCore\n")

        # Create symlinks pointing to unauthorized files outside allowed roots
        cls.symlink_passwd = cls.test_dir / "symlink_passwd.ini"
        try:
            cls.symlink_passwd.symlink_to("/etc/passwd")
        except OSError:
            pass

        cls.symlink_proc = cls.test_dir / "symlink_proc.env"
        try:
            cls.symlink_proc.symlink_to("/proc/version")
        except OSError:
            pass

        cls.symlink_sys = cls.test_dir / "symlink_sys.properties"
        try:
            cls.symlink_sys.symlink_to("/sys/kernel/profiling")
        except OSError:
            pass

        # Create nested symlink: link2 -> link1 -> /etc/passwd
        cls.symlink_nested = cls.test_dir / "symlink_nested.ini"
        try:
            if cls.symlink_passwd.exists() or cls.symlink_passwd.is_symlink():
                cls.symlink_nested.symlink_to(cls.symlink_passwd)
        except OSError:
            pass

        # Create sensitive files inside allowed root
        cls.sensitive_dir = cls.test_dir / ".ssh"
        cls.sensitive_dir.mkdir(exist_ok=True)
        cls.sensitive_file = cls.sensitive_dir / "id_rsa"
        cls.sensitive_file.write_text("DUMMY_PRIVATE_KEY")

        # Create protected .env credential file
        cls.sensitive_env = cls.test_dir / ".env"
        cls.sensitive_env.write_text("SECRET_KEY=12345")

        # Create oversized file (>512KB)
        cls.oversized_file = cls.test_dir / "oversized.ini"
        cls.oversized_file.write_text("A" * (513 * 1024))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.test_dir, ignore_errors=True)

    def test_unauthorized_host_paths_rejected_across_all_actions(self):
        """Verify host paths outside allowed roots are blocked across all 4 actions."""
        restricted_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/proc/version",
            "/proc/cpuinfo",
            "/sys/kernel/profiling",
            "/var/log/syslog",
            "/usr/bin/python3",
        ]
        actions = [
            ("parse", {"format": "ini"}),
            ("get_value", {"format": "ini", "key": "root"}),
            ("format", {"format": "ini"}),
            ("validate", {"format": "ini", "required_keys": ["root"]}),
        ]

        for target_path in restricted_paths:
            for action_name, extra_args in actions:
                with self.subTest(path=target_path, action=action_name):
                    payload = {"action": action_name, "path": target_path, **extra_args}
                    result = cp.config_parser(payload)
                    self.assertFalse(result["ok"], f"Expected ok=False for {action_name} on {target_path}")
                    self.assertFalse(result["success"])
                    self.assertIsNone(result["data"])
                    self.assertIsNone(result["result"])
                    self.assertIsNotNone(result["error"])
                    err_msg = result["error"].lower()
                    self.assertTrue(
                        "outside allowed" in err_msg or "permissionerror" in err_msg or "not found" in err_msg,
                        f"Unexpected error message: {result['error']}",
                    )

    def test_directory_traversal_sequences_rejected(self):
        """Verify directory traversal sequences fail across all actions."""
        traversal_paths = [
            "/tmp/../../etc/passwd",
            "/tmp/test/../../../etc/shadow",
            str(Path.home() / "../../etc/passwd"),
            "../../../../etc/passwd",
            "./../../etc/shadow",
            "~/../../etc/passwd",
        ]
        actions = ["parse", "get_value", "format", "validate"]

        for tpath in traversal_paths:
            for act in actions:
                with self.subTest(path=tpath, action=act):
                    payload = {"action": act, "path": tpath}
                    if act == "get_value":
                        payload["key"] = "test"
                    result = cp.config_parser(payload)
                    self.assertFalse(result["ok"])
                    self.assertIsNotNone(result["error"])
                    err_msg = result["error"].lower()
                    self.assertTrue(
                        "directory traversal" in err_msg or "outside allowed" in err_msg or "permissionerror" in err_msg,
                        f"Expected traversal/permission rejection, got: {result['error']}",
                    )

    def test_symlinks_pointing_outside_allowed_roots_rejected(self):
        """Verify symlinks created in allowed roots that target host files are rejected."""
        symlinks = [self.symlink_passwd, self.symlink_proc, self.symlink_sys, self.symlink_nested]
        actions = ["parse", "get_value", "format", "validate"]

        for link in symlinks:
            if not link.is_symlink() and not link.exists():
                continue
            for act in actions:
                with self.subTest(link=str(link), action=act):
                    payload = {"action": act, "path": str(link)}
                    if act == "get_value":
                        payload["key"] = "test"
                    result = cp.config_parser(payload)
                    self.assertFalse(result["ok"], f"Symlink escape not blocked on {act}: {link}")
                    self.assertFalse(result["success"])
                    self.assertIsNotNone(result["error"])
                    err_msg = result["error"].lower()
                    self.assertTrue(
                        "outside allowed roots" in err_msg or "permissionerror" in err_msg or "protected credential" in err_msg,
                        f"Expected outside allowed roots error, got: {result['error']}",
                    )

    def test_sensitive_files_inside_allowed_roots_rejected(self):
        """Verify credential and sensitive target protection works inside allowed roots."""
        sensitive_targets = [
            str(self.sensitive_file),
            str(self.sensitive_env),
            str(Path.home() / ".ssh" / "id_rsa"),
            str(Path.home() / ".jarvis-tools" / "secrets.json"),
        ]
        for s_target in sensitive_targets:
            res = cp.config_parser({"action": "parse", "path": s_target, "format": "ini"})
            self.assertFalse(res["ok"])
            self.assertIn("protected credential target", res["error"])

    def test_legitimate_files_in_allowed_roots_succeed(self):
        """Verify that legitimate INI, Dotenv, and Properties files parse and operate properly."""
        # Test INI file
        res_ini = cp.config_parser({"action": "parse", "path": str(self.valid_ini), "format": "ini"})
        self.assertTrue(res_ini["ok"])
        self.assertEqual(res_ini["data"]["format"], "ini")
        self.assertEqual(res_ini["data"]["config"]["database"]["host"], "127.0.0.1")

        # Test INI get_value
        res_gv = cp.config_parser({
            "action": "get_value",
            "path": str(self.valid_ini),
            "format": "ini",
            "section": "database",
            "key": "port",
        })
        self.assertTrue(res_gv["ok"])
        self.assertEqual(res_gv["data"]["value"], "5432")
        self.assertTrue(res_gv["data"]["found"])

        # Test INI format
        res_fmt = cp.config_parser({"action": "format", "path": str(self.valid_ini), "format": "ini"})
        self.assertTrue(res_fmt["ok"])
        self.assertIn("[database]", res_fmt["data"]["formatted"])

        # Test INI validate
        res_val = cp.config_parser({
            "action": "validate",
            "path": str(self.valid_ini),
            "format": "ini",
            "required_keys": ["host", "port"],
        })
        self.assertTrue(res_val["ok"])
        self.assertTrue(res_val["data"]["valid"])

        # Test Dotenv file
        res_env = cp.config_parser({"action": "parse", "path": str(self.valid_env), "format": "dotenv"})
        self.assertTrue(res_env["ok"])
        self.assertEqual(res_env["data"]["config"]["APP_ENV"], "production")

        res_env_val = cp.config_parser({
            "action": "validate",
            "path": str(self.valid_env),
            "format": "dotenv",
            "required_keys": ["APP_ENV", "MISSING_KEY"],
        })
        self.assertTrue(res_env_val["ok"])
        self.assertFalse(res_env_val["data"]["valid"])
        self.assertIn("MISSING_KEY", res_env_val["data"]["missing_keys"])

        # Test Properties file
        res_prop = cp.config_parser({"action": "parse", "path": str(self.valid_prop), "format": "properties"})
        self.assertTrue(res_prop["ok"])
        self.assertEqual(res_prop["data"]["config"]["server.port"], "9000")

    def test_boundary_and_invalid_paths(self):
        """Verify non-existent files, directory paths, oversized files, and invalid paths fail safely."""
        # Non-existent file inside allowed root
        non_existent = str(self.test_dir / "does_not_exist.ini")
        res_ne = cp.config_parser({"action": "parse", "path": non_existent})
        self.assertFalse(res_ne["ok"])
        self.assertIn("FileNotFoundError", res_ne["error"])

        # Directory target inside allowed root
        res_dir = cp.config_parser({"action": "parse", "path": str(self.test_dir)})
        self.assertFalse(res_dir["ok"])
        self.assertIn("FileNotFoundError", res_dir["error"])

        # Oversized file (> 512 KB)
        res_over = cp.config_parser({"action": "parse", "path": str(self.oversized_file)})
        self.assertFalse(res_over["ok"])
        self.assertIn("maximum size", res_over["error"])

        # Empty path
        res_empty = cp.config_parser({"action": "parse", "path": ""})
        self.assertFalse(res_empty["ok"])
        self.assertIn("non-empty string", res_empty["error"])

        # Non-string path
        res_nonstr = cp.config_parser({"action": "parse", "path": 12345})
        self.assertFalse(res_nonstr["ok"])
        self.assertIn("must be a string", res_nonstr["error"])


class TestIdGeneratorAdversarialRemediation(unittest.TestCase):
    """Adversarial challenge for id_generator alphabet validation and generation parameters."""

    def test_empty_alphabet_rejected_with_error(self):
        """Explicit alphabet='' must fail with ok=False and error message."""
        res = ig.id_generator({"action": "nanoid", "alphabet": ""})
        self.assertFalse(res["ok"])
        self.assertFalse(res["success"])
        self.assertIsNone(res["data"])
        self.assertIsNone(res["result"])
        self.assertIn("at least 2 unique characters", res["error"])

    def test_single_character_and_duplicates_rejected(self):
        """Single character or duplicate character alphabets must fail."""
        invalid_alphabets = [
            "A",
            "AA",
            "AAA",
            "AAAAAA",
            "   ",  # whitespace only, single unique char
            "!!!!!",
            "0000000000",
        ]
        for alph in invalid_alphabets:
            with self.subTest(alphabet=alph):
                res = ig.id_generator({"action": "nanoid", "alphabet": alph})
                self.assertFalse(res["ok"])
                self.assertFalse(res["success"])
                self.assertIn("at least 2 unique characters", res["error"])

    def test_control_and_nonprintable_characters_rejected(self):
        """Alphabets containing non-printable control characters must fail."""
        control_alphabets = [
            "abc\x00",
            "abc\x01",
            "abc\n",
            "abc\r",
            "abc\t",
            "abc\x1b",
            "abc\x7f",
        ]
        for alph in control_alphabets:
            with self.subTest(alphabet=repr(alph)):
                res = ig.id_generator({"action": "nanoid", "alphabet": alph})
                self.assertFalse(res["ok"])
                self.assertFalse(res["success"])
                self.assertIn("cannot contain non-printable control characters", res["error"])

    def test_non_string_alphabet_rejected(self):
        """Non-string alphabet values must fail safely."""
        non_string_alphabets = [123, True, ["a", "b"], {"a": 1, "b": 2}, 3.14]
        for alph in non_string_alphabets:
            with self.subTest(alphabet=type(alph).__name__):
                res = ig.id_generator({"action": "nanoid", "alphabet": alph})
                self.assertFalse(res["ok"])
                self.assertFalse(res["success"])
                self.assertIn("at least 2 unique characters", res["error"])

    def test_omitted_and_none_alphabet_uses_default(self):
        """Omitted or None alphabet must succeed using DEFAULT_NANOID_ALPHABET."""
        # Case 1: omitted alphabet key
        res_omitted = ig.id_generator({"action": "nanoid"})
        self.assertTrue(res_omitted["ok"])
        self.assertTrue(res_omitted["success"])
        self.assertEqual(res_omitted["data"]["length"], 32)
        self.assertEqual(res_omitted["data"]["alphabet_size"], 64)
        nanoid_val = res_omitted["data"]["id"]
        self.assertEqual(len(nanoid_val), 32)
        for char in nanoid_val:
            self.assertIn(char, ig.DEFAULT_NANOID_ALPHABET)

        # Case 2: explicit None alphabet
        res_none = ig.id_generator({"action": "nanoid", "alphabet": None})
        self.assertTrue(res_none["ok"])
        self.assertTrue(res_none["success"])
        self.assertEqual(res_none["data"]["alphabet_size"], 64)
        nanoid_none_val = res_none["data"]["id"]
        self.assertEqual(len(nanoid_none_val), 32)
        for char in nanoid_none_val:
            self.assertIn(char, ig.DEFAULT_NANOID_ALPHABET)

    def test_minimal_valid_alphabets(self):
        """Alphabets with exactly 2 unique characters must succeed."""
        valid_minimal = ["01", "ab", "AB", " _", "xy", "+-"]
        for alph in valid_minimal:
            with self.subTest(alphabet=alph):
                res = ig.id_generator({"action": "nanoid", "alphabet": alph, "length": 16})
                self.assertTrue(res["ok"])
                self.assertEqual(len(res["data"]["id"]), 16)
                for char in res["data"]["id"]:
                    self.assertIn(char, alph)

    def test_extreme_and_clamped_length_and_count(self):
        """Verify length and count are clamped to safe bounded intervals."""
        # Length clamped between 4 and 512
        res_low_len = ig.id_generator({"action": "nanoid", "length": 0})
        self.assertTrue(res_low_len["ok"])
        self.assertEqual(res_low_len["data"]["length"], 4)
        self.assertEqual(len(res_low_len["data"]["id"]), 4)

        res_neg_len = ig.id_generator({"action": "nanoid", "length": -50})
        self.assertTrue(res_neg_len["ok"])
        self.assertEqual(res_neg_len["data"]["length"], 4)

        res_high_len = ig.id_generator({"action": "nanoid", "length": 99999})
        self.assertTrue(res_high_len["ok"])
        self.assertEqual(res_high_len["data"]["length"], 512)
        self.assertEqual(len(res_high_len["data"]["id"]), 512)

        # Count clamped between 1 and 1000
        res_low_count = ig.id_generator({"action": "nanoid", "count": -10})
        self.assertTrue(res_low_count["ok"])
        self.assertEqual(res_low_count["data"]["count"], 1)
        self.assertEqual(len(res_low_count["data"]["ids"]), 1)

        res_high_count = ig.id_generator({"action": "nanoid", "count": 2000})
        self.assertTrue(res_high_count["ok"])
        self.assertEqual(res_high_count["data"]["count"], 1000)
        self.assertEqual(len(res_high_count["data"]["ids"]), 1000)

        # Invalid non-integer count / length returns error
        res_bad_cnt = ig.id_generator({"action": "nanoid", "count": "abc"})
        self.assertFalse(res_bad_cnt["ok"])
        self.assertIn("must be an integer", res_bad_cnt["error"])

        res_bad_len = ig.id_generator({"action": "nanoid", "length": "xyz"})
        self.assertFalse(res_bad_len["ok"])
        self.assertIn("must be an integer", res_bad_len["error"])

    def test_other_id_generator_actions_resilience(self):
        """Verify all other actions operate with proper contracts."""
        # uuid4
        res_u4 = ig.id_generator({"action": "uuid4", "count": 3})
        self.assertTrue(res_u4["ok"])
        self.assertEqual(len(res_u4["data"]["ids"]), 3)

        # uuid5 missing name
        res_u5_missing = ig.id_generator({"action": "uuid5"})
        self.assertFalse(res_u5_missing["ok"])
        self.assertIn("Field 'name' is required", res_u5_missing["error"])

        # uuid5 valid
        res_u5 = ig.id_generator({"action": "uuid5", "name": "jarvis.local", "namespace": "dns"})
        self.assertTrue(res_u5["ok"])
        self.assertEqual(res_u5["data"]["type"], "uuid5")

        # token_hex
        res_hex = ig.id_generator({"action": "token_hex", "length": 24, "count": 2})
        self.assertTrue(res_hex["ok"])
        self.assertEqual(len(res_hex["data"]["id"]), 24)

        # token_urlsafe
        res_url = ig.id_generator({"action": "token_urlsafe", "length": 20})
        self.assertTrue(res_url["ok"])
        self.assertEqual(len(res_url["data"]["id"]), 20)

        # validate
        res_val = ig.id_generator({"action": "validate", "value": res_u4["data"]["id"]})
        self.assertTrue(res_val["ok"])
        self.assertTrue(res_val["data"]["valid"])

        res_val_invalid = ig.id_generator({"action": "validate", "value": "not-a-valid-uuid"})
        self.assertTrue(res_val_invalid["ok"])
        self.assertFalse(res_val_invalid["data"]["valid"])

        res_val_empty = ig.id_generator({"action": "validate", "value": ""})
        self.assertFalse(res_val_empty["ok"])
        self.assertIn("non-empty string", res_val_empty["error"])

        # batch
        res_batch = ig.id_generator({"action": "batch", "count": 5})
        self.assertTrue(res_batch["ok"])
        self.assertEqual(len(res_batch["data"]["ids"]), 5)


if __name__ == "__main__":
    unittest.main()
