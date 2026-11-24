"""Automated unit test suite for operator_modules/op_archive_builder.py.

Verifies:
1. Tool registration contract, input_schema (additionalProperties: False), and approval=True.
2. Standard 5-key return envelope (ok, success, data, result, error).
3. ZIP archive creation with single files, recursive directories, compression levels, and patterns.
4. TAR archive creation across formats (.tar, .tar.gz, .tar.bz2, .tar.xz).
5. Stream compression and decompression (gzip, bz2, lzma) in-memory and to disk.
6. 10 MB decompression bomb safeguard.
7. Path confinement to ALLOWED_ROOTS and path traversal rejection.
8. Sensitive file blacklisting and recursive exclusion.
9. Atomic file creation and 0o600 permissions.
"""

from __future__ import annotations

import base64
import bz2
import gzip
import lzma
import stat
import tarfile
import tempfile
import os
import unittest
SANDBOXED = os.environ.get("JARVIS_VERIFY_SANDBOX") == "1"
import zipfile
from pathlib import Path

import operator_modules.op_archive_builder as op_archive_builder


class TestOpArchiveBuilder(unittest.TestCase):
    def setUp(self):
        # Create isolated temporary directory inside /tmp (part of ALLOWED_ROOTS)
        self.temp_dir = tempfile.TemporaryDirectory(dir="/tmp")
        self.root = Path(self.temp_dir.name).resolve()

        # Build sample directory structure
        self.src_dir = self.root / "project"
        self.src_dir.mkdir(parents=True, exist_ok=True)

        (self.src_dir / "main.py").write_text("print('hello world')\n", encoding="utf-8")
        (self.src_dir / "notes.txt").write_text("Jarvis M2 Archive Builder Test\n", encoding="utf-8")

        sub = self.src_dir / "subpkg"
        sub.mkdir(parents=True, exist_ok=True)
        (sub / "module.py").write_text("def run(): pass\n", encoding="utf-8")
        (sub / "data.bin").write_bytes(b"\x01\x02\x03\x04\x05\x06\x07\x08")

    def tearDown(self):
        self.temp_dir.cleanup()

    def _assert_envelope(self, res: dict, expected_ok: bool):
        """Assert standard 5-key Jarvis operator envelope structure."""
        self.assertIsInstance(res, dict)
        self.assertIn("ok", res)
        self.assertIn("success", res)
        self.assertIn("data", res)
        self.assertIn("result", res)
        self.assertIn("error", res)
        self.assertEqual(res["ok"], expected_ok)
        self.assertEqual(res["success"], expected_ok)
        if expected_ok:
            self.assertIsNone(res["error"])
            self.assertEqual(res["data"], res["result"])
        else:
            self.assertIsNone(res["data"])
            self.assertIsNone(res["result"])
            self.assertIsInstance(res["error"], str)
            self.assertGreater(len(res["error"]), 0)

    # =========================================================================
    # Contract & Schema Conformance Tests
    # =========================================================================

    def test_01_tool_declaration_contract(self):
        tool = op_archive_builder.TOOL
        self.assertEqual(tool["name"], "archive_builder")
        self.assertTrue(tool["approval"], "archive_builder must require approval (approval: True)")
        self.assertTrue(callable(tool["handler"]))
        self.assertEqual(tool["input_schema"]["type"], "object")
        self.assertFalse(tool["input_schema"]["additionalProperties"])
        self.assertIn("action", tool["input_schema"]["required"])

    def test_02_approval_is_true(self):
        self.assertIs(op_archive_builder.TOOL.get("approval"), True)

    def test_03_schema_additional_properties_false(self):
        schema = op_archive_builder.TOOL["input_schema"]
        self.assertFalse(schema.get("additionalProperties", True))
        actions = schema["properties"]["action"]["enum"]
        for expected in ["create_zip", "create_tar", "compress_stream", "decompress_stream"]:
            self.assertIn(expected, actions)

    def test_04_missing_action_rejected(self):
        res = op_archive_builder.archive_builder({})
        self._assert_envelope(res, expected_ok=False)
        self.assertIn("action", res["error"].lower())

    def test_05_invalid_action_rejected(self):
        res = op_archive_builder.archive_builder({"action": "unsupported_action"})
        self._assert_envelope(res, expected_ok=False)
        self.assertIn("unsupported_action", res["error"])

    def test_06_unknown_argument_rejected(self):
        res = op_archive_builder.archive_builder({
            "action": "create_zip",
            "destination_path": str(self.root / "test.zip"),
            "source_paths": [str(self.src_dir)],
            "unauthorized_flag": True,
        })
        self._assert_envelope(res, expected_ok=False)
        self.assertIn("unauthorized_flag", res["error"])

    # =========================================================================
    # Tier 1: Happy Paths
    # =========================================================================

    def test_07_create_zip_single_file_integrity(self):
        dest_zip = self.root / "single.zip"
        res = op_archive_builder.archive_builder({
            "action": "create_zip",
            "source_paths": [str(self.src_dir / "notes.txt")],
            "destination_path": str(dest_zip),
        })
        self._assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertEqual(data["format"], "zip")
        self.assertEqual(data["file_count"], 1)
        self.assertTrue(dest_zip.exists())

        # Verify ZIP integrity
        with zipfile.ZipFile(dest_zip, "r") as zf:
            self.assertIsNone(zf.testzip())
            names = zf.namelist()
            self.assertEqual(len(names), 1)
            self.assertTrue(names[0].endswith("notes.txt"))
            self.assertEqual(zf.read(names[0]).decode("utf-8"), "Jarvis M2 Archive Builder Test\n")

    def test_08_create_zip_directory_tree_recursion(self):
        dest_zip = self.root / "full_project.zip"
        res = op_archive_builder.archive_builder({
            "action": "create_zip",
            "source_paths": [str(self.src_dir)],
            "destination_path": str(dest_zip),
            "base_dir": str(self.src_dir),
        })
        self._assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertGreaterEqual(data["file_count"], 4)
        self.assertTrue(dest_zip.exists())

        with zipfile.ZipFile(dest_zip, "r") as zf:
            self.assertIsNone(zf.testzip())
            names = set(zf.namelist())
            self.assertIn("main.py", names)
            self.assertIn("notes.txt", names)
            self.assertIn("subpkg/module.py", names)
            self.assertIn("subpkg/data.bin", names)

    def test_09_create_zip_compression_levels(self):
        dest_store = self.root / "stored.zip"
        dest_max = self.root / "max.zip"

        res_store = op_archive_builder.archive_builder({
            "action": "create_zip",
            "source_paths": [str(self.src_dir)],
            "destination_path": str(dest_store),
            "compression_level": 0,
        })
        self._assert_envelope(res_store, expected_ok=True)

        res_max = op_archive_builder.archive_builder({
            "action": "create_zip",
            "source_paths": [str(self.src_dir)],
            "destination_path": str(dest_max),
            "compression_level": 9,
        })
        self._assert_envelope(res_max, expected_ok=True)

        self.assertTrue(dest_store.exists())
        self.assertTrue(dest_max.exists())

    def test_10_create_zip_pattern_filtering(self):
        dest_zip = self.root / "filtered.zip"
        res = op_archive_builder.archive_builder({
            "action": "create_zip",
            "source_paths": [str(self.src_dir)],
            "destination_path": str(dest_zip),
            "include_pattern": ["*.py"],
            "exclude_pattern": ["*notes*"],
            "base_dir": str(self.src_dir),
        })
        self._assert_envelope(res, expected_ok=True)

        with zipfile.ZipFile(dest_zip, "r") as zf:
            names = zf.namelist()
            for name in names:
                self.assertTrue(name.endswith(".py"))
                self.assertNotIn("notes.txt", name)

    def test_11_create_tar_gz_creation_and_integrity(self):
        dest_tar = self.root / "archive.tar.gz"
        res = op_archive_builder.archive_builder({
            "action": "create_tar",
            "source_paths": [str(self.src_dir)],
            "destination_path": str(dest_tar),
            "format": "tar.gz",
            "base_dir": str(self.src_dir),
        })
        self._assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertEqual(data["format"], "tar.gz")
        self.assertTrue(dest_tar.exists())

        with tarfile.open(dest_tar, "r:gz") as tf:
            names = tf.getnames()
            self.assertIn("main.py", names)
            self.assertIn("subpkg/module.py", names)

    def test_12_create_tar_bz2_and_xz_creation(self):
        for fmt, ext in [("tar.bz2", ".tar.bz2"), ("tar.xz", ".tar.xz"), ("tar", ".tar")]:
            dest_tar = self.root / f"archive{ext}"
            res = op_archive_builder.archive_builder({
                "action": "create_tar",
                "source_paths": [str(self.src_dir)],
                "destination_path": str(dest_tar),
                "format": fmt,
            })
            self._assert_envelope(res, expected_ok=True)
            self.assertTrue(dest_tar.exists())

    def test_13_compress_stream_in_memory_gzip(self):
        plain_text = "Jarvis Stream Compression Unit Test Payload " * 10
        res = op_archive_builder.archive_builder({
            "action": "compress_stream",
            "data": plain_text,
            "format": "gzip",
        })
        self._assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertTrue(data["is_base64"])
        self.assertGreater(data["compressed_bytes"], 0)
        self.assertEqual(data["uncompressed_bytes"], len(plain_text.encode("utf-8")))

        raw_compressed = base64.b64decode(data["data"])
        decompressed = gzip.decompress(raw_compressed).decode("utf-8")
        self.assertEqual(decompressed, plain_text)

    def test_14_compress_stream_in_memory_bz2_and_lzma(self):
        payload = "Binary stream data test bz2 and lzma " * 5
        for fmt, dec_fn in [("bz2", bz2.decompress), ("lzma", lzma.decompress)]:
            res = op_archive_builder.archive_builder({
                "action": "compress_stream",
                "data": payload,
                "format": fmt,
            })
            self._assert_envelope(res, expected_ok=True)
            raw = base64.b64decode(res["data"]["data"])
            self.assertEqual(dec_fn(raw).decode("utf-8"), payload)

    def test_15_compress_stream_to_file(self):
        dest_file = self.root / "stream_out.gz"
        payload = "Write stream directly to compressed file on disk"
        res = op_archive_builder.archive_builder({
            "action": "compress_stream",
            "data": payload,
            "destination_path": str(dest_file),
            "format": "gzip",
        })
        self._assert_envelope(res, expected_ok=True)
        self.assertTrue(dest_file.exists())
        self.assertIsNone(res["data"]["data"])

        decompressed = gzip.decompress(dest_file.read_bytes()).decode("utf-8")
        self.assertEqual(decompressed, payload)

    def test_16_decompress_stream_in_memory_text(self):
        text = "Decompress stream back into UTF-8 text"
        compressed = gzip.compress(text.encode("utf-8"))
        b64_in = base64.b64encode(compressed).decode("ascii")

        res = op_archive_builder.archive_builder({
            "action": "decompress_stream",
            "data": b64_in,
            "format": "gzip",
        })
        self._assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertTrue(data["is_text"])
        self.assertEqual(data["data"], text)

    def test_17_decompress_stream_in_memory_binary_base64(self):
        raw_binary = b"\x00\xff\xfe\x10\x20\x30\xaa\xbb\xcc"
        compressed = gzip.compress(raw_binary)
        b64_in = base64.b64encode(compressed).decode("ascii")

        res = op_archive_builder.archive_builder({
            "action": "decompress_stream",
            "data": b64_in,
            "format": "gzip",
            "return_base64": True,
        })
        self._assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertTrue(data["is_base64"])
        out_bytes = base64.b64decode(data["data"])
        self.assertEqual(out_bytes, raw_binary)

    def test_18_decompress_stream_to_file(self):
        text = "Decompress stream directly to target file on disk"
        compressed = gzip.compress(text.encode("utf-8"))
        b64_in = base64.b64encode(compressed).decode("ascii")
        dest_file = self.root / "restored.txt"

        res = op_archive_builder.archive_builder({
            "action": "decompress_stream",
            "data": b64_in,
            "destination_path": str(dest_file),
            "format": "gzip",
        })
        self._assert_envelope(res, expected_ok=True)
        self.assertTrue(dest_file.exists())
        self.assertEqual(dest_file.read_text(encoding="utf-8"), text)

    def test_19_atomic_file_creation_and_mode_0o600(self):
        dest_zip = self.root / "atomic_perm_test.zip"
        res = op_archive_builder.archive_builder({
            "action": "create_zip",
            "source_paths": [str(self.src_dir / "notes.txt")],
            "destination_path": str(dest_zip),
        })
        self._assert_envelope(res, expected_ok=True)
        self.assertTrue(dest_zip.exists())
        mode = stat.S_IMODE(dest_zip.stat().st_mode)
        self.assertEqual(mode, 0o600, f"Expected permissions 0o600, got {oct(mode)}")

    def test_20_overwrite_flag_behavior(self):
        dest_zip = self.root / "existing.zip"
        dest_zip.write_text("dummy", encoding="utf-8")

        # overwrite=False must fail
        res_fail = op_archive_builder.archive_builder({
            "action": "create_zip",
            "source_paths": [str(self.src_dir / "notes.txt")],
            "destination_path": str(dest_zip),
            "overwrite": False,
        })
        self._assert_envelope(res_fail, expected_ok=False)
        self.assertIn("already exists", res_fail["error"])

        # overwrite=True must succeed
        res_ok = op_archive_builder.archive_builder({
            "action": "create_zip",
            "source_paths": [str(self.src_dir / "notes.txt")],
            "destination_path": str(dest_zip),
            "overwrite": True,
        })
        self._assert_envelope(res_ok, expected_ok=True)

    # =========================================================================
    # Tier 2: Boundary & Security Tests
    # =========================================================================

    def test_21_decompression_bomb_rejected(self):
        # 12 MB of zeroes collapses to ~12 KB when gzipped
        bomb_raw = b"\x00" * (12 * 1024 * 1024)
        bomb_gz = gzip.compress(bomb_raw, compresslevel=9)
        bomb_b64 = base64.b64encode(bomb_gz).decode("ascii")

        res = op_archive_builder.archive_builder({
            "action": "decompress_stream",
            "data": bomb_b64,
            "format": "gzip",
        })
        self._assert_envelope(res, expected_ok=False)
        self.assertTrue(
            "DecompressionBombError" in res["error"]
            or "10 MB" in res["error"]
            or "safety limit" in res["error"]
        )

    def test_22_decompression_under_limit_accepted(self):
        # 1 MB of zeroes is well under the 10 MB limit
        payload = b"X" * (1024 * 1024)
        comp = gzip.compress(payload)
        b64 = base64.b64encode(comp).decode("ascii")

        res = op_archive_builder.archive_builder({
            "action": "decompress_stream",
            "data": b64,
            "format": "gzip",
            "return_base64": True,
        })
        self._assert_envelope(res, expected_ok=True)
        self.assertEqual(res["data"]["uncompressed_bytes"], 1024 * 1024)

    def test_23_destination_outside_allowed_roots_rejected(self):
        res = op_archive_builder.archive_builder({
            "action": "create_zip",
            "source_paths": [str(self.src_dir)],
            "destination_path": "/etc/malicious.zip",
        })
        self._assert_envelope(res, expected_ok=False)
        self.assertTrue("outside" in res["error"] or "allowed roots" in res["error"])

    def test_24_source_outside_allowed_roots_rejected(self):
        res = op_archive_builder.archive_builder({
            "action": "create_zip",
            "source_paths": ["/etc/passwd"],
            "destination_path": str(self.root / "leak.zip"),
        })
        self._assert_envelope(res, expected_ok=False)
        self.assertTrue("outside" in res["error"] or "allowed roots" in res["error"])

    @unittest.skipIf(SANDBOXED, "needs the developer's local env (vault/Hermes/Piper/desktop); skipped in CI")

    def test_25_direct_sensitive_target_blocked(self):
        sensitive_target = Path.home() / ".ssh"
        res = op_archive_builder.archive_builder({
            "action": "create_zip",
            "source_paths": [str(sensitive_target)],
            "destination_path": str(self.root / "ssh.zip"),
        })
        self._assert_envelope(res, expected_ok=False)
        self.assertTrue("sensitive" in res["error"].lower() or "blocked" in res["error"].lower())

    def test_26_recursive_sensitive_files_excluded_from_archive(self):
        # Add sensitive files inside the source directory
        env_file = self.src_dir / ".env"
        env_file.write_text("SECRET_KEY=12345\n", encoding="utf-8")
        conf_file = self.src_dir / "config.json"
        conf_file.write_text('{"token": "xyz"}\n', encoding="utf-8")

        dest_zip = self.root / "safe_project.zip"
        res = op_archive_builder.archive_builder({
            "action": "create_zip",
            "source_paths": [str(self.src_dir)],
            "destination_path": str(dest_zip),
            "base_dir": str(self.src_dir),
        })
        self._assert_envelope(res, expected_ok=True)
        data = res["data"]

        # Sensitive files must be reported in excluded_sensitive_files
        self.assertIn(".env", data["excluded_sensitive_files"])
        self.assertIn("config.json", data["excluded_sensitive_files"])

        # Archive members must not contain sensitive files
        with zipfile.ZipFile(dest_zip, "r") as zf:
            names = zf.namelist()
            self.assertNotIn(".env", names)
            self.assertNotIn("config.json", names)
            self.assertIn("main.py", names)

    def test_27_nonexistent_source_path_error(self):
        res = op_archive_builder.archive_builder({
            "action": "create_zip",
            "source_paths": [str(self.root / "nonexistent_file.txt")],
            "destination_path": str(self.root / "fail.zip"),
        })
        self._assert_envelope(res, expected_ok=False)
        self.assertTrue("FileNotFoundError" in res["error"] or "not exist" in res["error"])

    def test_28_corrupted_stream_decompression_error(self):
        corrupted_b64 = base64.b64encode(b"this is not valid gzip data").decode("ascii")
        res = op_archive_builder.archive_builder({
            "action": "decompress_stream",
            "data": corrupted_b64,
            "format": "gzip",
        })
        self._assert_envelope(res, expected_ok=False)
        self.assertTrue("corrupted" in res["error"].lower() or "invalid" in res["error"].lower())

    def test_29_unsupported_format_error(self):
        res = op_archive_builder.archive_builder({
            "action": "create_tar",
            "source_paths": [str(self.src_dir)],
            "destination_path": str(self.root / "test.rar"),
            "format": "rar",
        })
        self._assert_envelope(res, expected_ok=False)
        self.assertIn("Unsupported", res["error"])

    def test_30_backslash_zip_slip_sanitization(self):
        """Verify backslash traversal vectors are detected and normalized in _sanitize_arcname."""
        traversal_vectors = [
            r"..\..\windows\system32\calc.exe",
            r"foo\..\..\bar",
            r"sub\..\..\..\secret.txt",
            r"..\escape.txt",
            r"foo/../../bar",
            r"\..\..\etc\passwd",
        ]
        for vec in traversal_vectors:
            with self.assertRaises(op_archive_builder.SecurityError, msg=f"Vector {vec} should raise SecurityError"):
                op_archive_builder._sanitize_arcname(vec)

        safe_mappings = [
            (r"subpkg\module.py", "subpkg/module.py"),
            (r"C:\safe\path\doc.txt", "safe/path/doc.txt"),
            (r"\safe\path.txt", "safe/path.txt"),
            ("notes.txt", "notes.txt"),
            ("", "archive_entry"),
            (".", "archive_entry"),
        ]
        for raw, expected in safe_mappings:
            self.assertEqual(op_archive_builder._sanitize_arcname(raw), expected)

    def test_31_symlink_exfiltration_directory_packaging(self):
        """Verify symlinks pointing outside ALLOWED_ROOTS or to sensitive files are excluded from archives."""
        proj = self.root / "symlink_test_project"
        proj.mkdir(parents=True, exist_ok=True)
        (proj / "safe.py").write_text("print('safe')\n", encoding="utf-8")

        # Create symlinks pointing to unauthorized / sensitive targets
        leak_passwd = proj / "leak_passwd.txt"
        leak_passwd.symlink_to(Path("/etc/passwd"))

        leak_ssh = proj / "leak_ssh.txt"
        leak_ssh.symlink_to(Path.home() / ".ssh")

        # Create safe symlink pointing to an allowed file inside project
        safe_link = proj / "safe_link.py"
        safe_link.symlink_to(proj / "safe.py")

        dest_zip = self.root / "defense_test.zip"
        res_zip = op_archive_builder.archive_builder({
            "action": "create_zip",
            "source_paths": [str(proj)],
            "destination_path": str(dest_zip),
            "base_dir": str(proj),
        })
        self._assert_envelope(res_zip, expected_ok=True)
        data_zip = res_zip["data"]

        # The unauthorized symlinks must be reported in excluded_sensitive_files
        self.assertIn("leak_passwd.txt", data_zip["excluded_sensitive_files"])
        self.assertIn("leak_ssh.txt", data_zip["excluded_sensitive_files"])

        # Archive members must contain safe files but NOT the leaked targets
        with zipfile.ZipFile(dest_zip, "r") as zf:
            names = zf.namelist()
            self.assertIn("safe.py", names)
            self.assertIn("safe_link.py", names)
            self.assertNotIn("leak_passwd.txt", names)
            self.assertNotIn("leak_ssh.txt", names)

        # Repeat for TAR creation
        dest_tar = self.root / "defense_test.tar.gz"
        res_tar = op_archive_builder.archive_builder({
            "action": "create_tar",
            "source_paths": [str(proj)],
            "destination_path": str(dest_tar),
            "format": "tar.gz",
            "base_dir": str(proj),
        })
        self._assert_envelope(res_tar, expected_ok=True)
        data_tar = res_tar["data"]
        self.assertIn("leak_passwd.txt", data_tar["excluded_sensitive_files"])
        self.assertIn("leak_ssh.txt", data_tar["excluded_sensitive_files"])

        with tarfile.open(dest_tar, "r:gz") as tf:
            names = tf.getnames()
            self.assertIn("safe.py", names)
            self.assertIn("safe_link.py", names)
            self.assertNotIn("leak_passwd.txt", names)
            self.assertNotIn("leak_ssh.txt", names)

    def test_32_bz2_lzma_stream_truncation_eof_check(self):
        """Verify truncated bz2 and lzma streams are rejected with error envelopes."""
        payload = b"CRITICAL_DATA_STREAM_INTEGRITY_CHECK_" * 50

        # 1. Truncated bz2
        comp_bz2 = bz2.compress(payload)
        trunc_bz2 = comp_bz2[:len(comp_bz2) // 2]
        res_bz2 = op_archive_builder.archive_builder({
            "action": "decompress_stream",
            "data": base64.b64encode(trunc_bz2).decode("ascii"),
            "format": "bz2",
        })
        self._assert_envelope(res_bz2, expected_ok=False)
        self.assertTrue(
            "incomplete" in res_bz2["error"].lower()
            or "truncated" in res_bz2["error"].lower()
        )

        # 2. Truncated lzma
        comp_lzma = lzma.compress(payload)
        trunc_lzma = comp_lzma[:len(comp_lzma) // 2]
        res_lzma = op_archive_builder.archive_builder({
            "action": "decompress_stream",
            "data": base64.b64encode(trunc_lzma).decode("ascii"),
            "format": "lzma",
        })
        self._assert_envelope(res_lzma, expected_ok=False)
        self.assertTrue(
            "incomplete" in res_lzma["error"].lower()
            or "truncated" in res_lzma["error"].lower()
        )

        # 3. Valid bz2 and lzma streams must decompress successfully
        res_valid_bz2 = op_archive_builder.archive_builder({
            "action": "decompress_stream",
            "data": base64.b64encode(comp_bz2).decode("ascii"),
            "format": "bz2",
        })
        self._assert_envelope(res_valid_bz2, expected_ok=True)
        self.assertEqual(res_valid_bz2["data"]["uncompressed_bytes"], len(payload))

        res_valid_lzma = op_archive_builder.archive_builder({
            "action": "decompress_stream",
            "data": base64.b64encode(comp_lzma).decode("ascii"),
            "format": "lzma",
        })
        self._assert_envelope(res_valid_lzma, expected_ok=True)
        self.assertEqual(res_valid_lzma["data"]["uncompressed_bytes"], len(payload))



if __name__ == "__main__":
    unittest.main()
