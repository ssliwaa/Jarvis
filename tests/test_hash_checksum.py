"""Tests for operator_modules/hash_checksum.py."""

from __future__ import annotations

import hashlib
import hmac
import tempfile
import unittest
from pathlib import Path

import operator_modules.hash_checksum as hash_checksum_mod


class TestHashChecksum(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_tool_declaration_contract(self):
        tool = hash_checksum_mod.TOOL
        self.assertEqual(tool["name"], "hash_checksum")
        self.assertFalse(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        self.assertLessEqual(len(tool["description"]), 1600)
        schema = tool["input_schema"]
        self.assertEqual(schema["type"], "object")
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("action", schema["required"])

    def test_hash_text_sha256(self):
        text = "hello world"
        expected = hashlib.sha256(text.encode("utf-8")).hexdigest()
        res = hash_checksum_mod.hash_checksum({
            "action": "hash_text",
            "text": text,
            "algorithm": "sha256",
        })
        self.assertTrue(res["ok"])
        self.assertTrue(res["success"])
        self.assertIsNone(res["error"])
        self.assertEqual(res["data"]["hash"], expected)
        self.assertEqual(res["data"]["algorithm"], "sha256")
        self.assertEqual(res["result"], res["data"])

    def test_hash_text_algorithms(self):
        for algo in ["md5", "sha1", "sha512", "blake2b"]:
            res = hash_checksum_mod.hash_checksum({
                "action": "hash_text",
                "text": "test content",
                "algorithm": algo,
            })
            self.assertTrue(res["ok"], f"Failed for algo {algo}")
            expected = getattr(hashlib, algo)(b"test content").hexdigest()
            self.assertEqual(res["data"]["hash"], expected)

    def test_hash_file_streaming(self):
        f = self.root / "sample.bin"
        content = b"x" * (128 * 1024 + 42)  # Multi-chunk (128 KB + 42 bytes)
        f.write_bytes(content)

        expected = hashlib.sha256(content).hexdigest()
        res = hash_checksum_mod.hash_checksum({
            "action": "hash_file",
            "path": str(f),
            "algorithm": "sha256",
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["hash"], expected)
        self.assertEqual(res["data"]["size_bytes"], len(content))

    def test_hmac_computation(self):
        secret_key = "super_secret_test_key"
        message = "payload data to authenticate"
        expected = hmac.new(secret_key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()

        res = hash_checksum_mod.hash_checksum({
            "action": "hmac",
            "key": secret_key,
            "text": message,
            "algorithm": "sha256",
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["hmac"], expected)
        # Verify secret key is never leaked in response
        self.assertNotIn(secret_key, str(res))

    def test_hmac_file_computation(self):
        f = self.root / "hmac_target.txt"
        content = b"content to sign"
        f.write_bytes(content)

        secret_key = "test_key_123"
        expected = hmac.new(secret_key.encode("utf-8"), content, hashlib.sha256).hexdigest()

        res = hash_checksum_mod.hash_checksum({
            "action": "hmac",
            "key": secret_key,
            "path": str(f),
            "algorithm": "sha256",
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["hmac"], expected)
        self.assertNotIn(secret_key, str(res))

    def test_verify_hash_success_and_failure(self):
        text = "verify me"
        real_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

        # Success case (case-insensitive)
        res_ok = hash_checksum_mod.hash_checksum({
            "action": "verify",
            "text": text,
            "expected_hash": real_hash.upper(),
            "algorithm": "sha256",
        })
        self.assertTrue(res_ok["ok"])
        self.assertTrue(res_ok["data"]["matches"])

        # Failure case
        res_fail = hash_checksum_mod.hash_checksum({
            "action": "verify",
            "text": text,
            "expected_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "algorithm": "sha256",
        })
        self.assertTrue(res_fail["ok"])
        self.assertFalse(res_fail["data"]["matches"])

    def test_verify_checksums_manifest(self):
        f1 = self.root / "file1.txt"
        f1.write_text("file 1 content", encoding="utf-8")
        h1 = hashlib.sha256(b"file 1 content").hexdigest()

        f2 = self.root / "file2.txt"
        f2.write_text("file 2 content", encoding="utf-8")
        h2 = hashlib.sha256(b"file 2 content").hexdigest()

        manifest_text = f"{h1}  file1.txt\n{h2} *file2.txt\n"

        res = hash_checksum_mod.hash_checksum({
            "action": "verify_checksums",
            "checksums_text": manifest_text,
            "path": str(self.root / "checksums.txt"),  # used for base_dir
        })
        self.assertTrue(res["ok"])
        self.assertTrue(res["data"]["all_ok"])
        self.assertEqual(res["data"]["passed"], 2)
        self.assertEqual(res["data"]["failed"], 0)

    def test_verify_checksums_missing_and_failed(self):
        f1 = self.root / "existing.txt"
        f1.write_text("content", encoding="utf-8")

        manifest_text = (
            "0000000000000000000000000000000000000000000000000000000000000000  existing.txt\n"
            "1111111111111111111111111111111111111111111111111111111111111111  nonexistent.txt\n"
        )
        res = hash_checksum_mod.hash_checksum({
            "action": "verify_checksums",
            "checksums_text": manifest_text,
            "path": str(self.root / "manifest.txt"),
        })
        self.assertTrue(res["ok"])
        self.assertFalse(res["data"]["all_ok"])
        self.assertEqual(res["data"]["passed"], 0)
        self.assertEqual(res["data"]["failed"], 2)
        statuses = {r["file"]: r["status"] for r in res["data"]["results"]}
        self.assertEqual(statuses["existing.txt"], "FAILED")
        self.assertEqual(statuses["nonexistent.txt"], "MISSING")

    def test_unsupported_algorithm_rejected(self):
        res = hash_checksum_mod.hash_checksum({
            "action": "hash_text",
            "text": "test",
            "algorithm": "sha3_256",  # Not in whitelisted set
        })
        self.assertFalse(res["ok"])
        self.assertIn("Unsupported algorithm", res["error"])

    def test_path_traversal_blocked(self):
        res = hash_checksum_mod.hash_checksum({
            "action": "hash_file",
            "path": "../../../etc/passwd",
        })
        self.assertFalse(res["ok"])
        self.assertIn("traversal", res["error"].lower())

    def test_sensitive_file_blocked(self):
        sensitive_path = Path.home() / ".ssh" / "id_rsa"
        res = hash_checksum_mod.hash_checksum({
            "action": "hash_file",
            "path": str(sensitive_path),
        })
        self.assertFalse(res["ok"])

    def test_unsupported_action(self):
        res = hash_checksum_mod.hash_checksum({"action": "unknown_op"})
        self.assertFalse(res["ok"])
        self.assertIn("Unsupported action", res["error"])

    def test_missing_action(self):
        res = hash_checksum_mod.hash_checksum({})
        self.assertFalse(res["ok"])
        self.assertIn("action", res["error"].lower())
