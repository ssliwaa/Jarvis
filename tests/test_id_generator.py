"""Comprehensive test suite for operator_modules/id_generator.py."""

from __future__ import annotations

import re
import unittest
import uuid

import operator_modules.id_generator as id_generator


class TestIdGenerator(unittest.TestCase):
    def test_tool_contract(self):
        tool = id_generator.TOOL
        self.assertEqual(tool["name"], "id_generator")
        self.assertFalse(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        self.assertEqual(tool["input_schema"]["type"], "object")
        self.assertFalse(tool["input_schema"]["additionalProperties"])
        self.assertIn("action", tool["input_schema"]["required"])

    def test_uuid4_generation_single_and_batch(self):
        # Single
        res1 = id_generator.id_generator({"action": "uuid4"})
        self.assertTrue(res1["ok"])
        u1 = res1["data"]["id"]
        parsed1 = uuid.UUID(u1)
        self.assertEqual(parsed1.version, 4)
        self.assertEqual(len(res1["data"]["ids"]), 1)

        # Batch of 50 unique UUIDs
        res2 = id_generator.id_generator({"action": "uuid4", "count": 50})
        self.assertTrue(res2["ok"])
        ids = res2["data"]["ids"]
        self.assertEqual(len(ids), 50)
        self.assertEqual(len(set(ids)), 50)  # All distinct

    def test_uuid5_deterministic_generation(self):
        # Same namespace + name must always yield the same UUIDv5
        res_a = id_generator.id_generator({
            "action": "uuid5",
            "namespace": "dns",
            "name": "jarvis.local",
        })
        res_b = id_generator.id_generator({
            "action": "uuid5",
            "namespace": "dns",
            "name": "jarvis.local",
        })
        self.assertTrue(res_a["ok"])
        self.assertTrue(res_b["ok"])
        self.assertEqual(res_a["data"]["id"], res_b["data"]["id"])
        parsed = uuid.UUID(res_a["data"]["id"])
        self.assertEqual(parsed.version, 5)

        # Different name yields different UUID
        res_c = id_generator.id_generator({
            "action": "uuid5",
            "namespace": "dns",
            "name": "other.local",
        })
        self.assertNotEqual(res_a["data"]["id"], res_c["data"]["id"])

        # Test namespaces: url, oid, x500
        for ns in ("url", "oid", "x500"):
            r = id_generator.id_generator({"action": "uuid5", "namespace": ns, "name": "test"})
            self.assertTrue(r["ok"])

    def test_token_hex_generation_and_length(self):
        for length in (8, 16, 32, 64):
            res = id_generator.id_generator({
                "action": "token_hex",
                "length": length,
            })
            self.assertTrue(res["ok"])
            token = res["data"]["id"]
            self.assertEqual(len(token), length)
            self.assertTrue(re.fullmatch(r"^[0-9a-f]+$", token))

    def test_token_urlsafe_generation(self):
        res = id_generator.id_generator({
            "action": "token_urlsafe",
            "length": 24,
        })
        self.assertTrue(res["ok"])
        token = res["data"]["id"]
        self.assertEqual(len(token), 24)
        self.assertTrue(re.fullmatch(r"^[A-Za-z0-9_-]+$", token))

    def test_nanoid_custom_alphabet_and_length(self):
        # Default alphabet
        res1 = id_generator.id_generator({"action": "nanoid", "length": 21})
        self.assertTrue(res1["ok"])
        self.assertEqual(len(res1["data"]["id"]), 21)

        # Custom alphabet: numeric only
        res2 = id_generator.id_generator({
            "action": "nanoid",
            "length": 10,
            "alphabet": "0123456789",
        })
        self.assertTrue(res2["ok"])
        self.assertEqual(len(res2["data"]["id"]), 10)
        self.assertTrue(res2["data"]["id"].isdigit())

        # Alphabet validation errors
        empty_alpha = id_generator.id_generator({
            "action": "nanoid",
            "alphabet": "",  # Empty alphabet
        })
        self.assertFalse(empty_alpha["ok"])
        self.assertIn("at least 2 unique characters", empty_alpha["error"])

        bad_alpha = id_generator.id_generator({
            "action": "nanoid",
            "alphabet": "A",  # Less than 2 unique characters
        })
        self.assertFalse(bad_alpha["ok"])

        ctrl_alpha = id_generator.id_generator({
            "action": "nanoid",
            "alphabet": "AB\x00C",  # Control char
        })
        self.assertFalse(ctrl_alpha["ok"])

    def test_validate_uuid_action(self):
        valid_uuid = str(uuid.uuid4())
        res_valid = id_generator.id_generator({
            "action": "validate",
            "value": valid_uuid,
        })
        self.assertTrue(res_valid["ok"])
        self.assertTrue(res_valid["data"]["valid"])
        self.assertEqual(res_valid["data"]["version"], 4)
        self.assertEqual(res_valid["data"]["value"], valid_uuid)

        # Invalid UUID string
        res_invalid = id_generator.id_generator({
            "action": "validate",
            "value": "not-a-valid-uuid",
        })
        self.assertTrue(res_invalid["ok"])
        self.assertFalse(res_invalid["data"]["valid"])
        self.assertIsNone(res_invalid["data"]["version"])

    def test_bounds_clamping(self):
        # count clamp: > 1000 clamped to 1000, length clamp: < 4 clamped to 4
        res = id_generator.id_generator({
            "action": "token_hex",
            "count": 5000,
            "length": 2,
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["count"], 1000)
        self.assertEqual(res["data"]["length"], 4)
        self.assertEqual(len(res["data"]["id"]), 4)

    def test_error_handling(self):
        res1 = id_generator.id_generator({})
        self.assertFalse(res1["ok"])

        res2 = id_generator.id_generator({"action": "unknown_action"})
        self.assertFalse(res2["ok"])

        res3 = id_generator.id_generator({"action": "uuid5"})  # missing name
        self.assertFalse(res3["ok"])


if __name__ == "__main__":
    unittest.main()
