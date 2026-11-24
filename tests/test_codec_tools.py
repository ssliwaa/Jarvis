"""Comprehensive test suite for operator_modules/codec_tools.py."""

from __future__ import annotations

import base64
import json
import time
import unittest

import operator_modules.codec_tools as codec_tools


class TestCodecTools(unittest.TestCase):
    def test_tool_contract(self):
        tool = codec_tools.TOOL
        self.assertEqual(tool["name"], "codec_tools")
        self.assertFalse(tool["approval"])
        self.assertTrue(callable(tool["handler"]))
        self.assertEqual(tool["input_schema"]["type"], "object")
        self.assertFalse(tool["input_schema"]["additionalProperties"])
        self.assertIn("action", tool["input_schema"]["required"])
        self.assertIn("data", tool["input_schema"]["required"])

    def test_encode_and_decode_roundtrip_all_formats(self):
        test_cases = [
            ("base64", "Hello, World! 🚀"),
            ("base32", "Jarvis operator module test 12345"),
            ("hex", "Arbitrary bytes and text: 123!"),
            ("url", "https://example.com/search?q=hello world & safe=true"),
            ("html", "<div class=\"test\">Tom & Jerry 'special'</div>"),
            ("ascii85", "The quick brown fox jumps over the lazy dog."),
            ("unicode_escape", "Zażółć gęślą jaźń — Polish letters"),
            ("quoted_printable", "Line 1\r\nLine 2 with special = characters & symbols."),
        ]

        for fmt, sample in test_cases:
            with self.subTest(format=fmt):
                # Encode
                enc_res = codec_tools.codec_tools({
                    "action": "encode",
                    "format": fmt,
                    "data": sample,
                })
                self.assertTrue(enc_res["ok"], f"Encode failed for {fmt}: {enc_res.get('error')}")
                self.assertTrue(enc_res["success"])
                self.assertIsNone(enc_res["error"])
                encoded_data = enc_res["data"]["encoded"]

                # Decode
                dec_res = codec_tools.codec_tools({
                    "action": "decode",
                    "format": fmt,
                    "data": encoded_data,
                })
                self.assertTrue(dec_res["ok"], f"Decode failed for {fmt}: {dec_res.get('error')}")
                self.assertTrue(dec_res["success"])
                self.assertIsNone(dec_res["error"])
                self.assertFalse(dec_res["data"]["binary"])
                # For HTML and URL unescape/unquote may normalize spaces/quotes
                if fmt == "html":
                    import html
                    self.assertEqual(dec_res["data"]["decoded"], html.unescape(html.escape(sample)))
                else:
                    self.assertEqual(dec_res["data"]["decoded"], sample)

    def test_decode_binary_fallback_without_crashing(self):
        # Construct non-UTF8 binary data (0xFF, 0xFE, 0x80, etc.)
        binary_bytes = bytes([0xFF, 0xFE, 0xAA, 0xBB, 0xCC, 0x00, 0x80, 0x81])
        b64_binary = base64.b64encode(binary_bytes).decode("ascii")

        res = codec_tools.codec_tools({
            "action": "decode",
            "format": "base64",
            "data": b64_binary,
        })
        self.assertTrue(res["ok"])
        self.assertTrue(res["success"])
        self.assertTrue(res["data"]["binary"])
        self.assertEqual(res["data"]["hex"], binary_bytes.hex())
        self.assertEqual(res["data"]["byte_length"], len(binary_bytes))

    def test_jwt_inspect_valid_and_expiration(self):
        now = int(time.time())
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": "user_12345",
            "name": "Operator",
            "iat": now - 3600,
            "exp": now + 3600,  # Unexpired
        }
        h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        sig_b64 = "MOCK_SIGNATURE_BYTES_123"
        jwt_token = f"{h_b64}.{p_b64}.{sig_b64}"

        res = codec_tools.codec_tools({
            "action": "jwt_inspect",
            "data": jwt_token,
        })
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["header"], header)
        self.assertEqual(res["data"]["payload"]["sub"], "user_12345")
        self.assertFalse(res["data"]["expired"])
        self.assertIsNotNone(res["data"]["exp_iso"])
        self.assertIsNotNone(res["data"]["iat_iso"])
        self.assertEqual(res["data"]["signature"], sig_b64)

        # Test expired JWT
        expired_payload = {"sub": "user_expired", "exp": now - 60}
        exp_p_b64 = base64.urlsafe_b64encode(json.dumps(expired_payload).encode()).decode().rstrip("=")
        expired_token = f"{h_b64}.{exp_p_b64}.{sig_b64}"

        exp_res = codec_tools.codec_tools({
            "action": "jwt_inspect",
            "data": expired_token,
        })
        self.assertTrue(exp_res["ok"])
        self.assertTrue(exp_res["data"]["expired"])

    def test_jwt_inspect_malformed(self):
        # Missing segments
        res = codec_tools.codec_tools({
            "action": "jwt_inspect",
            "data": "only.two_parts",
        })
        self.assertFalse(res["ok"])
        self.assertIn("Invalid JWT structure", res["error"])

        # Invalid JSON in payload
        bad_token = f"eyJhbGciOiAiSFMyNTYifQ.bm90LWpzb24-c3RyaW5n.{'s' * 10}"
        bad_res = codec_tools.codec_tools({
            "action": "jwt_inspect",
            "data": bad_token,
        })
        self.assertFalse(bad_res["ok"])

    def test_detect_action(self):
        # Hex detection
        hex_res = codec_tools.codec_tools({"action": "detect", "data": "48656c6c6f20576f726c64"})
        self.assertTrue(hex_res["ok"])
        self.assertIn("hex", hex_res["data"]["candidates"])

        # URL detection
        url_res = codec_tools.codec_tools({"action": "detect", "data": "https://example.com/%20query%21"})
        self.assertTrue(url_res["ok"])
        self.assertIn("url", url_res["data"]["candidates"])

        # HTML detection
        html_res = codec_tools.codec_tools({"action": "detect", "data": "Hello &amp; welcome &lt;user&gt;"})
        self.assertTrue(html_res["ok"])
        self.assertIn("html", html_res["data"]["candidates"])

    def test_payload_limit_enforced(self):
        oversized = "A" * (1024 * 1024 + 10)
        res = codec_tools.codec_tools({
            "action": "encode",
            "format": "base64",
            "data": oversized,
        })
        self.assertFalse(res["ok"])
        self.assertIn("Payload exceeds maximum", res["error"])

    def test_error_handling_unsupported_format_or_action(self):
        # Missing action
        res1 = codec_tools.codec_tools({"data": "test"})
        self.assertFalse(res1["ok"])

        # Unsupported action
        res2 = codec_tools.codec_tools({"action": "unknown_action", "data": "test"})
        self.assertFalse(res2["ok"])

        # Unsupported format
        res3 = codec_tools.codec_tools({"action": "encode", "format": "unsupported_fmt", "data": "test"})
        self.assertFalse(res3["ok"])


if __name__ == "__main__":
    unittest.main()
