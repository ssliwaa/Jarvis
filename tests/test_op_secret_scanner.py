"""Automated unit test suite for operator_modules/op_secret_scanner.py.

Verifies:
1. Tool registration contract, input_schema (additionalProperties: False), and approval=False.
2. Standard 5-key return envelope (ok, success, data, result, error).
3. Feature 25: scan_entropy (Shannon entropy, adaptive thresholds, sliding window, token isolation).
4. Feature 26: scan_patterns (AWS, GitHub, Slack, OpenAI, SSH private keys, ReDoS resistance, redaction).
5. Feature 27: audit_pem (X.509 certificate decoding, expiration, RSA/EC key metadata, corrupted blocks).
6. Feature 28: crypto_utils (CSPRNG token generation, PBKDF2/Scrypt, constant-time comparison).
7. Path confinement to ALLOWED_ROOTS, sensitive path blocking, and input size limits.
8. Dynamic discovery via ToolRegistry.
"""

from __future__ import annotations

import secrets
import tempfile
import time
import os
import unittest
SANDBOXED = os.environ.get("JARVIS_VERIFY_SANDBOX") == "1"
from pathlib import Path

import operator_modules.op_secret_scanner as op_secret_scanner
from tool_registry import ToolRegistry

# Test certificate fixture (valid X.509 self-signed)
SAMPLE_CERT_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDFzCCAf+gAwIBAgIUAT8Xt61U31v3OLwb7AJoSt4J8XEwDQYJKoZIhvcNAQEL\n"
    "BQAwGzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTAeFw0yNjExMjEyMTU4MDda\n"
    "Fw0zNjExMjEyMTU4MDdaMBsxGTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20wggEi\n"
    "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCkdIHv6tpAxdQuEgf9PjzFkR2k\n"
    "yO4Cr7/oCOGt6Sk/483djNhTCvljUmHJIvjKzcqPPB/TU3EBkZRZiZuSG0pp9k8P\n"
    "krMilR45o/xGqLJAFJMItXi9JRl68EAYK5IXpgJYLkunW3efjbIHp3eyyeL4Fn2s\n"
    "pLm2ttO346xIC5Wfobrvqn8M9OPiuKOCP0J/CYuw0vBPPrMm5acOFtJp0W7AoAk6\n"
    "mnBXKnJVxh/iBdXvJTl2Q7MKdNM79KWLK+se+//fSAbcKWLcqp40RPqcXt3DPt1O\n"
    "bZiTMLRsEpvLlC5Nz+x1UMEM7L4dFpTDzp0bROmCxf2upYMkvRBo9OTr2QbDAgMB\n"
    "AAGjUzBRMB0GA1UdDgQWBBREbPxqd/2bBhnLwbu4GIaVXGK65zAfBgNVHSMEGDAW\n"
    "gBREbPxqd/2bBhnLwbu4GIaVXGK65zAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\n"
    "DQEBCwUAA4IBAQCF1ySd/1LuZFcQBJC2/8BZnBfAvQd3UH3gBzJRam44J2oBlwnP\n"
    "AkEO7p4g/UuZZmd8ba09H+YhEsiVV0IdDdbjCq3EBHntm1oGrwLSoL87giQKX73t\n"
    "FhTqZXGpLMmydXeZSCP+W3y/VEhBlhFsvEEjE6ZRgILmtPFlUfRVlHjf/xNE8sN2\n"
    "1q4CW0WkoyczjnOCWtUTWBhCnHzAGk9rwR0oUX9npFpeCIxrDVMdDP09A3k+F/on\n"
    "kRnRge3hnQbl46AGRR2IVvS0cYk5ncKf0ARm2V2fwhuFlyjUOfCap17lZpEPkDzm\n"
    "/llpT/5h+n/0FVG11Mv3ocwcdsJQbt3fJiZt\n"
    "-----END CERTIFICATE-----\n"
)

# Test certificate fixture with notAfter in year 2020 (expired)
EXPIRED_CERT_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDFzCCAf+gAwIBAgIUAT8Xt61U31v3OLwb7AJoSt4J8XEwDQYJKoZIhvcNAQEL\n"
    "BQAwGzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTAeFw0yNjExMjEyMTU4MDda\n"
    "Fw0yMDExMjIyMTU4MDdaMBsxGTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20wggEi\n"
    "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCkdIHv6tpAxdQuEgf9PjzFkR2k\n"
    "yO4Cr7/oCOGt6Sk/483djNhTCvljUmHJIvjKzcqPPB/TU3EBkZRZiZuSG0pp9k8P\n"
    "krMilR45o/xGqLJAFJMItXi9JRl68EAYK5IXpgJYLkunW3efjbIHp3eyyeL4Fn2s\n"
    "pLm2ttO346xIC5Wfobrvqn8M9OPiuKOCP0J/CYuw0vBPPrMm5acOFtJp0W7AoAk6\n"
    "mnBXKnJVxh/iBdXvJTl2Q7MKdNM79KWLK+se+//fSAbcKWLcqp40RPqcXt3DPt1O\n"
    "bZiTMLRsEpvLlC5Nz+x1UMEM7L4dFpTDzp0bROmCxf2upYMkvRBo9OTr2QbDAgMB\n"
    "AAGjUzBRMB0GA1UdDgQWBBREbPxqd/2bBhnLwbu4GIaVXGK65zAfBgNVHSMEGDAW\n"
    "gBREbPxqd/2bBhnLwbu4GIaVXGK65zAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\n"
    "DQEBCwUAA4IBAQCF1ySd/1LuZFcQBJC2/8BZnBfAvQd3UH3gBzJRam44J2oBlwnP\n"
    "AkEO7p4g/UuZZmd8ba09H+YhEsiVV0IdDdbjCq3EBHntm1oGrwLSoL87giQKX73t\n"
    "FhTqZXGpLMmydXeZSCP+W3y/VEhBlhFsvEEjE6ZRgILmtPFlUfRVlHjf/xNE8sN2\n"
    "1q4CW0WkoyczjnOCWtUTWBhCnHzAGk9rwR0oUX9npFpeCIxrDVMdDP09A3k+F/on\n"
    "kRnRge3hnQbl46AGRR2IVvS0cYk5ncKf0ARm2V2fwhuFlyjUOfCap17lZpEPkDzm\n"
    "/llpT/5h+n/0FVG11Mv3ocwcdsJQbt3fJiZt\n"
    "-----END CERTIFICATE-----\n"
)

# Sample 2048-bit RSA Private Key header fixture
SAMPLE_RSA_KEY_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEA0M5yQxY5Z9p9V4N5vL3k2t8x8zY8a7b6c5d4e3f2a1b0c9d8\n"
    "e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6\n"
    "a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4\n"
    "c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2\n"
    "e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0\n"
    "a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8\n"
    "c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6\n"
    "e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4\n"
    "a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2\n"
    "c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0\n"
    "AgMBAAECggEBAKAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMk\n"
    "JSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNU\n"
    "VVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOE\n"
    "hYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0\n"
    "tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk\n"
    "5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f4BAgMEBQYHCAkKCwwNDg8QERITFBUW\n"
    "FxYYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RF\n"
    "RkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1\n"
    "dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6Sl\n"
    "pqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV\n"
    "1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f4BAgMEBQYH\n"
    "CAkKCwwNDg8QERITFBUWFxYYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2\n"
    "Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVm\n"
    "Z2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo+QkZKTlJWW\n"
    "l5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXG\n"
    "x8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX2\n"
    "9/j5+vv8/f4=\n"
    "-----END RSA PRIVATE KEY-----\n"
)


class TestOpSecretScanner(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(dir="/tmp")
        self.root = Path(self.temp_dir.name).resolve()

        # Create sample test files
        self.source_file = self.root / "sample_code.py"
        self.source_file.write_text(
            "# Configuration settings\n"
            "APP_ENV = 'production'\n"
            "AWS_KEY = 'AKIAAAAAAAAAAAAAAAAA'\n"
            "AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n",
            encoding="utf-8",
        )

        self.cert_file = self.root / "server.crt"
        self.cert_file.write_text(SAMPLE_CERT_PEM, encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def _assert_envelope(self, res: dict, expected_ok: bool):
        """Assert the standard 5-key Jarvis operator envelope structure."""
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
        tool = op_secret_scanner.TOOL
        self.assertEqual(tool["name"], "secret_scanner")
        self.assertFalse(tool["approval"], "secret_scanner is read-only and must have approval=False")
        self.assertTrue(callable(tool["handler"]))
        self.assertEqual(tool["input_schema"]["type"], "object")
        self.assertFalse(tool["input_schema"]["additionalProperties"])
        self.assertIn("action", tool["input_schema"]["required"])

    def test_02_toolregistry_discovery(self):
        reg = ToolRegistry()
        self.assertIn("secret_scanner", reg.tools)
        tool = reg.tools["secret_scanner"]
        self.assertEqual(tool.name, "secret_scanner")
        self.assertFalse(tool.approval)

    def test_03_envelope_structure_on_success_and_error(self):
        res_ok = op_secret_scanner.secret_scanner({
            "action": "scan_entropy",
            "text": "Hello world this is clean text.",
        })
        self._assert_envelope(res_ok, True)

        res_err = op_secret_scanner.secret_scanner({"action": "unknown_action_xyz"})
        self._assert_envelope(res_err, False)

    def test_04_unknown_argument_rejected(self):
        res = op_secret_scanner.secret_scanner({
            "action": "scan_entropy",
            "text": "sample",
            "malicious_inject": True,
        })
        self._assert_envelope(res, False)
        self.assertIn("Unknown argument", res["error"])

    def test_05_missing_or_invalid_action(self):
        res = op_secret_scanner.secret_scanner({"action": ""})
        self._assert_envelope(res, False)
        self.assertIn("Invalid or missing action", res["error"])

    # =========================================================================
    # Tier 1: Feature 25 — Shannon Entropy Scanning
    # =========================================================================

    def test_06_entropy_zero_and_repetitive(self):
        # Repeated character has 0.0 entropy
        res = op_secret_scanner.secret_scanner({
            "action": "scan_entropy",
            "text": "0" * 32,
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["overall_entropy"], 0.0)
        self.assertTrue(res["data"]["clean"])
        self.assertEqual(res["data"]["findings_count"], 0)

    def test_07_entropy_natural_text_below_threshold(self):
        text = "This is a standard English comment in source code with normal distribution."
        res = op_secret_scanner.secret_scanner({
            "action": "scan_entropy",
            "text": text,
        })
        self._assert_envelope(res, True)
        self.assertTrue(res["data"]["clean"])
        self.assertEqual(res["data"]["findings_count"], 0)

    def test_08_entropy_hex_secret_detection(self):
        # 64-char random hex token has entropy ~3.8, which exceeds hex threshold 3.2
        hex_secret = secrets.token_hex(32)
        text = f"API_SECRET_HEX = '{hex_secret}'"
        res = op_secret_scanner.secret_scanner({
            "action": "scan_entropy",
            "text": text,
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["clean"])
        self.assertGreaterEqual(res["data"]["findings_count"], 1)
        found = res["data"]["findings"][0]
        self.assertEqual(found["charset"], "hex")
        self.assertGreater(found["entropy"], 3.2)
        self.assertIn("[REDACTED]", found["sample"])

    def test_09_entropy_base64_secret_detection(self):
        # High entropy base64 token
        token = secrets.token_urlsafe(32)
        text = f"SESSION_TOKEN = '{token}'"
        res = op_secret_scanner.secret_scanner({
            "action": "scan_entropy",
            "text": text,
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["clean"])
        self.assertGreaterEqual(res["data"]["findings_count"], 1)
        found = res["data"]["findings"][0]
        self.assertGreater(found["entropy"], 4.3)

    def test_10_entropy_sliding_window_mode(self):
        # Deterministic 36-char alphabet: every 24-char window fully inside it holds
        # 24 unique characters => H = log2(24) ~ 4.585 > base_threshold 4.5 (non-hex).
        # NOTE: previous `secrets.token_hex(20)` was FLAKY (~0.6% of draws failed):
        # pure-hex windows cap at H=4.0 and mixed prefix/secret windows hovered at
        # the 4.5 cutoff, so some random draws produced zero findings.
        secret = "0123456789abcdefghijklmnopqrstuvwxyz"
        line = f"config_val = 'prefix_{secret}_suffix'"
        res = op_secret_scanner.secret_scanner({
            "action": "scan_entropy",
            "text": line,
            "mode": "sliding_window",
            "window_size": 24,
            "step": 6,
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["clean"])
        self.assertGreaterEqual(len(res["data"]["findings"]), 1)
        self.assertIn("high_entropy", res["data"]["findings"][0]["type"])

    def test_11_entropy_file_source(self):
        res = op_secret_scanner.secret_scanner({
            "action": "scan_entropy",
            "path": str(self.source_file),
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["source_path"], str(self.source_file))

    # =========================================================================
    # Tier 1: Feature 26 — Pattern Matching Secrets
    # =========================================================================

    def test_12_pattern_match_aws_credentials(self):
        text = (
            "export AWS_ACCESS_KEY_ID=AKIAAAAAAAAAAAAAAAAA\n"
            "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        )
        res = op_secret_scanner.secret_scanner({
            "action": "scan_patterns",
            "text": text,
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["clean"])
        types = [f["type"] for f in res["data"]["findings"]]
        self.assertIn("aws_access_key", types)
        self.assertIn("aws_secret_key", types)
        for f in res["data"]["findings"]:
            self.assertIn("[REDACTED]", f["match_preview"])

    def test_13_pattern_match_github_tokens(self):
        text = (
            "classic = 'ghp_000000000000000000000000000000000000'\n"
            "fine_grained = 'github_pat_0000000000000000000000000000000000000000000000000000000000000000000000000000000000'\n"
            "oauth = 'gho_000000000000000000000000000000000000'\n"
        )
        res = op_secret_scanner.secret_scanner({
            "action": "scan_patterns",
            "text": text,
        })
        self._assert_envelope(res, True)
        self.assertGreaterEqual(res["data"]["findings_count"], 3)
        for f in res["data"]["findings"]:
            self.assertEqual(f["severity"], "CRITICAL")

    def test_14_pattern_match_slack_and_openai_tokens(self):
        text = (
            "slack_bot = 'xoxb-xxxxxxxxxxxxxxxxxxxxxxxx'\n"
            "openai_key = 'sk-000000000000000000000000000000'\n"
        )
        res = op_secret_scanner.secret_scanner({
            "action": "scan_patterns",
            "text": text,
        })
        self._assert_envelope(res, True)
        types = [f["type"] for f in res["data"]["findings"]]
        self.assertIn("slack_token", types)
        self.assertIn("openai_api_key", types)

    def test_15_pattern_match_ssh_private_key_header(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        res = op_secret_scanner.secret_scanner({
            "action": "scan_patterns",
            "text": text,
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["clean"])
        types = [f["type"] for f in res["data"]["findings"]]
        self.assertIn("ssh_private_key", types)

    def test_16_pattern_filter_subset(self):
        text = (
            "aws = 'AKIAAAAAAAAAAAAAAAAA'\n"
            "gh = 'ghp_000000000000000000000000000000000000'\n"
        )
        res = op_secret_scanner.secret_scanner({
            "action": "scan_patterns",
            "text": text,
            "patterns": ["aws"],
        })
        self._assert_envelope(res, True)
        types = [f["type"] for f in res["data"]["findings"]]
        self.assertIn("aws_access_key", types)
        self.assertNotIn("github_token", types)

    def test_17_pattern_invalid_filter_rejected(self):
        res = op_secret_scanner.secret_scanner({
            "action": "scan_patterns",
            "text": "test",
            "patterns": ["non_existent_pattern"],
        })
        self._assert_envelope(res, False)
        self.assertIn("Invalid pattern group", res["error"])

    # =========================================================================
    # Tier 1: Feature 27 — PEM & Certificate Audit
    # =========================================================================

    def test_18_pem_audit_x509_valid_cert(self):
        res = op_secret_scanner.secret_scanner({
            "action": "audit_pem",
            "text": SAMPLE_CERT_PEM,
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["blocks_count"], 1)
        block = res["data"]["blocks"][0]
        self.assertTrue(block["valid"])
        self.assertFalse(block["is_expired"])
        self.assertGreater(block["days_remaining"], 0)
        self.assertEqual(block["block_type"], "CERTIFICATE")
        self.assertTrue(block["is_self_signed"])

    def test_19_pem_audit_expired_cert(self):
        res = op_secret_scanner.secret_scanner({
            "action": "audit_pem",
            "text": EXPIRED_CERT_PEM,
        })
        self._assert_envelope(res, True)
        self.assertTrue(res["data"]["has_expired"])
        block = res["data"]["blocks"][0]
        self.assertTrue(block["is_expired"])
        self.assertLess(block["days_remaining"], 0)

    def test_20_pem_audit_multi_cert_bundle(self):
        bundle = f"{SAMPLE_CERT_PEM}\n{EXPIRED_CERT_PEM}"
        res = op_secret_scanner.secret_scanner({
            "action": "audit_pem",
            "text": bundle,
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["blocks_count"], 2)
        self.assertTrue(res["data"]["has_expired"])

    def test_21_pem_audit_rsa_private_key(self):
        res = op_secret_scanner.secret_scanner({
            "action": "audit_pem",
            "text": SAMPLE_RSA_KEY_PEM,
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["blocks_count"], 1)
        self.assertTrue(res["data"]["has_private_key"])
        block = res["data"]["blocks"][0]
        self.assertTrue(block["valid"])
        self.assertEqual(block["key_type"], "RSA")

    def test_22_pem_audit_corrupted_pem(self):
        corrupted = "-----BEGIN CERTIFICATE-----\nCorrupted!NotValidBase64!!!---\n-----END CERTIFICATE-----"
        res = op_secret_scanner.secret_scanner({
            "action": "audit_pem",
            "text": corrupted,
        })
        self._assert_envelope(res, True)
        block = res["data"]["blocks"][0]
        self.assertFalse(block["valid"])
        self.assertIn("error", block)

    def test_23_pem_audit_mismatched_headers(self):
        mismatched = "-----BEGIN CERTIFICATE-----\nsomething\n-----END RSA PRIVATE KEY-----"
        res = op_secret_scanner.secret_scanner({
            "action": "audit_pem",
            "text": mismatched,
        })
        self._assert_envelope(res, True)
        block = res["data"]["blocks"][0]
        self.assertFalse(block["valid"])
        self.assertIn("Mismatched", block["error"])

    # =========================================================================
    # Tier 1: Feature 28 — Cryptographic Primitives
    # =========================================================================

    def test_24_crypto_generate_token_hex(self):
        res = op_secret_scanner.secret_scanner({
            "action": "crypto_utils",
            "operation": "generate_token",
            "nbytes": 16,
            "token_type": "hex",
        })
        self._assert_envelope(res, True)
        token = res["data"]["token"]
        self.assertEqual(len(token), 32)
        self.assertGreater(res["data"]["entropy"], 3.0)

    def test_25_crypto_generate_token_urlsafe(self):
        res = op_secret_scanner.secret_scanner({
            "action": "crypto_utils",
            "operation": "generate_token",
            "nbytes": 32,
            "token_type": "urlsafe",
        })
        self._assert_envelope(res, True)
        self.assertGreater(res["data"]["length"], 40)
        self.assertGreater(res["data"]["entropy"], 4.0)

    def test_26_crypto_derive_key_pbkdf2(self):
        res = op_secret_scanner.secret_scanner({
            "action": "crypto_utils",
            "operation": "derive_key",
            "password": "correct horse battery staple",
            "salt": "salt_string",
            "iterations": 1000,
            "hash_name": "sha256",
            "dklen": 32,
        })
        self._assert_envelope(res, True)
        self.assertIn("derived_key_hex", res["data"])
        self.assertEqual(len(res["data"]["derived_key_hex"]), 64)

    def test_27_crypto_derive_key_scrypt(self):
        res = op_secret_scanner.secret_scanner({
            "action": "crypto_utils",
            "operation": "derive_key",
            "kdf_algorithm": "scrypt",
            "password": "my_master_password",
            "salt": "scrypt_salt",
            "dklen": 32,
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["algorithm"], "scrypt")
        self.assertEqual(len(res["data"]["derived_key_hex"]), 64)

    def test_28_crypto_compare_digest_constant_time(self):
        res_match = op_secret_scanner.secret_scanner({
            "action": "crypto_utils",
            "operation": "compare_digest",
            "val_a": "super_secret_token_123",
            "val_b": "super_secret_token_123",
        })
        self._assert_envelope(res_match, True)
        self.assertTrue(res_match["data"]["match"])

        res_diff = op_secret_scanner.secret_scanner({
            "action": "crypto_utils",
            "operation": "compare_digest",
            "val_a": "token_a",
            "val_b": "token_b",
        })
        self._assert_envelope(res_diff, True)
        self.assertFalse(res_diff["data"]["match"])

    def test_29_crypto_hmac_generate_and_verify(self):
        res_gen = op_secret_scanner.secret_scanner({
            "action": "crypto_utils",
            "operation": "hmac_generate",
            "key": "secret_key",
            "message": "transaction_payload_data",
        })
        self._assert_envelope(res_gen, True)
        sig = res_gen["data"]["hmac_hex"]

        res_ver = op_secret_scanner.secret_scanner({
            "action": "crypto_utils",
            "operation": "hmac_verify",
            "key": "secret_key",
            "message": "transaction_payload_data",
            "signature": sig,
        })
        self._assert_envelope(res_ver, True)
        self.assertTrue(res_ver["data"]["match"])

    # =========================================================================
    # Tier 2: Boundary, Security, and Defensive Hardening Tests
    # =========================================================================

    def test_30_boundary_empty_inputs(self):
        for act in ("scan_entropy", "scan_patterns", "audit_pem"):
            res = op_secret_scanner.secret_scanner({"action": act, "text": ""})
            self._assert_envelope(res, True)

    @unittest.skipIf(SANDBOXED, "needs the developer's local env (vault/Hermes/Piper/desktop); skipped in CI")

    def test_31_boundary_path_traversal_rejection(self):
        res = op_secret_scanner.secret_scanner({
            "action": "scan_patterns",
            "path": "../../../etc/shadow",
        })
        self._assert_envelope(res, False)
        self.assertIn("PathSecurityError", res["error"])

    def test_32_boundary_sensitive_directory_rejection(self):
        fake_ssh = self.root / ".ssh"
        fake_ssh.mkdir()
        fake_key = fake_ssh / "id_rsa"
        fake_key.write_text("private", encoding="utf-8")

        res = op_secret_scanner.secret_scanner({
            "action": "scan_patterns",
            "path": str(fake_key),
        })
        self._assert_envelope(res, False)
        self.assertIn("SensitivePathError", res["error"])

    def test_33_boundary_null_bytes_in_path(self):
        res = op_secret_scanner.secret_scanner({
            "action": "scan_patterns",
            "path": "/tmp/test\0file.txt",
        })
        self._assert_envelope(res, False)
        self.assertIn("PathSecurityError", res["error"])

    def test_34_boundary_token_bytes_limits(self):
        res_low = op_secret_scanner.secret_scanner({
            "action": "crypto_utils",
            "operation": "generate_token",
            "nbytes": 4,  # Under MIN_TOKEN_BYTES (8)
        })
        self._assert_envelope(res_low, False)

        res_high = op_secret_scanner.secret_scanner({
            "action": "crypto_utils",
            "operation": "generate_token",
            "nbytes": 2048,  # Over MAX_TOKEN_BYTES (1024)
        })
        self._assert_envelope(res_high, False)

    def test_35_boundary_pbkdf2_iteration_bounds(self):
        # Exceeds 1,000,000 iteration ceiling
        res = op_secret_scanner.secret_scanner({
            "action": "crypto_utils",
            "operation": "derive_key",
            "password": "pwd",
            "iterations": 2_000_000,
        })
        self._assert_envelope(res, False)
        self.assertIn("safety limits", res["error"])

        # Under 1,000 iteration floor
        res_low = op_secret_scanner.secret_scanner({
            "action": "crypto_utils",
            "operation": "derive_key",
            "password": "pwd",
            "iterations": 500,
        })
        self._assert_envelope(res_low, False)

    def test_36_boundary_redos_resistance(self):
        # 50,000 characters of repetitive input
        hostile_text = "AKIA" + ("A" * 50000)
        t0 = time.time()
        res = op_secret_scanner.secret_scanner({
            "action": "scan_patterns",
            "text": hostile_text,
        })
        elapsed = time.time() - t0
        self._assert_envelope(res, True)
        self.assertLess(elapsed, 0.5, "Pattern match took longer than 500ms (potential ReDoS)")

    def test_37_boundary_large_single_line_entropy(self):
        line = "prefix_" + secrets.token_hex(32) + "_middle_" + ("0" * 10000)
        res = op_secret_scanner.secret_scanner({
            "action": "scan_entropy",
            "text": line,
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["clean"])

    def test_38_boundary_unicode_multibyte(self):
        text = "这是一个带有中文字符和表情符号的测试 🔐 密钥 = 'AKIAAAAAAAAAAAAAAAAA'"
        res = op_secret_scanner.secret_scanner({
            "action": "scan_patterns",
            "text": text,
        })
        self._assert_envelope(res, True)
        self.assertFalse(res["data"]["clean"])
        self.assertEqual(res["data"]["findings"][0]["type"], "aws_access_key")

    # =========================================================================
    # Tier 3: Combinatorial & Cross-Feature Workflows
    # =========================================================================

    def test_39_workflow_generate_token_and_entropy_scan(self):
        # Generate CSPRNG token
        res_gen = op_secret_scanner.secret_scanner({
            "action": "crypto_utils",
            "operation": "generate_token",
            "nbytes": 32,
            "token_type": "urlsafe",
        })
        token = res_gen["data"]["token"]

        # Feed token into scan_entropy
        res_scan = op_secret_scanner.secret_scanner({
            "action": "scan_entropy",
            "text": f"JWT_SECRET = '{token}'",
        })
        self._assert_envelope(res_scan, True)
        self.assertFalse(res_scan["data"]["clean"])
        self.assertGreaterEqual(res_scan["data"]["findings_count"], 1)

    def test_40_workflow_derive_key_hmac_sign_and_verify(self):
        # 1. Derive key
        res_kdf = op_secret_scanner.secret_scanner({
            "action": "crypto_utils",
            "operation": "derive_key",
            "password": "user_session_secret_pw",
            "salt": "auth_service_salt",
            "iterations": 10000,
        })
        derived_key = res_kdf["data"]["derived_key_hex"]

        # 2. Sign message
        msg = "action=transfer&amount=5000&dest=acct_84920"
        res_sign = op_secret_scanner.secret_scanner({
            "action": "crypto_utils",
            "operation": "hmac_generate",
            "key": derived_key,
            "message": msg,
        })
        sig = res_sign["data"]["hmac_hex"]

        # 3. Verify signature
        res_verify = op_secret_scanner.secret_scanner({
            "action": "crypto_utils",
            "operation": "hmac_verify",
            "key": derived_key,
            "message": msg,
            "signature": sig,
        })
        self.assertTrue(res_verify["data"]["match"])

    # =========================================================================
    # Tier 4: Real-World Operational Scenarios
    # =========================================================================

    def test_41_scenario_repository_pre_commit_credential_audit(self):
        """Simulate release gate scanning repo source files for leaked secrets and cert expiry."""
        # 1. Pattern scan source file
        res_pat = op_secret_scanner.secret_scanner({
            "action": "scan_patterns",
            "path": str(self.source_file),
        })
        self._assert_envelope(res_pat, True)
        self.assertFalse(res_pat["data"]["clean"])
        self.assertEqual(res_pat["data"]["findings_count"], 2)

        # 2. Audit cert file
        res_cert = op_secret_scanner.secret_scanner({
            "action": "audit_pem",
            "path": str(self.cert_file),
        })
        self._assert_envelope(res_cert, True)
        self.assertFalse(res_cert["data"]["has_expired"])


if __name__ == "__main__":
    unittest.main()
