"""Adversarial challenge and empirical stress-test suite for op_secret_scanner.

Covers:
- Vector 1: Charset-adaptive Shannon entropy & threshold edge cases (Hex vs Base64 vs ASCII)
- Vector 2: ASN.1 DER parser resilience (truncated headers, huge length octets, invalid sequences)
- Vector 3: Multi-block PEM audit (mixed certs, keys, public keys, corrupted blocks)
- Vector 4: ReDoS immunity (50,000 - 100,000 repetitive characters on all regexes)
- Vector 5: Cryptographic parameter boundaries (PBKDF2/Scrypt iteration limits, dklen, token lengths)
- Vector 6: Path confinement and symlink security escapes
- Vector 7: 10 MB payload boundaries (UTF-8 multi-byte and disk files)
- Vector 8: Credential masking verification (zero cleartext leaks)
"""

import base64
import hashlib
import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from operator_modules.op_secret_scanner import (
    MAX_INPUT_BYTES,
    PEM_BLOCK_RE,
    SECRET_PATTERNS,
    _inspect_key_der,
    _parse_der_tlv,
    secret_scanner,
    shannon_entropy,
)
from tests.test_op_secret_scanner import SAMPLE_CERT_PEM, SAMPLE_RSA_KEY_PEM


class TestOpSecretScannerAdversarial(unittest.TestCase):
    """Empirical adversarial test suite for secret_scanner."""

    # =========================================================================
    # Vector 1: Entropy Threshold Edge Cases & Adaptive Charset
    # =========================================================================

    def test_v1_01_random_hex_md5_and_sha256_detection(self):
        """Verify adaptive threshold detects 32-char MD5 and 64-char SHA256 under default."""
        md5_token = hashlib.md5(b"adversarial_probe_md5").hexdigest()
        sha256_token = hashlib.sha256(b"adversarial_probe_sha256").hexdigest()

        # MD5
        res_md5 = secret_scanner({"action": "scan_entropy", "text": f"md5_hash = '{md5_token}'"})
        self.assertTrue(res_md5["ok"])
        self.assertFalse(res_md5["data"]["clean"])
        self.assertEqual(res_md5["data"]["findings_count"], 1)
        self.assertEqual(res_md5["data"]["findings"][0]["charset"], "hex")

        # SHA256
        res_sha = secret_scanner({"action": "scan_entropy", "text": f"sha256_hash = '{sha256_token}'"})
        self.assertTrue(res_sha["ok"])
        self.assertFalse(res_sha["data"]["clean"])
        self.assertEqual(res_sha["data"]["findings_count"], 1)
        self.assertEqual(res_sha["data"]["findings"][0]["charset"], "hex")

    def test_v1_02_hex_charset_filter_strictness(self):
        """Charset filter 'hex' must ignore high-entropy base64 tokens."""
        b64_token = base64.b64encode(os.urandom(32)).decode()
        res = secret_scanner({
            "action": "scan_entropy",
            "text": f"token = '{b64_token}'",
            "charset": "hex",
        })
        self.assertTrue(res["ok"])
        # If the b64 token contains non-hex chars (+, /, uppercase beyond F), hex filter skips it
        if any(c.lower() not in "0123456789abcdef" for c in b64_token.rstrip("=")):
            self.assertEqual(res["data"]["findings_count"], 0)

    def test_v1_03_normalized_entropy_extremes(self):
        """Normalized Shannon entropy: 0.0 for uniform, 1.0 for all distinct."""
        self.assertEqual(shannon_entropy("", normalize=True), 0.0)
        self.assertEqual(shannon_entropy("A" * 100, normalize=True), 0.0)
        self.assertAlmostEqual(shannon_entropy("abcdefghij", normalize=True), 1.0, places=5)

    def test_v1_04_sliding_window_zero_window_or_step(self):
        """Zero or negative window_size and step must not crash or hang."""
        res_zero_win = secret_scanner({
            "action": "scan_entropy",
            "text": "abcdefghijklmnopqrstuvwxyz0123456789",
            "window_size": 0,
        })
        self.assertTrue(res_zero_win["ok"])

        res_neg_step = secret_scanner({
            "action": "scan_entropy",
            "text": "abcdefghijklmnopqrstuvwxyz0123456789",
            "step": -5,
            "mode": "sliding_window",
        })
        self.assertTrue(res_neg_step["ok"])

    # =========================================================================
    # Vector 2: ASN.1 DER Parser Robustness
    # =========================================================================

    def test_v2_01_der_tlv_truncated_and_invalid_lengths(self):
        """_parse_der_tlv must return None on truncated or malformed octets without crashing."""
        self.assertIsNone(_parse_der_tlv(b""))
        self.assertIsNone(_parse_der_tlv(b"\x30"))
        self.assertIsNone(_parse_der_tlv(b"\x30\x82"))
        self.assertIsNone(_parse_der_tlv(b"\x30\x84\x7f\xff\xff\xff"))
        self.assertIsNone(_parse_der_tlv(b"\x30\x80"))  # Indefinite length byte
        self.assertIsNone(_parse_der_tlv(b"\x30\x05\x01\x02"))  # Length claims 5, only 2 remain

    def test_v2_02_inspect_key_der_corrupted_roots(self):
        """_inspect_key_der must safely report invalid DER root sequence."""
        res_non_seq = _inspect_key_der(b"\x02\x01\x00", "RSA PRIVATE KEY")
        self.assertFalse(res_non_seq["valid"])
        self.assertIn("Invalid DER", res_non_seq["error"])

        res_trunc = _inspect_key_der(b"\x30\x05\x02\x01", "RSA PRIVATE KEY")
        self.assertFalse(res_trunc["valid"])

    def test_v2_03_deeply_nested_der_sequences(self):
        """Nested DER sequences must parse without RecursionError or crash."""
        nested = b"\x02\x01\x00"
        for _ in range(50):
            nested = b"\x30\x82" + (len(nested)).to_bytes(2, "big") + nested
        res = _inspect_key_der(nested, "PRIVATE KEY")
        self.assertIsInstance(res, dict)

    # =========================================================================
    # Vector 3: Multi-Block Mixed PEM Processing
    # =========================================================================

    def test_v3_01_mixed_cert_and_private_key_bundle(self):
        """Mixed bundle containing both X.509 cert and RSA private key must identify both."""
        bundle = f"{SAMPLE_CERT_PEM}\n{SAMPLE_RSA_KEY_PEM}"
        res = secret_scanner({"action": "audit_pem", "text": bundle})
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["blocks_count"], 2)
        self.assertTrue(res["data"]["has_private_key"])
        types = [b["block_type"] for b in res["data"]["blocks"]]
        self.assertIn("CERTIFICATE", types)
        self.assertIn("RSA PRIVATE KEY", types)

    def test_v3_02_public_key_and_cert_bundle(self):
        """Bundle containing Public Key and Certificate must process successfully."""
        pub_der = b"\x30\x12\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x07\x2a\x86\x48\xce\x3d\x02\x01"
        pub_pem = f"-----BEGIN PUBLIC KEY-----\n{base64.b64encode(pub_der).decode()}\n-----END PUBLIC KEY-----\n"
        bundle = f"{pub_pem}\n{SAMPLE_CERT_PEM}"
        res = secret_scanner({"action": "audit_pem", "text": bundle})
        self.assertTrue(res["ok"])
        self.assertEqual(res["data"]["blocks_count"], 2)

    # =========================================================================
    # Vector 4: ReDoS Stress Testing (50,000 - 100,000 Repetitive Characters)
    # =========================================================================

    def test_v4_01_redos_resistance_against_all_secret_patterns(self):
        """All regex patterns in SECRET_PATTERNS must complete in < 0.05s on 100k strings."""
        payloads = [
            "A" * 100_000,
            "-" * 100_000,
            "\"" * 100_000,
            "AKIA" + "A" * 100_000,
            "sk-proj-" + "a" * 100_000,
            "xoxb-" + "1" * 100_000,
            "eyJ" + "A" * 50_000 + "." + "B" * 50_000,
            "api_key = \"" + "A" * 100_000,
            "aws_secret_access_key = \"" + "A" * 100_000,
        ]

        for p_name, (regex, _, _) in SECRET_PATTERNS.items():
            for text in payloads:
                t0 = time.perf_counter()
                list(regex.finditer(text))
                dt = time.perf_counter() - t0
                self.assertLess(dt, 0.05, f"ReDoS vulnerability in {p_name}: took {dt:.4f}s")

    def test_v4_02_pem_block_regex_unclosed_boundary_redos(self):
        """Unclosed PEM block with 100k chars must not cause exponential backtracking."""
        unclosed = "-----BEGIN CERTIFICATE-----\n" + ("A" * 100_000)
        t0 = time.perf_counter()
        matches = list(PEM_BLOCK_RE.finditer(unclosed))
        dt = time.perf_counter() - t0
        self.assertLess(dt, 0.05)
        self.assertEqual(len(matches), 0)

    # =========================================================================
    # Vector 5: Cryptographic Parameter Bounds
    # =========================================================================

    def test_v5_01_pbkdf2_iteration_bounds(self):
        """PBKDF2 iteration bounds: reject > 1M, reject < 1000, reject negative/zero."""
        # Above max (1,000,001)
        r1 = secret_scanner({"action": "crypto_utils", "operation": "derive_key", "password": "p", "iterations": 1_000_001})
        self.assertFalse(r1["ok"])
        self.assertIn("exceeds safety limits", r1["error"])

        # Below min (999)
        r2 = secret_scanner({"action": "crypto_utils", "operation": "derive_key", "password": "p", "iterations": 999})
        self.assertFalse(r2["ok"])

        # Zero
        r3 = secret_scanner({"action": "crypto_utils", "operation": "derive_key", "password": "p", "iterations": 0})
        self.assertFalse(r3["ok"])

        # Negative
        r4 = secret_scanner({"action": "crypto_utils", "operation": "derive_key", "password": "p", "iterations": -100})
        self.assertFalse(r4["ok"])

    def test_v5_02_dklen_bounds(self):
        """dklen bounds: 16 to 128 bytes."""
        r_low = secret_scanner({"action": "crypto_utils", "operation": "derive_key", "password": "p", "dklen": 15})
        self.assertFalse(r_low["ok"])

        r_high = secret_scanner({"action": "crypto_utils", "operation": "derive_key", "password": "p", "dklen": 129})
        self.assertFalse(r_high["ok"])

        r_valid = secret_scanner({"action": "crypto_utils", "operation": "derive_key", "password": "p", "dklen": 64})
        self.assertTrue(r_valid["ok"])
        self.assertEqual(len(bytes.fromhex(r_valid["data"]["derived_key_hex"])), 64)

    def test_v5_03_token_generation_bounds(self):
        """Token generator nbytes bounds: 8 to 1024 bytes."""
        r_low = secret_scanner({"action": "crypto_utils", "operation": "generate_token", "nbytes": 7})
        self.assertFalse(r_low["ok"])

        r_high = secret_scanner({"action": "crypto_utils", "operation": "generate_token", "nbytes": 1025})
        self.assertFalse(r_high["ok"])

        r_neg = secret_scanner({"action": "crypto_utils", "operation": "generate_token", "nbytes": -5})
        self.assertFalse(r_neg["ok"])

        r_valid = secret_scanner({"action": "crypto_utils", "operation": "generate_token", "nbytes": 32})
        self.assertTrue(r_valid["ok"])

    def test_v5_04_constant_time_compare_digest_robustness(self):
        """compare_digest must safely compare differing types without throwing TypeError."""
        r1 = secret_scanner({"action": "crypto_utils", "operation": "compare_digest", "val_a": "token", "val_b": "token"})
        self.assertTrue(r1["ok"])
        self.assertTrue(r1["data"]["match"])

        r2 = secret_scanner({"action": "crypto_utils", "operation": "compare_digest", "val_a": 12345, "val_b": "12345"})
        self.assertTrue(r2["ok"])
        self.assertTrue(r2["data"]["match"])

        r3 = secret_scanner({"action": "crypto_utils", "operation": "compare_digest", "val_a": None, "val_b": None})
        self.assertTrue(r3["ok"])
        self.assertTrue(r3["data"]["match"])

    # =========================================================================
    # Vector 6: Path Confinement & Symlink Traversal
    # =========================================================================

    def test_v6_01_path_traversal_and_symlinks(self):
        """Verify strict rejection of path traversal, symlink escapes, and sensitive files."""
        tmp_dir = Path(tempfile.mkdtemp(prefix="adv_test_ss_"))
        try:
            safe_file = tmp_dir / "safe.txt"
            safe_file.write_text("safe content")

            # Symlink to /etc/passwd
            sym_etc = tmp_dir / "sym_etc"
            try:
                sym_etc.symlink_to("/etc/passwd")
            except OSError:
                pass

            # Mock sensitive .ssh dir
            ssh_dir = tmp_dir / ".ssh"
            ssh_dir.mkdir()
            mock_id = ssh_dir / "id_rsa"
            mock_id.write_text("private key mock")
            sym_ssh = tmp_dir / "sym_ssh"
            sym_ssh.symlink_to(mock_id)

            # Circular symlink
            circ = tmp_dir / "circular"
            try:
                circ.symlink_to(circ)
            except OSError:
                pass

            # 1. Traversal outside allowed roots
            r1 = secret_scanner({"action": "scan_entropy", "path": f"{tmp_dir}/../../../../etc/passwd"})
            self.assertFalse(r1["ok"])
            self.assertIn("PathSecurityError", r1["error"])

            # 2. Symlink to /etc/passwd
            if sym_etc.exists():
                r2 = secret_scanner({"action": "scan_entropy", "path": str(sym_etc)})
                self.assertFalse(r2["ok"])
                self.assertIn("PathSecurityError", r2["error"])

            # 3. Symlink to sensitive .ssh/id_rsa
            r3 = secret_scanner({"action": "scan_entropy", "path": str(sym_ssh)})
            self.assertFalse(r3["ok"])
            self.assertIn("SensitivePathError", r3["error"])

            # 4. Null byte in path
            r4 = secret_scanner({"action": "scan_entropy", "path": f"{safe_file}\0evil.txt"})
            self.assertFalse(r4["ok"])
            self.assertIn("PathSecurityError", r4["error"])

            # 5. Circular symlink
            r5 = secret_scanner({"action": "scan_entropy", "path": str(circ)})
            self.assertFalse(r5["ok"])

        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    # =========================================================================
    # Vector 7: 10 MB Payload Boundary Enforcement
    # =========================================================================

    def test_v7_01_payload_size_boundary(self):
        """Ensure inputs exceeding MAX_INPUT_BYTES (10 MB) are rejected."""
        # 10 MB + 1 byte inline text
        big_text = "a" * (MAX_INPUT_BYTES + 1)
        r_text = secret_scanner({"action": "scan_entropy", "text": big_text})
        self.assertFalse(r_text["ok"])
        self.assertIn("PayloadSizeError", r_text["error"])

        # Multi-byte UTF-8 boundary
        unicode_text = "\u4e00" * 3_500_000  # 3.5M chars * 3 bytes = 10.5 MB
        r_uni = secret_scanner({"action": "scan_entropy", "text": unicode_text})
        self.assertFalse(r_uni["ok"])
        self.assertIn("PayloadSizeError", r_uni["error"])

    # =========================================================================
    # Vector 8: Credential Masking & Cleartext Token Verification
    # =========================================================================

    def test_v8_01_cleartext_tokens_never_leaked(self):
        """Tokens and secrets must never be exposed unredacted in outputs."""
        sensitive_cases = [
            ("AKIAAAAAAAAAAAAAAAAA", "export AWS_KEY=AKIAAAAAAAAAAAAAAAAA"),
            ("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "aws_secret_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"),
            ("ghp_000000000000000000000000000000000000", "github_token = 'ghp_000000000000000000000000000000000000'"),
            ("sk-000000000000000000000000000000", "api_key = 'sk-000000000000000000000000000000'"),
            ("xoxb-xxxxxxxxxxxxxxxxxxxxxxxx", "slack_token = 'xoxb-xxxxxxxxxxxxxxxxxxxxxxxx'"),
        ]

        for token, line in sensitive_cases:
            # Pattern scan
            r_pat = secret_scanner({"action": "scan_patterns", "text": line})
            dumped_pat = json.dumps(r_pat)
            self.assertNotIn(token, dumped_pat, f"Cleartext leak in pattern scan for {token}")

            # Entropy scan
            r_ent = secret_scanner({"action": "scan_entropy", "text": line})
            dumped_ent = json.dumps(r_ent)
            self.assertNotIn(token, dumped_ent, f"Cleartext leak in entropy scan for {token}")


if __name__ == "__main__":
    unittest.main()
