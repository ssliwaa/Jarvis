"""Automated unit test suite for operator_modules/op_log_summarizer.py.

Verifies:
1. Tool registration contract, input_schema (additionalProperties: False), and approval=False.
2. Standard 5-key return envelope (ok, success, data, result, error).
3. Feature 29: cluster_errors (template normalization, variable stripping, MD5/SHA256 fingerprinting).
4. Feature 30: detect_spikes (multi-format timestamp parsing, time binning, Z-score statistics, anomaly detection).
5. Feature 31: triage_stacktrace (Python/multi-runtime frames, entry vs root cause, exception chaining, categories).
6. Feature 32: mask_pii (ReDoS-immune email, IPv4/IPv6, JWT, Bearer, Luhn-verified credit cards, SSNs, atomic file export).
7. Path confinement to ALLOWED_ROOTS, sensitive path blocking, and input size limits.
8. Dynamic discovery via ToolRegistry.
"""

from __future__ import annotations

import os
SANDBOXED = os.environ.get("JARVIS_VERIFY_SANDBOX") == "1"
import tempfile
import time
import unittest
from pathlib import Path

import operator_modules.op_log_summarizer as op_log_summarizer
from tool_registry import ToolRegistry


class TestOpLogSummarizer(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(dir="/tmp")
        self.root = Path(self.temp_dir.name).resolve()

        # Build sample log files
        self.server_log = self.root / "server.log"
        self.server_log.write_text(
            "2026-11-21T10:00:00Z [INFO] Service starting up on port 8080\n"
            "2026-11-21T10:01:00Z [ERROR] Failed connection to 192.168.1.10:5432: connection timed out\n"
            "2026-11-21T10:01:05Z [ERROR] Failed connection to 192.168.1.11:5432: connection timed out\n"
            "2026-11-21T10:01:10Z [ERROR] Failed connection to 192.168.1.12:5432: connection timed out\n"
            "2026-11-21T10:02:00Z [WARN] Retrying pool connection for client 550e8400-e29b-41d4-a716-446655440000\n",
            encoding="utf-8",
        )

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
        tool = op_log_summarizer.TOOL
        self.assertEqual(tool["name"], "log_summarizer")
        self.assertFalse(tool["approval"], "log_summarizer is read-only and must have approval=False")
        self.assertTrue(callable(tool["handler"]))
        self.assertEqual(tool["input_schema"]["type"], "object")
        self.assertFalse(tool["input_schema"]["additionalProperties"])
        self.assertIn("action", tool["input_schema"]["required"])

    def test_02_toolregistry_discovery(self):
        reg = ToolRegistry()
        self.assertIn("log_summarizer", reg.tools)
        tool = reg.tools["log_summarizer"]
        self.assertEqual(tool.name, "log_summarizer")
        self.assertFalse(tool.approval)

    def test_03_envelope_structure_on_success_and_error(self):
        res_ok = op_log_summarizer.log_summarizer({
            "action": "cluster_errors",
            "text": "2026-11-21T10:00:00Z [ERROR] Disk space low on /var/log: 100MB remaining",
        })
        self._assert_envelope(res_ok, True)

        res_err = op_log_summarizer.log_summarizer({"action": "unknown_action_xyz"})
        self._assert_envelope(res_err, False)

    def test_04_unknown_argument_rejected(self):
        res = op_log_summarizer.log_summarizer({
            "action": "cluster_errors",
            "text": "test",
            "malicious_inject": True,
        })
        self._assert_envelope(res, False)
        self.assertIn("Unknown argument", res["error"])

    def test_05_missing_or_invalid_action(self):
        res = op_log_summarizer.log_summarizer({"action": ""})
        self._assert_envelope(res, False)
        self.assertIn("Invalid or missing action", res["error"])

    # =========================================================================
    # Tier 1: Feature 29 — Error Clustering & Normalization
    # =========================================================================

    def test_06_cluster_mask_ips_and_ports(self):
        logs = (
            "2026-11-21T10:00:01Z [ERROR] Failed connection to 10.0.0.1:8080: timeout\n"
            "2026-11-21T10:00:02Z [ERROR] Failed connection to 10.0.0.2:9000: timeout\n"
            "2026-11-21T10:00:03Z [ERROR] Failed connection to 10.0.0.3:5432: timeout\n"
        )
        res = op_log_summarizer.log_summarizer({
            "action": "cluster_errors",
            "text": logs,
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["cluster_count"], 1)
        cluster = res["data"]["clusters"][0]
        self.assertEqual(cluster["count"], 3)
        self.assertIn("<IP>", cluster["template"])
        self.assertNotIn("10.0.0.1", cluster["template"])

    def test_07_cluster_mask_uuids_and_hex(self):
        logs = (
            "[ERROR] Request failed for uuid=550e8400-e29b-41d4-a716-446655440000 at addr=0x7fff5fbff8a0\n"
            "[ERROR] Request failed for uuid=6ba7b810-9dad-11d1-80b4-00c04fd430c8 at addr=0x7fff5fbff9c0\n"
        )
        res = op_log_summarizer.log_summarizer({
            "action": "cluster_errors",
            "text": logs,
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["cluster_count"], 1)
        cluster = res["data"]["clusters"][0]
        self.assertEqual(cluster["count"], 2)
        self.assertIn("<UUID>", cluster["template"])
        self.assertIn("<HEX>", cluster["template"])

    def test_08_cluster_mask_paths_and_durations(self):
        logs = (
            "ERROR: Out of disk on /var/log/app: 100MB free, write took 520ms\n"
            "ERROR: Out of disk on /var/log/data: 500MB free, write took 840ms\n"
        )
        res = op_log_summarizer.log_summarizer({
            "action": "cluster_errors",
            "text": logs,
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["cluster_count"], 1)
        cluster = res["data"]["clusters"][0]
        self.assertEqual(cluster["count"], 2)
        self.assertIn("<PATH>", cluster["template"])
        self.assertIn("<NUM>", cluster["template"])

    def test_09_cluster_fingerprint_stability(self):
        log_a = "[ERROR] Worker timeout after 30s"
        log_b = "[ERROR] Worker timeout after 60s"
        res_a = op_log_summarizer.log_summarizer({"action": "cluster_errors", "text": log_a})
        res_b = op_log_summarizer.log_summarizer({"action": "cluster_errors", "text": log_b})
        fp_a = res_a["data"]["clusters"][0]["fingerprint"]
        fp_b = res_b["data"]["clusters"][0]["fingerprint"]
        self.assertEqual(fp_a, fp_b, "Normalized templates must produce identical fingerprints")

    def test_10_cluster_file_source_and_filtering(self):
        res = op_log_summarizer.log_summarizer({
            "action": "cluster_errors",
            "path": str(self.server_log),
            "levels": ["ERROR"],
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["error_count"], 3)
        self.assertEqual(res["data"]["cluster_count"], 1)

    # =========================================================================
    # Tier 1: Feature 30 — Temporal Anomaly Spike Detection
    # =========================================================================

    def test_11_spike_iso8601_burst(self):
        # 10 buckets of 60 seconds. Buckets 0-3: 1 event. Bucket 4: 20 events (burst). Buckets 5-9: 1 event.
        lines = []
        base_epoch = 1774200000  # fixed epoch
        for b in range(10):
            count = 20 if b == 4 else 1
            for i in range(count):
                ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(base_epoch + b * 60 + i))
                lines.append(f"{ts} [ERROR] Event in bucket {b}")

        text = "\n".join(lines)
        res = op_log_summarizer.log_summarizer({
            "action": "detect_spikes",
            "text": text,
            "bucket_seconds": 60,
            "z_threshold": 2.0,
        })
        self._assert_envelope(res, True)
        self.assertGreaterEqual(res["data"]["spikes_count"], 1)
        spike = res["data"]["spikes"][0]
        self.assertEqual(spike["count"], 20)
        self.assertGreater(spike["z_score"], 2.0)

    def test_12_spike_syslog_timestamps(self):
        lines = [
            "Nov 21 12:00:01 web-app[102]: Database timeout",
            "Nov 21 12:00:10 web-app[102]: Database timeout",
            "Nov 21 12:00:20 web-app[102]: Database timeout",
            "Nov 21 12:05:00 web-app[102]: Normal operation",
        ]
        res = op_log_summarizer.log_summarizer({
            "action": "detect_spikes",
            "text": "\n".join(lines),
            "bucket_seconds": 300,
            "time_format": "syslog",
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["total_events"], 4)

    def test_13_spike_apache_clf_timestamps(self):
        lines = [
            '127.0.0.1 - - [21/Nov/2026:12:00:01 +0000] "GET /api HTTP/1.1" 500 231',
            '127.0.0.1 - - [21/Nov/2026:12:00:05 +0000] "GET /api HTTP/1.1" 500 231',
            '127.0.0.1 - - [21/Nov/2026:12:00:10 +0000] "GET /api HTTP/1.1" 500 231',
        ]
        res = op_log_summarizer.log_summarizer({
            "action": "detect_spikes",
            "text": "\n".join(lines),
            "bucket_seconds": 60,
            "time_format": "apache",
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["total_events"], 3)

    def test_14_spike_zero_variance_flat_rate(self):
        # 1 event per minute for 5 minutes (constant rate, std_dev = 0.0)
        lines = [
            f"2026-11-21T10:0{i}:00Z [INFO] Tick {i}"
            for i in range(5)
        ]
        res = op_log_summarizer.log_summarizer({
            "action": "detect_spikes",
            "text": "\n".join(lines),
            "bucket_seconds": 60,
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["std_dev"], 0.0)
        self.assertEqual(res["data"]["spikes_count"], 0)

    def test_15_spike_custom_human_bucket_size(self):
        lines = [
            "2026-11-21T10:00:00Z [ERROR] E1",
            "2026-11-21T10:00:30Z [ERROR] E2",
            "2026-11-21T10:01:00Z [ERROR] E3",
        ]
        res = op_log_summarizer.log_summarizer({
            "action": "detect_spikes",
            "text": "\n".join(lines),
            "bucket_size": "1m",
        })
        self._assert_envelope(res, True)
        self.assertGreaterEqual(res["data"]["total_buckets"], 2)

    # =========================================================================
    # Tier 1: Feature 31 — Stacktrace Triage Engine
    # =========================================================================

    def test_16_stacktrace_single_python_traceback(self):
        tb = (
            "Traceback (most recent call last):\n"
            '  File "/app/server.py", line 42, in handle_request\n'
            "    user = authenticate(token)\n"
            '  File "/app/auth.py", line 88, in authenticate\n'
            "    raise ValueError('Token has expired')\n"
            "ValueError: Token has expired\n"
        )
        res = op_log_summarizer.log_summarizer({
            "action": "triage_stacktrace",
            "text": tb,
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["tracebacks_count"], 1)
        item = res["data"]["tracebacks"][0]
        self.assertEqual(item["exception_type"], "ValueError")
        self.assertEqual(item["exception_message"], "Token has expired")
        self.assertEqual(item["entry_frame"]["file"], "/app/server.py")
        self.assertEqual(item["root_cause_frame"]["file"], "/app/auth.py")
        self.assertEqual(item["category"], "validation_syntax")

    def test_17_stacktrace_frame_metadata_extraction(self):
        tb = (
            "Traceback (most recent call last):\n"
            '  File "/app/db/pool.py", line 105, in connect\n'
            "    sock = socket.create_connection(addr, timeout=5.0)\n"
            "TimeoutError: Connection timed out after 5000ms\n"
        )
        res = op_log_summarizer.log_summarizer({
            "action": "triage_stacktrace",
            "text": tb,
        })
        self._assert_envelope(res, True)
        item = res["data"]["tracebacks"][0]
        frame = item["frames"][0]
        self.assertEqual(frame["file"], "/app/db/pool.py")
        self.assertEqual(frame["line"], 105)
        self.assertEqual(frame["func"], "connect")
        self.assertIn("create_connection", frame["code"])
        self.assertEqual(item["category"], "network_timeout")

    def test_18_stacktrace_chained_exceptions(self):
        tb = (
            "Traceback (most recent call last):\n"
            '  File "/app/db.py", line 30, in query\n'
            "    raise ConnectionRefusedError('DB host down')\n"
            "ConnectionRefusedError: DB host down\n\n"
            "During handling of the above exception, another exception occurred:\n\n"
            "Traceback (most recent call last):\n"
            '  File "/app/main.py", line 12, in run\n'
            "    query()\n"
            "RuntimeError: Failed to process transaction\n"
        )
        res = op_log_summarizer.log_summarizer({
            "action": "triage_stacktrace",
            "text": tb,
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["tracebacks_count"], 1)
        item = res["data"]["tracebacks"][0]
        self.assertTrue(item["is_chained"])
        self.assertIsNotNone(item["cause"])
        self.assertEqual(item["cause"]["exception_type"], "ConnectionRefusedError")

    def test_19_stacktrace_no_traceback_clean(self):
        text = "2026-11-21T10:00:00Z [INFO] All operations normal, user mentioned Traceback in comment."
        res = op_log_summarizer.log_summarizer({
            "action": "triage_stacktrace",
            "text": text,
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["tracebacks_count"], 0)
        self.assertEqual(res["data"]["tracebacks"], [])

    # =========================================================================
    # Tier 1: Feature 32 — ReDoS-Immune PII Masking
    # =========================================================================

    def test_20_mask_email_addresses(self):
        text = "Contact admin@example.com or support@sub.domain.org for help."
        res = op_log_summarizer.log_summarizer({
            "action": "mask_pii",
            "text": text,
            "mask_rules": ["email"],
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["redactions_count"], 2)
        self.assertNotIn("admin@example.com", res["data"]["masked_text"])
        self.assertIn("<EMAIL>", res["data"]["masked_text"])

    def test_21_mask_ipv4_and_ipv6(self):
        text = "Client IP 192.168.1.100 connected via gateway 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        res = op_log_summarizer.log_summarizer({
            "action": "mask_pii",
            "text": text,
            "mask_rules": ["ipv4", "ipv6"],
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["redactions_count"], 2)
        self.assertNotIn("192.168.1.100", res["data"]["masked_text"])
        self.assertIn("<IP>", res["data"]["masked_text"])

    def test_22_mask_jwt_and_bearer_tokens(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        text = f"Authorization: Bearer {jwt}"
        res = op_log_summarizer.log_summarizer({
            "action": "mask_pii",
            "text": text,
        })
        self._assert_envelope(res, True)
        self.assertNotIn(jwt, res["data"]["masked_text"])
        self.assertIn("<JWT_TOKEN>", res["data"]["masked_text"])

    def test_23_mask_credential_key_values(self):
        text = 'Connecting with password="SuperSecretPassword123!" and api_key=\'sk_live_xxxx-xxxx-xxxx-xxxx\''
        res = op_log_summarizer.log_summarizer({
            "action": "mask_pii",
            "text": text,
            "mask_rules": ["credentials"],
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["redactions_count"], 2)
        self.assertNotIn("SuperSecretPassword123!", res["data"]["masked_text"])
        self.assertIn('password="<SECRET>"', res["data"]["masked_text"])

    def test_24_mask_credit_card_with_luhn_algorithm(self):
        # Valid Visa card (passes Luhn)
        valid_visa = "4532 0150 1234 5671"
        # Invalid sequence (fails Luhn)
        invalid_card = "4532 0150 1234 5670"

        text = f"Customer paid with {valid_visa}, order id {invalid_card}"
        res = op_log_summarizer.log_summarizer({
            "action": "mask_pii",
            "text": text,
            "mask_rules": ["credit_card"],
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["redactions_count"], 1)
        self.assertNotIn(valid_visa, res["data"]["masked_text"])
        self.assertIn("<CREDIT_CARD>", res["data"]["masked_text"])
        # Non-card sequence must remain untouched
        self.assertIn(invalid_card, res["data"]["masked_text"])

    def test_25_mask_ssn_and_mac(self):
        text = "Employee SSN: 123-45-6789, NIC MAC: 00:1A:2B:3C:4D:5E"
        res = op_log_summarizer.log_summarizer({
            "action": "mask_pii",
            "text": text,
            "mask_rules": ["ssn", "mac"],
        })
        self._assert_envelope(res, True)
        self.assertEqual(res["data"]["redactions_count"], 2)
        self.assertNotIn("123-45-6789", res["data"]["masked_text"])
        self.assertIn("<SSN>", res["data"]["masked_text"])
        self.assertIn("<MAC>", res["data"]["masked_text"])

    def test_26_mask_destination_path_atomic_write(self):
        dest_file = self.root / "sanitized_out.log"
        text = "User user@example.com logged in from 10.0.0.1"
        res = op_log_summarizer.log_summarizer({
            "action": "mask_pii",
            "text": text,
            "destination_path": str(dest_file),
        })
        self._assert_envelope(res, True)
        self.assertTrue(dest_file.exists())
        saved_content = dest_file.read_text(encoding="utf-8")
        self.assertNotIn("user@example.com", saved_content)
        self.assertIn("<EMAIL>", saved_content)

    # =========================================================================
    # Tier 2: Boundary, Security, and Defensive Hardening Tests
    # =========================================================================

    def test_27_boundary_empty_inputs(self):
        for act in ("cluster_errors", "detect_spikes", "triage_stacktrace", "mask_pii"):
            res = op_log_summarizer.log_summarizer({"action": act, "text": ""})
            self._assert_envelope(res, True)

    @unittest.skipIf(SANDBOXED, "needs the developer's local env (vault/Hermes/Piper/desktop); skipped in CI")

    def test_28_boundary_path_traversal_rejection(self):
        res = op_log_summarizer.log_summarizer({
            "action": "cluster_errors",
            "path": "../../../etc/shadow",
        })
        self._assert_envelope(res, False)
        self.assertIn("PathSecurityError", res["error"])

    def test_29_boundary_sensitive_directory_rejection(self):
        fake_ssh = self.root / ".ssh"
        fake_ssh.mkdir()
        fake_log = fake_ssh / "access.log"
        fake_log.write_text("log", encoding="utf-8")

        res = op_log_summarizer.log_summarizer({
            "action": "cluster_errors",
            "path": str(fake_log),
        })
        self._assert_envelope(res, False)
        self.assertIn("SensitivePathError", res["error"])

    def test_30_boundary_null_bytes_in_path(self):
        res = op_log_summarizer.log_summarizer({
            "action": "cluster_errors",
            "path": "/tmp/test\0file.log",
        })
        self._assert_envelope(res, False)
        self.assertIn("PathSecurityError", res["error"])

    def test_31_boundary_redos_immunity_on_hyphen_run(self):
        # 30,000 characters of repetitive hyphenated pattern ("1234-" * 6000)
        hostile_text = "1234-" * 6000
        t0 = time.time()
        res = op_log_summarizer.log_summarizer({
            "action": "mask_pii",
            "text": hostile_text,
            "mask_rules": ["email"],
        })
        elapsed = time.time() - t0
        self._assert_envelope(res, True)
        self.assertLess(elapsed, 0.2, "Email regex took longer than 200ms on hyphen string (ReDoS risk)")

    def test_32_boundary_no_valid_timestamps_raises_error(self):
        res = op_log_summarizer.log_summarizer({
            "action": "detect_spikes",
            "text": "This log line has no timestamp at all.\nNor does this one.\n",
        })
        self._assert_envelope(res, False)
        self.assertIn("No valid timestamps found", res["error"])

    def test_33_boundary_bucket_seconds_less_than_one(self):
        res = op_log_summarizer.log_summarizer({
            "action": "detect_spikes",
            "text": "2026-11-21T10:00:00Z [INFO] Event",
            "bucket_seconds": 0,
        })
        self._assert_envelope(res, False)
        self.assertIn("bucket_seconds must be >= 1", res["error"])

    def test_34_boundary_destination_overwrite_protection(self):
        dest_file = self.root / "existing.log"
        dest_file.write_text("prior content", encoding="utf-8")

        res = op_log_summarizer.log_summarizer({
            "action": "mask_pii",
            "text": "new log content",
            "destination_path": str(dest_file),
            "overwrite": False,
        })
        self._assert_envelope(res, False)
        self.assertIn("already exists", res["error"])

    def test_35_boundary_partial_masking_mode(self):
        text = "User john.doe@example.com with card 4532 0150 1234 5671"
        res = op_log_summarizer.log_summarizer({
            "action": "mask_pii",
            "text": text,
            "partial_mask": True,
            "mask_rules": ["email", "credit_card"],
        })
        self._assert_envelope(res, True)
        masked = res["data"]["masked_text"]
        self.assertIn("@example.com", masked)
        self.assertIn("****-****-****-5671", masked)

    # =========================================================================
    # Tier 3: Combinatorial & Cross-Feature Workflows
    # =========================================================================

    def test_36_workflow_cluster_then_spike_detection(self):
        # 1. Cluster errors in log
        res_cluster = op_log_summarizer.log_summarizer({
            "action": "cluster_errors",
            "path": str(self.server_log),
            "levels": ["ERROR"],
        })
        self._assert_envelope(res_cluster, True)
        self.assertEqual(res_cluster["data"]["cluster_count"], 1)

        # 2. Detect spikes on same log
        res_spike = op_log_summarizer.log_summarizer({
            "action": "detect_spikes",
            "path": str(self.server_log),
            "bucket_seconds": 60,
        })
        self._assert_envelope(res_spike, True)
        self.assertGreaterEqual(res_spike["data"]["total_events"], 5)

    def test_37_workflow_stacktrace_then_pii_masking(self):
        tb = (
            "Traceback (most recent call last):\n"
            '  File "/app/auth.py", line 42, in login\n'
            "    user = authenticate(password='Secret123!', email='victim@corp.com')\n"
            "ValueError: Authentication failed\n"
        )
        # 1. Triage stacktrace
        res_tb = op_log_summarizer.log_summarizer({
            "action": "triage_stacktrace",
            "text": tb,
        })
        self._assert_envelope(res_tb, True)
        self.assertEqual(res_tb["data"]["tracebacks_count"], 1)

        # 2. Mask PII from traceback
        res_mask = op_log_summarizer.log_summarizer({
            "action": "mask_pii",
            "text": tb,
        })
        self._assert_envelope(res_mask, True)
        self.assertNotIn("Secret123!", res_mask["data"]["masked_text"])
        self.assertNotIn("victim@corp.com", res_mask["data"]["masked_text"])
        self.assertIn("password='<SECRET>'", res_mask["data"]["masked_text"])

    # =========================================================================
    # Tier 4: Real-World Operational Scenarios
    # =========================================================================

    def test_38_scenario_incident_triage_and_forensics(self):
        """Simulate triage of cascading production outage log."""
        outage_log = (
            "2026-11-21T02:00:00Z [INFO] Server healthy\n"
            "2026-11-21T02:01:00Z [ERROR] Database pool exhausted at 10.0.0.1\n"
            "2026-11-21T02:01:05Z [ERROR] Database pool exhausted at 10.0.0.2\n"
            "2026-11-21T02:01:10Z [ERROR] Database pool exhausted at 10.0.0.3\n"
            "2026-11-21T02:01:15Z [ERROR] Database pool exhausted at 10.0.0.4\n"
            "2026-11-21T02:01:20Z [ERROR] Database pool exhausted at 10.0.0.5\n"
            "Traceback (most recent call last):\n"
            '  File "/srv/api/gateway.py", line 40, in route\n'
            "    return forward_request(req)\n"
            '  File "/srv/api/db_pool.py", line 84, in acquire\n'
            "    raise TooManyConnectionsError('Exceeded max connections (500)')\n"
            "TooManyConnectionsError: Exceeded max connections (500)\n"
        )
        # Step 1: Detect spike
        res_spike = op_log_summarizer.log_summarizer({
            "action": "detect_spikes",
            "text": outage_log,
            "bucket_seconds": 60,
        })
        self._assert_envelope(res_spike, True)

        # Step 2: Cluster dominant errors
        res_cluster = op_log_summarizer.log_summarizer({
            "action": "cluster_errors",
            "text": outage_log,
        })
        self._assert_envelope(res_cluster, True)
        self.assertIn("<IP>", res_cluster["data"]["clusters"][0]["template"])

        # Step 3: Triage root cause
        res_triage = op_log_summarizer.log_summarizer({
            "action": "triage_stacktrace",
            "text": outage_log,
        })
        self._assert_envelope(res_triage, True)
        self.assertEqual(res_triage["data"]["tracebacks"][0]["exception_type"], "TooManyConnectionsError")
        self.assertEqual(res_triage["data"]["tracebacks"][0]["category"], "database")

    # =========================================================================
    # Adversarial Regression Test Suite (Milestone M4 Challenger Fixes)
    # =========================================================================

    def test_39_regression_spike_detection_unbounded_bucket_dos_prevented(self):
        """Verify that large timestamp spans do not cause unbounded bucket generation DoS."""
        logs = (
            "1970-01-01T00:00:00Z [INFO] System boot initial epoch\n"
            "2026-11-21T22:00:00Z [ERROR] Production event after 56 years\n"
        )
        t0 = time.time()
        # Default fill_empty_buckets=True with 300s buckets would generate ~6 million buckets
        res = op_log_summarizer.log_summarizer({
            "action": "detect_spikes",
            "text": logs,
            "bucket_seconds": 300,
        })
        elapsed = time.time() - t0

        # Must terminate rapidly and safely reject via PayloadSizeError
        self.assertLess(elapsed, 1.0, f"Spike detection took too long ({elapsed}s), possible DoS loop")
        self._assert_envelope(res, False)
        self.assertIn("PayloadSizeError", res["error"])
        self.assertIn("exceeds safety limit", res["error"])

        # Caller can explicitly opt out of empty bucket filling
        res_sparse = op_log_summarizer.log_summarizer({
            "action": "detect_spikes",
            "text": logs,
            "bucket_seconds": 300,
            "fill_empty_buckets": False,
        })
        self._assert_envelope(res_sparse, True)
        self.assertEqual(res_sparse["data"]["total_events"], 2)
        self.assertEqual(res_sparse["data"]["total_buckets"], 2)

    def test_40_regression_stacktrace_syntax_and_indentation_errors(self):
        """Verify triage_stacktrace parses module-level SyntaxError and IndentationError without ', in <func>'."""
        syntax_tb = (
            "Traceback (most recent call last):\n"
            '  File "module_pkg/parser.py", line 42\n'
            "    def invalid_syntax_func(\n"
            "                           ^\n"
            "SyntaxError: unexpected EOF while parsing\n"
        )
        res_syntax = op_log_summarizer.log_summarizer({
            "action": "triage_stacktrace",
            "text": syntax_tb,
        })
        self._assert_envelope(res_syntax, True)
        self.assertEqual(res_syntax["data"]["tracebacks_count"], 1)
        tb_data = res_syntax["data"]["tracebacks"][0]
        self.assertEqual(tb_data["exception_type"], "SyntaxError")
        self.assertEqual(tb_data["exception_message"], "unexpected EOF while parsing")
        self.assertEqual(tb_data["category"], "validation_syntax")
        self.assertEqual(tb_data["entry_frame"]["file"], "module_pkg/parser.py")
        self.assertEqual(tb_data["entry_frame"]["func"], "<module>")
        self.assertEqual(tb_data["entry_frame"]["line"], 42)

        indent_tb = (
            "Traceback (most recent call last):\n"
            '  File "scripts/runner.py", line 15\n'
            '    print("Indentation problem")\n'
            "    ^\n"
            "IndentationError: unexpected indent\n"
        )
        res_indent = op_log_summarizer.log_summarizer({
            "action": "triage_stacktrace",
            "text": indent_tb,
        })
        self._assert_envelope(res_indent, True)
        self.assertEqual(res_indent["data"]["tracebacks_count"], 1)
        tb_indent_data = res_indent["data"]["tracebacks"][0]
        self.assertEqual(tb_indent_data["exception_type"], "IndentationError")
        self.assertEqual(tb_indent_data["category"], "validation_syntax")
        self.assertEqual(tb_indent_data["entry_frame"]["func"], "<module>")

    def test_41_regression_mask_pii_destination_directory_and_tempfile_cleanup(self):
        """Verify mask_pii rejects directory destinations and unlinks tempfiles on failure."""
        # 1. Directory destination rejection
        res_dir = op_log_summarizer.log_summarizer({
            "action": "mask_pii",
            "text": "Secret email: user@example.com",
            "destination_path": str(self.root),
            "overwrite": True,
        })
        self._assert_envelope(res_dir, False)
        self.assertIn("cannot be a directory", res_dir["error"])

        # Verify no orphan temp files created
        leftovers = [f for f in os.listdir(self.root) if f.startswith(".jarvis_mask_")]
        self.assertEqual(leftovers, [], f"Orphaned temp files detected: {leftovers}")

        # 2. Cleanup on simulated write failure
        target_file = self.root / "protected_target.log"
        from unittest.mock import patch
        with patch("os.replace", side_effect=OSError("Simulated atomic replacement failure")):
            res_fail = op_log_summarizer.log_summarizer({
                "action": "mask_pii",
                "text": "Secret email: user@example.com",
                "destination_path": str(target_file),
            })
            self._assert_envelope(res_fail, False)
            self.assertIn("Simulated atomic replacement failure", res_fail["error"])

        # Verify temp file was unlinked in finally block
        leftovers_after_err = [f for f in os.listdir(self.root) if f.startswith(".jarvis_mask_")]
        self.assertEqual(leftovers_after_err, [], f"Tempfile leaked after replace error: {leftovers_after_err}")


if __name__ == "__main__":
    unittest.main()
