"""Milestone M5: White-Box Tier 5 Adversarial Coverage Hardening Test Suite.

Adversarial stress-testing, boundary extremes, and uncovered branch verification
across all 8 zero-dependency Jarvis production operator modules:
1. op_net_probe.py (net_probe)
2. op_process_inspector.py (process_inspector)
3. op_archive_builder.py (archive_builder)
4. op_fs_analyzer.py (fs_analyzer)
5. op_tabular_data.py (tabular_data)
6. op_config_validator.py (config_validator)
7. op_secret_scanner.py (secret_scanner)
8. op_log_summarizer.py (log_summarizer)

Uses exclusively the Python standard library. 100% offline-reliable.
Enforces the standard 5-key return envelope on all tool invocations.
"""

from __future__ import annotations

import base64
import gzip
import json
import os
import socket
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import operator_modules.op_archive_builder as op_archive_builder
import operator_modules.op_config_validator as op_config_validator
import operator_modules.op_fs_analyzer as op_fs_analyzer
import operator_modules.op_log_summarizer as op_log_summarizer
import operator_modules.op_net_probe as op_net_probe
import operator_modules.op_process_inspector as op_process_inspector
import operator_modules.op_secret_scanner as op_secret_scanner
import operator_modules.op_tabular_data as op_tabular_data

# =============================================================================
# Shared Base Test Case
# =============================================================================

class BaseAdversarialTestCase(unittest.TestCase):
    """Base test case with standardized envelope validation and temp dir lifecycle."""

    def setUp(self):
        self.tmp_dir_obj = tempfile.TemporaryDirectory(prefix="jarvis_m5_adv_")
        self.tmp_dir = Path(self.tmp_dir_obj.name).resolve()

    def tearDown(self):
        try:
            self.tmp_dir_obj.cleanup()
        except Exception:
            pass

    def assert_envelope(self, res: dict, expected_ok: bool = True):
        """Assert compliance with the standard 5-key Jarvis operator envelope."""
        self.assertIsInstance(res, dict, f"Expected dict envelope, got {type(res).__name__}")
        for key in ("ok", "success", "data", "result", "error"):
            self.assertIn(key, res, f"Missing standard envelope key '{key}'")
        self.assertEqual(res["ok"], expected_ok, f"Expected ok={expected_ok}, got {res.get('ok')}: {res.get('error')}")
        self.assertEqual(res["success"], expected_ok, f"Expected success={expected_ok}, got {res.get('success')}")
        if expected_ok:
            self.assertIsNone(res["error"], f"Expected error=None on success, got {res.get('error')}")
            self.assertEqual(res["data"], res["result"])
        else:
            self.assertIsInstance(res["error"], str, f"Expected error string on failure, got {type(res.get('error'))}")
            self.assertGreater(len(res["error"]), 0)
            self.assertIsNone(res["data"])
            self.assertIsNone(res["result"])


# =============================================================================
# 1. op_net_probe Adversarial Tests
# =============================================================================

class TestM5NetProbeAdversarial(BaseAdversarialTestCase):
    """White-box Tier 5 adversarial hardening for op_net_probe."""

    def test_adv_tls_expired_cert_and_edge_dates(self):
        """Verify handling of expired TLS certs, negative days_remaining, and invalid dates."""
        mock_sock = MagicMock()
        mock_ssock = MagicMock()
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.getpeercert.return_value = {
            "notBefore": "Jan 01 00:00:00 2000 GMT",
            "notAfter": "Jan 01 00:00:00 2005 GMT",
            "subject": ((("commonName", "expired.example.com"),),),
            "issuer": ((("commonName", "Test CA"),),),
            "serialNumber": "A1B2C3D4",
        }

        with patch("socket.create_connection", return_value=mock_sock), \
             patch("ssl.SSLContext.wrap_socket", return_value=mock_ssock):
            res = op_net_probe.net_probe({
                "action": "cert_inspect",
                "host": "127.0.0.1",
                "port": 443,
                "allow_private": True,
            })
            self.assert_envelope(res, True)
            data = res["data"]
            self.assertTrue(data["expired"])
            self.assertIsNotNone(data["days_remaining"])
            self.assertLess(data["days_remaining"], 0)
            self.assertEqual(data["subject"].get("commonName"), "expired.example.com")

        # Test unparseable date strings in internal date parser
        iso_str, dt = op_net_probe._parse_cert_date("InvalidDateString123")
        self.assertEqual(iso_str, "InvalidDateString123")
        self.assertIsNone(dt)

    def test_adv_tls_complex_sans_and_empty_rdn(self):
        """Verify cert_inspect with mixed SAN types and empty/None RDN sequences."""
        mock_sock = MagicMock()
        mock_ssock = MagicMock()
        mock_ssock.version.return_value = "TLSv1.2"
        mock_ssock.cipher.return_value = ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128)
        mock_ssock.getpeercert.return_value = {
            "notBefore": "Jan 01 00:00:00 2026 GMT",
            "notAfter": "Dec 31 23:59:59 2028 GMT",
            "subject": (),
            "issuer": ((("organizationName", "Org"), ("commonName", "Root")),),
            "subjectAltName": (("DNS", "alt1.example.com"), ("IP Address", "192.168.1.1"), ("DNS", "alt2.example.com")),
        }

        with patch("socket.create_connection", return_value=mock_sock), \
             patch("ssl.SSLContext.wrap_socket", return_value=mock_ssock):
            res = op_net_probe.net_probe({
                "action": "cert_inspect",
                "host": "127.0.0.1",
                "port": 8443,
                "allow_private": True,
            })
            self.assert_envelope(res, True)
            data = res["data"]
            self.assertEqual(data["subject"], {})
            self.assertEqual(data["subject_alt_names"], ["alt1.example.com", "192.168.1.1", "alt2.example.com"])

        # Test RDN helper with None
        self.assertEqual(op_net_probe._format_rdn_sequence(None), {})

    def test_adv_tls_binary_der_fallback_when_unverified(self):
        """Verify binary DER fallback and PEM conversion when verify_peer=False and getpeercert() is empty."""
        fake_der = b"\x30\x82\x01\x0a" + b"\x00" * 200
        mock_sock = MagicMock()
        mock_ssock = MagicMock()
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.cipher.return_value = ("TLS_CHACHA20_POLY1305_SHA256", "TLSv1.3", 256)
        mock_ssock.getpeercert.side_effect = lambda binary_form=False: fake_der if binary_form else None

        with patch("socket.create_connection", return_value=mock_sock), \
             patch("ssl.SSLContext.wrap_socket", return_value=mock_ssock), \
             patch("ssl.DER_cert_to_PEM_cert", return_value="-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"):
            res = op_net_probe.net_probe({
                "action": "cert_inspect",
                "host": "127.0.0.1",
                "port": 443,
                "verify_peer": False,
                "allow_private": True,
            })
            self.assert_envelope(res, True)
            self.assertIn("raw_pem", res["data"])
            self.assertIn("-----BEGIN CERTIFICATE-----", res["data"]["raw_pem"])

    def test_adv_dns_ptr_queries_and_ssrf(self):
        """Verify PTR reverse DNS validation, SSRF checks, and invalid IP inputs."""
        # Invalid IP for PTR
        res_invalid = op_net_probe.net_probe({
            "action": "dns_lookup",
            "host": "not-an-ip-address",
            "query_type": "PTR",
        })
        self.assert_envelope(res_invalid, False)
        self.assertIn("must be a valid IPv4 or IPv6 address", res_invalid["error"])

        # Private IP blocked when allow_private=False
        res_ssrf = op_net_probe.net_probe({
            "action": "dns_lookup",
            "host": "192.168.1.50",
            "query_type": "PTR",
            "allow_private": False,
        })
        self.assert_envelope(res_ssrf, False)
        self.assertIn("SSRFSecurityError", res_ssrf["error"])

        # Permitted private PTR with mock
        with patch("socket.gethostbyaddr", return_value=("router.local", ["gw.local"], ["192.168.1.50"])):
            res_ok = op_net_probe.net_probe({
                "action": "dns_lookup",
                "host": "192.168.1.50",
                "query_type": "PTR",
                "allow_private": True,
            })
            self.assert_envelope(res_ok, True)
            self.assertEqual(res_ok["data"]["canonical_name"], "router.local")
            self.assertIn("gw.local", res_ok["data"]["aliases"])

    def test_adv_dns_query_types_and_invalid(self):
        """Verify CNAME, ALL query types, and rejection of unsupported DNS queries."""
        # Unsupported query type
        res_bad_q = op_net_probe.net_probe({
            "action": "dns_lookup",
            "host": "127.0.0.1",
            "query_type": "MX",
            "allow_private": True,
        })
        self.assert_envelope(res_bad_q, False)
        self.assertIn("Invalid query_type", res_bad_q["error"])

        # CNAME resolution with mock
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "cname.target.com", ("127.0.0.1", 0))]), \
             patch("socket.gethostbyname_ex", return_value=("cname.target.com", ["alias.com"], ["127.0.0.1"])):
            res_cname = op_net_probe.net_probe({
                "action": "dns_lookup",
                "host": "test.com",
                "query_type": "CNAME",
                "allow_private": True,
            })
            self.assert_envelope(res_cname, True)
            self.assertEqual(res_cname["data"]["canonical_name"], "cname.target.com")

    def test_adv_ip_quirks_ipv6_brackets_and_zone_ids(self):
        """Verify IPv6 bracket notation, zone/scope IDs, and URL host parsing."""
        # IPv6 zone ID is private/local
        self.assertTrue(op_net_probe._is_private_or_local("fe80::1%eth0"))
        self.assertTrue(op_net_probe._is_private_or_local("[::1]"))

        # URL host extraction
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8080))]):
            ip, family, port = op_net_probe._resolve_target_ip("https://127.0.0.1:8080/api", 8080, allow_private=True)
            self.assertEqual(ip, "127.0.0.1")

        # URL without hostname raises ValueError
        res_empty_url = op_net_probe.net_probe({
            "action": "tcp_ping",
            "host": "http:///path/only",
            "port": 80,
        })
        self.assert_envelope(res_empty_url, False)
        self.assertIn("invalid URL structure without a hostname", res_empty_url["error"])

    def test_adv_http_head_crlf_null_byte_injection(self):
        """Verify active rejection of CRLF and NULL control characters in HTTP HEAD path."""
        for bad_path in ("/test\r\nInjected: evil", "/test\nBadHeader: 1", "/test\x00secret"):
            res = op_net_probe.net_probe({
                "action": "http_head",
                "host": "127.0.0.1",
                "port": 8080,
                "path": bad_path,
                "allow_private": True,
            })
            self.assert_envelope(res, False)
            self.assertIn("CR, LF, or NULL control characters", res["error"])

    def test_adv_http_head_sensitive_header_redaction(self):
        """Verify thorough redaction of sensitive credentials and session headers."""
        raw_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Server: Jarvis/1.0\r\n"
            b"Authorization: Bearer secret_token_123\r\n"
            b"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
            b"X-Api-Key: topsecretkey\r\n"
            b"Cookie: session=xyz789\r\n"
            b"Set-Cookie: auth=session456\r\n"
            b"Token: sensitive_token\r\n"
            b"X-Auth-Token: header_token\r\n\r\n"
        )
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [raw_response, b""]

        with patch("socket.create_connection", return_value=mock_sock), \
             patch.object(op_net_probe, "_resolve_target_ip", return_value=("127.0.0.1", socket.AF_INET, 80)):
            res = op_net_probe.net_probe({
                "action": "http_head",
                "host": "127.0.0.1",
                "port": 80,
                "allow_private": True,
            })
            self.assert_envelope(res, True)
            hdrs = res["data"]["headers"]
            self.assertEqual(hdrs.get("Content-Type"), "application/json")
            self.assertEqual(hdrs.get("Server"), "Jarvis/1.0")
            for sensitive_key in ("Authorization", "Proxy-Authorization", "X-Api-Key", "Cookie", "Set-Cookie", "Token", "X-Auth-Token"):
                self.assertEqual(hdrs.get(sensitive_key), "[REDACTED]")

    def test_adv_http_head_nonstandard_delimiter_and_oversized(self):
        """Verify single \\n\\n delimiter handling and rejection of headers exceeding 64 KB."""
        # Single newline delimiter
        raw_single_nl = b"HTTP/1.1 204 No Content\nServer: MiniServer\nX-Custom: Val\n\n"
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [raw_single_nl, b""]

        with patch("socket.create_connection", return_value=mock_sock), \
             patch.object(op_net_probe, "_resolve_target_ip", return_value=("127.0.0.1", socket.AF_INET, 80)):
            res = op_net_probe.net_probe({
                "action": "http_head",
                "host": "127.0.0.1",
                "port": 80,
                "allow_private": True,
            })
            self.assert_envelope(res, True)
            self.assertEqual(res["data"]["status_code"], 204)
            self.assertEqual(res["data"]["headers"].get("X-Custom"), "Val")

        # Exceeding 64 KB header limit
        mock_sock_huge = MagicMock()
        mock_sock_huge.recv.side_effect = [b"A" * 35000, b"B" * 35000]
        with patch("socket.create_connection", return_value=mock_sock_huge), \
             patch.object(op_net_probe, "_resolve_target_ip", return_value=("127.0.0.1", socket.AF_INET, 80)):
            res_huge = op_net_probe.net_probe({
                "action": "http_head",
                "host": "127.0.0.1",
                "port": 80,
                "allow_private": True,
            })
            self.assert_envelope(res_huge, False)
            self.assertIn("HTTP headers exceeded maximum limit", res_huge["error"])


# =============================================================================
# 2. op_process_inspector Adversarial Tests
# =============================================================================

class TestM5ProcessInspectorAdversarial(BaseAdversarialTestCase):
    """White-box Tier 5 adversarial hardening for op_process_inspector."""

    def test_adv_signal_kernel_thread_and_critical_pid_protections(self):
        """Verify strict refusal to signal PID 1, PID 2, self, parent, and kernel threads."""
        # PID 1
        res_pid1 = op_process_inspector.process_inspector({"action": "send_signal", "pid": 1, "signal": "SIGTERM"})
        self.assert_envelope(res_pid1, False)
        self.assertIn("Refusing to send signal to PID 1", res_pid1["error"])

        # PID 2
        res_pid2 = op_process_inspector.process_inspector({"action": "send_signal", "pid": 2, "signal": "SIGTERM"})
        self.assert_envelope(res_pid2, False)
        self.assertIn("kernel thread (PID 2)", res_pid2["error"])

        # Self PID
        res_self = op_process_inspector.process_inspector({"action": "send_signal", "pid": os.getpid(), "signal": "SIGTERM"})
        self.assert_envelope(res_self, False)
        self.assertIn("Refusing to send signal to self", res_self["error"])

        # Parent PID
        res_ppid = op_process_inspector.process_inspector({"action": "send_signal", "pid": os.getppid(), "signal": "SIGTERM"})
        self.assert_envelope(res_ppid, False)
        self.assertIn("Refusing to send signal to parent", res_ppid["error"])

        # Mock process with PPid 2
        mock_status = "Name:\tkworker/u:0\nPPid:\t2\nState:\tS (sleeping)\n"
        with patch("builtins.open", unittest.mock.mock_open(read_data=mock_status)):
            res_kthread = op_process_inspector.process_inspector({"action": "send_signal", "pid": 5555, "signal": "SIGTERM"})
            self.assert_envelope(res_kthread, False)
            self.assertIn("Refusing to send signal to kernel thread (PID 5555, PPID 2)", res_kthread["error"])

    def test_adv_signal_sigkill_confirmation_enforcement(self):
        """Verify SIGKILL demands confirm=True explicitly."""
        # Missing confirm
        res_unconfirmed = op_process_inspector.process_inspector({
            "action": "send_signal",
            "pid": 999999,
            "signal": "SIGKILL",
            "confirm": False,
        })
        self.assert_envelope(res_unconfirmed, False)
        self.assertIn("SIGKILL requires explicit confirmation", res_unconfirmed["error"])

        # With confirm=True, proceeds to os.kill
        with patch("os.kill") as mock_kill, \
             patch("builtins.open", unittest.mock.mock_open(read_data="Name:\ttest\nPPid:\t100\n")):
            res_confirmed = op_process_inspector.process_inspector({
                "action": "send_signal",
                "pid": 999999,
                "signal": "SIGKILL",
                "confirm": True,
            })
            self.assert_envelope(res_confirmed, True)
            mock_kill.assert_called_once_with(999999, op_process_inspector.signal.SIGKILL)

    def test_adv_signal_representations_and_invalid_signals(self):
        """Verify signal name variants (SIGTERM, TERM) and rejection of forbidden signals."""
        with patch("os.kill") as mock_kill, \
             patch("builtins.open", unittest.mock.mock_open(read_data="Name:\ttest\nPPid:\t100\n")):
            # TERM alias without prefix
            res_term = op_process_inspector.process_inspector({"action": "send_signal", "pid": 88888, "signal": "TERM"})
            self.assert_envelope(res_term, True)
            self.assertEqual(res_term["data"]["signal"], "SIGTERM")

            # Numeric signal
            res_int = op_process_inspector.process_inspector({"action": "send_signal", "pid": 88888, "signal": int(op_process_inspector.signal.SIGINT)})
            self.assert_envelope(res_int, True)
            self.assertEqual(res_int["data"]["signal"], "SIGINT")
            self.assertEqual(
                mock_kill.call_args_list,
                [unittest.mock.call(88888, op_process_inspector.signal.SIGTERM),
                 unittest.mock.call(88888, op_process_inspector.signal.SIGINT)],
            )

        # Disallowed signal (SIGSTOP not permitted for safety)
        res_disallowed = op_process_inspector.process_inspector({"action": "send_signal", "pid": 88888, "signal": "SIGSTOP"})
        self.assert_envelope(res_disallowed, False)
        self.assertIn("Invalid signal", res_disallowed["error"])

    def test_adv_socket_owners_all_tcp_states_and_ipv6_hex_decoding(self):
        """Verify address parsing for IPv4/IPv6 hex strings and TCP state mapping."""
        # IPv4 127.0.0.1:80 (little-endian hex 0100007F:0050)
        ip, port = op_process_inspector._parse_net_address("0100007F:0050")
        self.assertEqual(ip, "127.0.0.1")
        self.assertEqual(port, 80)

        # IPv6 ::1:8080 (32-char hex)
        ip6, port6 = op_process_inspector._parse_net_address("00000000000000000000000001000000:1F90")
        self.assertEqual(ip6, "::1")
        self.assertEqual(port6, 8080)

        # All 11 TCP states mapping
        for code, expected_state in op_process_inspector.TCP_STATE_MAP.items():
            self.assertIn(expected_state, ("ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING"))

    def test_adv_process_stat_parentheses_in_comm(self):
        """Verify _parse_proc_stat robustly parses process names containing nested parentheses."""
        raw_stat = (
            "12345 (worker (pool) thread) S 1 12345 12345 0 -1 4194304 100 0 0 0 "
            "15 25 0 0 20 0 4 0 1000 52428800 2000 18446744073709551615"
        )
        parsed = op_process_inspector._parse_proc_stat(raw_stat)
        self.assertEqual(parsed.get("comm"), "worker (pool) thread")
        self.assertEqual(parsed.get("state"), "S")
        self.assertEqual(parsed.get("ppid"), 1)
        self.assertEqual(parsed.get("num_threads"), 4)
        self.assertEqual(parsed.get("rss"), 2000 * op_process_inspector.PAGE_SIZE)

    def test_adv_process_environ_token_and_credential_redaction(self):
        """Verify _redact_environ strips all secret keywords and tokens."""
        raw_env = (
            b"API_KEY=sk-proj-supersecret123\x00"
            b"GITHUB_TOKEN=ghp_secrettokenabc\x00"
            b"DATABASE_PASSWORD=mypassword123\x00"
            b"AUTH_HEADER=Bearer mytoken\x00"
            b"SAFE_CONFIG_PATH=/opt/app/config\x00"
            b"PORT=8080\x00"
        )
        redacted = op_process_inspector._redact_environ(raw_env)
        self.assertEqual(redacted["API_KEY"], "[REDACTED]")
        self.assertEqual(redacted["GITHUB_TOKEN"], "[REDACTED]")
        self.assertEqual(redacted["DATABASE_PASSWORD"], "[REDACTED]")
        self.assertEqual(redacted["AUTH_HEADER"], "[REDACTED]")
        self.assertEqual(redacted["SAFE_CONFIG_PATH"], "/opt/app/config")
        self.assertEqual(redacted["PORT"], "8080")

    def test_adv_process_list_and_inspect_limit_clamping(self):
        """Verify limit parameter clamping and non-existent PID handling."""
        res_limit_clamped = op_process_inspector.process_inspector({"action": "list_processes", "limit": 9999})
        self.assert_envelope(res_limit_clamped, True)
        self.assertLessEqual(res_limit_clamped["data"]["count"], 200)

        res_bad_pid = op_process_inspector.process_inspector({"action": "inspect_pid", "pid": 999999999})
        self.assert_envelope(res_bad_pid, False)
        self.assertIn("ProcessLookupError", res_bad_pid["error"])


# =============================================================================
# 3. op_archive_builder Adversarial Tests
# =============================================================================

class TestM5ArchiveBuilderAdversarial(BaseAdversarialTestCase):
    """White-box Tier 5 adversarial hardening for op_archive_builder."""

    def test_adv_symlinks_mixed_allowed_and_escapes(self):
        """Verify symlinks to allowed paths succeed, while escapes outside ALLOWED_ROOTS are blocked."""
        source_dir = self.tmp_dir / "src_symlinks"
        source_dir.mkdir()
        target_file = source_dir / "target.txt"
        target_file.write_text("Hello inside")

        # Symlink within allowed roots
        valid_symlink = source_dir / "valid_link.txt"
        valid_symlink.symlink_to(target_file)

        dest_zip = self.tmp_dir / "valid_symlink.zip"
        res_ok = op_archive_builder.archive_builder({
            "action": "create_zip",
            "source_paths": [str(source_dir)],
            "destination_path": str(dest_zip),
        })
        self.assert_envelope(res_ok, True)

        # Symlink pointing to /etc
        escape_symlink = source_dir / "escape_etc"
        escape_symlink.symlink_to(Path("/etc"))
        dest_escape = self.tmp_dir / "escape.zip"
        # Direct escape symlink as source path is blocked with SecurityError
        res_direct = op_archive_builder.archive_builder({
            "action": "create_zip",
            "source_paths": [str(escape_symlink)],
            "destination_path": str(dest_escape),
        })
        self.assert_envelope(res_direct, False)
        self.assertIn("SecurityError", res_direct["error"])

        # Symlink within directory tree is defensively excluded
        res_escape = op_archive_builder.archive_builder({
            "action": "create_zip",
            "source_paths": [str(source_dir)],
            "destination_path": str(dest_escape),
        })
        self.assert_envelope(res_escape, True)
        self.assertTrue(any("escape_etc" in p for p in res_escape["data"]["excluded_sensitive_files"]))

    def test_adv_nested_archive_inside_source_tree(self):
        """Verify creating an archive whose destination is inside the source directory."""
        source_dir = self.tmp_dir / "nested_tree"
        source_dir.mkdir()
        (source_dir / "file1.txt").write_text("Content 1")
        sub_dir = source_dir / "archives"
        sub_dir.mkdir()
        dest_archive = sub_dir / "output.zip"

        res = op_archive_builder.archive_builder({
            "action": "create_zip",
            "source_paths": [str(source_dir)],
            "destination_path": str(dest_archive),
        })
        self.assert_envelope(res, True)
        self.assertTrue(dest_archive.is_file())
        self.assertGreater(dest_archive.stat().st_size, 0)

    def test_adv_glob_include_exclude_edge_patterns(self):
        """Verify fine-grained glob include and exclude filtering."""
        source_dir = self.tmp_dir / "glob_test"
        source_dir.mkdir()
        (source_dir / "keep.py").write_text("print('keep')")
        (source_dir / "ignore.tmp").write_text("temporary")
        (source_dir / "test.py").write_text("print('test')")
        (source_dir / "test.bak").write_text("backup")

        dest_zip = self.tmp_dir / "filtered.zip"
        res = op_archive_builder.archive_builder({
            "action": "create_zip",
            "source_paths": [str(source_dir)],
            "destination_path": str(dest_zip),
            "include_pattern": ["*.py"],
            "exclude_pattern": ["*test*"],
            "base_dir": str(source_dir),
        })
        self.assert_envelope(res, True)
        data = res["data"]
        self.assertEqual(data["file_count"], 1)
        self.assertEqual(data["files"], ["keep.py"])

    def test_adv_empty_and_whitespace_stream_compression(self):
        """Verify stream compression and decompression of empty payloads across all codecs."""
        for codec in ("gzip", "bz2", "lzma"):
            # Compress empty text
            res_comp = op_archive_builder.archive_builder({
                "action": "compress_stream",
                "compression": codec,
                "data": "",
                "return_base64": True,
            })
            self.assert_envelope(res_comp, True)
            compressed_b64 = res_comp["data"]["data"]
            self.assertGreater(len(compressed_b64), 0)

            # Decompress back to empty
            res_decomp = op_archive_builder.archive_builder({
                "action": "decompress_stream",
                "compression": codec,
                "data": compressed_b64,
                "is_base64": True,
            })
            self.assert_envelope(res_decomp, True)
            self.assertEqual(res_decomp["data"]["data"], "")

    def test_adv_stream_base64_and_binary_roundtrip(self):
        """Verify binary base64 roundtrip for arbitrary binary payloads."""
        raw_binary = os.urandom(2048)
        raw_b64 = base64.b64encode(raw_binary).decode("ascii")

        for codec in ("gzip", "bz2", "lzma"):
            res_comp = op_archive_builder.archive_builder({
                "action": "compress_stream",
                "compression": codec,
                "data": raw_b64,
                "is_base64": True,
                "return_base64": True,
            })
            self.assert_envelope(res_comp, True)

            res_decomp = op_archive_builder.archive_builder({
                "action": "decompress_stream",
                "compression": codec,
                "data": res_comp["data"]["data"],
                "is_base64": True,
                "return_base64": True,
            })
            self.assert_envelope(res_decomp, True)
            self.assertEqual(res_decomp["data"]["data"], raw_b64)

    def test_adv_decompression_bomb_safety_threshold(self):
        """Verify interception of decompression bombs exceeding 10 MB limit."""
        # Highly compressible 12 MB of zeroes (compresses to ~12 KB)
        huge_payload = b"\x00" * (12 * 1024 * 1024)
        compressed_gzip = gzip.compress(huge_payload)
        compressed_b64 = base64.b64encode(compressed_gzip).decode("ascii")

        res = op_archive_builder.archive_builder({
            "action": "decompress_stream",
            "compression": "gzip",
            "data": compressed_b64,
            "is_base64": True,
        })
        self.assert_envelope(res, False)
        self.assertIn("DecompressionBombError", res["error"])

    def test_adv_all_archive_formats_and_permissions(self):
        """Verify archive creation for tar, tar.gz, tar.bz2, tar.xz with 0o600 mode."""
        src_dir = self.tmp_dir / "formats_src"
        src_dir.mkdir()
        (src_dir / "sample.txt").write_text("Archive test content")

        for fmt in ("tar", "tar.gz", "tar.bz2", "tar.xz"):
            dest_file = self.tmp_dir / f"test.{fmt}"
            res = op_archive_builder.archive_builder({
                "action": "create_tar",
                "format": fmt,
                "source_paths": [str(src_dir)],
                "destination_path": str(dest_file),
            })
            self.assert_envelope(res, True)
            self.assertTrue(dest_file.is_file())
            # Verify file permission mode is 0o600
            file_mode = stat.S_IMODE(dest_file.stat().st_mode)
            self.assertEqual(file_mode, 0o600)

    def test_adv_archive_overwrite_protection(self):
        """Verify overwrite=False guards against accidental clobbering."""
        src_dir = self.tmp_dir / "ow_src"
        src_dir.mkdir()
        (src_dir / "a.txt").write_text("data")
        dest_zip = self.tmp_dir / "existing.zip"
        dest_zip.write_text("already exists")

        # overwrite=False fails
        res_fail = op_archive_builder.archive_builder({
            "action": "create_zip",
            "source_paths": [str(src_dir)],
            "destination_path": str(dest_zip),
            "overwrite": False,
        })
        self.assert_envelope(res_fail, False)
        self.assertIn("already exists", res_fail["error"])

        # overwrite=True succeeds
        res_ok = op_archive_builder.archive_builder({
            "action": "create_zip",
            "source_paths": [str(src_dir)],
            "destination_path": str(dest_zip),
            "overwrite": True,
        })
        self.assert_envelope(res_ok, True)


# =============================================================================
# 4. op_fs_analyzer Adversarial Tests
# =============================================================================

class TestM5FsAnalyzerAdversarial(BaseAdversarialTestCase):
    """White-box Tier 5 adversarial hardening for op_fs_analyzer."""

    def test_adv_circular_symlinks_detection_without_hang(self):
        """Verify detection of circular symlink loops without infinite recursion."""
        circ_dir = self.tmp_dir / "circ_test"
        circ_dir.mkdir()
        link_a = circ_dir / "link_a"
        link_b = circ_dir / "link_b"
        link_a.symlink_to(link_b)
        link_b.symlink_to(link_a)

        dangling = circ_dir / "dangling_link"
        dangling.symlink_to(circ_dir / "non_existent_file")

        res = op_fs_analyzer.fs_analyzer({
            "action": "find_broken_symlinks",
            "path": str(circ_dir),
        })
        self.assert_envelope(res, True)
        data = res["data"]
        self.assertGreaterEqual(data["total_issues"], 2)
        broken_names = [Path(item["path"]).name for item in data["broken_symlinks"]]
        self.assertIn("link_a", broken_names)
        self.assertIn("link_b", broken_names)
        self.assertIn("dangling_link", broken_names)

    def test_adv_tree_max_depth_extremes(self):
        """Verify max_depth boundaries (0, deeply nested, negative clamping)."""
        deep_dir = self.tmp_dir / "deep_tree"
        curr = deep_dir
        for i in range(8):
            curr = curr / f"level_{i}"
            curr.mkdir(parents=True, exist_ok=True)
            (curr / f"file_{i}.txt").write_text(f"Depth {i}")

        # max_depth = 0 (clamped to 1)
        res_depth0 = op_fs_analyzer.fs_analyzer({
            "action": "tree_summary",
            "path": str(deep_dir),
            "max_depth": 0,
        })
        self.assert_envelope(res_depth0, True)
        self.assertEqual(res_depth0["data"]["max_depth"], 1)
        self.assertEqual(len(res_depth0["data"]["first_level_entries"]), 1)

        # max_depth = 2
        res_depth2 = op_fs_analyzer.fs_analyzer({
            "action": "tree_summary",
            "path": str(deep_dir),
            "max_depth": 2,
        })
        self.assert_envelope(res_depth2, True)
        self.assertEqual(res_depth2["data"]["max_depth"], 2)

    def test_adv_hygiene_audit_world_writable_and_anomalies(self):
        """Verify hygiene_audit detects world-writable files, temporary files, and lock files."""
        audit_dir = self.tmp_dir / "hygiene_test"
        audit_dir.mkdir()

        # Temporary artifacts
        (audit_dir / "test.swp").write_text("vim swap")
        (audit_dir / "backup~").write_text("backup")
        (audit_dir / "junk.tmp").write_text("temp")

        # Lock files (> 24h old to trigger stale lock detection)
        l1 = audit_dir / "server.lock"
        l1.write_text("lock")
        l2 = audit_dir / "process.pid"
        l2.write_text("12345")
        old_time = time.time() - (36 * 3600)
        os.utime(str(l1), (old_time, old_time))
        os.utime(str(l2), (old_time, old_time))

        # Empty directory
        (audit_dir / "empty_sub").mkdir()

        # World-writable file
        ww_file = audit_dir / "world_writable.txt"
        ww_file.write_text("open to all")
        ww_file.chmod(0o777)

        res = op_fs_analyzer.fs_analyzer({
            "action": "hygiene_audit",
            "path": str(audit_dir),
        })
        self.assert_envelope(res, True)
        data = res["data"]
        summary = data["summary"]
        self.assertGreaterEqual(summary["temp_artifacts_count"], 3)
        self.assertGreaterEqual(summary["stale_locks_count"], 2)
        self.assertGreaterEqual(summary["empty_directories_count"], 1)
        self.assertGreaterEqual(summary["permission_anomalies_count"], 1)
        anomaly_paths = [Path(a["path"]).name for a in data["issues"] if a["category"] == "permission_anomaly"]
        self.assertIn("world_writable.txt", anomaly_paths)

    def test_adv_find_large_threshold_and_sorting(self):
        """Verify find_large accurately filters by size threshold and sorts descending."""
        large_dir = self.tmp_dir / "large_files"
        large_dir.mkdir()
        (large_dir / "small.dat").write_bytes(b"A" * (200 * 1024))         # 200 KB
        (large_dir / "medium.dat").write_bytes(b"B" * (1024 * 1024))       # 1 MB
        (large_dir / "huge.dat").write_bytes(b"C" * (2 * 1024 * 1024))     # 2 MB

        res = op_fs_analyzer.fs_analyzer({
            "action": "find_large",
            "path": str(large_dir),
            "min_size_mb": 0.5,
        })
        self.assert_envelope(res, True)
        files = res["data"]["files"]
        self.assertEqual(len(files), 2)
        self.assertEqual(Path(files[0]["path"]).name, "huge.dat")
        self.assertEqual(Path(files[1]["path"]).name, "medium.dat")

    def test_adv_format_size_extreme_units(self):
        """Verify _format_size across B, KB, MB, GB, TB, PB scale."""
        fmt = op_fs_analyzer._format_size
        self.assertEqual(fmt(0), "0 B")
        self.assertEqual(fmt(-50), "0 B")
        self.assertEqual(fmt(500), "500 B")
        self.assertEqual(fmt(2048), "2.00 KB")
        self.assertEqual(fmt(10 * 1024 * 1024), "10.00 MB")
        self.assertEqual(fmt(int(1.5 * 1024**3)), "1.50 GB")
        self.assertEqual(fmt(int(2.25 * 1024**4)), "2.25 TB")
        self.assertEqual(fmt(int(4.0 * 1024**5)), "4.00 PB")

    def test_adv_confinement_and_sensitive_dir_guard(self):
        """Verify rejection of paths outside ALLOWED_ROOTS and sensitive locations."""
        # Outside allowed roots
        res_out = op_fs_analyzer.fs_analyzer({"action": "tree_summary", "path": "/etc"})
        self.assert_envelope(res_out, False)
        self.assertIn("PathSecurityError", res_out["error"])

        # Traversal attempt
        res_trav = op_fs_analyzer.fs_analyzer({"action": "tree_summary", "path": "/tmp/../etc"})
        self.assert_envelope(res_trav, False)
        self.assertIn("PathSecurityError", res_trav["error"])

        # Sensitive path
        res_sens = op_fs_analyzer.fs_analyzer({"action": "tree_summary", "path": str(Path.home() / ".ssh")})
        self.assert_envelope(res_sens, False)
        self.assertIn("SensitivePathError", res_sens["error"])


# =============================================================================
# 5. op_tabular_data Adversarial Tests
# =============================================================================

class TestM5TabularDataAdversarial(BaseAdversarialTestCase):
    """White-box Tier 5 adversarial hardening for op_tabular_data."""

    def test_adv_irregular_csv_quoting_and_multiline_fields(self):
        """Verify irregular quotes, escaped delimiters, and multiline CSV fields."""
        complex_csv = (
            'id,title,description,notes\n'
            '1,"Clean title","Multiline\ndescription with, comma","None"\n'
            '2,"Title with ""escaped"" quotes","Single line","Done"\n'
        )
        res = op_tabular_data.tabular_data({
            "action": "convert_format",
            "data": complex_csv,
            "from_format": "csv",
            "to_format": "json_records",
        })
        self.assert_envelope(res, True)
        records = json.loads(res["data"]["output"])
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["description"], "Multiline\ndescription with, comma")
        self.assertIn('"escaped"', records[1]["title"])

    def test_adv_unicode_and_nonstandard_delimiters(self):
        """Verify conversion with pipe, semicolon, tab, and unicode delimiters."""
        pipe_data = "name|age|city\nAlice|30|Berlin\nBob|25|Warsaw"
        res_pipe = op_tabular_data.tabular_data({
            "action": "convert_format",
            "data": pipe_data,
            "from_format": "csv",
            "to_format": "tsv",
            "delimiter": "|",
        })
        self.assert_envelope(res_pipe, True)
        tsv_out = res_pipe["data"]["output"]
        self.assertIn("Alice\t30\tBerlin", tsv_out)

    def test_adv_single_cell_and_single_row_tables(self):
        """Verify single cell and 1-row table conversion and profiling."""
        # 1x1 table
        single_cell = "only_column\nsingle_value"
        res = op_tabular_data.tabular_data({
            "action": "convert_format",
            "data": single_cell,
            "from_format": "csv",
            "to_format": "json_records",
        })
        self.assert_envelope(res, True)
        rec = json.loads(res["data"]["output"])
        self.assertEqual(rec, [{"only_column": "single_value"}])

        # Profile 1x1 table
        res_prof = op_tabular_data.tabular_data({
            "action": "profile_columns",
            "data": single_cell,
        })
        self.assert_envelope(res_prof, True)
        cols_by_name = {c["name"]: c for c in res_prof["data"]["columns"]}
        col = cols_by_name["only_column"]
        self.assertEqual(col["total_count"], 1)
        self.assertEqual(col["distinct_count"], 1)

    def test_adv_sparse_matrices_and_jagged_rows(self):
        """Verify jagged rows with uneven column lengths are safely handled."""
        jagged_csv = (
            "colA,colB,colC\n"
            "valA1,valB1\n"
            "valA2,valB2,valC2,valExtra1,valExtra2\n"
            "valA3\n"
        )
        res = op_tabular_data.tabular_data({
            "action": "convert_format",
            "data": jagged_csv,
            "from_format": "csv",
            "to_format": "json_records",
        })
        self.assert_envelope(res, True)
        records = json.loads(res["data"]["output"])
        self.assertEqual(len(records), 3)

    def test_adv_profiler_null_inference_and_type_coercion(self):
        """Verify profiler type detection across int, float, bool, date, and varied null representations."""
        mixed_data = (
            "id,rating,active,created_at,comments\n"
            "101,4.5,true,2026-01-10,Good\n"
            "102,NaN,false,2026-02-15,null\n"
            "103,3.8,True,,N/A\n"
            "104,5.0,None,2026-04-20,Excellent\n"
        )
        res = op_tabular_data.tabular_data({
            "action": "profile_columns",
            "data": mixed_data,
        })
        self.assert_envelope(res, True)
        cols = {c["name"]: c for c in res["data"]["columns"]}
        self.assertEqual(cols["id"]["inferred_type"], "integer")
        self.assertEqual(cols["rating"]["inferred_type"], "float")
        self.assertEqual(cols["active"]["inferred_type"], "boolean")
        self.assertEqual(cols["created_at"]["inferred_type"], "date")
        self.assertEqual(cols["rating"]["null_count"], 1)
        self.assertEqual(cols["created_at"]["null_count"], 1)

    def test_adv_markdown_table_alignments_and_width_truncation(self):
        """Verify Markdown table generation with custom column alignment and text truncation."""
        csv_data = (
            "product,price,description\n"
            "Keyboard,89.99,High quality mechanical gaming keyboard with RGB\n"
            "Mouse,49.99,Wireless ergonomic mouse\n"
        )
        res = op_tabular_data.tabular_data({
            "action": "to_markdown",
            "data": csv_data,
            "alignments": {"product": "left", "price": "right", "description": "center"},
            "max_col_width": 20,
        })
        self.assert_envelope(res, True)
        md = res["data"]["markdown"]
        self.assertIn(":---", md)
        self.assertIn("---:", md)
        self.assertIn("...", md)  # Truncation indicator

    def test_adv_dialect_sniffer_fallbacks(self):
        """Verify dialect sniffer fallback on ambiguous single-column content."""
        ambiguous = "onlyonecolumnwithoutdelimiters\n"
        res = op_tabular_data.tabular_data({
            "action": "sniff_dialect",
            "data": ambiguous,
        })
        self.assert_envelope(res, True)
        self.assertEqual(res["data"]["delimiter"], ",")

    def test_adv_payload_size_limit_rejection(self):
        """Verify tabular operations reject payloads exceeding 10 MB."""
        huge_csv = "col\n" + ("x\n" * (6 * 1024 * 1024))
        res = op_tabular_data.tabular_data({
            "action": "convert_format",
            "data": huge_csv,
        })
        self.assert_envelope(res, False)
        self.assertIn("PayloadSizeError", res["error"])


# =============================================================================
# 6. op_config_validator Adversarial Tests
# =============================================================================

class TestM5ConfigValidatorAdversarial(BaseAdversarialTestCase):
    """White-box Tier 5 adversarial hardening for op_config_validator."""

    def test_adv_nested_json_schemas_and_constraints(self):
        """Verify nested object/array JSON schemas, numeric limits, and additionalProperties enforcement."""
        schema = {
            "type": "object",
            "properties": {
                "server": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                    },
                    "required": ["host", "port"],
                    "additionalProperties": False,
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                },
            },
            "required": ["server", "tags"],
            "additionalProperties": False,
        }

        # Valid payload
        valid_json = json.dumps({
            "server": {"host": "127.0.0.1", "port": 8080},
            "tags": ["prod", "v1"],
        })
        res_ok = op_config_validator.config_validator({
            "action": "validate_json",
            "content": valid_json,
            "schema": schema,
        })
        self.assert_envelope(res_ok, True)
        self.assertTrue(res_ok["data"]["valid"])

        # Invalid payload with forbidden property
        invalid_json = json.dumps({
            "server": {"host": "127.0.0.1", "port": 8080, "unauthorized_key": True},
            "tags": ["prod"],
        })
        res_bad = op_config_validator.config_validator({
            "action": "validate_json",
            "content": invalid_json,
            "schema": schema,
        })
        self.assert_envelope(res_bad, True)
        self.assertFalse(res_bad["data"]["valid"])
        diagnostics = [d["message"] for d in res_bad["data"]["diagnostics"]]
        self.assertTrue(any("additionalproperties" in m.lower() for m in diagnostics))

    def test_adv_json_regex_pattern_redos_interception(self):
        """Verify ReDoS-vulnerable regex patterns in JSON schema are blocked proactively."""
        redos_schema = {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "pattern": "([a-zA-Z0-9]+)*$",  # Catastrophic backtracking quantifier
                },
            },
        }
        res = op_config_validator.config_validator({
            "action": "validate_json",
            "content": json.dumps({"token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!"}),
            "schema": redos_schema,
        })
        self.assert_envelope(res, False)
        self.assertIn("ReDoSSecurityError", res["error"])

    def test_adv_complex_ini_comments_and_interpolation(self):
        """Verify INI validation with mixed comments, required options, and interpolation safety."""
        ini_content = (
            "# Main system configuration\n"
            "[paths]\n"
            "base_dir = /opt/app\n"
            "log_dir = %(base_dir)s/logs  ; Inline comment\n"
            "\n"
            "; Database section\n"
            "[database]\n"
            "host = 127.0.0.1\n"
            "port = 5432\n"
        )
        res = op_config_validator.config_validator({
            "action": "validate_ini",
            "content": ini_content,
            "required_sections": ["paths", "database"],
            "required_options": {"database": ["host", "port"]},
            "check_interpolation": True,
        })
        self.assert_envelope(res, True)
        self.assertTrue(res["data"]["valid"])

        # Bad interpolation variable
        bad_ini = "[paths]\nlog = %(undefined_var)s/logs\n"
        res_bad_interp = op_config_validator.config_validator({
            "action": "validate_ini",
            "content": bad_ini,
            "check_interpolation": True,
        })
        self.assert_envelope(res_bad_interp, True)
        self.assertFalse(res_bad_interp["data"]["valid"])

    def test_adv_dotenv_export_prefixes_and_multiline_quotes(self):
        """Verify .env validation supporting export prefixes and quoted multiline values."""
        dotenv_content = (
            "export ENVIRONMENT=staging\n"
            "export API_PORT=9000\n"
            'DATABASE_URL="postgres://user:pass@localhost:5432/db"\n'
            'PUBLIC_CERT="-----BEGIN CERTIFICATE-----\n'
            'MIIB...line1\n'
            'line2\n'
            '-----END CERTIFICATE-----"\n'
        )
        res = op_config_validator.config_validator({
            "action": "validate_dotenv",
            "content": dotenv_content,
            "strict_naming": True,
        })
        self.assert_envelope(res, True)
        self.assertTrue(res["data"]["valid"])
        self.assertIn("PUBLIC_CERT", res["data"]["details"]["variables"])

    def test_adv_dotenv_unquoted_multiline_syntax_error(self):
        """Verify .env syntax error reporting for unquoted multiline variables."""
        bad_dotenv = (
            "VALID_VAR=123\n"
            "BROKEN_VAR=first line\n"
            "second line without variable assignment\n"
        )
        res = op_config_validator.config_validator({
            "action": "validate_dotenv",
            "content": bad_dotenv,
        })
        self.assert_envelope(res, True)
        self.assertFalse(res["data"]["valid"])
        diags = [d["message"] for d in res["data"]["diagnostics"]]
        self.assertTrue(any("syntax" in d.lower() or "line" in d.lower() for d in diags))

    def test_adv_dotenv_placeholder_and_template_audit(self):
        """Verify placeholder token warnings and template conformity checks."""
        env_content = "API_KEY=your_api_key_here\nDATABASE_URL=postgres://localhost/db\n"
        template = "API_KEY=\nDATABASE_URL=\nREDIS_HOST=\n"

        res = op_config_validator.config_validator({
            "action": "validate_dotenv",
            "content": env_content,
            "template_content": template,
        })
        self.assert_envelope(res, True)
        diags = res["data"]["diagnostics"]
        messages = [d["message"] for d in diags]
        # Flag placeholder value
        self.assertTrue(any("placeholder" in m.lower() for m in messages))
        # Flag missing variable from template
        self.assertTrue(any("REDIS_HOST" in m for m in messages))

    def test_adv_config_lint_trailing_whitespace_and_duplicate_keys(self):
        """Verify lint_config flags trailing whitespace and duplicate keys in JSON/INI."""
        # Trailing whitespace
        json_trailing = '{\n  "key": "value"   \n}\n'
        res_ws = op_config_validator.config_validator({
            "action": "lint_config",
            "content": json_trailing,
            "format": "json",
        })
        self.assert_envelope(res_ws, True)
        diags = res_ws["data"]["diagnostics"]
        self.assertTrue(any("trailing whitespace" in d["message"].lower() for d in diags))

        # Duplicate keys in JSON
        json_dup = '{"item": 1, "item": 2}'
        res_dup = op_config_validator.config_validator({
            "action": "lint_config",
            "content": json_dup,
            "format": "json",
            "allow_duplicate_keys": False,
        })
        self.assert_envelope(res_dup, True)
        self.assertTrue(any("duplicate key" in d["message"].lower() for d in res_dup["data"]["diagnostics"]))


# =============================================================================
# 7. op_secret_scanner Adversarial Tests
# =============================================================================

class TestM5SecretScannerAdversarial(BaseAdversarialTestCase):
    """White-box Tier 5 adversarial hardening for op_secret_scanner."""

    def test_adv_interleaved_private_keys_and_exotic_pem_headers(self):
        """Verify detection of interleaved PEM blocks with exotic private key headers."""
        interleaved_log = (
            "2026-11-22 01:00:00 [INFO] Loading application certificates...\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA=\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
            "2026-11-22 01:00:01 [DEBUG] Processing secondary transport key...\n"
            "-----BEGIN EC PRIVATE KEY-----\n"
            "MHQCAQEEIB4fT8Xt61U31v3OLwb7AJoSt4J8XEwDQYJKoZIhvcNAQELBQAwGzEZ\n"
            "-----END EC PRIVATE KEY-----\n"
            "2026-11-22 01:00:02 [INFO] Server ready.\n"
        )
        res = op_secret_scanner.secret_scanner({
            "action": "scan_patterns",
            "text": interleaved_log,
            "patterns": ["private_key"],
        })
        self.assert_envelope(res, True)
        findings = res["data"]["findings"]
        self.assertEqual(len(findings), 2)
        kinds = [m["type"] for m in findings]
        self.assertTrue(all("private_key" in k for k in kinds))

    def test_adv_pem_audit_validity_window_and_metadata(self):
        """Verify audit_pem extracts validity window, self-signed flag, and flags expired certs."""
        cert_pem = (
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
        res = op_secret_scanner.secret_scanner({
            "action": "audit_pem",
            "text": cert_pem,
        })
        self.assert_envelope(res, True)
        data = res["data"]
        self.assertEqual(len(data["blocks"]), 1)
        block = data["blocks"][0]
        self.assertFalse(block["is_expired"])
        self.assertTrue(block["is_self_signed"])
        self.assertEqual(block["subject"][0][0][1], "test.example.com")

    def test_adv_shannon_entropy_boundary_and_sliding_window(self):
        """Verify Shannon entropy bounds (0.0 for uniform, > 5.0 for CSPRNG tokens)."""
        # Repetitive zero-entropy text
        res_zero = op_secret_scanner.secret_scanner({
            "action": "scan_entropy",
            "text": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "threshold": 3.0,
        })
        self.assert_envelope(res_zero, True)
        self.assertEqual(res_zero["data"]["findings_count"], 0)

        # High-entropy random token
        high_entropy_token = base64.b64encode(os.urandom(32)).decode("ascii")
        res_high = op_secret_scanner.secret_scanner({
            "action": "scan_entropy",
            "text": f"User token is {high_entropy_token} please keep safe.",
            "threshold": 4.5,
            "min_length": 20,
        })
        self.assert_envelope(res_high, True)
        self.assertGreaterEqual(res_high["data"]["findings_count"], 1)

    def test_adv_secret_patterns_and_redaction(self):
        """Verify pattern matching for cloud credentials and token redaction."""
        text_with_secrets = (
            "AWS=AKIAAAAAAAAAAAAAAAAA "
            "GITHUB=ghp_000000000000000000000000000000000000 "
            "SLACK=xoxb-xxxxxxxxxxxxxxxxxxxxxxxx"
        )
        res = op_secret_scanner.secret_scanner({
            "action": "scan_patterns",
            "text": text_with_secrets,
            "redact_matches": True,
        })
        self.assert_envelope(res, True)
        findings = res["data"]["findings"]
        self.assertGreater(len(findings), 0)
        for f in findings:
            self.assertNotIn("AKIAAAAAAAAAAAAAAAAA", f["match_preview"])
            self.assertNotIn("ghp_000000000000000000000000000000000000", f["match_preview"])
            self.assertIn("[REDACTED]", f["match_preview"])

    def test_adv_crypto_utils_pbkdf2_clamping_and_constant_time(self):
        """Verify PBKDF2 iteration bounds, constant-time compare, and CSPRNG token formats."""
        # PBKDF2 safety rejection for low iterations
        res_low = op_secret_scanner.secret_scanner({
            "action": "crypto_utils",
            "operation": "derive_key",
            "password": "pass",
            "salt": "salt123",
            "iterations": 100,  # Below min 1,000
            "hash_name": "sha256",
        })
        self.assert_envelope(res_low, False)
        self.assertIn("ValueError", res_low["error"])
        self.assertIn("exceeds safety limits", res_low["error"])

        # Valid PBKDF2 at minimum boundary (1,000)
        res_kdf = op_secret_scanner.secret_scanner({
            "action": "crypto_utils",
            "operation": "derive_key",
            "password": "pass",
            "salt": "salt123",
            "iterations": 1000,
            "hash_name": "sha256",
        })
        self.assert_envelope(res_kdf, True)
        self.assertEqual(res_kdf["data"]["iterations"], 1000)

        # Constant-time comparison
        res_match = op_secret_scanner.secret_scanner({
            "action": "crypto_utils",
            "operation": "compare_digest",
            "val_a": "secret_token_123",
            "val_b": "secret_token_123",
        })
        self.assert_envelope(res_match, True)
        self.assertTrue(res_match["data"]["match"])

        res_nomatch = op_secret_scanner.secret_scanner({
            "action": "crypto_utils",
            "operation": "compare_digest",
            "val_a": "secret_token_123",
            "val_b": "wrong_token_456",
        })
        self.assert_envelope(res_nomatch, True)
        self.assertFalse(res_nomatch["data"]["match"])

        # CSPRNG tokens
        for fmt in ("hex", "urlsafe", "alphanumeric", "ascii_printable"):
            res_tok = op_secret_scanner.secret_scanner({
                "action": "crypto_utils",
                "operation": "generate_token",
                "token_type": fmt,
                "nbytes": 16,
            })
            self.assert_envelope(res_tok, True)
            self.assertGreaterEqual(len(res_tok["data"]["token"]), 16)

    def test_adv_secret_scanner_confinement_and_null_bytes(self):
        """Verify secret_scanner blocks traversal and sensitive directories."""
        res_sens = op_secret_scanner.secret_scanner({
            "action": "scan_patterns",
            "path": str(Path.home() / ".ssh" / "id_rsa"),
        })
        self.assert_envelope(res_sens, False)
        self.assertIn("SensitivePathError", res_sens["error"])

        res_null = op_secret_scanner.secret_scanner({
            "action": "scan_patterns",
            "path": "/tmp/test\x00file",
        })
        self.assert_envelope(res_null, False)
        self.assertIn("PathSecurityError", res_null["error"])


# =============================================================================
# 8. op_log_summarizer Adversarial Tests
# =============================================================================

class TestM5LogSummarizerAdversarial(BaseAdversarialTestCase):
    """White-box Tier 5 adversarial hardening for op_log_summarizer."""

    def test_adv_interleaved_multi_year_timestamps(self):
        """Verify spike detection handles interleaved multi-year timestamps without crashing."""
        log_stream = (
            "2024-12-31T23:59:50Z [ERROR] Year-end issue\n"
            "2025-01-01T00:00:10Z [ERROR] New-year event\n"
            "2026-06-15T12:00:00Z [ERROR] Milestone event\n"
            "2027-01-01T00:00:00Z [ERROR] Future event\n"
        )
        res = op_log_summarizer.log_summarizer({
            "action": "detect_spikes",
            "text": log_stream,
            "bucket_seconds": 60,
            "fill_empty_buckets": False,
        })
        self.assert_envelope(res, True)
        self.assertEqual(res["data"]["total_events"], 4)

    def test_adv_spike_detection_statistics_and_empty_buckets(self):
        """Verify Z-score anomaly detection identifies bursts against baseline."""
        lines = []
        # Baseline: 1 error every minute for 10 minutes
        base_epoch = 1770000000
        for i in range(10):
            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(base_epoch + i * 60))
            lines.append(f"{ts} [ERROR] routine error {i}")

        # Spike: 30 errors in the 11th minute
        spike_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(base_epoch + 10 * 60))
        for j in range(30):
            lines.append(f"{spike_ts} [ERROR] burst error {j}")

        res = op_log_summarizer.log_summarizer({
            "action": "detect_spikes",
            "text": "\n".join(lines),
            "bucket_seconds": 60,
            "threshold_zscore": 2.0,
            "fill_empty_buckets": True,
        })
        self.assert_envelope(res, True)
        data = res["data"]
        self.assertGreater(data["spikes_count"], 0)
        spikes = [b for b in data["buckets"] if b["is_spike"]]
        self.assertTrue(any(s["count"] == 30 for s in spikes))

    def test_adv_custom_regex_masking_collisions_and_partial_mask(self):
        """Verify collision-free PII masking and partial masking retention."""
        log_line = (
            "Client john.doe@example.com from 10.20.30.40 using Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz "
            "attempted transaction on account."
        )
        # Full masking
        res_full = op_log_summarizer.log_summarizer({
            "action": "mask_pii",
            "text": log_line,
            "replacement_map": {"email": "#EMAIL#", "ipv4": "#IP#"},
        })
        self.assert_envelope(res_full, True)
        masked_full = res_full["data"]["masked_text"]
        self.assertNotIn("john.doe@example.com", masked_full)
        self.assertNotIn("10.20.30.40", masked_full)
        self.assertIn("#", masked_full)

        # Partial masking preserves domain / boundaries
        res_part = op_log_summarizer.log_summarizer({
            "action": "mask_pii",
            "text": log_line,
            "partial_mask": True,
        })
        self.assert_envelope(res_part, True)
        masked_part = res_part["data"]["masked_text"]
        self.assertIn("@example.com", masked_part)

    def test_adv_multi_runtime_stacktrace_triage_and_chains(self):
        """Verify stacktrace triage across Python chained exceptions, Java, Node.js, and Go panics."""
        # Python chained traceback
        python_traceback = (
            "Traceback (most recent call last):\n"
            '  File "worker.py", line 15, in connect\n'
            "    raise ConnectionError('broker unavailable')\n"
            "ConnectionError: broker unavailable\n"
            "\nDuring handling of the above exception, another exception occurred:\n\n"
            "Traceback (most recent call last):\n"
            '  File "main.py", line 45, in run\n'
            "    raise RuntimeError('task failed')\n"
            "RuntimeError: task failed\n"
        )
        res_py = op_log_summarizer.log_summarizer({
            "action": "triage_stacktrace",
            "text": python_traceback,
        })
        self.assert_envelope(res_py, True)
        tb_py = res_py["data"]["tracebacks"][0]
        self.assertEqual(tb_py["runtime"], "python")
        self.assertEqual(tb_py["exception_type"], "RuntimeError")
        self.assertTrue(tb_py["is_chained"])
        self.assertEqual(tb_py["cause"]["exception_type"], "ConnectionError")

        # Java exception with Caused by
        java_traceback = (
            "java.lang.RuntimeException: Application failed\n"
            "\tat com.example.App.start(App.java:30)\n"
            "Caused by: java.io.FileNotFoundException: config.yaml not found\n"
            "\tat com.example.Config.load(Config.java:12)\n"
        )
        res_java = op_log_summarizer.log_summarizer({
            "action": "triage_stacktrace",
            "text": java_traceback,
        })
        self.assert_envelope(res_java, True)
        self.assertIsInstance(res_java["data"]["tracebacks"], list)

        # Go panic
        go_panic = (
            "panic: runtime error: index out of range [5] with length 3\n"
            "goroutine 1 [running]:\n"
            "main.process(0xc00001)\n"
            "\t/app/main.go:42 +0x39\n"
        )
        res_go = op_log_summarizer.log_summarizer({
            "action": "triage_stacktrace",
            "text": go_panic,
        })
        self.assert_envelope(res_go, True)
        self.assertIsInstance(res_go["data"]["tracebacks"], list)

    def test_adv_error_clustering_dynamic_variable_masking(self):
        """Verify clustering collapses dynamic UUIDs, IPs, and timestamps into common templates."""
        log_sample = (
            "2026-11-22T01:00:00Z [ERROR] Failed transaction 550e8400-e29b-41d4-a716-446655440000 for user 1042 from 10.0.0.5 after 450ms\n"
            "2026-11-22T01:00:05Z [ERROR] Failed transaction 6ba7b810-9dad-11d1-80b4-00c04fd430c8 for user 2088 from 10.0.0.8 after 520ms\n"
            "2026-11-22T01:00:10Z [ERROR] Failed transaction 7ca7b820-9dad-11d1-80b4-00c04fd430c9 for user 3012 from 10.0.0.9 after 610ms\n"
        )
        res = op_log_summarizer.log_summarizer({
            "action": "cluster_errors",
            "text": log_sample,
        })
        self.assert_envelope(res, True)
        clusters = res["data"]["clusters"]
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0]["count"], 3)

    def test_adv_log_summarizer_payload_limit_and_confinement(self):
        """Verify rejection of oversized payloads and sensitive paths."""
        huge_log = "INFO message\n" * (1024 * 1024)
        res_huge = op_log_summarizer.log_summarizer({
            "action": "cluster_errors",
            "text": huge_log,
        })
        self.assert_envelope(res_huge, False)
        self.assertIn("PayloadSizeError", res_huge["error"])

        res_sens = op_log_summarizer.log_summarizer({
            "action": "cluster_errors",
            "path": str(Path.home() / ".ssh" / "known_hosts"),
        })
        self.assert_envelope(res_sens, False)
        self.assertIn("SensitivePathError", res_sens["error"])


if __name__ == "__main__":
    unittest.main()
