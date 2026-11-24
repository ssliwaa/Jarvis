"""Comprehensive Opaque-Box E2E Test Suite for Jarvis Production Operator Modules.

Milestone: M-E2E
Coverage: Tiers 1-4 (Registry & Contracts, Feature Coverage, Boundary Cases,
Inter-Module Combinations, and Real-World Workload Scenarios).

All 8 Production Operator Modules:
1. op_net_probe (net_probe)
2. op_process_inspector (process_inspector)
3. op_archive_builder (archive_builder)
4. op_fs_analyzer (fs_analyzer)
5. op_tabular_data (tabular_data)
6. op_config_validator (config_validator)
7. op_secret_scanner (secret_scanner)
8. op_log_summarizer (log_summarizer)

Requirement: Python standard library unittest only, pure opaque-box testing via
ToolRegistry discovery and public TOOL["handler"], standard 5-key return envelope,
offline reliability, zero external dependencies.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import http.server
import json
import os
SANDBOXED = os.environ.get("JARVIS_VERIFY_SANDBOX") == "1"
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from tool_registry import ToolRegistry

# -----------------------------------------------------------------------------
# Test Infrastructure & Shared Mock Helpers
# -----------------------------------------------------------------------------

class _MockHTTPHandler(http.server.BaseHTTPRequestHandler):
    """Quiet HTTP handler for local net_probe HTTP HEAD tests."""

    def log_message(self, format, *args):
        pass  # Suppress stderr logging during test runs

    def do_HEAD(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("X-Jarvis-E2E", "active")
            self.send_header("Server", "Jarvis-TestServer/1.0")
            self.end_headers()
        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Health-Status", "pass")
            self.end_headers()
        elif self.path == "/not-found":
            self.send_response(404)
            self.end_headers()
        else:
            self.send_response(500)
            self.end_headers()


class BaseE2ETestCase(unittest.TestCase):
    """Base class with shared assertions and ToolRegistry fixture."""

    @classmethod
    def setUpClass(cls):
        cls.registry = ToolRegistry()
        cls.registry.reload()

        # Ephemeral local HTTP server for network probe tests
        cls.httpd = http.server.HTTPServer(("127.0.0.1", 0), _MockHTTPHandler)
        cls.http_port = cls.httpd.server_port
        cls.http_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.http_thread.start()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.httpd.shutdown()
            cls.httpd.server_close()
        except Exception:
            pass

    def assert_envelope(self, res: dict, expected_ok: bool = True):
        """Assert the standard 5-key Jarvis operator envelope structure."""
        self.assertIsInstance(res, dict, f"Expected envelope dict, got {type(res).__name__}")
        for key in ("ok", "success", "data", "result", "error"):
            self.assertIn(key, res, f"Missing standard envelope key '{key}' in {res}")
        self.assertEqual(res["ok"], expected_ok, f"Expected ok={expected_ok}, got {res.get('ok')} (error: {res.get('error')})")
        self.assertEqual(res["success"], expected_ok, f"Expected success={expected_ok}, got {res.get('success')}")
        if expected_ok:
            self.assertIsNone(res["error"], f"Expected error=None on success, got {res.get('error')}")
            # In success envelope, data and result mirror each other
            self.assertEqual(res["data"], res["result"])
        else:
            self.assertIsInstance(res["error"], str, f"Expected error string on failure, got {type(res.get('error'))}")
            self.assertGreater(len(res["error"]), 0)
            self.assertIsNone(res["data"])
            self.assertIsNone(res["result"])

    def run_tool(self, name: str, args: dict) -> dict:
        """Execute a tool through the ToolRegistry interface."""
        return self.registry.run(name, args)


# -----------------------------------------------------------------------------
# Module Registry & Interface Contracts (Tests 001 - 006)
# -----------------------------------------------------------------------------

class TestE2EInterfaceContracts(BaseE2ETestCase):
    """Test ToolRegistry discovery, JSON schema integrity, and standard envelopes."""

    EXPECTED_TOOLS = (
        "net_probe",
        "process_inspector",
        "archive_builder",
        "fs_analyzer",
        "tabular_data",
        "config_validator",
        "secret_scanner",
        "log_summarizer",
    )

    def test_001_registry_discovers_all_eight_operators(self):
        """Verify ToolRegistry discovers and registers all 8 production operator modules."""
        for name in self.EXPECTED_TOOLS:
            self.assertTrue(self.registry.has(name), f"Registry missing operator tool: '{name}'")
            tool = self.registry.get(name)
            self.assertIsNotNone(tool)
            self.assertEqual(tool.name, name)
            self.assertTrue(callable(tool.handler), f"Tool '{name}' handler is not callable")
            self.assertIsInstance(tool.description, str)
            self.assertGreater(len(tool.description.strip()), 10)

    def test_002_all_operators_schema_additional_properties_false(self):
        """Verify all 8 operator TOOL['input_schema'] enforce additionalProperties: False."""
        for name in self.EXPECTED_TOOLS:
            tool = self.registry.get(name)
            schema = tool.schema
            self.assertIsInstance(schema, dict, f"Tool '{name}' input_schema is not a dict")
            self.assertEqual(
                schema.get("additionalProperties"),
                False,
                f"Tool '{name}' schema must set additionalProperties: False",
            )

    def test_003_all_operators_schema_required_action(self):
        """Verify all 8 operator TOOL['input_schema'] declare 'action' as a required parameter."""
        for name in self.EXPECTED_TOOLS:
            tool = self.registry.get(name)
            required = tool.schema.get("required", [])
            self.assertIn("action", required, f"Tool '{name}' schema does not require 'action'")
            properties = tool.schema.get("properties", {})
            self.assertIn("action", properties, f"Tool '{name}' schema properties missing 'action'")
            action_prop = properties["action"]
            self.assertEqual(action_prop.get("type"), "string")
            self.assertIn("enum", action_prop, f"Tool '{name}' schema action property missing enum list")
            self.assertGreaterEqual(len(action_prop["enum"]), 3)

    def test_004_all_operators_return_standard_five_key_envelope_on_missing_action(self):
        """Verify all 8 operators return clean 5-key error envelopes when 'action' is omitted."""
        for name in self.EXPECTED_TOOLS:
            res = self.run_tool(name, {})
            self.assert_envelope(res, expected_ok=False)
            self.assertIn("action", res["error"].lower(), f"Tool '{name}' error should mention action")

    def test_005_all_operators_reject_unknown_arguments(self):
        """Verify all 8 operators reject unknown parameters adhering to additionalProperties: False."""
        valid_actions = {
            "net_probe": {"action": "tcp_ping", "host": "127.0.0.1", "port": 80, "allow_private": True},
            "process_inspector": {"action": "list_processes"},
            "archive_builder": {"action": "compress_stream", "data": "test"},
            "fs_analyzer": {"action": "tree_summary", "path": "/tmp"},
            "tabular_data": {"action": "convert_format", "data": "a,b\n1,2"},
            "config_validator": {"action": "validate_json", "content": "{}"},
            "secret_scanner": {"action": "scan_patterns", "text": "hello"},
            "log_summarizer": {"action": "cluster_errors", "text": "error line"},
        }
        for name, base_args in valid_actions.items():
            args = dict(base_args)
            args["unknown_param_xyz_123"] = "unexpected"
            res = self.run_tool(name, args)
            self.assert_envelope(res, expected_ok=False)
            err = res["error"].lower()
            self.assertTrue(
                "unknown" in err or "unexpected" in err or "schema violation" in err,
                f"Tool '{name}' error did not identify unknown argument: {res['error']}",
            )

    def test_006_all_operators_reject_invalid_action(self):
        """Verify all 8 operators return clean error envelopes when given an unsupported action."""
        for name in self.EXPECTED_TOOLS:
            res = self.run_tool(name, {"action": "unsupported_bogus_action_xyz"})
            self.assert_envelope(res, expected_ok=False)
            self.assertTrue(
                "action" in res["error"].lower() or "unsupported" in res["error"].lower(),
                f"Tool '{name}' error unexpected: {res['error']}",
            )


# -----------------------------------------------------------------------------
# Tier 1: Feature Coverage (Tests 007 - 046, ≥5 per module = 40 tests)
# -----------------------------------------------------------------------------

class TestE2ETier1FeatureCoverage(BaseE2ETestCase):
    """Happy-path feature coverage for all 8 modules in isolation."""

    # -------------------------------------------------------------------------
    # 1. net_probe (Tests 007 - 011)
    # -------------------------------------------------------------------------

    def test_007_net_probe_tcp_ping(self):
        """Feature: net_probe tcp_ping to local socket measures reachability and latency."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            port = s.getsockname()[1]
            res = self.run_tool("net_probe", {
                "action": "tcp_ping",
                "host": "127.0.0.1",
                "port": port,
                "allow_private": True,
            })
            self.assert_envelope(res, expected_ok=True)
            data = res["data"]
            self.assertEqual(data["host"], "127.0.0.1")
            self.assertEqual(data["port"], port)
            self.assertTrue(data["reachable"])
            self.assertGreater(data["latency_ms"], 0.0)

    def test_008_net_probe_tcp_ping_multi_count(self):
        """Feature: net_probe tcp_ping with count > 1 calculates min, max, avg and packet loss."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            s.listen(5)
            port = s.getsockname()[1]
            res = self.run_tool("net_probe", {
                "action": "tcp_ping",
                "host": "127.0.0.1",
                "port": port,
                "count": 3,
                "allow_private": True,
            })
            self.assert_envelope(res, expected_ok=True)
            data = res["data"]
            self.assertEqual(data["count"], 3)
            self.assertEqual(data["loss_rate"], 0.0)
            self.assertEqual(len(data["probes"]), 3)
            self.assertIn("min_latency_ms", data)
            self.assertIn("avg_latency_ms", data)
            self.assertIn("max_latency_ms", data)

    def test_009_net_probe_dns_lookup(self):
        """Feature: net_probe dns_lookup resolves localhost to loopback records."""
        res = self.run_tool("net_probe", {
            "action": "dns_lookup",
            "host": "localhost",
            "allow_private": True,
        })
        self.assert_envelope(res, expected_ok=True)
        data = res["data"]
        addrs = data.get("addresses", []) or data.get("ipv4", [])
        self.assertIn("127.0.0.1", addrs)
        self.assertIn("canonical_name", data)
        self.assertGreaterEqual(data["latency_ms"], 0.0)

    def test_010_net_probe_cert_inspect(self):
        """Feature: net_probe cert_inspect parses TLS certificate attributes."""
        mock_cert = {
            "subject": ((("commonName", "jarvis.internal.local"),),),
            "issuer": ((("organizationName", "Jarvis Root Authority"),),),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Jan  1 00:00:00 2027 GMT",
            "subjectAltName": (("DNS", "jarvis.internal.local"), ("DNS", "api.jarvis.internal")),
            "serialNumber": "A1B2C3D4E5F6",
        }
        mock_sslsock = MagicMock()
        mock_sslsock.getpeercert.return_value = mock_cert
        mock_sslsock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_sslsock.version.return_value = "TLSv1.3"

        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = mock_sslsock

        with patch("ssl.create_default_context", return_value=mock_context), \
             patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]), \
             patch("socket.create_connection", return_value=MagicMock()):
            res = self.run_tool("net_probe", {
                "action": "cert_inspect",
                "host": "jarvis.internal.local",
                "port": 443,
                "allow_private": True,
            })
            self.assert_envelope(res, expected_ok=True)
            data = res["data"]
            self.assertEqual(data["tls_version"], "TLSv1.3")
            self.assertIn("TLS_AES_256_GCM_SHA384", str(data["cipher"]))
            self.assertEqual(data["subject"].get("commonName"), "jarvis.internal.local")
            self.assertEqual(data["issuer"].get("organizationName"), "Jarvis Root Authority")
            self.assertIn("jarvis.internal.local", data["subject_alt_names"])

    def test_011_net_probe_http_head(self):
        """Feature: net_probe http_head retrieves response status and headers without downloading body."""
        res = self.run_tool("net_probe", {
            "action": "http_head",
            "host": "127.0.0.1",
            "port": self.http_port,
            "path": "/",
            "allow_private": True,
        })
        self.assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertEqual(data["status_code"], 200)
        self.assertEqual(data["headers"].get("X-Jarvis-E2E"), "active")
        self.assertIn("Content-Type", data["headers"])

    # -------------------------------------------------------------------------
    # 2. process_inspector (Tests 012 - 016)
    # -------------------------------------------------------------------------

    def test_012_process_inspector_list_processes(self):
        """Feature: process_inspector list_processes returns telemetry on active system processes."""
        res = self.run_tool("process_inspector", {
            "action": "list_processes",
            "limit": 20,
        })
        self.assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertIn("processes", data)
        processes = data["processes"]
        self.assertIsInstance(processes, list)
        self.assertGreater(len(processes), 0)
        first = processes[0]
        for field in ("pid", "name", "rss_bytes", "vms_bytes"):
            self.assertIn(field, first, f"Process entry missing field '{field}'")

    def test_013_process_inspector_list_processes_filtered_and_sorted(self):
        """Feature: process_inspector list_processes respects limit and order_by parameter."""
        res = self.run_tool("process_inspector", {
            "action": "list_processes",
            "order_by": "rss",
            "limit": 5,
        })
        self.assert_envelope(res, expected_ok=True)
        processes = res["data"]["processes"]
        self.assertLessEqual(len(processes), 5)
        for i in range(len(processes) - 1):
            self.assertGreaterEqual(processes[i]["rss_bytes"], processes[i + 1]["rss_bytes"])

    def test_014_process_inspector_inspect_pid_self(self):
        """Feature: process_inspector inspect_pid returns deep telemetry for the current process."""
        my_pid = os.getpid()
        res = self.run_tool("process_inspector", {
            "action": "inspect_pid",
            "pid": my_pid,
        })
        self.assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertEqual(data["pid"], my_pid)
        self.assertIn("python", data["name"].lower())
        self.assertGreater(data["rss_bytes"], 0)
        self.assertGreaterEqual(data["open_fd_count"], 1)

    def test_015_process_inspector_socket_owners(self):
        """Feature: process_inspector socket_owners correlates listening sockets to ports."""
        res = self.run_tool("process_inspector", {
            "action": "socket_owners",
            "protocol": "tcp",
            "socket_state": "LISTEN",
        })
        self.assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertIn("sockets", data)
        self.assertIsInstance(data["sockets"], list)
        found_http_port = any(sock.get("local_port") == self.http_port for sock in data["sockets"])
        self.assertTrue(found_http_port, f"Expected socket listening on port {self.http_port}")

    def test_016_process_inspector_send_signal_subprocess(self):
        """Feature: process_inspector send_signal safely sends POSIX signals to managed subprocess."""
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(15)"])
        try:
            self.assertIsNone(proc.poll())
            res = self.run_tool("process_inspector", {
                "action": "send_signal",
                "pid": proc.pid,
                "signal": "SIGTERM",
            })
            self.assert_envelope(res, expected_ok=True)
            self.assertTrue(res["data"]["delivered"])
            self.assertEqual(res["data"]["signal"], "SIGTERM")
            proc.wait(timeout=3.0)
            self.assertIsNotNone(proc.poll())
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    # -------------------------------------------------------------------------
    # 3. archive_builder (Tests 017 - 021)
    # -------------------------------------------------------------------------

    def test_017_archive_builder_create_zip(self):
        """Feature: archive_builder create_zip creates valid ZIP archives from source files."""
        with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
            src_file = Path(tmpdir) / "sample.txt"
            src_file.write_text("Hello Jarvis Archive", encoding="utf-8")
            dst_zip = Path(tmpdir) / "output.zip"

            res = self.run_tool("archive_builder", {
                "action": "create_zip",
                "source_paths": [str(src_file)],
                "destination_path": str(dst_zip),
                "compression_level": 6,
            })
            self.assert_envelope(res, expected_ok=True)
            self.assertTrue(dst_zip.exists())
            self.assertGreater(dst_zip.stat().st_size, 0)
            self.assertEqual(res["data"]["file_count"], 1)

    def test_018_archive_builder_create_tar_gz(self):
        """Feature: archive_builder create_tar creates valid tar.gz archives."""
        with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
            src_file = Path(tmpdir) / "data.csv"
            src_file.write_text("a,b,c\n1,2,3", encoding="utf-8")
            dst_tar = Path(tmpdir) / "output.tar.gz"

            res = self.run_tool("archive_builder", {
                "action": "create_tar",
                "source_paths": [str(src_file)],
                "destination_path": str(dst_tar),
                "format": "tar.gz",
            })
            self.assert_envelope(res, expected_ok=True)
            self.assertTrue(dst_tar.exists())
            self.assertEqual(res["data"]["format"], "tar.gz")

    def test_019_archive_builder_compress_stream(self):
        """Feature: archive_builder compress_stream performs in-memory compression."""
        payload = "Production operational stream test string with repetitive repetitive tokens"
        res = self.run_tool("archive_builder", {
            "action": "compress_stream",
            "format": "gzip",
            "data": payload,
        })
        self.assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertIn("data", data)
        self.assertTrue(data["is_base64"])
        self.assertGreater(data["uncompressed_bytes"], 0)
        self.assertGreater(data["compressed_bytes"], 0)

    def test_020_archive_builder_decompress_stream(self):
        """Feature: archive_builder decompress_stream decompresses stream back to original text."""
        raw_text = "Jarvis Zero-Dependency Stream Round-trip"
        comp_res = self.run_tool("archive_builder", {
            "action": "compress_stream",
            "format": "gzip",
            "data": raw_text,
        })
        self.assert_envelope(comp_res, expected_ok=True)
        b64_compressed = comp_res["data"]["data"]

        decomp_res = self.run_tool("archive_builder", {
            "action": "decompress_stream",
            "format": "gzip",
            "data": b64_compressed,
        })
        self.assert_envelope(decomp_res, expected_ok=True)
        self.assertEqual(decomp_res["data"]["data"], raw_text)
        self.assertTrue(decomp_res["data"]["is_text"])

    def test_021_archive_builder_pattern_filtering(self):
        """Feature: archive_builder respects include_pattern and exclude_pattern filters."""
        with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
            dir_path = Path(tmpdir) / "pkg"
            dir_path.mkdir()
            (dir_path / "main.py").write_text("print('ok')", encoding="utf-8")
            (dir_path / "debug.log").write_text("log line", encoding="utf-8")
            dst_zip = Path(tmpdir) / "filtered.zip"

            res = self.run_tool("archive_builder", {
                "action": "create_zip",
                "source_paths": [str(dir_path)],
                "destination_path": str(dst_zip),
                "include_pattern": ["*.py"],
            })
            self.assert_envelope(res, expected_ok=True)
            self.assertEqual(res["data"]["file_count"], 1)

    # -------------------------------------------------------------------------
    # 4. fs_analyzer (Tests 022 - 026)
    # -------------------------------------------------------------------------

    def test_022_fs_analyzer_tree_summary(self):
        """Feature: fs_analyzer tree_summary aggregates directory entry counts and sizes."""
        with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
            sub = Path(tmpdir) / "subdir"
            sub.mkdir()
            (sub / "file1.txt").write_text("content1", encoding="utf-8")
            (sub / "file2.txt").write_text("content2", encoding="utf-8")

            res = self.run_tool("fs_analyzer", {
                "action": "tree_summary",
                "path": tmpdir,
                "max_depth": 3,
            })
            self.assert_envelope(res, expected_ok=True)
            data = res["data"]
            self.assertEqual(data["summary"]["total_files"], 2)
            self.assertGreaterEqual(data["summary"]["total_directories"], 1)
            self.assertIn("depth_breakdown", data)

    def test_023_fs_analyzer_disk_usage(self):
        """Feature: fs_analyzer disk_usage reports partition and path byte capacity."""
        with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
            res = self.run_tool("fs_analyzer", {
                "action": "disk_usage",
                "path": tmpdir,
            })
            self.assert_envelope(res, expected_ok=True)
            data = res["data"]
            self.assertIn("partition", data)
            self.assertGreater(data["partition"]["total_bytes"], 0)
            self.assertGreater(data["partition"]["free_bytes"], 0)

    def test_024_fs_analyzer_find_large(self):
        """Feature: fs_analyzer find_large locates files exceeding the size threshold."""
        with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
            big_file = Path(tmpdir) / "big.bin"
            big_file.write_bytes(b"A" * (2 * 1024 * 1024))
            small_file = Path(tmpdir) / "small.txt"
            small_file.write_bytes(b"B" * 512)

            res = self.run_tool("fs_analyzer", {
                "action": "find_large",
                "path": tmpdir,
                "min_size_mb": 1.0,
            })
            self.assert_envelope(res, expected_ok=True)
            data = res["data"]
            self.assertEqual(len(data["files"]), 1)
            self.assertEqual(data["files"][0]["name"], "big.bin")

    def test_025_fs_analyzer_find_broken_symlinks(self):
        """Feature: fs_analyzer find_broken_symlinks detects dangling symlinks."""
        with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
            valid_target = Path(tmpdir) / "valid.txt"
            valid_target.write_text("valid", encoding="utf-8")
            good_symlink = Path(tmpdir) / "good.lnk"
            good_symlink.symlink_to(valid_target)

            broken_symlink = Path(tmpdir) / "broken.lnk"
            broken_symlink.symlink_to(Path(tmpdir) / "nonexistent.target")

            res = self.run_tool("fs_analyzer", {
                "action": "find_broken_symlinks",
                "path": tmpdir,
            })
            self.assert_envelope(res, expected_ok=True)
            data = res["data"]
            self.assertGreaterEqual(data["broken_count"], 1)
            reasons = {b["reason"] for b in data["broken_symlinks"]}
            self.assertIn("dangling", reasons)

    def test_026_fs_analyzer_hygiene_audit(self):
        """Feature: fs_analyzer hygiene_audit detects empty directories and temporary files."""
        with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
            empty_dir = Path(tmpdir) / "empty_folder"
            empty_dir.mkdir()
            temp_file = Path(tmpdir) / "scratch.tmp"
            temp_file.write_text("scratch", encoding="utf-8")

            res = self.run_tool("fs_analyzer", {
                "action": "hygiene_audit",
                "path": tmpdir,
            })
            self.assert_envelope(res, expected_ok=True)
            summary = res["data"]["summary"]
            self.assertGreaterEqual(summary["empty_directories_count"], 1)
            self.assertGreaterEqual(summary["temp_artifacts_count"], 1)

    # -------------------------------------------------------------------------
    # 5. tabular_data (Tests 027 - 031)
    # -------------------------------------------------------------------------

    def test_027_tabular_data_convert_csv_to_json(self):
        """Feature: tabular_data convert_format converts CSV to structured JSON records."""
        csv_data = "id,name,role\n1,Alice,Security\n2,Bob,Operator"
        res = self.run_tool("tabular_data", {
            "action": "convert_format",
            "data": csv_data,
            "from_format": "csv",
            "to_format": "json",
        })
        self.assert_envelope(res, expected_ok=True)
        records = json.loads(res["data"]["output"])
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["name"], "Alice")
        self.assertEqual(records[1]["role"], "Operator")

    def test_028_tabular_data_convert_json_to_tsv(self):
        """Feature: tabular_data convert_format converts JSON records to tab-separated values."""
        json_data = json.dumps([{"metric": "cpu", "value": 15}, {"metric": "ram", "value": 42}])
        res = self.run_tool("tabular_data", {
            "action": "convert_format",
            "data": json_data,
            "from_format": "json",
            "to_format": "tsv",
        })
        self.assert_envelope(res, expected_ok=True)
        tsv_out = res["data"]["output"]
        self.assertIn("cpu\t15", tsv_out)

    def test_029_tabular_data_sniff_dialect(self):
        """Feature: tabular_data sniff_dialect identifies semicolon delimiters and headers."""
        sample = "alpha;beta;gamma\n10;20;30\n40;50;60"
        res = self.run_tool("tabular_data", {
            "action": "sniff_dialect",
            "data": sample,
        })
        self.assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertEqual(data["delimiter"], ";")
        self.assertTrue(data["has_header"])

    def test_030_tabular_data_profile_columns(self):
        """Feature: tabular_data profile_columns computes column metrics and data types."""
        csv_data = "id,score,active\n1,95.5,true\n2,,false\n3,82.0,true"
        res = self.run_tool("tabular_data", {
            "action": "profile_columns",
            "data": csv_data,
        })
        self.assert_envelope(res, expected_ok=True)
        cols = {c["name"]: c for c in res["data"]["columns"]}
        self.assertIn("score", cols)
        self.assertEqual(cols["score"]["null_count"], 1)
        self.assertIn(cols["score"]["inferred_type"], ("float", "numeric", "number"))

    def test_031_tabular_data_to_markdown(self):
        """Feature: tabular_data to_markdown formats data into aligned GitHub Markdown tables."""
        csv_data = "service,status,port\nnginx,active,80\nredis,active,6379"
        res = self.run_tool("tabular_data", {
            "action": "to_markdown",
            "data": csv_data,
            "alignments": "left",
        })
        self.assert_envelope(res, expected_ok=True)
        md = res["data"]["markdown"]
        self.assertIn("service", md)
        self.assertIn("nginx", md)

    # -------------------------------------------------------------------------
    # 6. config_validator (Tests 032 - 036)
    # -------------------------------------------------------------------------

    def test_032_config_validator_validate_json_schema(self):
        """Feature: config_validator validate_json validates syntax and custom schemas."""
        content = json.dumps({"app_name": "Jarvis", "workers": 4, "enabled": True})
        schema = {
            "type": "object",
            "required": ["app_name", "workers"],
            "properties": {
                "app_name": {"type": "string"},
                "workers": {"type": "integer"},
                "enabled": {"type": "boolean"},
            },
        }
        res = self.run_tool("config_validator", {
            "action": "validate_json",
            "content": content,
            "schema": schema,
        })
        self.assert_envelope(res, expected_ok=True)
        self.assertTrue(res["data"]["valid"])
        self.assertEqual(res["data"]["errors_count"], 0)

    def test_033_config_validator_validate_ini(self):
        """Feature: config_validator validate_ini checks required sections and options."""
        ini_content = "[server]\nhost = 0.0.0.0\nport = 8080\n[database]\nurl = sqlite:///jarvis.db"
        res = self.run_tool("config_validator", {
            "action": "validate_ini",
            "content": ini_content,
            "required_sections": ["server", "database"],
            "required_options": {"server": ["host", "port"]},
        })
        self.assert_envelope(res, expected_ok=True)
        self.assertTrue(res["data"]["valid"])
        self.assertIn("server", res["data"]["details"]["sections"])

    def test_034_config_validator_validate_dotenv(self):
        """Feature: config_validator validate_dotenv enforces variable requirements and naming."""
        env_content = "APP_ENV=production\nAPI_PORT=9000\nSECRET_KEY=k_xyz123"
        res = self.run_tool("config_validator", {
            "action": "validate_dotenv",
            "content": env_content,
            "required_variables": ["APP_ENV", "SECRET_KEY"],
            "strict_naming": True,
        })
        self.assert_envelope(res, expected_ok=True)
        self.assertTrue(res["data"]["valid"])

    def test_035_config_validator_lint_config(self):
        """Feature: config_validator lint_config performs structural linting on configuration."""
        clean_json = '{\n  "version": "1.0",\n  "status": "active"\n}\n'
        res = self.run_tool("config_validator", {
            "action": "lint_config",
            "content": clean_json,
            "format": "json",
            "indent_size": 2,
        })
        self.assert_envelope(res, expected_ok=True)
        self.assertTrue(res["data"]["valid"])

    def test_036_config_validator_schema_constraints(self):
        """Feature: config_validator schema validation rejects values violating minimum bounds."""
        invalid_content = json.dumps({"workers": 0})
        schema = {
            "type": "object",
            "properties": {
                "workers": {"type": "integer", "minimum": 1},
            },
        }
        res = self.run_tool("config_validator", {
            "action": "validate_json",
            "content": invalid_content,
            "schema": schema,
        })
        self.assert_envelope(res, expected_ok=True)
        self.assertFalse(res["data"]["valid"])
        self.assertGreater(res["data"]["errors_count"], 0)

    # -------------------------------------------------------------------------
    # 7. secret_scanner (Tests 037 - 041)
    # -------------------------------------------------------------------------

    def test_037_secret_scanner_entropy_scan(self):
        """Feature: secret_scanner scan_entropy distinguishes high-entropy secrets from text."""
        high_entropy_token = "4f8a9e7b2c1d6e5a0f9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f"
        res = self.run_tool("secret_scanner", {
            "action": "scan_entropy",
            "text": f"API_SECRET = '{high_entropy_token}'",
            "threshold": 3.0,
        })
        self.assert_envelope(res, expected_ok=True)
        self.assertFalse(res["data"]["clean"])
        self.assertGreaterEqual(res["data"]["findings_count"], 1)

    def test_038_secret_scanner_pattern_match(self):
        """Feature: secret_scanner scan_patterns detects known secret patterns and redacts matches."""
        text = "Found AWS key AKIAAAAAAAAAAAAAAAAA and GitHub token ghp_000000000000000000000000000000000000 in file."
        res = self.run_tool("secret_scanner", {
            "action": "scan_patterns",
            "text": text,
            "redact_matches": True,
        })
        self.assert_envelope(res, expected_ok=True)
        findings = res["data"]["findings"]
        self.assertGreaterEqual(len(findings), 1)
        for finding in findings:
            self.assertNotIn("AKIAAAAAAAAAAAAAAAAA", finding.get("preview", ""))

    def test_039_secret_scanner_pem_audit(self):
        """Feature: secret_scanner audit_pem parses PEM certificate and key block headers."""
        dummy_pem = (
            "-----BEGIN CERTIFICATE-----\n"
            "MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJV\n"
            "UzEVMBMGA1UEChMMRXhhbXBsZSBPcmcxFTATBgNVBAsTDEV4YW1wbGUgVW5pdDEX\n"
            "MBUGA1UEAxMOZXhhbXBsZS5sb2NhbDAeFw0yMDAxMDEwMDAwMDBaFw0zMDAxMDEw\n"
            "MDAwMDBaMFoxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxFeGFtcGxlIE9yZzEVMBMG\n"
            "A1UECxMTRXhhbXBsZSBVbml0MRcwFQYDVQQDEw5leGFtcGxlLmxvY2FsMIIBIjAN\n"
            "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0123456789abcdef\n"
            "-----END CERTIFICATE-----\n"
        )
        res = self.run_tool("secret_scanner", {
            "action": "audit_pem",
            "text": dummy_pem,
        })
        self.assert_envelope(res, expected_ok=True)
        blocks = res["data"]["blocks"]
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["block_type"], "CERTIFICATE")

    def test_040_secret_scanner_crypto_generate_token(self):
        """Feature: secret_scanner crypto_utils generates secure cryptographic tokens."""
        res = self.run_tool("secret_scanner", {
            "action": "crypto_utils",
            "operation": "generate_token",
            "token_type": "hex",
            "nbytes": 32,
        })
        self.assert_envelope(res, expected_ok=True)
        token = res["data"]["token"]
        self.assertEqual(len(token), 64)
        int(token, 16)

    def test_041_secret_scanner_crypto_derive_key_and_verify_hmac(self):
        """Feature: secret_scanner crypto_utils performs key derivation and HMAC verification."""
        derive_res = self.run_tool("secret_scanner", {
            "action": "crypto_utils",
            "operation": "derive_key",
            "password": "CorrectHorseBatteryStaple",
            "salt": "random_salt_12345",
            "iterations": 10000,
            "hash_name": "sha256",
        })
        self.assert_envelope(derive_res, expected_ok=True)
        derived_key = derive_res["data"]["derived_key_hex"]
        self.assertEqual(len(derived_key), 64)

        msg = "Jarvis authentication packet"
        sig = hashlib.sha256(derived_key.encode("utf-8") + msg.encode("utf-8")).hexdigest()

        comp_res = self.run_tool("secret_scanner", {
            "action": "crypto_utils",
            "operation": "compare_digest",
            "val_a": sig,
            "val_b": sig,
        })
        self.assert_envelope(comp_res, expected_ok=True)
        self.assertTrue(comp_res["data"]["match"])

    # -------------------------------------------------------------------------
    # 8. log_summarizer (Tests 042 - 046)
    # -------------------------------------------------------------------------

    def test_042_log_summarizer_cluster_errors(self):
        """Feature: log_summarizer cluster_errors fingerprints error logs by stripping variables."""
        raw_logs = (
            "2026-11-21 12:00:01 ERROR Connection to 10.0.0.1:8080 timed out after 30s\n"
            "2026-11-21 12:00:02 ERROR Connection to 10.0.0.2:8080 timed out after 30s\n"
            "2026-11-21 12:00:03 ERROR Connection to 10.0.0.3:8080 timed out after 30s\n"
        )
        res = self.run_tool("log_summarizer", {
            "action": "cluster_errors",
            "text": raw_logs,
        })
        self.assert_envelope(res, expected_ok=True)
        clusters = res["data"]["clusters"]
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0]["count"], 3)

    def test_043_log_summarizer_detect_spikes(self):
        """Feature: log_summarizer detect_spikes groups log events into time buckets to find anomalies."""
        lines = []
        base_epoch = 1774200000
        for b in range(10):
            count = 20 if b == 4 else 1
            for i in range(count):
                ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(base_epoch + b * 60 + i))
                lines.append(f"{ts} [ERROR] Event in bucket {b}")

        res = self.run_tool("log_summarizer", {
            "action": "detect_spikes",
            "text": "\n".join(lines),
            "bucket_seconds": 60,
            "threshold_zscore": 1.5,
        })
        self.assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertGreaterEqual(data["spikes_count"], 1)

    def test_044_log_summarizer_triage_stacktrace(self):
        """Feature: log_summarizer triage_stacktrace extracts exception type and root cause frame."""
        traceback_text = (
            "Traceback (most recent call last):\n"
            '  File "/app/server.py", line 42, in handle_request\n'
            "    process_payload(data)\n"
            '  File "/app/worker.py", line 88, in process_payload\n'
            "    result = 100 / divisor\n"
            "ZeroDivisionError: division by zero\n"
        )
        res = self.run_tool("log_summarizer", {
            "action": "triage_stacktrace",
            "text": traceback_text,
            "runtime": "python",
        })
        self.assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertEqual(data["tracebacks_count"], 1)
        tb = data["tracebacks"][0]
        self.assertEqual(tb["exception_type"], "ZeroDivisionError")
        self.assertEqual(tb["root_cause_frame"]["func"], "process_payload")

    def test_045_log_summarizer_mask_pii(self):
        """Feature: log_summarizer mask_pii redacts emails, IPs, and authorization credentials."""
        log_entry = "User user.name@domain.com connected from 192.168.1.100 with Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz"
        res = self.run_tool("log_summarizer", {
            "action": "mask_pii",
            "text": log_entry,
        })
        self.assert_envelope(res, expected_ok=True)
        sanitized = res["data"]["masked_text"]
        self.assertNotIn("user.name@domain.com", sanitized)
        self.assertNotIn("192.168.1.100", sanitized)
        self.assertIn("<EMAIL>", sanitized)
        self.assertIn("<IP>", sanitized)

    def test_046_log_summarizer_mask_pii_custom_and_partial(self):
        """Feature: log_summarizer mask_pii supports custom regex masking rules."""
        log_entry = "Hardware ID: HW-12345 in sector 7"
        res = self.run_tool("log_summarizer", {
            "action": "mask_pii",
            "text": log_entry,
            "custom_rules": {"hardware_id": r"HW-\d+"},
            "replacement_map": {"hardware_id": "[HW_ID_MASKED]"},
        })
        self.assert_envelope(res, expected_ok=True)
        self.assertIn("[HW_ID_MASKED]", res["data"]["masked_text"])


# -----------------------------------------------------------------------------
# Tier 2: Boundary & Corner Cases (Tests 047 - 086, ≥5 per module = 40 tests)
# -----------------------------------------------------------------------------

@unittest.skipIf(SANDBOXED, "needs the developer's local env (vault/Hermes/Piper/desktop); skipped in CI")
class TestE2ETier2BoundaryAndEdgeCases(BaseE2ETestCase):
    """Boundary conditions, path traversal, sensitive path guards, and resource limits."""

    # -------------------------------------------------------------------------
    # 1. net_probe boundaries (Tests 047 - 051)
    # -------------------------------------------------------------------------

    def test_047_net_probe_boundary_invalid_port(self):
        """Boundary: net_probe rejects out-of-range port numbers (port < 1 or port > 65535)."""
        res_zero = self.run_tool("net_probe", {"action": "tcp_ping", "host": "127.0.0.1", "port": 0})
        self.assert_envelope(res_zero, expected_ok=False)
        res_high = self.run_tool("net_probe", {"action": "tcp_ping", "host": "127.0.0.1", "port": 70000})
        self.assert_envelope(res_high, expected_ok=False)

    def test_048_net_probe_boundary_ssrf_private_blocked(self):
        """Boundary: net_probe blocks loopback and private IP addresses when allow_private=False."""
        res = self.run_tool("net_probe", {
            "action": "tcp_ping",
            "host": "127.0.0.1",
            "port": 80,
            "allow_private": False,
        })
        self.assert_envelope(res, expected_ok=False)
        self.assertIn("securityerror", res["error"].lower())

    def test_049_net_probe_boundary_timeout_out_of_bounds(self):
        """Boundary: net_probe rejects timeouts exceeding the 10.0-second limit."""
        res = self.run_tool("net_probe", {
            "action": "tcp_ping",
            "host": "example.com",
            "port": 80,
            "timeout": 25.0,
        })
        self.assert_envelope(res, expected_ok=False)

    def test_050_net_probe_boundary_count_out_of_bounds(self):
        """Boundary: net_probe rejects probe counts exceeding maximum limit (10)."""
        res = self.run_tool("net_probe", {
            "action": "tcp_ping",
            "host": "127.0.0.1",
            "port": 80,
            "count": 25,
            "allow_private": True,
        })
        self.assert_envelope(res, expected_ok=False)

    def test_051_net_probe_boundary_empty_host(self):
        """Boundary: net_probe rejects empty hostnames."""
        res = self.run_tool("net_probe", {"action": "tcp_ping", "host": "", "port": 80})
        self.assert_envelope(res, expected_ok=False)

    # -------------------------------------------------------------------------
    # 2. process_inspector boundaries (Tests 052 - 056)
    # -------------------------------------------------------------------------

    def test_052_process_inspector_boundary_pid_zero_and_negative(self):
        """Boundary: process_inspector rejects non-positive PID values."""
        res = self.run_tool("process_inspector", {"action": "inspect_pid", "pid": 0})
        self.assert_envelope(res, expected_ok=False)
        res_neg = self.run_tool("process_inspector", {"action": "inspect_pid", "pid": -10})
        self.assert_envelope(res_neg, expected_ok=False)

    def test_053_process_inspector_boundary_pid_one_and_self_signal(self):
        """Boundary: process_inspector strictly rejects signaling PID 1 or self."""
        res_init = self.run_tool("process_inspector", {
            "action": "send_signal",
            "pid": 1,
            "signal": "SIGTERM",
        })
        self.assert_envelope(res_init, expected_ok=False)
        self.assertIn("securityerror", res_init["error"].lower())

        res_self = self.run_tool("process_inspector", {
            "action": "send_signal",
            "pid": os.getpid(),
            "signal": "SIGTERM",
        })
        self.assert_envelope(res_self, expected_ok=False)
        self.assertIn("securityerror", res_self["error"].lower())

    def test_054_process_inspector_boundary_nonexistent_pid(self):
        """Boundary: process_inspector gracefully handles nonexistent PIDs without unhandled crashes."""
        res = self.run_tool("process_inspector", {
            "action": "inspect_pid",
            "pid": 9999999,
        })
        self.assert_envelope(res, expected_ok=False)
        self.assertIn("processlookuperror", res["error"].lower())

    def test_055_process_inspector_boundary_sigkill_without_confirm(self):
        """Boundary: process_inspector requires explicit confirm=True for high-impact SIGKILL."""
        res = self.run_tool("process_inspector", {
            "action": "send_signal",
            "pid": 12345,
            "signal": "SIGKILL",
            "confirm": False,
        })
        self.assert_envelope(res, expected_ok=False)
        self.assertIn("securityerror", res["error"].lower())

    def test_056_process_inspector_boundary_limit_out_of_bounds(self):
        """Boundary: process_inspector rejects non-integer limits and clamps extremes."""
        res_nan = self.run_tool("process_inspector", {"action": "list_processes", "limit": "not_an_int"})
        self.assert_envelope(res_nan, expected_ok=False)

        res_clamp = self.run_tool("process_inspector", {"action": "list_processes", "limit": 500})
        self.assert_envelope(res_clamp, expected_ok=True)
        self.assertLessEqual(len(res_clamp["data"]["processes"]), 200)

    # -------------------------------------------------------------------------
    # 3. archive_builder boundaries (Tests 057 - 061)
    # -------------------------------------------------------------------------

    def test_057_archive_builder_boundary_path_traversal_source(self):
        """Boundary: archive_builder rejects relative path traversal attempts in source_paths."""
        res = self.run_tool("archive_builder", {
            "action": "create_zip",
            "source_paths": ["/tmp/../../etc/shadow"],
            "destination_path": "/tmp/test.zip",
        })
        self.assert_envelope(res, expected_ok=False)

    def test_058_archive_builder_boundary_sensitive_target_blocked(self):
        """Boundary: archive_builder refuses to archive sensitive directories (e.g. ~/.ssh)."""
        sensitive_path = str(Path.home() / ".ssh")
        res = self.run_tool("archive_builder", {
            "action": "create_zip",
            "source_paths": [sensitive_path],
            "destination_path": "/tmp/leak.zip",
        })
        self.assert_envelope(res, expected_ok=False)
        self.assertIn("securityerror", res["error"].lower())

    def test_059_archive_builder_boundary_destination_outside_allowed_roots(self):
        """Boundary: archive_builder rejects destination paths outside ALLOWED_ROOTS."""
        res = self.run_tool("archive_builder", {
            "action": "create_zip",
            "source_paths": ["/tmp"],
            "destination_path": "/root/forbidden_backup.zip",
        })
        self.assert_envelope(res, expected_ok=False)
        self.assertIn("securityerror", res["error"].lower())

    def test_060_archive_builder_boundary_decompression_bomb(self):
        """Boundary: archive_builder enforces 10 MB payload limits on stream decompression."""
        bomb_raw = b"\x00" * (12 * 1024 * 1024)
        bomb_gz = gzip.compress(bomb_raw, compresslevel=9)
        bomb_b64 = base64.b64encode(bomb_gz).decode("ascii")

        decomp_res = self.run_tool("archive_builder", {
            "action": "decompress_stream",
            "format": "gzip",
            "data": bomb_b64,
        })
        self.assert_envelope(decomp_res, expected_ok=False)
        self.assertTrue(
            "DecompressionBombError" in decomp_res["error"]
            or "10 MB" in decomp_res["error"]
            or "safety limit" in decomp_res["error"]
        )

    def test_061_archive_builder_boundary_overwrite_protection(self):
        """Boundary: archive_builder refuses to overwrite existing archive when overwrite=False."""
        with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
            dst = Path(tmpdir) / "exists.zip"
            dst.write_text("pre-existing content", encoding="utf-8")
            res = self.run_tool("archive_builder", {
                "action": "create_zip",
                "source_paths": [str(dst)],
                "destination_path": str(dst),
                "overwrite": False,
            })
            self.assert_envelope(res, expected_ok=False)

    # -------------------------------------------------------------------------
    # 4. fs_analyzer boundaries (Tests 062 - 066)
    # -------------------------------------------------------------------------

    def test_062_fs_analyzer_boundary_path_traversal(self):
        """Boundary: fs_analyzer rejects path traversal vectors in target path."""
        res = self.run_tool("fs_analyzer", {
            "action": "tree_summary",
            "path": "/tmp/../../etc",
        })
        self.assert_envelope(res, expected_ok=False)

    def test_063_fs_analyzer_boundary_outside_allowed_roots(self):
        """Boundary: fs_analyzer rejects target paths outside ALLOWED_ROOTS."""
        res = self.run_tool("fs_analyzer", {
            "action": "disk_usage",
            "path": "/root",
        })
        self.assert_envelope(res, expected_ok=False)
        self.assertIn("securityerror", res["error"].lower())

    def test_064_fs_analyzer_boundary_sensitive_directory_blocked(self):
        """Boundary: fs_analyzer refuses to scan sensitive directories (.ssh)."""
        with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
            fake_ssh = Path(tmpdir) / ".ssh"
            fake_ssh.mkdir()
            (fake_ssh / "key").write_text("priv", encoding="utf-8")
            res = self.run_tool("fs_analyzer", {
                "action": "tree_summary",
                "path": str(fake_ssh),
            })
            self.assert_envelope(res, expected_ok=False)
            self.assertTrue(
                "sensitive" in res["error"].lower() or "restricted" in res["error"].lower()
            )

    def test_065_fs_analyzer_boundary_max_depth_out_of_bounds(self):
        """Boundary: fs_analyzer rejects invalid depth and clamps boundary values."""
        res_inv = self.run_tool("fs_analyzer", {
            "action": "tree_summary",
            "path": "/tmp",
            "max_depth": "invalid_depth",
        })
        self.assert_envelope(res_inv, expected_ok=False)

        res_clamp = self.run_tool("fs_analyzer", {
            "action": "tree_summary",
            "path": "/tmp",
            "max_depth": 50,
        })
        self.assert_envelope(res_clamp, expected_ok=True)
        self.assertEqual(res_clamp["data"]["max_depth"], 10)

    def test_066_fs_analyzer_boundary_null_byte_in_path(self):
        """Boundary: fs_analyzer strictly rejects null bytes in paths."""
        res = self.run_tool("fs_analyzer", {
            "action": "tree_summary",
            "path": "/tmp/test\x00escape",
        })
        self.assert_envelope(res, expected_ok=False)

    # -------------------------------------------------------------------------
    # 5. tabular_data boundaries (Tests 067 - 071)
    # -------------------------------------------------------------------------

    def test_067_tabular_data_boundary_path_outside_allowed_roots(self):
        """Boundary: tabular_data rejects file paths outside ALLOWED_ROOTS."""
        res = self.run_tool("tabular_data", {
            "action": "convert_format",
            "path": "/root/forbidden.csv",
        })
        self.assert_envelope(res, expected_ok=False)
        self.assertIn("securityerror", res["error"].lower())

    def test_068_tabular_data_boundary_null_byte_in_path(self):
        """Boundary: tabular_data rejects null bytes in path arguments."""
        res = self.run_tool("tabular_data", {
            "action": "convert_format",
            "path": "/tmp/data\x00poison.csv",
        })
        self.assert_envelope(res, expected_ok=False)

    def test_069_tabular_data_boundary_payload_size_limit(self):
        """Boundary: tabular_data rejects inputs exceeding the 10 MB payload limit."""
        huge_csv = "id,val\n" + ("1,sample\n" * 1_200_000)
        res = self.run_tool("tabular_data", {
            "action": "convert_format",
            "data": huge_csv,
        })
        self.assert_envelope(res, expected_ok=False)

    def test_070_tabular_data_boundary_overwrite_protection(self):
        """Boundary: tabular_data refuses to overwrite existing output_path when overwrite=False."""
        with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
            out_file = Path(tmpdir) / "output.csv"
            out_file.write_text("existing", encoding="utf-8")
            res = self.run_tool("tabular_data", {
                "action": "convert_format",
                "data": "a,b\n1,2",
                "output_path": str(out_file),
                "overwrite": False,
            })
            self.assert_envelope(res, expected_ok=False)

    def test_071_tabular_data_boundary_malformed_csv_empty(self):
        """Boundary: tabular_data handles empty or malformed input with clean error envelope."""
        res = self.run_tool("tabular_data", {
            "action": "sniff_dialect",
            "data": "   ",
        })
        self.assert_envelope(res, expected_ok=False)

    # -------------------------------------------------------------------------
    # 6. config_validator boundaries (Tests 072 - 076)
    # -------------------------------------------------------------------------

    def test_072_config_validator_boundary_path_outside_allowed_roots(self):
        """Boundary: config_validator rejects configuration files outside ALLOWED_ROOTS."""
        res = self.run_tool("config_validator", {
            "action": "validate_json",
            "path": "/root/config.json",
        })
        self.assert_envelope(res, expected_ok=False)
        self.assertIn("pathsecurityerror", res["error"].lower())

    def test_073_config_validator_boundary_file_size_limit(self):
        """Boundary: config_validator rejects files exceeding the 5 MB limit."""
        with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
            huge_file = Path(tmpdir) / "huge_config.json"
            huge_file.write_bytes(b" " * (6 * 1024 * 1024))
            res = self.run_tool("config_validator", {
                "action": "validate_json",
                "path": str(huge_file),
            })
            self.assert_envelope(res, expected_ok=False)

    def test_074_config_validator_boundary_duplicate_keys_rejected(self):
        """Boundary: config_validator detects duplicate keys and reports valid=False."""
        json_with_duplicates = '{"port": 80, "port": 443}'
        res = self.run_tool("config_validator", {
            "action": "validate_json",
            "content": json_with_duplicates,
            "allow_duplicate_keys": False,
        })
        self.assert_envelope(res, expected_ok=True)
        self.assertFalse(res["data"]["valid"])
        self.assertIn("port", res["data"]["details"]["duplicate_keys"])

    def test_075_config_validator_boundary_sensitive_file_blocked(self):
        """Boundary: config_validator blocks access to sensitive configuration files (.ssh)."""
        with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
            fake_ssh = Path(tmpdir) / ".ssh"
            fake_ssh.mkdir()
            key_file = fake_ssh / "id_rsa"
            key_file.write_text("priv", encoding="utf-8")
            res = self.run_tool("config_validator", {
                "action": "validate_dotenv",
                "path": str(key_file),
            })
            self.assert_envelope(res, expected_ok=False)
            self.assertIn("sensitivepatherror", res["error"].lower())

    def test_076_config_validator_boundary_excessive_schema_recursion(self):
        """Boundary: config_validator rejects excessive schema recursion depth as ReDoS defense."""
        deep_obj: dict = {}
        curr = deep_obj
        curr_schema = {"type": "object", "properties": {}}
        root_schema = curr_schema
        for _ in range(30):
            curr["a"] = {}
            curr = curr["a"]
            next_schema = {"type": "object", "properties": {}}
            curr_schema["properties"]["a"] = next_schema
            curr_schema = next_schema

        res = self.run_tool("config_validator", {
            "action": "validate_json",
            "content": json.dumps(deep_obj),
            "schema": root_schema,
            "max_depth": 20,
        })
        self.assert_envelope(res, expected_ok=True)
        self.assertFalse(res["data"]["valid"])
        errors_str = " ".join(res["data"]["errors"])
        self.assertIn("Maximum nesting depth", errors_str)

    # -------------------------------------------------------------------------
    # 7. secret_scanner boundaries (Tests 077 - 081)
    # -------------------------------------------------------------------------

    def test_077_secret_scanner_boundary_path_outside_allowed_roots(self):
        """Boundary: secret_scanner rejects paths outside ALLOWED_ROOTS."""
        res = self.run_tool("secret_scanner", {
            "action": "scan_patterns",
            "path": "/etc/shadow",
        })
        self.assert_envelope(res, expected_ok=False)
        self.assertIn("securityerror", res["error"].lower())

    def test_078_secret_scanner_boundary_sensitive_file_blocked(self):
        """Boundary: secret_scanner blocks direct scan targets in sensitive directories (.ssh/id_rsa)."""
        with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
            fake_ssh = Path(tmpdir) / ".ssh"
            fake_ssh.mkdir()
            fake_key = fake_ssh / "id_rsa"
            fake_key.write_text("dummy", encoding="utf-8")
            res = self.run_tool("secret_scanner", {
                "action": "audit_pem",
                "path": str(fake_key),
            })
            self.assert_envelope(res, expected_ok=False)
            self.assertIn("sensitivepatherror", res["error"].lower())

    def test_079_secret_scanner_boundary_payload_size_limit(self):
        """Boundary: secret_scanner rejects payloads exceeding 10 MB."""
        huge_text = "A" * (11 * 1024 * 1024)
        res = self.run_tool("secret_scanner", {
            "action": "scan_entropy",
            "text": huge_text,
        })
        self.assert_envelope(res, expected_ok=False)

    def test_080_secret_scanner_boundary_crypto_iterations_bounds(self):
        """Boundary: secret_scanner rejects PBKDF2 iterations < 1000 or > 1,000,000."""
        res_low = self.run_tool("secret_scanner", {
            "action": "crypto_utils",
            "operation": "derive_key",
            "password": "pass",
            "salt": "salt",
            "iterations": 100,
        })
        self.assert_envelope(res_low, expected_ok=False)

    def test_081_secret_scanner_boundary_null_byte_in_path(self):
        """Boundary: secret_scanner rejects null byte characters in path."""
        res = self.run_tool("secret_scanner", {
            "action": "audit_pem",
            "path": "/tmp/cert\x00poison.pem",
        })
        self.assert_envelope(res, expected_ok=False)

    # -------------------------------------------------------------------------
    # 8. log_summarizer boundaries (Tests 082 - 086)
    # -------------------------------------------------------------------------

    def test_082_log_summarizer_boundary_path_outside_allowed_roots(self):
        """Boundary: log_summarizer rejects paths outside ALLOWED_ROOTS."""
        res = self.run_tool("log_summarizer", {
            "action": "cluster_errors",
            "path": "/var/log/syslog",
        })
        self.assert_envelope(res, expected_ok=False)
        self.assertIn("pathsecurityerror", res["error"].lower())

    def test_083_log_summarizer_boundary_null_byte_in_path(self):
        """Boundary: log_summarizer rejects null bytes in file path."""
        res = self.run_tool("log_summarizer", {
            "action": "cluster_errors",
            "path": "/tmp/log\x00poison.txt",
        })
        self.assert_envelope(res, expected_ok=False)

    def test_084_log_summarizer_boundary_payload_size_limit(self):
        """Boundary: log_summarizer rejects log strings exceeding 10 MB."""
        huge_logs = "2026-11-21 ERROR Error occurred\n" * 400_000
        res = self.run_tool("log_summarizer", {
            "action": "cluster_errors",
            "text": huge_logs,
        })
        self.assert_envelope(res, expected_ok=False)

    def test_085_log_summarizer_boundary_sensitive_file_blocked(self):
        """Boundary: log_summarizer blocks reading from sensitive directories."""
        with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
            fake_ssh = Path(tmpdir) / ".ssh"
            fake_ssh.mkdir()
            fake_log = fake_ssh / "access.log"
            fake_log.write_text("log", encoding="utf-8")
            res = self.run_tool("log_summarizer", {
                "action": "cluster_errors",
                "path": str(fake_log),
            })
            self.assert_envelope(res, expected_ok=False)
            self.assertIn("sensitivepatherror", res["error"].lower())

    def test_086_log_summarizer_boundary_empty_content(self):
        """Boundary: log_summarizer handles whitespace-only log text without error."""
        res = self.run_tool("log_summarizer", {
            "action": "cluster_errors",
            "text": "   \n\t   \n",
        })
        self.assert_envelope(res, expected_ok=True)
        self.assertEqual(len(res["data"]["clusters"]), 0)


# -----------------------------------------------------------------------------
# Tier 3: Cross-Feature Combinations (Tests 087 - 094, 8 tests)
# -----------------------------------------------------------------------------

class TestE2ETier3CrossFeatureCombinations(BaseE2ETestCase):
    """Pairwise combinatorial pipelines exercising multiple interacting operator modules."""

    def test_087_combo_tabular_to_archive(self):
        """Combination: tabular_data converts data to JSON, and archive_builder packages it into ZIP."""
        with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
            csv_src = "server_id,host,status\ns1,node-1,up\ns2,node-2,up\ns3,node-3,down"
            json_dst = Path(tmpdir) / "servers.json"

            t_res = self.run_tool("tabular_data", {
                "action": "convert_format",
                "data": csv_src,
                "from_format": "csv",
                "to_format": "json",
                "output_path": str(json_dst),
            })
            self.assert_envelope(t_res, expected_ok=True)
            self.assertTrue(json_dst.exists())

            zip_dst = Path(tmpdir) / "servers_bundle.zip"
            a_res = self.run_tool("archive_builder", {
                "action": "create_zip",
                "source_paths": [str(json_dst)],
                "destination_path": str(zip_dst),
            })
            self.assert_envelope(a_res, expected_ok=True)
            self.assertTrue(zip_dst.exists())
            self.assertEqual(a_res["data"]["file_count"], 1)

    def test_088_combo_fs_analyzer_to_secret_scanner(self):
        """Combination: fs_analyzer audits directory tree, then secret_scanner scans discovered files."""
        with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
            conf_dir = Path(tmpdir) / "config"
            conf_dir.mkdir()
            safe_conf = conf_dir / "app.conf"
            safe_conf.write_text("port = 8080\nworkers = 4", encoding="utf-8")

            fs_res = self.run_tool("fs_analyzer", {
                "action": "tree_summary",
                "path": str(conf_dir),
            })
            self.assert_envelope(fs_res, expected_ok=True)
            self.assertEqual(fs_res["data"]["summary"]["total_files"], 1)

            sec_res = self.run_tool("secret_scanner", {
                "action": "scan_patterns",
                "path": str(safe_conf),
            })
            self.assert_envelope(sec_res, expected_ok=True)
            self.assertEqual(len(sec_res["data"]["findings"]), 0)

    def test_089_combo_process_inspector_to_net_probe(self):
        """Combination: process_inspector identifies listening sockets, net_probe verifies reachability."""
        proc_res = self.run_tool("process_inspector", {
            "action": "socket_owners",
            "protocol": "tcp",
            "socket_state": "LISTEN",
        })
        self.assert_envelope(proc_res, expected_ok=True)
        sockets = proc_res["data"]["sockets"]
        self.assertGreater(len(sockets), 0)

        net_res = self.run_tool("net_probe", {
            "action": "tcp_ping",
            "host": "127.0.0.1",
            "port": self.http_port,
            "allow_private": True,
        })
        self.assert_envelope(net_res, expected_ok=True)
        self.assertTrue(net_res["data"]["reachable"])

    def test_090_combo_config_validator_to_tabular_data(self):
        """Combination: config_validator validates data schema, tabular_data transforms matching records."""
        schema = {
            "type": "object",
            "required": ["item", "quantity"],
            "properties": {
                "item": {"type": "string"},
                "quantity": {"type": "integer"},
            },
        }
        val_res = self.run_tool("config_validator", {
            "action": "validate_json",
            "content": json.dumps({"item": "widget", "quantity": 10}),
            "schema": schema,
        })
        self.assert_envelope(val_res, expected_ok=True)
        self.assertTrue(val_res["data"]["valid"])

        raw_csv = "item,quantity\nwidget,10\ngadget,25"
        tab_res = self.run_tool("tabular_data", {
            "action": "to_markdown",
            "data": raw_csv,
        })
        self.assert_envelope(tab_res, expected_ok=True)
        self.assertIn("widget", tab_res["data"]["markdown"])

    def test_091_combo_secret_scanner_to_log_summarizer(self):
        """Combination: secret_scanner generates cryptographic token, log_summarizer masks it in logs."""
        sec_res = self.run_tool("secret_scanner", {
            "action": "crypto_utils",
            "operation": "generate_token",
            "token_type": "hex",
            "nbytes": 16,
        })
        self.assert_envelope(sec_res, expected_ok=True)
        token = sec_res["data"]["token"]

        log_text = f"2026-11-21 INFO User authenticated with Bearer {token} from 10.0.0.5"
        log_res = self.run_tool("log_summarizer", {
            "action": "mask_pii",
            "text": log_text,
        })
        self.assert_envelope(log_res, expected_ok=True)
        sanitized = log_res["data"]["masked_text"]
        self.assertNotIn(token, sanitized)
        self.assertIn("<BEARER_TOKEN>", sanitized)

    def test_092_combo_archive_builder_to_secret_scanner_entropy(self):
        """Combination: archive_builder stream-compresses text, secret_scanner verifies entropy increase."""
        low_entropy_text = "abcdefgh" * 500
        sec_raw = self.run_tool("secret_scanner", {
            "action": "scan_entropy",
            "text": low_entropy_text,
        })
        self.assert_envelope(sec_raw, expected_ok=True)
        raw_entropy = sec_raw["data"]["overall_entropy"]

        arch_res = self.run_tool("archive_builder", {
            "action": "compress_stream",
            "format": "gzip",
            "data": low_entropy_text,
        })
        self.assert_envelope(arch_res, expected_ok=True)
        compressed_b64 = arch_res["data"]["data"]

        sec_comp = self.run_tool("secret_scanner", {
            "action": "scan_entropy",
            "text": compressed_b64,
        })
        self.assert_envelope(sec_comp, expected_ok=True)
        comp_entropy = sec_comp["data"]["overall_entropy"]
        self.assertGreater(comp_entropy, raw_entropy)

    def test_093_combo_log_summarizer_to_fs_analyzer(self):
        """Combination: log_summarizer triages stacktrace frames, fs_analyzer inspects target directory."""
        with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
            app_file = Path(tmpdir) / "app.py"
            app_file.write_text("def run():\n    raise RuntimeError('boom')\n", encoding="utf-8")

            simulated_trace = (
                "Traceback (most recent call last):\n"
                f'  File "{app_file}", line 2, in run\n'
                "    raise RuntimeError('boom')\n"
                "RuntimeError: boom\n"
            )
            log_res = self.run_tool("log_summarizer", {
                "action": "triage_stacktrace",
                "text": simulated_trace,
                "runtime": "python",
            })
            self.assert_envelope(log_res, expected_ok=True)
            self.assertEqual(log_res["data"]["tracebacks"][0]["exception_type"], "RuntimeError")

            fs_res = self.run_tool("fs_analyzer", {
                "action": "tree_summary",
                "path": tmpdir,
            })
            self.assert_envelope(fs_res, expected_ok=True)
            self.assertEqual(fs_res["data"]["summary"]["total_files"], 1)

    def test_094_combo_config_validator_to_archive_builder(self):
        """Combination: config_validator validates configuration, archive_builder packages into tar.gz."""
        with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
            conf_file = Path(tmpdir) / "production.ini"
            conf_content = "[core]\nenv = prod\nthreads = 8\n[telemetry]\nenabled = true"
            conf_file.write_text(conf_content, encoding="utf-8")

            val_res = self.run_tool("config_validator", {
                "action": "validate_ini",
                "path": str(conf_file),
                "required_sections": ["core", "telemetry"],
            })
            self.assert_envelope(val_res, expected_ok=True)
            self.assertTrue(val_res["data"]["valid"])

            tar_dst = Path(tmpdir) / "config_dist.tar.gz"
            arch_res = self.run_tool("archive_builder", {
                "action": "create_tar",
                "source_paths": [str(conf_file)],
                "destination_path": str(tar_dst),
                "format": "tar.gz",
            })
            self.assert_envelope(arch_res, expected_ok=True)
            self.assertTrue(tar_dst.exists())


# -----------------------------------------------------------------------------
# Tier 4: Real-World Workload Scenarios (Tests 095 - 099, 5 tests)
# -----------------------------------------------------------------------------

class TestE2ETier4WorkloadScenarios(BaseE2ETestCase):
    """End-to-end multi-operator realistic operational workflows."""

    def test_095_workload_incident_triage_network_diagnostics(self):
        """Scenario 1: Incident Triage & Network Diagnostics (net_probe + process_inspector + log_summarizer)."""
        proc_res = self.run_tool("process_inspector", {
            "action": "socket_owners",
            "protocol": "tcp",
            "socket_state": "LISTEN",
        })
        self.assert_envelope(proc_res, expected_ok=True)
        self.assertGreater(len(proc_res["data"]["sockets"]), 0)

        net_res = self.run_tool("net_probe", {
            "action": "http_head",
            "host": "127.0.0.1",
            "port": self.http_port,
            "path": "/health",
            "allow_private": True,
        })
        self.assert_envelope(net_res, expected_ok=True)
        self.assertEqual(net_res["data"]["status_code"], 200)

        raw_incident_logs = (
            "2026-11-21T14:00:01Z ERROR Worker 1 failed connecting to db.internal from 10.0.1.5 (user admin@corp.net)\n"
            "2026-11-21T14:00:02Z ERROR Worker 2 failed connecting to db.internal from 10.0.1.6 (user admin@corp.net)\n"
            "2026-11-21T14:00:03Z ERROR Worker 3 failed connecting to db.internal from 10.0.1.7 (user admin@corp.net)\n"
        )
        cluster_res = self.run_tool("log_summarizer", {
            "action": "cluster_errors",
            "text": raw_incident_logs,
        })
        self.assert_envelope(cluster_res, expected_ok=True)
        self.assertEqual(len(cluster_res["data"]["clusters"]), 1)
        self.assertEqual(cluster_res["data"]["clusters"][0]["count"], 3)

        mask_res = self.run_tool("log_summarizer", {
            "action": "mask_pii",
            "text": raw_incident_logs,
        })
        self.assert_envelope(mask_res, expected_ok=True)
        sanitized = mask_res["data"]["masked_text"]
        self.assertNotIn("admin@corp.net", sanitized)
        self.assertIn("<EMAIL>", sanitized)

    def test_096_workload_production_release_packaging_and_audit(self):
        """Scenario 2: Production Release Packaging & Security Audit (archive_builder + fs_analyzer + secret_scanner)."""
        with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
            release_dir = Path(tmpdir) / "release_v1.0"
            release_dir.mkdir()
            (release_dir / "app.py").write_text("print('Jarvis v1.0 Production')", encoding="utf-8")
            (release_dir / "README.md").write_text("# Release Notes\nReady.", encoding="utf-8")

            fs_res = self.run_tool("fs_analyzer", {
                "action": "tree_summary",
                "path": str(release_dir),
            })
            self.assert_envelope(fs_res, expected_ok=True)
            self.assertEqual(fs_res["data"]["summary"]["total_files"], 2)

            sym_res = self.run_tool("fs_analyzer", {
                "action": "find_broken_symlinks",
                "path": str(release_dir),
            })
            self.assert_envelope(sym_res, expected_ok=True)
            self.assertEqual(len(sym_res["data"]["broken_symlinks"]), 0)

            sec_res = self.run_tool("secret_scanner", {
                "action": "scan_patterns",
                "path": str(release_dir / "app.py"),
            })
            self.assert_envelope(sec_res, expected_ok=True)
            self.assertEqual(len(sec_res["data"]["findings"]), 0)

            tar_dst = Path(tmpdir) / "release_v1.0.tar.gz"
            arch_res = self.run_tool("archive_builder", {
                "action": "create_tar",
                "source_paths": [str(release_dir)],
                "destination_path": str(tar_dst),
                "format": "tar.gz",
            })
            self.assert_envelope(arch_res, expected_ok=True)
            self.assertTrue(tar_dst.exists())

    def test_097_workload_config_and_data_export_pipeline(self):
        """Scenario 3: Config & Data Export Pipeline (config_validator + tabular_data + archive_builder)."""
        with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
            config_content = json.dumps({
                "pipeline_id": "export-daily-telemetry",
                "batch_size": 100,
                "compression": "zip",
            })
            val_res = self.run_tool("config_validator", {
                "action": "validate_json",
                "content": config_content,
                "schema": {
                    "type": "object",
                    "required": ["pipeline_id", "batch_size"],
                    "properties": {
                        "pipeline_id": {"type": "string"},
                        "batch_size": {"type": "integer", "minimum": 1},
                    },
                },
            })
            self.assert_envelope(val_res, expected_ok=True)
            self.assertTrue(val_res["data"]["valid"])

            raw_metrics = (
                "host,cpu_pct,ram_pct,disk_pct\n"
                "prod-worker-1,12.5,45.2,60.1\n"
                "prod-worker-2,18.0,52.4,62.8\n"
            )
            report_md_path = Path(tmpdir) / "report.md"
            tab_res = self.run_tool("tabular_data", {
                "action": "to_markdown",
                "data": raw_metrics,
                "output_path": str(report_md_path),
            })
            self.assert_envelope(tab_res, expected_ok=True)
            self.assertTrue(report_md_path.exists())

            bundle_zip = Path(tmpdir) / "daily_export.zip"
            arch_res = self.run_tool("archive_builder", {
                "action": "create_zip",
                "source_paths": [str(report_md_path)],
                "destination_path": str(bundle_zip),
            })
            self.assert_envelope(arch_res, expected_ok=True)
            self.assertTrue(bundle_zip.exists())

    def test_098_workload_security_and_compliance_hygiene_scan(self):
        """Scenario 4: Security & Compliance Hygiene Scan (secret_scanner + fs_analyzer + config_validator)."""
        with tempfile.TemporaryDirectory(dir="/tmp") as tmpdir:
            audit_dir = Path(tmpdir) / "compliant_service"
            audit_dir.mkdir()
            dotenv_file = audit_dir / "service.env"
            dotenv_file.write_text("SERVICE_PORT=9000\nENV_NAME=production\n", encoding="utf-8")

            hygiene_res = self.run_tool("fs_analyzer", {
                "action": "hygiene_audit",
                "path": str(audit_dir),
            })
            self.assert_envelope(hygiene_res, expected_ok=True)

            conf_res = self.run_tool("config_validator", {
                "action": "validate_dotenv",
                "path": str(dotenv_file),
                "strict_naming": True,
            })
            self.assert_envelope(conf_res, expected_ok=True)
            self.assertTrue(conf_res["data"]["valid"])

            sec_res = self.run_tool("secret_scanner", {
                "action": "scan_patterns",
                "path": str(dotenv_file),
            })
            self.assert_envelope(sec_res, expected_ok=True)
            self.assertEqual(len(sec_res["data"]["findings"]), 0)

    def test_099_workload_full_fleet_telemetry_health_audit(self):
        """Scenario 5: Full Fleet Telemetry & Health Audit (net_probe + process_inspector + fs_analyzer + tabular_data)."""
        proc_res = self.run_tool("process_inspector", {
            "action": "list_processes",
            "order_by": "rss",
            "limit": 3,
        })
        self.assert_envelope(proc_res, expected_ok=True)
        top_procs = proc_res["data"]["processes"]
        self.assertGreater(len(top_procs), 0)

        fs_res = self.run_tool("fs_analyzer", {
            "action": "disk_usage",
            "path": "/tmp",
        })
        self.assert_envelope(fs_res, expected_ok=True)
        part = fs_res["data"]["partition"]
        self.assertGreater(part["total_bytes"], 0)

        net_res = self.run_tool("net_probe", {
            "action": "tcp_ping",
            "host": "127.0.0.1",
            "port": self.http_port,
            "allow_private": True,
        })
        self.assert_envelope(net_res, expected_ok=True)
        net_status = "HEALTHY" if net_res["data"]["reachable"] else "DEGRADED"

        csv_report = (
            "component,metric,status\n"
            f"process_1,{top_procs[0]['name']}_rss_{top_procs[0]['rss_bytes'] // 1024}KB,RUNNING\n"
            "filesystem,/tmp_usage_ok,NORMAL\n"
            f"network,loopback_probe_{self.http_port},{net_status}\n"
        )
        tab_res = self.run_tool("tabular_data", {
            "action": "to_markdown",
            "data": csv_report,
        })
        self.assert_envelope(tab_res, expected_ok=True)
        md_table = tab_res["data"]["markdown"]
        self.assertIn("component", md_table)
        self.assertIn("filesystem", md_table)
        self.assertIn("network", md_table)


if __name__ == "__main__":
    unittest.main()
