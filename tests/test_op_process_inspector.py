"""Automated test suite for operator_modules/op_process_inspector.py (Milestone M1).

Tests tool contract, 5-key return envelope, process listing, deep PID inspection,
socket-to-PID correlation via /proc/net/tcp, POSIX signal delivery with all defensive
guardrails (PID 1, self, parent, kernel threads, SIGKILL confirmation), and error modes.
"""

from __future__ import annotations

import os
import signal
import socket
import unittest
from unittest.mock import MagicMock, call, patch

import operator_modules.op_process_inspector as op_process_inspector


class TestOpProcessInspector(unittest.TestCase):
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

    # --- Contract Tests ---
    def test_01_tool_declaration_contract(self):
        tool = op_process_inspector.TOOL
        self.assertEqual(tool["name"], "process_inspector")
        self.assertTrue(tool["approval"], "process_inspector must require approval (approval: True) due to signaling")
        self.assertTrue(callable(tool["handler"]))
        self.assertEqual(tool["input_schema"]["type"], "object")
        self.assertFalse(tool["input_schema"]["additionalProperties"])
        self.assertIn("action", tool["input_schema"]["required"])

    def test_02_approval_is_true_and_schema_strict(self):
        schema = op_process_inspector.TOOL["input_schema"]
        self.assertFalse(schema.get("additionalProperties", True))
        self.assertEqual(
            schema["properties"]["action"]["enum"],
            ["list_processes", "inspect_pid", "socket_owners", "send_signal"],
        )
        self.assertIn("pid", schema["properties"])
        self.assertIn("signal", schema["properties"])
        self.assertIn("confirm", schema["properties"])

    # --- Tier 1: Happy Path ---
    def test_03_list_processes_current_system(self):
        res = op_process_inspector.process_inspector({"action": "list_processes", "limit": 10})
        self._assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertIn("processes", data)
        self.assertGreater(len(data["processes"]), 0)
        self.assertLessEqual(len(data["processes"]), 10)
        p = data["processes"][0]
        self.assertIn("pid", p)
        self.assertIn("ppid", p)
        self.assertIn("name", p)
        self.assertIn("state", p)
        self.assertIn("rss_bytes", p)
        self.assertIn("vms_bytes", p)
        self.assertIn("cmdline", p)
        self.assertIn("user", p)

    def test_04_list_processes_pattern_filter(self):
        res = op_process_inspector.process_inspector({
            "action": "list_processes",
            "pattern": "python",
            "limit": 20,
        })
        self._assert_envelope(res, expected_ok=True)
        processes = res["data"]["processes"]
        self.assertGreater(len(processes), 0)
        for p in processes:
            self.assertTrue(
                "python" in p["name"].lower() or "python" in str(p.get("cmdline", "")).lower(),
                f"Process PID {p.get('pid')} returned for filter 'python' but neither name ('{p.get('name')}') nor cmdline ('{p.get('cmdline')}') matched",
            )

    def test_05_list_processes_order_by(self):
        res = op_process_inspector.process_inspector({
            "action": "list_processes",
            "order_by": "rss",
            "limit": 15,
        })
        self._assert_envelope(res, expected_ok=True)
        procs = res["data"]["processes"]
        if len(procs) >= 2:
            for i in range(len(procs) - 1):
                self.assertGreaterEqual(procs[i]["rss_bytes"], procs[i + 1]["rss_bytes"])

    def test_06_inspect_own_pid(self):
        my_pid = os.getpid()
        res = op_process_inspector.process_inspector({"action": "inspect_pid", "pid": my_pid})
        self._assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertEqual(data["pid"], my_pid)
        self.assertIn("python", data["name"].lower())
        self.assertGreaterEqual(data["open_fd_count"], 1)
        self.assertGreater(data["rss_bytes"], 0)
        self.assertIn("memory", data)
        self.assertIn("cpu", data)
        self.assertIsNotNone(data["executable"])
        self.assertIsNotNone(data["cwd"])

    def test_07_inspect_pid_with_environ(self):
        with patch.dict(os.environ, {"JARVIS_SECRET_KEY": "sk-secret-key-123", "JARVIS_PUBLIC_SETTING": "normal_val"}):
            res = op_process_inspector.process_inspector({
                "action": "inspect_pid",
                "pid": os.getpid(),
                "include_environ": True,
            })
            self._assert_envelope(res, expected_ok=True)
            env = res["data"].get("environ")
            if env and "JARVIS_SECRET_KEY" in env:
                self.assertEqual(env["JARVIS_SECRET_KEY"], "[REDACTED]")

    def test_08_socket_owners_live_tcp_listener(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            port = s.getsockname()[1]

            res = op_process_inspector.process_inspector({
                "action": "socket_owners",
                "port": port,
                "protocol": "tcp",
            })
            self._assert_envelope(res, expected_ok=True)
            data = res["data"]
            self.assertTrue(data["listening"])
            self.assertIsNotNone(data["owner"])
            self.assertEqual(data["owner"]["pid"], os.getpid())

    def test_09_socket_owners_unbound_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]

        res = op_process_inspector.process_inspector({"action": "socket_owners", "port": port})
        self._assert_envelope(res, expected_ok=True)
        data = res["data"]
        self.assertFalse(data["listening"])
        self.assertIsNone(data["owner"])

    def test_10_send_signal_mocked_success(self):
        with patch("os.kill") as mock_kill, \
             patch("builtins.open", unittest.mock.mock_open(read_data="Name:\ttestproc\nPPid:\t100\n")):
            res = op_process_inspector.process_inspector({
                "action": "send_signal",
                "pid": 55555,
                "signal": "SIGTERM",
            })
            self._assert_envelope(res, expected_ok=True)
            self.assertTrue(res["data"]["delivered"])
            self.assertEqual(res["data"]["signal"], "SIGTERM")
            self.assertEqual(res["data"]["signal_number"], signal.SIGTERM)
            mock_kill.assert_called_once_with(55555, signal.SIGTERM)

    def test_11_send_signal_integer_and_short_names(self):
        with patch("os.kill") as mock_kill, \
             patch("builtins.open", unittest.mock.mock_open(read_data="Name:\ttestproc\nPPid:\t100\n")):
            # Integer signal
            res_int = op_process_inspector.process_inspector({
                "action": "send_signal",
                "pid": 55555,
                "signal": signal.SIGINT,
            })
            self._assert_envelope(res_int, expected_ok=True)
            self.assertEqual(res_int["data"]["signal"], "SIGINT")

            # Short name without "SIG"
            res_short = op_process_inspector.process_inspector({
                "action": "send_signal",
                "pid": 55555,
                "signal": "hup",
            })
            self._assert_envelope(res_short, expected_ok=True)
            self.assertEqual(res_short["data"]["signal"], "SIGHUP")
            self.assertEqual(
                mock_kill.call_args_list,
                [call(55555, signal.SIGINT), call(55555, signal.SIGHUP)],
            )

    # --- Tier 2: Boundary & Security Controls ---
    def test_12_inspect_nonexistent_pid(self):
        res = op_process_inspector.process_inspector({"action": "inspect_pid", "pid": 99999999})
        self._assert_envelope(res, expected_ok=False)
        self.assertIn("ProcessLookupError", res["error"])

    def test_13_inspect_invalid_pid(self):
        for invalid_pid in [0, -5, "not_an_int", True]:
            res = op_process_inspector.process_inspector({"action": "inspect_pid", "pid": invalid_pid})
            self._assert_envelope(res, expected_ok=False)
            self.assertIn("ValueError", res["error"])

    def test_14_send_signal_blocks_pid_1_immunity(self):
        with patch("os.kill") as mock_kill:
            res = op_process_inspector.process_inspector({
                "action": "send_signal",
                "pid": 1,
                "signal": "SIGTERM",
            })
            self._assert_envelope(res, expected_ok=False)
            self.assertIn("SecurityError", res["error"])
            self.assertIn("PID 1", res["error"])
            mock_kill.assert_not_called()

    def test_15_send_signal_blocks_self_and_parent(self):
        with patch("os.kill") as mock_kill:
            # Self
            res_self = op_process_inspector.process_inspector({
                "action": "send_signal",
                "pid": os.getpid(),
                "signal": "SIGTERM",
            })
            self._assert_envelope(res_self, expected_ok=False)
            self.assertIn("SecurityError", res_self["error"])
            self.assertIn("self", res_self["error"].lower())

            # Parent
            res_parent = op_process_inspector.process_inspector({
                "action": "send_signal",
                "pid": os.getppid(),
                "signal": "SIGTERM",
            })
            self._assert_envelope(res_parent, expected_ok=False)
            self.assertIn("SecurityError", res_parent["error"])
            self.assertIn("parent", res_parent["error"].lower())

            mock_kill.assert_not_called()

    def test_16_send_signal_blocks_kernel_threads(self):
        with patch("os.kill") as mock_kill:
            # PID 2 direct
            res_pid2 = op_process_inspector.process_inspector({
                "action": "send_signal",
                "pid": 2,
                "signal": "SIGTERM",
            })
            self._assert_envelope(res_pid2, expected_ok=False)
            self.assertIn("kernel thread", res_pid2["error"].lower())

            # Subthread with PPID 2
            with patch("builtins.open", unittest.mock.mock_open(read_data="Name:\tkworker\nPPid:\t2\n")):
                res_kthread = op_process_inspector.process_inspector({
                    "action": "send_signal",
                    "pid": 22222,
                    "signal": "SIGTERM",
                })
                self._assert_envelope(res_kthread, expected_ok=False)
                self.assertIn("kernel thread", res_kthread["error"].lower())

            mock_kill.assert_not_called()

    def test_17_send_signal_sigkill_confirmation_gate(self):
        with patch("os.kill") as mock_kill, \
             patch("builtins.open", unittest.mock.mock_open(read_data="Name:\tdummy\nPPid:\t100\n")):
            # SIGKILL without confirm -> blocked
            res_no_confirm = op_process_inspector.process_inspector({
                "action": "send_signal",
                "pid": 55555,
                "signal": "SIGKILL",
            })
            self._assert_envelope(res_no_confirm, expected_ok=False)
            self.assertIn("SecurityError", res_no_confirm["error"])
            self.assertIn("confirm", res_no_confirm["error"].lower())
            mock_kill.assert_not_called()

            # SIGKILL with confirm=True -> delivered
            res_confirmed = op_process_inspector.process_inspector({
                "action": "send_signal",
                "pid": 55555,
                "signal": "SIGKILL",
                "confirm": True,
            })
            self._assert_envelope(res_confirmed, expected_ok=True)
            mock_kill.assert_called_once_with(55555, signal.SIGKILL)

    def test_18_send_signal_invalid_signal_name(self):
        for bad_sig in ["SIGSEGV", "SIGKILLER", "UNKNOWN", 999, True]:
            res = op_process_inspector.process_inspector({
                "action": "send_signal",
                "pid": 55555,
                "signal": bad_sig,
            })
            self._assert_envelope(res, expected_ok=False)
            self.assertIn("ValueError", res["error"])

    def test_19_send_signal_permission_and_lookup_errors(self):
        with patch("builtins.open", unittest.mock.mock_open(read_data="Name:\tdummy\nPPid:\t100\n")):
            # PermissionError
            with patch("os.kill", side_effect=PermissionError("Operation not permitted")):
                res_perm = op_process_inspector.process_inspector({
                    "action": "send_signal",
                    "pid": 1000,
                    "signal": "SIGTERM",
                })
                self._assert_envelope(res_perm, expected_ok=False)
                self.assertIn("PermissionError", res_perm["error"])

            # ProcessLookupError
            with patch("os.kill", side_effect=ProcessLookupError("No such process")):
                res_lookup = op_process_inspector.process_inspector({
                    "action": "send_signal",
                    "pid": 88888,
                    "signal": "SIGTERM",
                })
                self._assert_envelope(res_lookup, expected_ok=False)
                self.assertIn("ProcessLookupError", res_lookup["error"])

    def test_20_cmdline_secret_token_redaction(self):
        synthetic_cmd = "python3 server.py --api-key=sk-000000000000000000000000000000 --password=supersecret"
        redacted = op_process_inspector._redact_cmdline_text(synthetic_cmd)
        self.assertNotIn("sk-000000000000000000000000000000", redacted)
        self.assertNotIn("supersecret", redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_21_invalid_action(self):
        res = op_process_inspector.process_inspector({"action": "invalid_action_name"})
        self._assert_envelope(res, expected_ok=False)
        self.assertIn("Unsupported action", res["error"])

    def test_22_additional_properties_rejected(self):
        res = op_process_inspector.process_inspector({
            "action": "list_processes",
            "bogus_field": "disallowed",
        })
        self._assert_envelope(res, expected_ok=False)
        self.assertIn("Unexpected argument", res["error"])

    def test_23_arguments_not_dict(self):
        res = op_process_inspector.process_inspector(None)  # type: ignore
        self._assert_envelope(res, expected_ok=False)
        self.assertIn("ValueError", res["error"])

    def test_24_list_processes_cmdline_truncation_filter_consistency(self):
        """Verify filter consistency between truncated cmdline output and pattern matching."""
        # 1. Live system check: all returned processes MUST match on name or returned cmdline
        res = op_process_inspector.process_inspector({
            "action": "list_processes",
            "pattern": "python",
            "limit": 50,
        })
        self._assert_envelope(res, expected_ok=True)
        processes = res["data"]["processes"]
        self.assertGreater(len(processes), 0)
        for p in processes:
            p_name = p.get("name", "").lower()
            p_cmd = str(p.get("cmdline", "")).lower()
            self.assertTrue(
                "python" in p_name or "python" in p_cmd,
                f"Process PID {p.get('pid')} matched filter 'python' but neither name ('{p_name}') "
                f"nor truncated cmdline ('{p_cmd}') contains 'python'!"
            )

        # 2. Deterministic mock check for boundary > 512 chars:
        # A process whose matching substring is past index 512 must NOT be included in rows
        long_tail_cmd = ("a " * 300) + "hidden_needle"
        with patch.object(op_process_inspector, "_get_process_cmdline", return_value=(long_tail_cmd, [])):
            with patch("pathlib.Path.iterdir") as mock_iterdir:
                mock_entry = MagicMock()
                mock_entry.name = "99999"
                mock_entry.__truediv__.return_value.read_text.return_value = "99999 (daemon_proc) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 1 0 1000 1000 10 0 0"
                mock_entry.stat.return_value.st_uid = 1000
                mock_iterdir.return_value = [mock_entry]

                # Filter for needle past 512 chars: must NOT match
                res_filtered = op_process_inspector.process_inspector({
                    "action": "list_processes",
                    "pattern": "hidden_needle",
                })
                self._assert_envelope(res_filtered, expected_ok=True)
                self.assertEqual(len(res_filtered["data"]["processes"]), 0)

                # Filter for process name: matches and returns 512-byte truncated cmdline
                res_name = op_process_inspector.process_inspector({
                    "action": "list_processes",
                    "pattern": "daemon_proc",
                })
                self._assert_envelope(res_name, expected_ok=True)
                self.assertEqual(len(res_name["data"]["processes"]), 1)
                self.assertEqual(len(res_name["data"]["processes"][0]["cmdline"]), 512)



if __name__ == "__main__":
    unittest.main()
