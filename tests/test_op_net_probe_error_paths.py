"""ERROR-path coverage tests for operator_modules/op_net_probe.py.

Fifth module of the sys.settrace audit and the last one chosen from the
noisy scan list: 27 raise sites, 18 executed by existing tests, 9 never
touched. This suite covers DNS resolver failure reporting (gaierror
wrapping and the empty-record case), reverse-DNS (PTR) failure, the
SSRF guardrail through resolved address lists, the three HTTP HEAD
timeout tiers and the headerless-connection reset, all offline through
the seams the existing suite already uses (socket.* patches, the
_resolve_target_ip boundary, fake sockets and a scripted time.monotonic).

One raise line is verified dead and stays untested, documented here:
the dispatcher's final ``Unsupported action`` raise can never fire,
because the action banner check rejects every action outside
VALID_ACTIONS earlier, and each of the four members has its own handler
branch.

"""
import socket
import unittest
from unittest.mock import MagicMock, patch

import operator_modules.op_net_probe as np


class NetProbeCase(unittest.TestCase):
    def call(self, **kwargs):
        return np.net_probe(kwargs)

    def bad(self, fragment, **kwargs):
        result = self.call(**kwargs)
        self.assertFalse(result["ok"], msg=str(result.get("error")))
        self.assertIn(fragment, result["error"])
        return result


class ResolveGuardTests(NetProbeCase):
    def test_dns_failure_is_wrapped_with_host_context(self):
        boom = socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        with patch("socket.getaddrinfo", side_effect=boom):
            with self.assertRaises(socket.gaierror) as ctx:
                np._resolve_target_ip("gone.example.com", 80, False)
        message = str(ctx.exception)
        self.assertIn("DNS resolution failed for 'gone.example.com'",
                      message)
        self.assertIn("Name or service not known", message)

    def test_empty_resolution_result_is_reported(self):
        with patch("socket.getaddrinfo", return_value=[]):
            with self.assertRaises(socket.gaierror) as ctx:
                np._resolve_target_ip("void.example.com", 80, False)
        self.assertIn("No address records found for 'void.example.com'",
                      str(ctx.exception))


class DnsLookupGuardTests(NetProbeCase):
    def test_ptr_failure_reports_reverse_dns(self):
        boom = socket.herror(1, "Unknown host")
        with patch("socket.gethostbyaddr", side_effect=boom):
            result = self.bad(
                "Reverse DNS lookup failed for '8.8.8.8'",
                action="dns_lookup", host="8.8.8.8", query_type="PTR")
        self.assertIn("gaierror", result["error"])

    def test_ssrf_refuses_private_address_in_record_list(self):
        private_infos = [(socket.AF_INET, None, None, "",
                          ("192.168.1.1", 80))]

        def fake_getaddrinfo(host, port, *args, **kwargs):
            family = kwargs.get("family", args[0] if args else None)
            if family == socket.AF_INET:
                return private_infos
            if family == socket.AF_INET6:
                raise socket.gaierror(socket.EAI_NONAME, "no AAAA")
            return private_infos

        with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
            result = self.bad(
                "SSRFSecurityError: Target address '192.168.1.1'",
                action="dns_lookup", host="hostile.example.com",
                query_type="A")
        self.assertIn("allow_private=True", result["error"])


class HttpHeadErrorTests(NetProbeCase):
    """Direct _do_http_head probes: resolution and sockets are faked and
    time.monotonic is scripted per tier so the three timeout raises run
    deterministically without sleeping."""

    def _head(self, use_tls=False, monotonic=None, recv=None,
              timeout=5.0):
        mock_sock = MagicMock()
        if recv is not None:
            mock_sock.recv.return_value = recv
        patches = [
            patch("operator_modules.op_net_probe._resolve_target_ip",
                  return_value=("176.113.115.57", socket.AF_INET, 80)),
            patch("socket.create_connection", return_value=mock_sock),
        ]
        if monotonic is not None:
            patches.append(patch("time.monotonic", side_effect=monotonic))
        with patches[0], patches[1]:
            if monotonic is not None:
                with patches[2]:
                    return np._do_http_head("example.com", 80, "/",
                                            use_tls, timeout,
                                            None, True, False)
            return np._do_http_head("example.com", 80, "/", use_tls,
                                    timeout, None, True, False)

    def test_tls_setup_past_deadline(self):
        with self.assertRaises(TimeoutError) as ctx:
            self._head(use_tls=True, monotonic=[0.0, 100.0])
        self.assertIn("exceeded timeout limit of 5.0s.",
                      str(ctx.exception))

    def test_send_past_deadline(self):
        with self.assertRaises(TimeoutError) as ctx:
            self._head(use_tls=False, monotonic=[0.0, 100.0])
        self.assertIn("exceeded timeout limit of 5.0s.",
                      str(ctx.exception))

    def test_receive_past_deadline(self):
        with self.assertRaises(TimeoutError) as ctx:
            self._head(use_tls=False, monotonic=[0.0, 1.0, 6.0])
        self.assertIn("timed out after 5.0 seconds.",
                      str(ctx.exception))

    def test_connection_closed_without_headers(self):
        with self.assertRaises(ConnectionResetError) as ctx:
            self._head(recv=b"")
        self.assertIn("Server closed connection without returning HTTP "
                      "headers.", str(ctx.exception))


class DispatcherContractTests(NetProbeCase):
    def test_unknown_action_banner_names_valid_actions(self):
        result = self.bad("Unsupported or missing action: 'frobnicate'",
                         action="frobnicate", host="example.com")
        self.assertIn("dns_lookup", result["error"])


if __name__ == "__main__":
    unittest.main()
