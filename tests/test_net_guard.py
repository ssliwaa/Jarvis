"""Shared SSRF classifier: one answer for every network lane."""
import socket
import unittest
from unittest import mock

import net_guard


class NetGuardTests(unittest.TestCase):
    def test_public_and_private_numeric_shapes(self):
        self.assertTrue(net_guard.is_public_ip("8.8.8.8"))
        self.assertFalse(net_guard.is_public_ip("127.0.0.1"))
        self.assertFalse(net_guard.is_public_ip("10.0.0.5"))
        self.assertFalse(net_guard.is_public_ip("100.64.0.9"))       # CGNAT
        self.assertFalse(net_guard.is_public_ip("224.0.0.5"))       # multicast
        self.assertFalse(net_guard.is_public_ip("::ffff:100.64.0.1"))  # IPv4-mapped
        self.assertFalse(net_guard.is_public_ip("64:ff9b::127.0.0.1"))  # NAT64

    def test_mixed_dns_answers_are_not_public(self):
        records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
                   (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]
        with mock.patch.object(net_guard.socket, "getaddrinfo", return_value=records):
            self.assertFalse(net_guard.is_public_host("mixed.example"))
            self.assertIsNone(net_guard.public_ip("mixed.example"))

    def test_url_requires_http_and_a_public_host(self):
        self.assertFalse(net_guard.is_public_url("ftp://8.8.8.8/"))
        self.assertFalse(net_guard.is_public_url("http://user:pass@8.8.8.8/"))
        self.assertTrue(net_guard.is_public_url("https://8.8.8.8/a"))


if __name__ == "__main__":
    unittest.main()
