import unittest

from web_research import _canonical


class CanonicalHostCaseTest(unittest.TestCase):
    def test_host_is_lowercased(self):
        self.assertEqual(_canonical("https://Example.COM/Path"), "https://example.com/Path")

    def test_host_lowercased_with_utm_removed(self):
        self.assertEqual(
            _canonical("https://WWW.Example.com/a?utm_source=x&b=1"),
            "https://www.example.com/a?b=1",
        )
