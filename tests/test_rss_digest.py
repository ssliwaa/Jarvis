import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from operator_modules import rss_digest


class DigestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'rss.json'
        self.patch = mock.patch.object(rss_digest, 'STATE_PATH', self.path)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_opt_in_subscriptions_are_persistent_and_do_not_fetch(self):
        with mock.patch.object(rss_digest, '_fetch') as fetch:
            self.assertEqual(rss_digest.rss_digest({'action': 'list'})['subscriptions'], [])
            added = rss_digest.rss_digest({'action': 'add', 'url': 'https://example.com/feed'})
            self.assertTrue(added['ok'])
            self.assertEqual(len(rss_digest.rss_digest({'action': 'list'})['subscriptions']), 1)
            self.assertEqual(rss_digest.rss_digest({'action': 'add', 'url': 'https://example.com/feed'})['status'], 'exists')
            fetch.assert_not_called()
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
