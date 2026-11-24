"""Isolated web backend: protocol, failure fallback and no-trust parsing."""
import json
import os
import subprocess
import unittest
from unittest import mock

import net_guard
import web_backends
import web_research

_DNS_PATCH = None


def setUpModule():
    # Same reason as test_web_runner: the guarded suite runs with no network.
    global _DNS_PATCH
    _DNS_PATCH = mock.patch.object(net_guard, "resolved_public_ips",
                                   return_value=["93.184.216.34"])
    _DNS_PATCH.start()


def tearDownModule():
    if _DNS_PATCH is not None:
        _DNS_PATCH.stop()


def completed(stdout, code=0):
    return subprocess.CompletedProcess(args=["runner"], returncode=code, stdout=stdout, stderr="")


class BackendTests(unittest.TestCase):
    def test_missing_venv_is_not_installed(self):
        with mock.patch.object(web_backends, "PYTHON", web_backends.VENV / "nope" / "python"):
            self.assertFalse(web_backends.installed())
            self.assertIsNone(web_backends.fetch("https://example.com"))

    def test_builtin_switch_disables_backend(self):
        with mock.patch.dict(os.environ, {"JARVIS_WEB_BACKEND": "builtin"}):
            self.assertFalse(web_backends.enabled())
            self.assertFalse(web_backends.installed())

    def test_fetch_parses_runner_json(self):
        payload = {"ok": True, "engine": "crawl4ai", "url": "https://example.com/a",
                   "title": "A", "text": "hello", "status": 200}
        with mock.patch.object(web_backends, "installed", return_value=True), \
                mock.patch.object(web_backends.subprocess, "run",
                                  return_value=completed(json.dumps(payload))):
            found = web_backends.fetch("https://example.com/a", 10)
        self.assertEqual(found["engine"], "crawl4ai")
        self.assertEqual(found["text"], "hello")

    def test_runner_failure_or_garbage_returns_none(self):
        with mock.patch.object(web_backends, "installed", return_value=True), \
                mock.patch.object(web_backends.subprocess, "run", return_value=completed("", 2)):
            self.assertIsNone(web_backends.fetch("https://example.com"))
        with mock.patch.object(web_backends, "installed", return_value=True), \
                mock.patch.object(web_backends.subprocess, "run", return_value=completed("not json")):
            self.assertIsNone(web_backends.fetch("https://example.com"))

    def test_empty_text_is_a_failure_not_a_page(self):
        payload = {"ok": True, "engine": "scrapling", "url": "https://example.com",
                   "title": "", "text": "   ", "status": 200}
        with mock.patch.object(web_backends, "installed", return_value=True), \
                mock.patch.object(web_backends.subprocess, "run",
                                  return_value=completed(json.dumps(payload))):
            self.assertIsNone(web_backends.fetch("https://example.com"))


class FetchPageTests(unittest.TestCase):
    def test_backend_result_is_used_first(self):
        backend = {"url": "https://example.com/x", "title": "X", "text": "clean markdown",
                   "engine": "crawl4ai", "status": 200}
        with mock.patch.object(web_backends, "enabled", return_value=True), \
                mock.patch.object(web_backends, "fetch", return_value=backend), \
                mock.patch.object(web_research, "_pinned_open") as urlopen:
            page = web_research.fetch_page("https://example.com/x")
        urlopen.assert_not_called()
        self.assertEqual(page["engine"], "crawl4ai")
        self.assertEqual(page["text"], "clean markdown")

    def test_backend_miss_falls_back_to_builtin(self):
        class Response:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def geturl(self):
                return "https://example.com/x"
            class headers:
                @staticmethod
                def get_content_type():
                    return "text/html"
            def read(self, limit=None):
                return b"<html><head><title>T</title></head><body>plain text</body></html>"

        with mock.patch.object(web_backends, "enabled", return_value=True), \
                mock.patch.object(web_backends, "fetch", return_value=None), \
                mock.patch.object(web_research, "_pinned_open", return_value=Response()):
            page = web_research.fetch_page("https://example.com/x")
        self.assertEqual(page["engine"], "builtin")
        self.assertIn("plain text", page["text"])

    def test_backend_cannot_return_a_private_redirect(self):
        backend = {"url": "http://127.0.0.1/admin", "title": "", "text": "secret",
                   "engine": "crawl4ai", "status": 200}
        with mock.patch.object(web_backends, "enabled", return_value=True), \
                mock.patch.object(web_backends, "fetch", return_value=backend):
            with self.assertRaises(web_research.ResearchError):
                web_research.fetch_page("https://example.com/x")


if __name__ == "__main__":
    unittest.main()
