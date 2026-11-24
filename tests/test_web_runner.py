"""Unit contracts for the isolated web-backend runner (no real browser).

The runner runs in ~/.jarvis-tools/venvs/web, but here it is imported straight
into the test venv: its module-level surface is stdlib-only by design, the
heavy engines load lazily inside their functions.
"""
import json
import subprocess
import sys
import unittest
from unittest import mock

import net_guard
import web_runner

_DNS_PATCH = None


def setUpModule():
    # The guarded self-modification suite runs under `bwrap --unshare-net`;
    # real DNS would make every hostname case fail with no network at all.
    # Public names resolve to a fixed TEST-NET address for this module only.
    global _DNS_PATCH
    _DNS_PATCH = mock.patch.object(net_guard, "resolved_public_ips",
                                   return_value=["93.184.216.34"])
    _DNS_PATCH.start()


def tearDownModule():
    if _DNS_PATCH is not None:
        _DNS_PATCH.stop()


class SsrfGuardTests(unittest.TestCase):
    """The runner must never address the local machine, its LAN or metadata."""

    public = ["https://example.com/page", "http://8.8.8.8/x",
              "https://[2606:4700::1111]/", "http://example.com:8080/a?b=c"]

    private = [
        "http://localhost/", "http://LOCALHOST/", "https://127.0.0.9/",
        "http://[::1]:8080/", "http://0.0.0.0/", "http://sub.localhost/",
        "http://printer.local/", "http://192.168.1.3/", "http://10.0.0.5/",
        "http://172.16.9.9/", "http://169.254.169.254/latest/meta-data/",
        "http://100.64.0.9/", "http://224.0.0.5/", "http://[::]/",
        "ftp://example.com/", "file:///etc/shadow", "javascript:alert(1)",
        "https://", "", None,
    ]

    def test_public_internet_targets_pass(self):
        for url in self.public:
            with self.subTest(url=url):
                self.assertTrue(web_runner._public(url))

    def test_every_local_shape_is_refused(self):
        for url in self.private:
            with self.subTest(url=url):
                self.assertFalse(web_runner._public(url))

    def test_fetch_refuses_private_urls_before_any_engine_runs(self):
        calls = []

        def forbidden(*args, **kwargs):
            calls.append("used")
            raise AssertionError("the engine must not run for a private URL")

        with mock.patch.object(web_runner, "_crawl4ai", forbidden), \
                mock.patch.object(web_runner, "_scrapling", forbidden):
            result = web_runner.fetch({"url": "http://127.0.0.1:9000/",
                                       "engines": ["crawl4ai", "scrapling"]})
        self.assertEqual(result, {"ok": False, "error": "not a public http(s) url"})
        self.assertEqual(calls, [])


class ScraplingRedirectTests(unittest.TestCase):
    @staticmethod
    def fixture(page_factory):
        import types
        fetcher = type("Fetcher", (), {"get": staticmethod(page_factory)})
        fetchers = types.ModuleType("scrapling.fetchers")
        fetchers.Fetcher = fetcher
        package = types.ModuleType("scrapling")
        package.fetchers = fetchers
        return {"scrapling": package, "scrapling.fetchers": fetchers}

    def test_private_redirect_is_refused_before_the_private_fetch(self):
        calls = []

        class Page:
            def __init__(self, url):
                self.url = url
                self.status = 302
                self.headers = {"location": "http://127.0.0.1:9000/self"}
                self.body = b""
                self.html_content = ""

        def page_factory(url, **_kwargs):
            calls.append(url)
            return Page(url)

        with mock.patch.dict(sys.modules, self.fixture(page_factory)):
            with self.assertRaises(RuntimeError):
                web_runner._scrapling("https://example.com/start", 5)
        self.assertEqual(calls, ["https://example.com/start"])

    def test_a_public_redirect_chain_is_validated_hop_by_hop(self):
        calls = []

        class Page:
            def __init__(self, url):
                self.url = url
                self.status = 200 if url.endswith("/final") else 301
                self.headers = ({"location": "https://example.com/final"}
                                if self.status == 301 else {})
                self.body = b"<title>Final</title><p>hello</p>"
                self.html_content = "<title>Final</title><p>hello</p>"

            def get_all_text(self):
                return "hello"

        def page_factory(url, **_kwargs):
            calls.append(url)
            return Page(url)

        with mock.patch.dict(sys.modules, self.fixture(page_factory)):
            result = web_runner._scrapling("https://example.com/start", 5)
        self.assertEqual(calls, ["https://example.com/start", "https://example.com/final"])
        self.assertEqual(result["url"], "https://example.com/final")
        self.assertEqual(result["text"], "hello")


class EngineFallbackTests(unittest.TestCase):
    def test_scrapling_is_never_used_for_a_network_fetch(self):
        def forbidden(url, timeout):
            raise AssertionError("scrapling has no pinned-peer check")

        with mock.patch.object(web_runner, "_scrapling", forbidden):
            result = web_runner.fetch({"url": "https://example.com/x",
                                       "engines": ["scrapling"]})
        self.assertFalse(result["ok"])
        self.assertIn("disabled", result["error"])

    def test_a_crawl_failure_is_carried_in_the_error(self):
        def broken(url, timeout):
            raise RuntimeError("also broken")

        with mock.patch.object(web_runner, "_crawl4ai", broken):
            result = web_runner.fetch({"url": "https://example.com/x"})

        self.assertFalse(result["ok"])
        self.assertIn("crawl4ai: RuntimeError", result["error"])

    def test_unknown_engine_names_are_skipped(self):
        result = web_runner.fetch({"url": "https://example.com/x",
                                   "engines": ["typo", ""]})
        self.assertEqual(result["ok"], False)
        self.assertEqual(result["error"], "no engines")

    def test_the_timeout_is_clamped(self):
        seen = []

        def works(url, timeout):
            seen.append(timeout)
            return {"engine": "crawl4ai", "url": url, "title": "", "text": "t", "status": 200}

        with mock.patch.object(web_runner, "_crawl4ai", works):
            web_runner.fetch({"url": "https://example.com/x", "timeout": 1})
            web_runner.fetch({"url": "https://example.com/x", "timeout": 900})
            web_runner.fetch({"url": "https://example.com/x", "timeout": ""})
        self.assertEqual(seen, [3.0, 45.0, 20.0])


class CleanTests(unittest.TestCase):
    def test_text_is_folded_and_capped(self):
        self.assertEqual(web_runner._clean("a \t b\n\n\n\n c\r\n d"), "a b\n\n c\n d")
        self.assertEqual(len(web_runner._clean("x" * (web_runner.MAX_TEXT + 50))),
                         web_runner.MAX_TEXT)
        self.assertEqual(web_runner._clean(None), "")


class ProbeTests(unittest.TestCase):
    def test_probe_reports_module_presence_and_chrome_path(self):
        fake = type("Engine", (), {})
        with mock.patch.dict(sys.modules, {"crawl4ai": fake, "scrapling": fake}):
            result = web_runner.probe()
        self.assertTrue(result["ok"])
        self.assertEqual(result["engines"], {"crawl4ai": True, "scrapling": True})
        self.assertIsInstance(result["chrome"], str)

    def test_probe_survives_a_missing_module(self):
        with mock.patch.dict(sys.modules, {"crawl4ai": None}):
            result = web_runner.probe()
        self.assertTrue(result["ok"])
        self.assertFalse(result["engines"]["crawl4ai"])


class ProtocolTests(unittest.TestCase):
    """The real contract: one JSON in on stdin, one MARKER+JSON out."""

    def test_a_probe_request_round_trips_through_stdin_stdout(self):
        code = "import sys; sys.path.insert(0, '.'); import web_runner; " \
               "raise SystemExit(web_runner.main())"
        done = subprocess.run([sys.executable, "-c", code], input=json.dumps({"mode": "probe"}),
                              capture_output=True, text=True, timeout=60, cwd=".")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.count(web_runner.MARKER), 1)
        payload = json.loads(done.stdout.split(web_runner.MARKER, 1)[1])
        self.assertTrue(payload["ok"])
        self.assertIn("engines", payload)

    def test_garbage_stdin_yields_a_clean_error_object(self):
        code = "import sys; sys.path.insert(0, '.'); import web_runner; " \
               "raise SystemExit(web_runner.main())"
        done = subprocess.run([sys.executable, "-c", code], input="this is not json{",
                              capture_output=True, text=True, timeout=60, cwd=".")
        self.assertEqual(done.returncode, 0, done.stderr)
        payload = json.loads(done.stdout.split(web_runner.MARKER, 1)[1])
        self.assertEqual(payload, {"ok": False, "error": "bad request"})


if __name__ == "__main__":
    unittest.main()
