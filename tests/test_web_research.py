"""Web research parser contract; the network call is replaced in the test."""
import http.server
import socket
import unittest
import urllib.error
import urllib.request
from unittest import mock

import web_research

HTML = """
<html><body>
<div class="result"><a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fone">Example One</a>
<a class="result__snippet">First useful snippet.</a></div>
<div class="result"><a class="result__a" href="https://example.org/two">Example Two</a>
<a class="result__snippet">Second useful snippet.</a></div>
</body></html>
"""


class Response:
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, limit=None):
        return HTML.encode()


NEWS_RSS = """<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>France braces for fresh protest weekend - Reuters</title>
<link>https://www.reuters.com/world/france/fresh-protests</link>
<pubDate>Sat, 24 Oct 2026 18:02:00 GMT</pubDate>
<source url="https://reuters.com">Reuters</source></item>
<item><title>Second headline - Le Monde</title>
<link>https://www.lemonde.fr/en/article/second</link>
<pubDate>Sun, 25 Oct 2026 07:30:00 GMT</pubDate>
<source url="https://lemonde.fr">Le Monde</source></item>
</channel></rss>"""


class RssResponse(Response):
    def read(self, limit=None):
        return NEWS_RSS.encode()


class ResearchTests(unittest.TestCase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(web_research.time, "time", return_value=1792914000.0)
        self.addCleanup(patcher.stop)
        patcher.start()

    def test_search_returns_only_real_http_citations(self):
        with mock.patch.object(web_research, "_pinned_open", return_value=Response()):
            rows = web_research.search("example", 5)
        self.assertEqual([row["url"] for row in rows], ["https://example.com/one", "https://example.org/two"])
        self.assertEqual(rows[0]["title"], "Example One")
        self.assertEqual(rows[1]["snippet"], "Second useful snippet.")

    def test_a_news_question_reads_the_rss_vertical_with_publication_dates(self):
        with mock.patch.object(web_research, "_pinned_open", return_value=RssResponse()) as opener:
            rows = web_research.search("jakie są aktualności we Francji", 5)
        self.assertTrue(web_research.is_news_query("jakie są aktualności we Francji"))
        self.assertIn(b"news.google.com/rss/search", opener.call_args.args[0].full_url.encode())
        self.assertEqual(rows[0]["title"], "France braces for fresh protest weekend")
        self.assertEqual(rows[0]["snippet"], "Reuters — Sat, 24 Oct 2026 18:02:00 GMT")
        self.assertEqual(rows[0]["source"], "google-news")
        self.assertEqual(rows[0]["published"], "2026-10-24 18:02 UTC")
        self.assertEqual(rows[0]["kind"], "news")
        self.assertEqual(rows[1]["title"], "Second headline")

    def test_a_broken_news_feed_falls_back_to_the_general_engine(self):
        class Empty(Response):
            def read(self, limit=None):
                return b"<html>not rss</html>"
        # The news vertical is tried twice now (as asked, then the bare topic),
        # and only then does the general engine answer.
        with mock.patch.object(web_research, "_pinned_open",
                               side_effect=[Empty(), Empty(), Response()]) as opener:
            rows = web_research.search("aktualności w Polsce", 5)
        self.assertEqual(rows[0]["title"], "Example One")
        self.assertEqual(opener.call_count, 3)

    def test_the_topic_retry_returns_dated_items(self):
        class Empty(Response):
            def read(self, limit=None):
                return b"<html>not rss</html>"
        with mock.patch.object(web_research, "_pinned_open",
                               side_effect=[Empty(), RssResponse()]) as opener:
            rows = web_research.search("what is currently going on in France", 5)
        self.assertEqual(rows[0]["kind"], "news")
        self.assertIn("France", opener.call_args.args[0].full_url)

    def test_the_command_wrapper_is_stripped_before_asking_the_engine(self):
        self.assertEqual(web_research.clean_query(
            "Check in Internet what is currently going on in France"),
            "what is currently going on in France")
        self.assertEqual(web_research.clean_query("sprawdź w internecie co się dzieje we Włoszech"),
                         "co się dzieje we Włoszech")
        self.assertEqual(web_research.clean_query("ile kosztuje iPad"), "ile kosztuje iPad")

    def test_empty_query_is_rejected(self):
        with self.assertRaises(web_research.ResearchError):
            web_research.search("")


    def test_private_hosts_are_refused(self):
        self.assertFalse(web_research._is_public_host("127.0.0.1"))
        self.assertFalse(web_research._is_public_host("localhost"))

    def test_price_extraction_keeps_currency(self):
        self.assertEqual(web_research.extract_price("już od 4,12 zł")["currency"], "PLN")
        self.assertEqual(web_research.extract_price("price 19.99 USD")["price"], "19.99")
        # Grouped thousands used to match only their fractional tail.
        for text, price in (("Total price 1,234.56 USD", "1234.56"),
                            ("Cena 1.234,56 zł", "1234.56"),
                            ("Cena 1 234,56 zł", "1234.56"),
                            ("Cena 12 345 678,90 zł", "12345678.90"),
                            ("only 1,234 zł", "1234")):
            with self.subTest(text=text):
                self.assertEqual(web_research.extract_price(text)["price"], price)

    def test_malformed_result_links_are_skipped(self):
        for url in ("http://[::1", "//duckduckgo.com/l/?uddg=http%3A%2F%2F%5B%3A%3A1"):
            with self.subTest(url=url):
                self.assertEqual(web_research._canonical(url), "")

    def test_truncation_marks_the_cut_visibly_once(self):
        self.assertEqual(web_research._truncate_text("short"), "short")
        cut = web_research._truncate_text("x" * 3500, 3000)
        self.assertEqual(cut, "x" * 3000 + " … [truncated]")
        # An earlier marker the second cut slices mid-word leaves no fragment.
        recut = web_research._truncate_text("a" * 5990 + " … [truncated]", 3000)
        self.assertTrue(recut.endswith(" … [truncated]"))
        body = recut[:-len(" … [truncated]")]
        self.assertFalse(body.endswith("["))
        self.assertFalse(body.endswith("…"))

    def test_ceneo_results_dedupe_the_same_product_listing(self):
        product = '{"@type": "Product", "name": "Iron", "url": "https://www.ceneo.pl/1", "offers": {"lowPrice": 100}}'
        relative = '{"@type": "Product", "name": "Kettle", "url": "/2", "offers": {"lowPrice": 80}}'
        body = ("<html>" + product +
                '<script type="application/ld+json">' + product + "</script>" +
                '<script type="application/ld+json">' + product + "</script>" +
                '<script type="application/ld+json">' + relative + "</script>" + "</html>")

        class Reply:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, limit):
                return body.encode()

        with mock.patch.object(web_research, "_pinned_open", return_value=Reply()), \
                mock.patch.object(web_research, "_search_terms", return_value="iron"):
            rows = web_research._search_ceneo("iron", 5, 1)
        urls = [row["url"] for row in rows]
        self.assertEqual(urls, ["https://www.ceneo.pl/1", "https://www.ceneo.pl/2"])


class ResearchCacheTests(unittest.TestCase):
    def test_extra_whitespace_hits_the_same_cache_entry(self):
        import tempfile
        from pathlib import Path
        rows = [{"title": "One", "url": "https://example.com/one", "snippet": "s", "source": "duckduckgo"}]
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(web_research, "CACHE_PATH",
                                   Path(directory) / "web-cache.json"), \
                    mock.patch.object(web_research, "search", return_value=rows) as searches:
                first = web_research.research("Wielkie  żelazko", fetch_top=0)
                second = web_research.research("wielkie żelazko", fetch_top=0)
        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])  # one cache entry for both spellings
        self.assertEqual(second["sources"], first["sources"])
        self.assertEqual(searches.call_count, 1)


class PinnedPeerTests(unittest.TestCase):
    """The built-in reader resolves DNS once and connects only to public addresses."""

    def _records(self, addresses):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 80))
                for address in addresses]

    def test_private_resolution_is_refused_at_connect_time(self):
        with mock.patch.object(web_research.socket, "getaddrinfo",
                               return_value=self._records(["10.0.0.5", "127.0.0.1"])):
            with self.assertRaises(urllib.error.URLError):
                web_research._validated_peer("rebind.example")

    def test_mixed_records_are_refused(self):
        # A mixed answer is a classic rebinding shape; connecting to the public
        # one silently would make the pre-check and the connect disagree.
        with mock.patch.object(web_research.socket, "getaddrinfo",
                               return_value=self._records(["93.184.216.34", "10.0.0.5"])):
            with self.assertRaises(urllib.error.URLError):
                web_research._validated_peer("mixed.example")

    def test_numeric_public_interfaces_pass_through(self):
        self.assertEqual(web_research._validated_peer("8.8.8.8"), "8.8.8.8")

    def test_fetch_refuses_a_host_that_resolves_private(self):
        # The pre-flight check resolves through the same stubbed stack as the
        # connection — a rebinding server cannot show a different answer for one.
        request = urllib.request.Request("http://rebind.example/", headers={"User-Agent": "t"})
        with mock.patch.object(web_research.socket, "getaddrinfo",
                               return_value=self._records(["127.0.0.1"])):
            with self.assertRaises(urllib.error.URLError):
                web_research._pinned_open(request, timeout=2)

    def test_fetch_connects_through_the_pinned_address(self):
        served = http.server.BaseHTTPRequestHandler

        class Handler(served):
            def do_GET(self):
                body = b"<html><body>pinned reply</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        import threading
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            port = server.server_port

            def fake_addrinfo(host, port_, *args, **kwargs):
                # claim a public name, while create_connection is sent to the
                # local test server — impossible in the real world, in the test
                # it proves the connect uses this resolution and not another
                return self._records(["93.184.216.34"])

            def fake_create(address, timeout=None, source_address=None):
                self.assertEqual(address[0], "93.184.216.34")
                # Build the socket directly: the real create_connection would
                # re-resolve the loopback pair through the patched getaddrinfo.
                conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                conn.settimeout(timeout or 5)
                conn.connect(("127.0.0.1", port))
                return conn

            request = urllib.request.Request("http://public.example/page",
                                             headers={"User-Agent": "t"})
            with mock.patch.object(web_research.socket, "getaddrinfo", side_effect=fake_addrinfo), \
                    mock.patch.object(web_research.socket, "create_connection", side_effect=fake_create):
                with web_research._pinned_open(request, timeout=5) as response:
                    body = response.read().decode()
            self.assertIn("pinned reply", body)
        finally:
            server.server_close()

    def test_private_hosts_are_refused_before_connecting(self):
        with self.assertRaises(web_research.ResearchError):
            web_research.fetch_page("http://127.0.0.1/x")


if __name__ == "__main__":
    unittest.main()
