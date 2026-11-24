"""Unit tests for `preflight.py` — warstwa transportu i walidacji (bez serwera, bez Chromium).

Preflight to oficjalny client-drill serwera Jarvisa (:4700 + live Chromium), ale cala
komunikacja HTTP przechodzi przez `self.http` (opener) — podmieniany falszywym w kazdym
teście. Pokryte: walidacja originu konstruktora, redakcja sekretow w safe(), kolejnosc
Failure dla connection/size/JSON/status, sciezki lokalne i ich anty-traversal,
validate_answer z granicami grafu, PageAssets, NoRedirect, check_server/check_config
na kontrolowanych odpowiedziach. Chromium/playwright i realny :4700 — NIGDY niedotkniete.
"""
from __future__ import annotations

import sys
import unittest
from io import BytesIO
from unittest import mock
from urllib.error import HTTPError, URLError

sys.path.insert(0, ".")

import preflight as pf  # noqa: E402


class _FakeResponse:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self._body = body if isinstance(body, bytes) else body.encode("utf-8")

    def read(self, n=-1):
        return self._body[:n] if n > 0 else self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeOpener:
    """Kolejkowany opener: open(req, timeout) zwraca kolejne sceny albo rzuca."""

    def __init__(self, responses=None, connect_error=None, seen=None):
        self.responses = list(responses or [])
        self.connect_error = connect_error
        self.seen = seen if seen is not None else []

    def open(self, request, timeout=None):
        self.seen.append({
            "url": request.full_url,
            "data": request.data,
            "timeout": timeout,
            "headers": dict(request.header_items()),
        })
        if self.connect_error is not None:
            raise self.connect_error
        scene = self.responses.pop(0)
        if isinstance(scene, Exception):
            raise scene
        return _FakeResponse(*scene)


def _http_error(status, body=b"", headers=None):
    return HTTPError("http://127.0.0.1:4700/x", status, "boom", headers or {}, BytesIO(body))


class PreflightBase(unittest.TestCase):
    def make(self, opener, **kwargs):
        bot = pf.Preflight(**kwargs)
        bot.http = opener
        return bot


class ConstructorTests(PreflightBase):
    def test_rejects_insecure_and_non_loopback_origins(self):
        bad = [
            "https://127.0.0.1:4700",
            "http://example.com", "http://10.0.0.5", "http://127.0.0.1/x",
            "http://127.0.0.1/?q=1", "http://127.0.0.1/#f",
            "http://user:pass@127.0.0.1:4700",
        ]
        for url in bad:
            with self.assertRaises(pf.Failure, msg=url):
                pf.Preflight(base_url=url)

    def test_accepts_plain_loopback_and_normalises_base(self):
        bot = pf.Preflight(base_url="http://localhost:4700/")
        self.assertEqual(bot.base, "http://localhost:4700")
        bot2 = pf.Preflight()
        self.assertEqual(bot2.base, "http://127.0.0.1:4700")
        self.assertTrue(str(bot.report).endswith("preflight.json"))
        self.assertTrue(str(bot.pending_path).endswith("preflight-pending.json"))


class RequireAndSafeTests(PreflightBase):
    def test_require_raises_only_on_falsy(self):
        pf.require(True, "nie byc")
        pf.require(1, "nie byc")
        with self.assertRaises(pf.Failure) as ctx:
            pf.require(0, "treść błędu")
        self.assertEqual(str(ctx.exception), "treść błędu")

    def test_safe_redacts_key_pattern_length_and_newlines(self):
        bot = pf.Preflight()
        bot.key = "sk-000000000000000000000000000000"
        out = bot.safe("klucz sk-000000000000000000000000000000 w tekście")
        self.assertNotIn("super-secret", out)
        self.assertIn("[REDACTED]", out)
        # obcy klucz sk- tez maskowany
        self.assertNotIn("sk-openai-token-wery", bot.safe("abc sk-openai-token-wery"))
        # limit 1200 znakow
        self.assertEqual(len(bot.safe("x" * 5000)), 1200)
        # newline sorry-> spacja
        self.assertNotIn("\n", bot.safe("linia1\nlinia2"))
        # bez klucza safe jest przyjazny
        bot2 = pf.Preflight()
        self.assertEqual(bot2.safe("zwykła treść"), "zwykła treść")


class RequestTests(PreflightBase):
    def test_success_returns_status_headers_raw_and_passes_timeout(self):
        scene = (200, {"Content-Type": "application/json"}, b'{"a":1}')
        opener = _FakeOpener(responses=[scene, scene])
        bot = self.make(opener)
        status, headers, raw = bot.request("http://127.0.0.1:4700/health", timeout=7)
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(raw, b'{"a":1}')
        self.assertEqual(opener.seen[0]["timeout"], 7)
        # brak jawnego timeoutu -> self.timeout
        bot.timeout = 33
        bot.request("http://127.0.0.1:4700/health")
        self.assertEqual(opener.seen[1]["timeout"], 33)

    def test_http_error_is_returned_not_raised(self):
        opener = _FakeOpener(responses=[_http_error(404, b"nope")])
        bot = self.make(opener)
        status, _, raw = bot.request("http://127.0.0.1:4700/brak")
        self.assertEqual(status, 404)
        self.assertEqual(raw, b"nope")

    def test_connection_failure_maps_to_failure(self):
        opener = _FakeOpener(connect_error=URLError("refused"))
        bot = self.make(opener)
        with self.assertRaises(pf.Failure) as ctx:
            bot.request("http://127.0.0.1:4700/x")
        self.assertIn("Connection failed (URLError)", str(ctx.exception))
        self.assertIn("/x", str(ctx.exception))

    def test_response_size_limit_enforced(self):
        big = b"x" * (20 * 1024 * 1024 + 1)
        opener = _FakeOpener(responses=[(200, {}, big)])
        bot = self.make(opener)
        with self.assertRaises(pf.Failure) as ctx:
            bot.request("http://127.0.0.1:4700/duzy")
        self.assertIn("size limit", str(ctx.exception))


class LocalTests(PreflightBase):
    def test_local_joins_base_and_validates_path(self):
        opener = _FakeOpener(responses=[(200, {}, b"ok")])
        bot = self.make(opener)
        status, _, _ = bot.local("/health")
        self.assertEqual(opener.seen[0]["url"], "http://127.0.0.1:4700/health")
        for bad in ("health", "//health"):
            with self.assertRaises(pf.Failure):
                bot.local(bad)

    def test_local_json_contract(self):
        opener = _FakeOpener(responses=[(200, {"Content-Type": "application/json"},
                                             b'{"ok": true}')])
        bot = self.make(opener)
        self.assertEqual(bot.local_json("/health"), {"ok": True})

        # status 500 z kodem bledu w payload
        opener = _FakeOpener(responses=[(500, {}, b'{"error": {"code": "E_XX"}}')])
        bot = self.make(opener)
        with self.assertRaises(pf.Failure) as ctx:
            bot.local_json("/boom")
        self.assertIn("HTTP 500", str(ctx.exception))
        self.assertIn("E_XX", str(ctx.exception))

        # nie-JSON
        opener = _FakeOpener(responses=[(200, {}, b"<html>")])
        bot = self.make(opener)
        with self.assertRaises(pf.Failure) as ctx2:
            bot.local_json("/tekst")
        self.assertIn("not JSON", str(ctx2.exception))

    def test_local_bytes_posts_payload_with_content_type(self):
        opener = _FakeOpener(responses=[(200, {}, b"done")])
        bot = self.make(opener)
        status, _, raw = bot.local_bytes("/upload", b"AUDIO", "audio/wav")
        self.assertEqual(status, 200)
        seen = opener.seen[0]
        self.assertEqual(seen["data"], b"AUDIO")
        self.assertEqual(seen["headers"].get("Content-type") or
                         seen["headers"].get("Content-Type")
                         or seen["headers"].get("Content-type"), "audio/wav")


class ValidateAnswerTests(PreflightBase):
    GRAPH = {"nodes": [{"id": 0}, {"id": 1}, {"id": 2}], "links": []}

    def test_full_contract(self):
        bot = pf.Preflight()
        with self.assertRaises(pf.Failure):
            bot.validate_answer({"error": "x"}, graph=self.GRAPH)
        with self.assertRaises(pf.Failure):
            bot.validate_answer({"answer": "   "}, graph=self.GRAPH)
        with self.assertRaises(pf.Failure):
            bot.validate_answer({"answer": "ok", "nodes": "1,2"}, graph=self.GRAPH)
        with self.assertRaises(pf.Failure):
            bot.validate_answer({"answer": "ok", "nodes": [0, 3]}, graph=self.GRAPH)
        with self.assertRaises(pf.Failure):
            bot.validate_answer({"answer": "ok", "nodes": [0.5]}, graph=self.GRAPH)
        good = {"answer": "prezentacja", "nodes": [0, 2]}
        self.assertIs(bot.validate_answer(good, graph=self.GRAPH), good)

    def test_validate_answer_uses_own_graph_when_none_given(self):
        """Bez jawnego grafu leci get_graph() — wypinamy, aby nie dotknac HTTP."""
        bot = pf.Preflight()
        with mock.patch.object(pf.Preflight, "get_graph", return_value=self.GRAPH) as gg:
            good = {"answer": "ok", "nodes": [1]}
            self.assertIs(bot.validate_answer(good), good)
            gg.assert_called_once()


class PageAssetsAndRedirectTests(PreflightBase):
    def test_page_assets_extracts_ids_scripts_styles_and_icon(self):
        html = (
            '<html><head>'
            '<link rel="stylesheet" href="/viewer/styl.css">'
            '<link rel="icon" href="/viewer/favicon.png">'
            '<link rel="preload" href="/viewer/pomijany.bin">'
            '</head><body>'
            '<div id="graph"></div><div id="chat-form"></div>'
            '<script src="/viewer/graf.js"></script>'
            '<script>inline()</script>'
            '</body></html>'
        )
        assets = pf.PageAssets(html)
        self.assertEqual({"graph", "chat-form"}, assets.ids)
        self.assertEqual(assets.urls, ["/viewer/styl.css", "/viewer/favicon.png",
                                      "/viewer/graf.js"])

    def test_no_redirect_has_redirect_request_none(self):
        handler = pf.NoRedirect()
        req = object()
        self.assertIsNone(handler.redirect_request(req, None, 302, "Found", {}, "http://x"))


class CheckRoutesTests(PreflightBase):
    def test_check_server_with_controlled_html(self):
        html = ('<!doctype html><html><body>'
                '<div id="graph"></div><form id="chat-form"><input id="question">'
                '</form></body></html>')
        opener = _FakeOpener(responses=[(200, {"Content-Type": "text/html; charset=utf-8"},
                                              html.encode("utf-8"))])
        bot = self.make(opener)
        self.assertIn("HTTP 200; correct viewer HTML", bot.check_server())
        self.assertIn("chat-form", bot.html)

        zle = _FakeOpener(responses=[(200, {"Content-Type": "text/html"},
                                        b"<html><body>inne</body></html>")])
        with self.assertRaises(pf.Failure) as ctx:
            self.make(zle).check_server()
        self.assertIn("not the knowledge viewer", str(ctx.exception))

        json_ct = _FakeOpener(responses=[(200, {"Content-Type": "application/json"}, b"{}")])
        with self.assertRaises(pf.Failure):
            self.make(json_ct).check_server()

    def test_check_config_denies_variants_and_detects_key_leak(self):
        # wszystkie dwie sciezki odmawiane -> check przechodzi
        ok_opener = _FakeOpener(responses=[
            _http_error(403, b"denied") for _ in range(5)
        ])
        bot = self.make(ok_opener)
        self.assertIn("denied", bot.check_config())
        ok_urls = [s["url"] for s in ok_opener.seen]
        self.assertEqual(len(ok_urls), 5)
        self.assertTrue(any("%2e" in u for u in ok_urls), ok_urls)
        self.assertTrue(any("%252e" in u for u in ok_urls), ok_urls)

        # jedna sciezka zwraca 200 -> SECURITY FAILURE
        leaking = _FakeOpener(responses=[
            _http_error(403, b"x"), _http_error(403, b"x"),
            _http_error(200, b"{}"), _http_error(404, b""),
            _http_error(404, b""),
        ])
        with self.assertRaises(pf.Failure) as ctx:
            self.make(leaking).check_config()
        self.assertIn("PRIVATE CONFIG REACHABLE", str(ctx.exception))
        # check przerwal na trzeciej sciezce (200 -> SECURITY FAILURE)
        urls = [s["url"] for s in leaking.seen]
        self.assertEqual(len(urls), 3)

        # 403 z kluczem w body -> wyciek klucza
        bot_key = pf.Preflight()
        bot_key.key = "sk-000000000000000000000000000000"
        leak_body = ("klucz=" + bot_key.key).encode("utf-8")
        leak_opener = _FakeOpener(responses=[_http_error(403, leak_body) for _ in range(5)])
        bot_key.http = leak_opener
        with self.assertRaises(pf.Failure) as ctx2:
            bot_key.check_config()
        self.assertIn("API KEY LEAKED", str(ctx2.exception))


if __name__ == "__main__":
    unittest.main()
