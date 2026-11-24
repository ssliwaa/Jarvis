"""ERROR-path coverage tests for operator_modules/watch_pages.py.

Fourth module of the sys.settrace audit and the biggest gap so far: 25
raise sites with exactly one ever executed - in the live watch-loop
module, whose validation chain (URL hygiene, redirect refusal, payload
and text bounds, condition grammar, watch-id grammar, queue and race
guards) is the safety net of the whole watch feature.

Everything is offline: ``net_guard.is_public_url`` is patched to True
for URL-grammar tests (validation order short-circuits before the net
for fragment/port cases), ``urllib.request.build_opener`` is swapped
for a fake opener whose responses/redirects are driven per test, and
``_fetch`` is patched wherever a watch lifecycle step needs page data.
The two guard races are simulated the way production can hit them: a
"fetcher" that deletes the watched row during the network window (the
second read inside the write transaction is then empty), and a seeded
full notification queue.
"""
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import operator_modules.watch_pages as wp


class _FakeResponse:
    def __init__(self, body=b"hello", url=None, status=200,
                 content_type="text/html"):
        self._body = body
        self._url = url
        self.status = status
        self.headers = SimpleNamespace(get_content_type=lambda: content_type)

    def geturl(self, request_url=None):
        return self._url

    def read(self, size=None):
        return self._body if size is None else self._body[:size]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeOpener:
    def __init__(self, behavior):
        self._behavior = behavior

    def open(self, request, timeout=None):
        return self._behavior(request.full_url)


def _opener_behavior(response=None, redirect=False,
                     status=None, content_type=None, body=b"hello",
                     mismatch_url=False):
    def behavior(url):
        if redirect:
            handler = wp._NoRedirect()
            # Execute the production redirect handler's own raise.
            handler.redirect_request(req=None, fp=None, code=302,
                                     msg="Found", headers={},
                                     newurl="https://elsewhere.example/")
        return _FakeResponse(body=body, url="https://elsewhere.example/"
                             if mismatch_url else url,
                             status=status or 200,
                             content_type=content_type or "text/html")
    return behavior


class WatchCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = self._tmp.name
        self.ctx = {"state_root": self.tmp}
        guard = patch.object(wp.net_guard, "is_public_url", return_value=True)
        guard.start()
        self.addCleanup(guard.stop)
        self.page = {"text": "Initial page", "price": None,
                     "currency": None, "stock": "unknown"}

    def call(self, **kwargs):
        return wp.watch_pages(kwargs, self.ctx)

    def create(self, conditions=None, notify=False, interval=None,
               url="https://example.com/watched"):
        args = {"action": "create", "url": url,
                "conditions": conditions or [{"type": "page_change"}]}
        if notify:
            args["notify"] = True
        if interval:
            args["interval_seconds"] = interval
        fetch = patch.object(wp, "_fetch", return_value=dict(self.page))
        with fetch:
            return self.call(**args)

    def seed_row(self, watch_id, **overrides):
        row = {"id": watch_id, "url": "https://example.com/watched",
               "conditions": [{"type": "page_change"}],
               "created_at": 1000.0,
               "observation": {"text_hash": "h0", "price": None,
                               "currency": None, "stock": "unknown",
                               "observed_at": 1000.0},
               "notify": True, "pending": [], "notification_times": [],
               "interval_seconds": None, "next_check_at": None}
        row.update(overrides)
        import json
        with wp._connection(self.ctx) as db:
            db.execute("INSERT INTO watches VALUES (?, ?)",
                       (watch_id, json.dumps(row)))
        return row


class FetchGuardTests(WatchCase):
    def test_public_url_requirement(self):
        with patch.object(wp.net_guard, "is_public_url", return_value=False):
            with self.assertRaises(ValueError) as ctx:
                wp._fetch("https://example.com/x")
        self.assertIn("public HTTP(S) URL", str(ctx.exception))

    def test_redirect_is_refused_by_the_real_handler(self):
        behavior = _opener_behavior(redirect=True)
        with patch.object(wp.urllib.request, "build_opener",
                          return_value=_FakeOpener(behavior)):
            with self.assertRaises(ValueError) as ctx:
                wp._fetch("https://example.com/final")
        self.assertIn("Redirects are not followed", str(ctx.exception))

    def test_response_must_be_the_exact_url_with_status_200(self):
        for kwargs in ({"mismatch_url": True}, {"status": 404}):
            behavior = _opener_behavior(**kwargs)
            with patch.object(wp.urllib.request, "build_opener",
                              return_value=_FakeOpener(behavior)):
                with self.assertRaises(ValueError) as ctx:
                    wp._fetch("https://example.com/final")
            self.assertIn("not an exact successful URL", str(ctx.exception))

    def test_content_type_must_be_html_or_plain(self):
        behavior = _opener_behavior(content_type="application/json")
        with patch.object(wp.urllib.request, "build_opener",
                          return_value=_FakeOpener(behavior)):
            with self.assertRaises(ValueError) as ctx:
                wp._fetch("https://example.com/final")
        self.assertIn("HTML or plain text", str(ctx.exception))

    def test_payload_size_ceiling(self):
        behavior = _opener_behavior(body=b"x" * 128)
        with patch.object(wp.urllib.request, "build_opener",
                          return_value=_FakeOpener(behavior)):
            with patch.object(wp, "MAX_BYTES", 64):
                with self.assertRaises(ValueError) as ctx:
                    wp._fetch("https://example.com/final")
        self.assertIn("exceeds the size limit", str(ctx.exception))

    def test_html_without_visible_text_is_refused(self):
        behavior = _opener_behavior(body=b"<script>data()</script>")
        with patch.object(wp.urllib.request, "build_opener",
                          return_value=_FakeOpener(behavior)):
            with self.assertRaises(ValueError) as ctx:
                wp._fetch("https://example.com/final")
        self.assertIn("no readable text", str(ctx.exception))

    def test_offer_json_with_duplicate_keys_is_ignored(self):
        # The duplicate-key guard raises inside the parse and the block is
        # then discarded: an unambiguous baseline is never established
        # from ambiguous JSON-LD.
        html = ('<script type="application/ld+json">'
                '{"@type": "Product", "@type": "Product"}</script>')
        offer = wp._extract_offer(html)
        self.assertIsNone(offer["price"])
        self.assertEqual(offer["stock"], "unknown")


class ObservationAndConditionTests(WatchCase):
    def test_observation_requires_bounded_text(self):
        for bad in (None, "", "   "):
            with self.assertRaises(ValueError) as ctx:
                wp._observation({"text": bad})
            self.assertIn("bounded readable text", str(ctx.exception))
        # The size bound mirrors the module constant; lower it instead of
        # building a half-megabyte string.
        with patch.object(wp, "MAX_BYTES", 16):
            with self.assertRaises(ValueError) as ctx:
                wp._observation({"text": "x" * 300000})
        self.assertIn("bounded readable text", str(ctx.exception))

    def _condition_error(self, conditions, fragment):
        with self.assertRaises(ValueError) as ctx:
            wp._conditions(conditions)
        self.assertIn(fragment, str(ctx.exception))

    def test_condition_count_and_types(self):
        self._condition_error(None, "one to three conditions")
        self._condition_error([], "one to three conditions")
        self._condition_error([{"type": "page_change"}] * 4,
                              "one to three conditions")
        self._condition_error(["page_change"], "Invalid condition.")
        self._condition_error([{"type": "bogus"}],
                              "Invalid or duplicate condition.")
        self._condition_error([{"type": "page_change"},
                              {"type": "page_change"}],
                              "Invalid or duplicate condition.")

    def test_price_threshold_grammar(self):
        bad_amounts = ("abc", -1, 1000000001, float("nan"))
        for amount in bad_amounts:
            self._condition_error(
                [{"type": "price_below", "amount": amount, "currency": "USD"}],
                "Invalid price threshold")
        self._condition_error(
            [{"type": "price_below", "amount": 10, "currency": "usd"}],
            "uppercase ISO currency code")

    def test_price_condition_is_accepted_when_well_formed(self):
        clean = wp._conditions([{"type": "price_below", "amount": "99.50",
                                 "currency": "PLN"},
                                {"type": "stock_available"}])
        self.assertEqual(clean, [{"type": "price_below", "amount": "99.50",
                                   "currency": "PLN"},
                                  {"type": "stock_available"}])


class CreateGuardTests(WatchCase):
    def _guard(self, fragment, **kwargs):
        result = self.create(**kwargs)
        self.assertFalse(result["ok"], msg=str(result))
        self.assertIn(fragment, result["error"])

    def test_url_grammar_is_enforced_by_create(self):
        with patch.object(wp, "_fetch", return_value=dict(self.page)):
            result = self.call(action="create",
                               url="https://example.com/#fragment",
                               conditions=[{"type": "page_change"}])
        self.assertFalse(result["ok"])
        self.assertIn("public HTTP(S) URL", result["error"])

    def test_interval_bounds(self):
        for interval in (60, "3600", 31 * 86400):
            self._guard("between one hour and 30 days",
                        interval=interval)

    def test_watch_limit_fires_and_rolls_back(self):
        with patch.object(wp, "MAX_WATCHES", 1):
            first = self.create()
            self.assertTrue(first["ok"], msg=str(first))
            with patch.object(wp, "_fetch", return_value=dict(self.page)):
                second = self.call(
                    action="create", url="https://example.com/other",
                    conditions=[{"type": "page_change"}])
            self.assertFalse(second["ok"])
            self.assertIn("Watch limit reached.", second["error"])
        listing = self.call(action="list")
        self.assertEqual(len(listing["watches"]), 1)


class IdentityGuardTests(WatchCase):
    def test_remove_requires_valid_and_existing_id(self):
        no_id = self.call(action="remove", id="zz")
        self.assertFalse(no_id["ok"])
        self.assertIn("A valid watch id is required.", no_id["error"])

        missing = self.call(action="remove", id="a" * 32)
        self.assertFalse(missing["ok"])
        self.assertIn("Watch not found.", missing["error"])

    def test_check_requires_valid_and_existing_id(self):
        no_id = self.call(action="check", id="zz")
        self.assertFalse(no_id["ok"])
        self.assertIn("A valid watch id is required.", no_id["error"])

        missing = self.call(action="check", id="b" * 32)
        self.assertFalse(missing["ok"])
        self.assertIn("Watch not found.", missing["error"])

    def test_race_when_row_disappears_during_fetch(self):
        created = self.create()
        watch_id = created["watch"]["id"]

        def racing_fetch(url):
            # Simulates the row being removed during the network window.
            with wp._connection(self.ctx) as db:
                db.execute("DELETE FROM watches WHERE id = ?", (watch_id,))
            return {"text": "changed", "price": None,
                    "currency": None, "stock": "unknown"}

        with patch.object(wp, "_fetch", side_effect=racing_fetch):
            result = self.call(action="check", id=watch_id)
        self.assertFalse(result["ok"])
        self.assertIn("Watch not found.", result["error"])

    def test_full_notification_queue_keeps_observation_unchanged(self):
        watch_id = "c" * 32
        self.seed_row(watch_id, pending=[
            {"id": f"e{i}", "type": "page_change", "url": "u",
             "observed_at": 1234} for i in range(50)])

        changed = {"text": "changed content", "price": None,
                   "currency": None, "stock": "unknown"}
        with patch.object(wp, "_fetch", return_value=changed):
            result = self.call(action="check", id=watch_id)
        self.assertFalse(result["ok"])
        self.assertIn("Notification queue full", result["error"])

        import json
        with wp._connection(self.ctx) as db:
            stored = json.loads(db.execute(
                "SELECT data FROM watches WHERE id = ?",
                (watch_id,)).fetchone()[0])
        self.assertEqual(stored["observation"]["text_hash"], "h0")
        self.assertEqual(len(stored["pending"]), 50)
        self.assertNotIn("checked_at", stored)


if __name__ == "__main__":
    unittest.main()
