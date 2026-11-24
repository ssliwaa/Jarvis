import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from operator_modules import watch_pages


class WatchPagesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        guard = patch.object(watch_pages.net_guard, "is_public_url", return_value=True)
        guard.start()
        self.addCleanup(guard.stop)

    def call(self, **args):
        return watch_pages.watch_pages(args, {"state_root": self.root})

    @patch.object(watch_pages, "_fetch", return_value={"text": "Initial page", "price": None, "currency": None, "stock": "unknown"})
    def test_create_requires_a_real_baseline_and_persists_exact_url(self, fetch):
        url = "https://example.com/product?variant=blue&utm_test=1"
        result = self.call(action="create", url=url, conditions=[{"type": "page_change"}])
        self.assertTrue(result["ok"])
        self.assertEqual(result["watch"]["url"], url)
        self.assertEqual(len(self.call(action="list")["watches"]), 1)
        self.assertEqual(result["watch"]["observation"]["text_hash"], watch_pages._hash_text("Initial page"))
        fetch.assert_called_once_with(url)

    def test_sqlite_connection_is_closed_after_use(self):
        import sqlite3
        with watch_pages._connection({'state_root': self.root}) as db:
            db.execute('SELECT 1')
        with self.assertRaises(sqlite3.ProgrammingError):
            db.execute('SELECT 1')

    def test_product_offer_extracts_exact_structured_price_and_stock(self):
        html = '''<html><script type="application/ld+json">{"@type":"Product","name":"Headphones",
        "offers":{"@type":"Offer","price":"1599.00","priceCurrency":"PLN",
                  "availability":"https://schema.org/InStock"}}</script><body>Headphones</body></html>'''
        result = watch_pages._extract_offer(html)
        self.assertEqual(result, {'price': '1599.00', 'currency': 'PLN', 'stock': 'available'})

    def test_fetch_exposes_structured_offer_without_guessing_shipping(self):
        import io
        from email.message import Message
        html = b'''<script type="application/ld+json">{"@type":"Product","offers":
          {"@type":"Offer","price":"44.99","priceCurrency":"PLN","availability":"https://schema.org/InStock"}}</script><p>Product</p>'''
        class Response(io.BytesIO):
            status = 200
            headers = Message()
            def __enter__(self): return self
            def __exit__(self, *args): self.close()
            def geturl(self): return 'https://example.com/product'
        Response.headers['Content-Type'] = 'text/html'
        opener = type('Opener', (), {'open': lambda self, request, timeout: Response(html)})()
        with patch.object(watch_pages.urllib.request, 'build_opener', return_value=opener):
            result = watch_pages._fetch('https://example.com/product')
        self.assertEqual(result['price'], '44.99')
        self.assertEqual(result['currency'], 'PLN')
        self.assertEqual(result['stock'], 'available')
        self.assertNotIn('shipping', result)

    def test_ambiguous_multiple_offers_are_not_guessed(self):
        html = '''<script type="application/ld+json">{"@type":"Product","offers":[
          {"@type":"Offer","price":"10","priceCurrency":"PLN"},
          {"@type":"Offer","price":"20","priceCurrency":"PLN"}]}</script>'''
        result = watch_pages._extract_offer(html)
        self.assertIsNone(result['price'])
        self.assertEqual(result['stock'], 'unknown')

    def test_price_watch_refuses_unknown_baseline(self):
        page = {'text': 'item', 'price': None, 'currency': None, 'stock': 'unknown'}
        with patch.object(watch_pages, '_fetch', return_value=page):
            result = self.call(action='create', url='https://example.com/p', interval_seconds=3600,
                               conditions=[{'type': 'price_below', 'amount': '100', 'currency': 'PLN'}])
        self.assertFalse(result['ok'])
        self.assertEqual(self.call(action='list')['watches'], [])

    def test_automatic_checks_are_explicit_and_obey_interval(self):
        a = {'text': 'old', 'price': None, 'currency': None, 'stock': 'unknown'}
        b = {**a, 'text': 'new'}
        with patch.object(watch_pages, '_fetch', side_effect=[a, b]) as fetch, \
             patch.object(watch_pages.time, 'time', return_value=1000):
            created = self.call(action='create', url='https://example.com/a', interval_seconds=3600,
                                conditions=[{'type': 'page_change'}])
        self.assertTrue(created['ok'])
        self.assertEqual(created['watch']['next_check_at'], 4600)
        with patch.object(watch_pages.time, 'time', return_value=4599):
            self.assertEqual(watch_pages.run_due(self.root), 0)
        with patch.object(watch_pages.time, 'time', return_value=4600), \
             patch.object(watch_pages, '_fetch', return_value=b):
            self.assertEqual(watch_pages.run_due(self.root), 1)
        self.assertEqual(fetch.call_count, 1)
        self.assertGreater(self.call(action='list')['watches'][0]['next_check_at'], 4600)

    def test_quiet_hours_keep_alert_until_later(self):
        a = {'text': 'old', 'price': None, 'currency': None, 'stock': 'unknown'}
        b = {**a, 'text': 'new'}
        with patch.object(watch_pages, '_fetch', side_effect=[a, b, b]), \
             patch.object(watch_pages, '_quiet_hours', side_effect=[True, False]), \
             patch.object(watch_pages, '_send_notification', return_value=True) as send:
            watch_id = self.call(action='create', url='https://example.com/a', notify=True,
                                 conditions=[{'type': 'page_change'}])['watch']['id']
            self.assertEqual(len(self.call(action='check', id=watch_id)['watch']['pending']), 1)
            self.assertEqual(send.call_count, 0)
            self.assertEqual(self.call(action='check', id=watch_id)['watch']['pending'], [])
            self.assertEqual(send.call_count, 1)

    def test_opted_in_alert_is_retried_after_delivery_failure_without_duplicates(self):
        a = {'text': 'old', 'price': '120', 'currency': 'PLN', 'stock': 'available'}
        b = {**a, 'price': '90'}
        with patch.object(watch_pages, '_fetch', side_effect=[a, b, b]), \
             patch.object(watch_pages, '_quiet_hours', return_value=False), \
             patch.object(watch_pages, '_send_notification', side_effect=[False, True]) as send:
            created = self.call(action='create', url='https://example.com/p?model=a', notify=True,
                                conditions=[{'type': 'price_below', 'amount': '100', 'currency': 'PLN'}])
            watch_id = created['watch']['id']
            first = self.call(action='check', id=watch_id)
            self.assertFalse(first['events'][0]['delivered'])
            self.assertEqual(len(first['watch']['pending']), 1)
            second = self.call(action='check', id=watch_id)
            self.assertEqual(second['events'], [])
            self.assertEqual(second['watch']['pending'], [])
            self.assertEqual(send.call_count, 2)
            self.assertIn('90', send.call_args.args[0])
            self.assertIn('https://example.com/p?model=a', send.call_args.args[0])
            self.assertIn('dostaw', send.call_args.args[0].lower())

    def test_price_and_stock_alert_only_on_transition_with_unknown_preserving_state(self):
        base = {'text': 'item', 'price': '150.00', 'currency': 'PLN', 'stock': 'unavailable'}
        good = {**base, 'price': '99.99', 'stock': 'available'}
        unknown = {**base, 'price': None, 'currency': None, 'stock': 'unknown'}
        with patch.object(watch_pages, '_fetch', side_effect=[base, good, unknown, good]):
            created = self.call(action='create', url='https://example.com/p', conditions=[
                {'type': 'price_below', 'amount': '100', 'currency': 'PLN'},
                {'type': 'stock_available'}])
            watch_id = created['watch']['id']
            first = self.call(action='check', id=watch_id)
            self.assertEqual({event['type'] for event in first['events']}, {'price_below', 'stock_available'})
            self.assertEqual(first['events'][0]['price'], '99.99')
            self.assertEqual(self.call(action='check', id=watch_id)['events'], [])
            self.assertEqual(self.call(action='check', id=watch_id)['events'], [])

    def test_check_compares_and_failure_preserves_last_good_then_remove(self):
        initial = {"text": "A", "price": None, "currency": None, "stock": "unknown"}
        changed = {**initial, "text": "B"}
        with patch.object(watch_pages, "_fetch", side_effect=[initial, changed, OSError("offline")]):
            created = self.call(action="create", url="https://example.com/a", conditions=[{"type": "page_change"}])
            watch_id = created["watch"]["id"]
            checked = self.call(action="check", id=watch_id)
            self.assertTrue(checked["ok"])
            self.assertEqual(checked["events"][0]["type"], "page_change")
            self.assertNotEqual(checked["watch"]["observation"]["text_hash"], created["watch"]["observation"]["text_hash"])
            failed = self.call(action="check", id=watch_id)
            self.assertFalse(failed["ok"])
            self.assertEqual(self.call(action="list")["watches"][0]["observation"], checked["watch"]["observation"])
            self.assertTrue(self.call(action="remove", id=watch_id)["ok"])
            self.assertEqual(self.call(action="list")["watches"], [])
