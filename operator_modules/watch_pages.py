"""Explicit, persistent public-page watches. No polling starts on import.

Checks run only when invoked by Operator (including an explicitly created schedule).
The Operator registry's approval flag applies to every action outside Full mode.
"""
from __future__ import annotations

import hashlib
import html
import json
import os
import re
import sqlite3
import time
import urllib.request
import uuid
from contextlib import contextmanager
from datetime import datetime
from decimal import Decimal, InvalidOperation
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

import net_guard
import web_research

MAX_WATCHES = 100
MAX_BYTES = 500_000
MAX_URL = 2048
MAX_CONDITIONS = 3
RETRY_BACKOFF_BASE = 300
RETRY_BACKOFF_MAX = 3600


def _root(context):
    context = context or {}
    job = context.get("job")
    service = getattr(job, "service", None)
    return Path(context.get("state_root") or getattr(service, "state_root", None)
                or Path.home() / ".jarvis-tools")


@contextmanager
def _connection(context):
    directory = _root(context) / "watch-pages"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / "watches.sqlite3"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    db = sqlite3.connect(path, timeout=10, isolation_level=None)
    try:
        db.execute("CREATE TABLE IF NOT EXISTS watches (id TEXT PRIMARY KEY, data TEXT NOT NULL)")
        yield db
    finally:
        db.close()


def _hash_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _valid_url(url):
    if not isinstance(url, str) or not url or len(url) > MAX_URL or url != url.strip():
        return False
    if any(ord(char) < 33 or ord(char) == 127 for char in url):
        return False
    try:
        parsed = urlsplit(url)
        if parsed.fragment or parsed.port is not None and not 1 <= parsed.port <= 65535:
            return False
        return net_guard.is_public_url(url)
    except ValueError:
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Redirects are not followed; use the exact final public URL.")


class _VisibleText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript", "svg"):
            self.skip += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript", "svg") and self.skip:
            self.skip -= 1

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


class _OfferScripts(HTMLParser):
    """Collect bounded JSON-LD blocks; page contents remain untrusted data."""
    def __init__(self):
        super().__init__()
        self.blocks = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        if tag.lower() == 'script' and (dict(attrs).get('type') or '').lower().split(';', 1)[0].strip() == 'application/ld+json':
            self.current = []

    def handle_data(self, data):
        if self.current is not None:
            self.current.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == 'script' and self.current is not None:
            self.blocks.append(''.join(self.current))
            self.current = None


def _extract_offer(html):
    """Use only a single unambiguous structured Product/Offer, never page text prices."""
    unknown = {'price': None, 'currency': None, 'stock': 'unknown'}
    if not isinstance(html, str) or len(html) > MAX_BYTES:
        return unknown
    parser = _OfferScripts()
    parser.feed(html)
    products = []

    def visit(value, depth=0):
        if depth > 24 or len(products) > 1:
            return
        if isinstance(value, list):
            for item in value[:1000]:
                visit(item, depth + 1)
        elif isinstance(value, dict):
            kinds = value.get('@type', [])
            kinds = [kinds] if isinstance(kinds, str) else kinds if isinstance(kinds, list) else []
            if any(isinstance(kind, str) and kind.rsplit('/', 1)[-1] == 'Product' for kind in kinds):
                products.append(value)
            for child in value.values():
                if isinstance(child, (list, dict)):
                    visit(child, depth + 1)

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON key')
            result[key] = value
        return result

    for block in parser.blocks[:32]:
        try:
            visit(json.loads(block, parse_float=Decimal, object_pairs_hook=unique_pairs,
                             parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid number'))))
        except (ValueError, RecursionError):
            continue
    if len(products) != 1:
        return unknown
    offers = products[0].get('offers')
    offers = offers if isinstance(offers, list) else [offers]
    if len(offers) != 1 or not isinstance(offers[0], dict):
        return unknown
    offer = offers[0]
    kind = offer.get('@type', 'Offer')
    if not isinstance(kind, str) or kind.rsplit('/', 1)[-1] != 'Offer':
        return unknown
    currency = offer.get('priceCurrency')
    price = offer.get('price')
    if isinstance(currency, str) and re.fullmatch(r'[A-Z]{3}', currency) and not isinstance(price, bool):
        try:
            amount = Decimal(str(price))
            if amount.is_finite() and 0 <= amount <= 1000000000:
                unknown.update(price=str(amount), currency=currency)
        except (InvalidOperation, ValueError):
            pass
    availability = offer.get('availability')
    if isinstance(availability, str):
        state = availability.rsplit('/', 1)[-1]
        if state == 'InStock':
            unknown['stock'] = 'available'
        elif state in ('OutOfStock', 'SoldOut', 'Discontinued'):
            unknown['stock'] = 'unavailable'
    return unknown


def _fetch(url):
    if not _valid_url(url):
        raise ValueError("URL must be a public HTTP(S) URL without credentials or fragment.")
    opener = urllib.request.build_opener(net_guard.PinnedHTTPHandler(),
                                        net_guard.PinnedHTTPSHandler(),
                                        _NoRedirect(), urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, headers={"User-Agent": web_research.USER_AGENT,
                                                   "Accept": "text/html,text/plain"})
    with opener.open(request, timeout=8) as response:
        if response.geturl() != url or response.status != 200:
            raise ValueError("Page response is not an exact successful URL.")
        content_type = response.headers.get_content_type().lower()
        if content_type not in ("text/html", "text/plain"):
            raise ValueError("Page must be HTML or plain text.")
        raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("Page exceeds the size limit.")
    text = raw.decode("utf-8", "replace")
    offer = {'price': None, 'currency': None, 'stock': 'unknown'}
    if content_type == "text/html":
        offer = _extract_offer(text)
        parser = _VisibleText()
        parser.feed(text)
        text = " ".join(parser.parts)
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        raise ValueError("Page has no readable text.")
    return {"text": text, **offer}


def _observation(page):
    text = page.get("text")
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_BYTES:
        raise ValueError("Page has no bounded readable text.")
    return {"text_hash": _hash_text(text), "price": page.get("price"),
            "currency": page.get("currency"), "stock": page.get("stock", "unknown"),
            "observed_at": time.time()}


def _conditions(conditions):
    if not isinstance(conditions, list) or not 1 <= len(conditions) <= MAX_CONDITIONS:
        raise ValueError("Specify one to three conditions.")
    clean = []
    seen = set()
    for condition in conditions:
        if not isinstance(condition, dict):
            raise ValueError("Invalid condition.")
        kind = condition.get("type")
        if kind not in ("page_change", "price_below", "stock_available") or kind in seen:
            raise ValueError("Invalid or duplicate condition.")
        seen.add(kind)
        row = {"type": kind}
        if kind == "price_below":
            try:
                amount = Decimal(str(condition.get("amount")))
                if not amount.is_finite() or amount < 0 or amount > 1000000000:
                    raise ValueError
            except (InvalidOperation, ValueError):
                raise ValueError("Invalid price threshold.") from None
            currency = condition.get("currency")
            if not isinstance(currency, str) or not re.fullmatch(r"[A-Z]{3}", currency):
                raise ValueError("Specify an uppercase ISO currency code.")
            row.update(amount=str(amount), currency=currency)
        clean.append(row)
    return clean


def _matches(condition, observation):
    kind = condition.get('type')
    if kind == 'price_below':
        if observation.get('currency') != condition.get('currency') or observation.get('price') is None:
            return None
        try:
            price = Decimal(str(observation['price']))
            threshold = Decimal(str(condition['amount']))
            if not price.is_finite() or not threshold.is_finite() or price < 0:
                return None
            return price <= threshold
        except (InvalidOperation, ValueError, KeyError):
            return None
    if kind == 'stock_available':
        stock = observation.get('stock')
        return True if stock == 'available' else False if stock == 'unavailable' else None
    return None


def _quiet_hours(now):
    hour = datetime.fromtimestamp(now).astimezone().hour
    return hour >= 22 or hour < 7


def _send_notification(body):
    from operator_modules.desktop_notify import _send_os_notification
    return _send_os_notification('Jarvis — obserwacja', html.escape(body[:500]))


def _event_message(row, pending):
    details = []
    for event in pending:
        if event['type'] == 'price_below':
            details.append(f"Cena: {event.get('price')} {event.get('currency')} (bez potwierdzenia kosztu dostawy i podatków)")
        elif event['type'] == 'stock_available':
            details.append('Produkt oznaczony jako dostępny')
        elif event['type'] == 'page_change':
            details.append('Treść strony uległa zmianie')
    extra = f"; oraz {len(details) - 3} innych zmian" if len(details) > 3 else ''
    stamp = datetime.fromtimestamp(pending[-1]['observed_at']).astimezone().strftime('%d.%m %H:%M')
    return '; '.join(details[-3:]) + extra + f' ({stamp}) — ' + row['url']


@contextmanager
def _write_tx(db):
    db.execute('BEGIN IMMEDIATE')
    try:
        yield
        db.execute('COMMIT')
    except BaseException:
        if db.in_transaction:
            db.execute('ROLLBACK')
        raise


def _deliver(context, watch_id):
    """Retain queued events until an opted-in notification succeeds."""
    with _connection(context) as db:
        found = db.execute('SELECT data FROM watches WHERE id = ?', (watch_id,)).fetchone()
    if not found:
        return None, set()
    row = json.loads(found[0])
    pending = row.get('pending') or []
    now = time.time()
    recent = [v for v in row.get('notification_times', [])
              if isinstance(v, (int, float)) and now - 86400 <= v <= now]
    if not row.get('notify') or not pending or _quiet_hours(now) or len(recent) >= 6:
        return row, set()
    if recent and now - recent[-1] < 3600:
        return row, set()
    message = _event_message(row, pending)
    delivered_ids = {event['id'] for event in pending if isinstance(event, dict) and event.get('id')}
    if not _send_notification(message):
        return row, set()
    with _connection(context) as db, _write_tx(db):
        found = db.execute('SELECT data FROM watches WHERE id = ?', (watch_id,)).fetchone()
        if not found:
            return None, set()
        row = json.loads(found[0])
        current_pending = row.get('pending') or []
        row['pending'] = [ev for ev in current_pending if ev.get('id') not in delivered_ids]
        fresh_recent = [v for v in row.get('notification_times', [])
                        if isinstance(v, (int, float)) and now - 86400 <= v <= now]
        row['notification_times'] = [*fresh_recent, now]
        db.execute('UPDATE watches SET data = ? WHERE id = ?', (json.dumps(row), watch_id))
        return row, delivered_ids


def watch_pages(arguments, context=None):
    args = arguments or {}
    action = args.get("action")
    try:
        if action == "list":
            with _connection(context) as db:
                rows = [json.loads(row[0]) for row in db.execute("SELECT data FROM watches ORDER BY id")]
            return {"ok": True, "watches": rows}
        if action == "create":
            url = args.get("url")
            if not _valid_url(url):
                raise ValueError("URL must be a public HTTP(S) URL without credentials or fragment.")
            conditions = _conditions(args.get("conditions"))
            interval = args.get('interval_seconds')
            if interval is not None and (type(interval) is not int or not 3600 <= interval <= 30 * 86400):
                raise ValueError('Automatic checks must be between one hour and 30 days apart.')
            observation = _observation(_fetch(url))
            if any(c['type'] != 'page_change' and _matches(c, observation) is None for c in conditions):
                raise ValueError('Cannot establish an unambiguous price or availability baseline for that condition.')
            row = {"id": uuid.uuid4().hex, "url": url, "conditions": conditions,
                   "created_at": time.time(), "observation": observation,
                   "condition_states": {c['type']: _matches(c, observation) for c in conditions
                                        if c['type'] != 'page_change'},
                   "notify": args.get("notify") is True, "pending": [], "notification_times": [],
                   "interval_seconds": interval, "next_check_at": time.time() + interval if interval else None}
            with _connection(context) as db, _write_tx(db):
                if db.execute("SELECT COUNT(*) FROM watches").fetchone()[0] >= MAX_WATCHES:
                    raise ValueError("Watch limit reached.")
                db.execute("INSERT INTO watches VALUES (?, ?)", (row["id"], json.dumps(row)))
            return {"ok": True, "watch": row, "baseline": True,
                    "note": "Automatic checks enabled." if interval else "No schedule was created; this watch runs only when checked."}
        if action == "remove":
            watch_id = args.get("id")
            if not isinstance(watch_id, str) or not re.fullmatch(r"[0-9a-f]{32}", watch_id):
                raise ValueError("A valid watch id is required.")
            with _connection(context) as db, _write_tx(db):
                found = db.execute("SELECT data FROM watches WHERE id = ?", (watch_id,)).fetchone()
                if not found:
                    raise ValueError("Watch not found.")
                db.execute("DELETE FROM watches WHERE id = ?", (watch_id,))
                return {"ok": True, "removed": watch_id}
        if action == "check":
            watch_id = args.get("id")
            if not isinstance(watch_id, str) or not re.fullmatch(r"[0-9a-f]{32}", watch_id):
                raise ValueError("A valid watch id is required.")
            # Read target URL without holding a write transaction during network I/O.
            with _connection(context) as db:
                found = db.execute("SELECT data FROM watches WHERE id = ?", (watch_id,)).fetchone()
            if not found:
                raise ValueError("Watch not found.")
            target_url = json.loads(found[0])["url"]
            observation = _observation(_fetch(target_url))

            with _connection(context) as db, _write_tx(db):
                found = db.execute("SELECT data FROM watches WHERE id = ?", (watch_id,)).fetchone()
                if not found:
                    raise ValueError("Watch not found.")
                row = json.loads(found[0])
                previous = row["observation"]
                events = []
                states = row.setdefault('condition_states', {})
                for condition in row["conditions"]:
                    kind = condition['type']
                    if kind == "page_change":
                        if previous["text_hash"] != observation["text_hash"]:
                            events.append({"type": kind, "delivered": False})
                        continue
                    match = _matches(condition, observation)
                    old_match = states.get(kind, _matches(condition, previous))
                    if match is not None:
                        if match and old_match is not True:
                            events.append({'type': kind, 'delivered': False,
                                           'price': observation.get('price'),
                                           'currency': observation.get('currency'),
                                           'stock': observation.get('stock')})
                        states[kind] = match
                for event in events:
                    event.update(id=uuid.uuid4().hex, url=row['url'], observed_at=observation['observed_at'])
                if row.get('notify') and events:
                    pending = row.setdefault('pending', [])
                    if len(pending) + len(events) > 50:
                        raise ValueError('Notification queue full; observation unchanged.')
                    pending.extend(dict(event) for event in events)
                row["observation"] = observation
                row["checked_at"] = time.time()
                row["retry_count"] = 0
                row.pop("last_error", None)
                db.execute("UPDATE watches SET data = ? WHERE id = ?", (json.dumps(row), watch_id))
            if row.get('notify'):
                row, delivered = _deliver(context, watch_id)
                for event in events:
                    event['delivered'] = event['id'] in delivered
            return {"ok": True, "watch": row, "events": events}
        return {"ok": False, "error": "Unsupported action."}
    except (ValueError, OSError, sqlite3.Error) as error:
        return {"ok": False, "error": str(error)[:300]}


def run_due(root, limit=2):
    """Run explicitly scheduled watches without starting an AI job."""
    context = {'state_root': Path(root)}
    now = time.time()
    due = []
    # Claim due watches with a short lease so concurrent ticks do not double-fetch,
    # and advance to the full interval only after `check` actually succeeds.
    with _connection(context) as db, _write_tx(db):
        rows = db.execute('SELECT id, data FROM watches ORDER BY id').fetchall()
        for watch_id, data in rows:
            row = json.loads(data)
            interval, next_at = row.get('interval_seconds'), row.get('next_check_at')
            if type(interval) is int and 3600 <= interval <= 30 * 86400 and isinstance(next_at, (int, float)) and next_at <= now:
                row['next_check_at'] = now + RETRY_BACKOFF_BASE
                db.execute('UPDATE watches SET data = ? WHERE id = ?', (json.dumps(row), watch_id))
                due.append((watch_id, interval, next_at))
                if len(due) >= limit:
                    break
    for watch_id, interval, planned_at in due:
        _deliver(context, watch_id)
        result = watch_pages({'action': 'check', 'id': watch_id}, context)
        finished_at = time.time()
        with _connection(context) as db, _write_tx(db):
            found = db.execute('SELECT data FROM watches WHERE id = ?', (watch_id,)).fetchone()
            if not found:
                continue
            row = json.loads(found[0])
            if result.get('ok'):
                scheduled = planned_at + interval
                while scheduled <= finished_at:
                    scheduled += interval
                row['next_check_at'] = scheduled
                row['retry_count'] = 0
                row.pop('last_error', None)
            else:
                retries = int(row.get('retry_count') or 0) + 1
                backoff = min(interval, RETRY_BACKOFF_MAX, RETRY_BACKOFF_BASE * (2 ** min(retries - 1, 4)))
                row['retry_count'] = retries
                row['next_check_at'] = finished_at + backoff
                row['last_error'] = str(result.get('error') or 'check failed')[:300]
            db.execute('UPDATE watches SET data = ? WHERE id = ?', (json.dumps(row), watch_id))
    return len(due)


TOOL = {
    "name": "watch_pages",
    "description": "Watch selected public pages, structured product prices or availability. Optional interval_seconds enables automatic checks (minimum 1 hour); notify=true enables desktop alerts. Product price excludes unverified shipping/taxes. Confirm exact variant from the baseline.",
    "input_schema": {"type": "object", "properties": {
        "action": {"type": "string", "enum": ["create", "list", "check", "remove"]},
        "url": {"type": "string"}, "id": {"type": "string"},
        "conditions": {"type": "array", "items": {"type": "object"}},
        "interval_seconds": {"type": "integer", "minimum": 3600, "maximum": 2592000},
        "notify": {"type": "boolean", "description": "Opt in to desktop notifications for this watch."}},
        "required": ["action"], "additionalProperties": False},
    "handler": watch_pages, "approval": True,
}

