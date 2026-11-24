"""Web research through a public HTML search endpoint, with real URLs.

This is deliberately a retriever, not a summarizer: Jarvis receives titles,
snippets and canonical links and must cite them. No API key, account or paid
service is used. If the network or parser fails, the caller gets an error rather
than invented results.
"""
from __future__ import annotations

import base64
import email.utils
import hashlib
import html
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ElementTree
from concurrent.futures import ThreadPoolExecutor
from datetime import timezone
from html.parser import HTMLParser
from pathlib import Path

import net_guard
import web_backends

SEARCH_URL = "https://html.duckduckgo.com/html/?q="
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"


class ResearchError(Exception):
    pass


class _Results(HTMLParser):
    def __init__(self):
        super().__init__()
        self.rows = []
        self._row = None
        self._field = None
        self._field_tag = None
        self._depth = 0

    def _finish(self):
        if self._row and self._row["title"].strip():
            self.rows.append(self._row)
        self._row = None
        self._field = None
        self._field_tag = None
        self._depth = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        classes = set((attrs.get("class") or "").split())
        if tag == "a" and "result__a" in classes:
            self._finish()
            self._row = {"title": "", "url": attrs.get("href", ""), "snippet": ""}
            self._field, self._field_tag, self._depth = "title", tag, 0
        elif self._row is not None and "result__snippet" in classes:
            self._field, self._field_tag, self._depth = "snippet", tag, 0
        elif self._field:
            self._depth += 1

    def handle_data(self, data):
        if self._row is not None and self._field:
            self._row[self._field] += data

    def handle_endtag(self, tag):
        if self._field and tag == self._field_tag:
            if self._field == "snippet":
                self._finish()
            else:
                self._field, self._field_tag, self._depth = None, None, 0
        elif self._field and self._depth:
            self._depth -= 1

    def finish(self):
        self._finish()
        return self.rows


def _split(url: str):
    """urlsplit that treats a malformed IPv6/port literal as "no URL"."""
    try:
        return urllib.parse.urlsplit(url)
    except ValueError:
        return None


def _canonical(url: str) -> str:
    url = html.unescape(url or "").strip()
    if url.startswith("//"):
        url = "https:" + url
    if url.startswith("/l/?uddg="):
        parsed = _split(url)
        if parsed is None:
            return ""
        query = urllib.parse.parse_qs(parsed.query)
        url = (query.get("uddg") or [""])[0]
    if not url.startswith(("http://", "https://")):
        return ""
    parsed = _split(url)
    if parsed is None:
        return ""
    if parsed.hostname in ("duckduckgo.com", "www.duckduckgo.com") and parsed.path == "/l/":
        url = (urllib.parse.parse_qs(parsed.query).get("uddg") or [""])[0]
        if not url.startswith(("http://", "https://")):
            return ""
        parsed = _split(url)
        if parsed is None:
            return ""
    if parsed.hostname and parsed.hostname.endswith("bing.com") and parsed.path == "/ck/a":
        encoded = (urllib.parse.parse_qs(parsed.query).get("u") or [""])[0]
        if encoded.startswith("a1"):
            try:
                raw = encoded[2:]
                raw += "=" * (-len(raw) % 4)
                decoded = base64.urlsafe_b64decode(raw).decode("utf-8", "replace")
                if decoded.startswith(("http://", "https://")):
                    url = decoded
                    parsed = _split(url)
                    if parsed is None:
                        return ""
            except Exception:
                return ""
    if not parsed.hostname or parsed.hostname in ("duckduckgo.com", "www.duckduckgo.com"):
        return ""
    if parsed.hostname.endswith("bing.com"):
        return ""
    kept = [(key, value) for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            if not (key.lower().startswith("utm_") or key.lower() in ("fbclid", "gclid", "msclkid"))]
    netloc = parsed.netloc.lower()
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path,
                                    urllib.parse.urlencode(kept, doseq=True), ""))


COMMAND_PREFIX = re.compile(
    r"^\s*(?:(?:please|proszę|prosze|hej|hey|ok)\s+)?"
    r"(?:(?:could|can)\s+you\s+|czy\s+możesz\s+|czy\s+mozesz\s+)?"
    r"(?:(?:check|look\s+up|search|find|see|read|sprawdź|sprawdz|poszukaj|szukaj|"
    r"przeczytaj|znajdź|znajdz)\s+"
    r"(?:(?:in|on|up|at|w|na)\s+)?(?:the\s+)?"
    r"(?:internet|web|online|necie|internecie|sieci)\b\s*(?:for|about)?\s*)+",
    re.I)
BARE_VERB = re.compile(
    r"^\s*(?:(?:please|proszę|prosze)\s+)?"
    r"(?:look\s+up|search\s+for|search|check|sprawdź|sprawdz|poszukaj|szukaj|"
    r"znajdź|znajdz|przeczytaj)\s+", re.I)
TALK_PREFIX = re.compile(
    r"^\s*(?:(?:tell\s+me|powiedz\s+mi|opowiedz\s+mi)\s+(?:what|co|o)?\s*)", re.I)


def clean_query(query: str) -> str:
    """Drop the command wrapper so the engine sees a topic, not an instruction.

    "Check in Internet what is currently going on in France" returned generic
    landing pages because the whole sentence went to the feed; without the
    wrapper the same words return dated articles. The question word stays: it
    is part of the topic, not of the command.
    """
    text = re.sub(r"\s+", " ", str(query or "")).strip()
    stripped = COMMAND_PREFIX.sub("", text)
    stripped = TALK_PREFIX.sub("", stripped).strip()
    stripped = BARE_VERB.sub("", stripped).strip(" ,.:;-")
    if len(stripped) >= 3 and len(stripped.split()) >= 1:
        return stripped[:300]
    return text[:300]


SCAFFOLD = re.compile(
    r"\b(?:what|whats|what's|is|are|was|were|going|goes|on|happening|currently|right|now|"
    r"today|the|a|an|please|tell|me|about|co|się|sie|dzieje|nowego|w|we|na|o|mi|powiedz)\b",
    re.I)


def news_queries(query: str) -> list[str]:
    """Two bounded attempts: as asked, then the bare topic plus "news".

    "what is currently going on in France" returns nothing from the dated feed,
    while "France news" returns real articles with timestamps. Both are tried so
    a question phrased like a sentence still reaches current items.
    """
    cleaned = clean_query(query)
    candidates = [cleaned]
    topic = re.sub(r"\s+", " ", SCAFFOLD.sub(" ", cleaned)).strip(" ,.:;-?")
    topic = re.sub(r"^(?:in|at|for|from|to|we|w|na|o)\s+", "", topic, flags=re.I)
    if topic and topic.casefold() != cleaned.casefold():
        candidates.append(f"{topic} news"[:200])
    return candidates


def search(query: str, limit: int = 5, timeout: float = 15) -> list[dict]:
    query = str(query or "").strip()
    if not query:
        raise ResearchError("A research query is required.")
    if len(query) > 500:
        raise ResearchError("A research query is too long.")
    limit = max(1, min(int(limit or 5), 12))
    query = clean_query(query)
    # News-like questions go to the news vertical first; a general result list
    # cannot offer publication dates and serves stale content for them.
    if is_news_query(query):
        for candidate in news_queries(query):
            try:
                news = _search_news(candidate, limit, timeout)
            except Exception:
                news = []  # a broken feed falls back to the general engine below
            if news:
                return news
    request = urllib.request.Request(SEARCH_URL + urllib.parse.quote_plus(query),
                                     headers={"User-Agent": USER_AGENT, "Accept": "text/html"})
    try:
        with _pinned_open(request, timeout) as response:
            body = response.read(2_000_000).decode("utf-8", errors="replace")
    except Exception:
        body = ""
    parser = _Results()
    try:
        parser.feed(body)
    except Exception as error:
        raise ResearchError(f"Web search response could not be parsed: {error}") from None
    results, seen = [], set()
    for row in parser.finish():
        url = _canonical(row.get("url", ""))
        title = re.sub(r"\s+", " ", html.unescape(row.get("title", ""))).strip()
        snippet = re.sub(r"\s+", " ", html.unescape(row.get("snippet", ""))).strip()
        if not url or not title or url in seen:
            continue
        seen.add(url)
        results.append({"title": title[:240], "url": url, "snippet": snippet[:500],
                        "source": "duckduckgo"})
        if len(results) >= limit:
            break
    if not results:
        if re.search(r"\b(?:cena|koszt|ile\s+kosztuje|price|cost)\b", query, re.I):
            try:
                ceneo = _search_ceneo(query, limit, timeout)
                if ceneo:
                    return ceneo
            except Exception:
                pass
        try:
            return _search_bing(query, limit, timeout)
        except Exception as error:
            raise ResearchError(f"Web search failed: {error}") from None
    return results


RESEARCH_HINTS = re.compile(
    r"\b(?:ile\s+kosztuje|jaka\s+(?:jest\s+)?cena|jaki\s+(?:jest\s+)?koszt|"
    r"cena|koszt|cennik|gdzie\s+kupić|gdzie\s+kupic|dostępn\w*|"
    r"price|cost|how\s+much|where\s+to\s+buy|availability|"
    r"aktualn\w*|najnow\w*|latest|current|news|wiadom\w*|"
    r"pogoda|weather|"
    r"kurs|exchange\s+rate|stock|ranking|najlepsz\w*|review|recenzj\w*|"
    r"porównaj|porownaj|compare|premiera|release\s+date|wynik|score|"
    r"kto\s+wygrał|mecz|match|sprawdź\s+w\s+internecie|"
    r"co\s+się\s+dzieje|co\s+sie\s+dzieje|what['’]?s\s+happening|events|"
    r"search\s+(?:the\s+)?web|look\s+up|"
    # "check in internet what is currently going on in France" missed every
    # alternative above: the verb was "check", the time word "currently" and the
    # source "internet". These pair the source with a research verb so that
    # "how does the internet work" stays a conceptual question.
    r"\b(?:check|look|search|find|read|see|sprawdź|sprawdz|szukaj|poszukaj|przeczytaj)\s+"
    r"(?:in|on|up|at|w|na)?\s*(?:the\s+)?(?:internet|web|online|necie|internecie|sieci)\b|"
    r"\bwhat\s+(?:is|are|'s)\b[^?.]{0,40}\b(?:going\s+on|happening)\b|"
    r"\b(?:going\s+on|happening)\s+(?:in|at|with|around)\b|"
    r"\bco\s+(?:się\s+|sie\s+)?(?:dzieje|nowego)\b|"
    r"\bnews\s+(?:about|from)\b|"
    r"\bcurrently\s+(?:going\s+on|happening|in\s+the\s+news))\b", re.I)

# A news vertical beat the general search for "co się dzieje we Francji": the
# HTML result list served months-old protest tags without dates, while Google
# News' server-rendered RSS returns actual items with publication timestamps.
# Non-commercial personal-use feed, no key or account.
NEWS_HINTS = re.compile(
    r"\b(?:aktualn\w*|najnow\w*|co\s+się\s+dzieje|co\s+sie\s+dzieje|co\s+nowego|wydarzen\w*|"
    r"news|wiadom\w*|top\s+stories|what['’]?s\s+happening|"
    r"what\s+is\s+(?:currently\s+)?(?:going\s+on|happening)|going\s+on|happening)\b", re.I)

NEWS_SUFFIX = os.environ.get("JARVIS_NEWS_LOCALE", "hl=pl&gl=PL&ceid=PL:pl").strip("?& ")


def is_news_query(query: str) -> bool:
    return bool(NEWS_HINTS.search(str(query or "")))


def _search_news(query: str, limit: int, timeout: float) -> list[dict]:
    """Current items from Google News RSS, each with a publication date.

    The search feed orders by relevance, so a plain query resurfaces the
    biggest story of past months; the `when:7d` operator pins it to this week,
    and anything older than seven days is dropped outright. A news question
    that cannot find anything fresh must say so, not resell stale items.
    """
    url = ("https://news.google.com/rss/search?q=" + urllib.parse.quote_plus(
        str(query) + " when:7d") + "&" + NEWS_SUFFIX)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/rss+xml, text/xml"})
    with _pinned_open(request, timeout) as response:
        body = response.read(1_500_000).decode("utf-8", errors="replace")
    try:
        channel = ElementTree.fromstring(body)
    except ElementTree.ParseError as error:
        raise ResearchError(f"News feed could not be parsed: {error}") from None
    now = time.time()
    output, seen = [], set()
    rows = channel.findall("./channel/item") if channel.tag == "rss" else channel.findall("./item")
    for row in rows:
        title = re.sub(r"\s+", " ", (row.findtext("title") or "").strip())
        link = (row.findtext("link") or "").strip()
        published = (row.findtext("pubDate") or "").strip()
        source_node = row.find("source")
        site = re.sub(r"\s+", " ", (source_node.text or "")) if source_node is not None else ""
        if " - " in title:
            headline, _, remainder = title.rpartition(" - ")
            if remainder and not site:
                site = remainder.strip()
            title = headline.strip() or title
        if not title or link in seen:
            continue
        seen.add(link)
        when = ""
        try:
            stamp = email.utils.parsedate_to_datetime(published)
            when = stamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            if now - stamp.timestamp() > 8 * 24 * 3600:
                continue  # fall-forward guard: the operator already pins a week
        except (ValueError, TypeError):
            pass
        snippet = f"{site} — {published}" if site else published
        output.append({"title": title[:240], "url": link, "snippet": snippet[:500],
                       "source": "google-news", "published": when,
                       "kind": "news"})
        if len(output) >= limit:
            break
    return output


def should_research(query: str) -> bool:
    """Cheap intent gate: prices, current facts, comparisons and explicit web asks."""
    return bool(RESEARCH_HINTS.search(str(query or "")))


# ---- Page reading, price extraction and a small local cache -----------------

socket = net_guard.socket

CACHE_PATH = Path.home() / ".jarvis-tools" / "web-cache.json"
CACHE_TTL = 3600
CACHE_MAX = 80
_CACHE_LOCK = threading.Lock()  # research() read-modify-write on web-cache.json
MAX_PAGE_BYTES = 500_000
MAX_PAGE_TEXT = 6_000


class _PageText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title = ""
        self.parts = []
        self._in_title = False
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in ("script", "style", "noscript", "svg"):
            self._skip += 1
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in ("script", "style", "noscript", "svg") and self._skip:
            self._skip -= 1
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._skip:
            return
        text = re.sub(r"\s+", " ", data).strip()
        if not text:
            return
        if self._in_title:
            self.title = (self.title + " " + text).strip()
        else:
            self.parts.append(text)

    def text(self):
        return re.sub(r"\s+", " ", " ".join(self.parts)).strip()


def _is_public_host(host: str) -> bool:
    return net_guard.is_public_host(host)


def _public_url(url: str) -> bool:
    return net_guard.is_public_url(url)


def _validated_peer(host: str) -> str:
    """Resolve *host* once; return a public address or raise URLError.

    ``net_guard`` refuses mixed public/private DNS answers, so the pre-flight
    check and the pinned TCP connect cannot disagree.
    """
    address = net_guard.public_ip(host)
    if address is None:
        raise urllib.error.URLError(f"Refusing a non-public address for {host}")
    return address


_PinnedHTTPConnection = net_guard.PinnedHTTPConnection
_PinnedHTTPSConnection = net_guard.PinnedHTTPSConnection


class _PinnedHTTPHandler(net_guard.PinnedHTTPHandler):
    def __init__(self):
        super().__init__(peer_validator=_validated_peer)


class _PinnedHTTPSHandler(net_guard.PinnedHTTPSHandler):
    def __init__(self):
        super().__init__(peer_validator=_validated_peer)


class _PublicRedirect(urllib.request.HTTPRedirectHandler):
    """Allow only public http/https redirect hops; never ftp/file/proxy."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _public_url(newurl):
            raise urllib.error.HTTPError(newurl, 403, "redirect target is not public",
                                         headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_PINNED_OPENER = None
_OPENER_LOCK = threading.Lock()


def _pinned_open(request, timeout):
    """``urlopen`` for this module: one DNS resolution per connection instead of two.

    Each redirect hop re-enters the connection class, so every hop is validated
    against its own host. An empty ProxyHandler disables urllib's automatic
    environment-proxy support, which would otherwise fetch around the pin.
    """
    global _PINNED_OPENER
    if _PINNED_OPENER is None:
        with _OPENER_LOCK:
            if _PINNED_OPENER is None:
                _PINNED_OPENER = urllib.request.build_opener(
                    _PinnedHTTPHandler, _PinnedHTTPSHandler,
                    _PublicRedirect, urllib.request.ProxyHandler({}))
    return _PINNED_OPENER.open(request, timeout=timeout)


def _read_cache():
    try:
        payload = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except (OSError, ValueError, UnicodeError):
        return {}


def _write_cache(payload):
    try:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        temp = CACHE_PATH.with_name(f".web-cache-{os.getpid()}-{time.time_ns()}.tmp")
        temp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        temp.chmod(0o600)
        temp.replace(CACHE_PATH)
    except OSError:
        pass


def fetch_page(url: str, timeout: float = 8) -> dict:
    """Read a public page as plain text. Private/loopback targets are refused.

    The isolated crawl4ai/Scrapling backend is tried first because it renders
    JavaScript and returns clean markdown; the built-in urllib reader remains
    the fallback when that venv is absent, slow or blocked.
    """
    if not _public_url(url):
        raise ResearchError("The result URL is not a public HTTP(S) page.")
    if web_backends.enabled():
        # Honour the caller's budget: a hard 12 s floor per page multiplied by
        # several sources overran the chat deadline.
        backend = web_backends.fetch(url, timeout=max(3.0, min(float(timeout), 20.0)))
        if backend and backend.get("text"):
            if not _public_url(backend["url"]):
                raise ResearchError("The result redirected outside the public web.")
            return {"url": backend["url"], "title": backend["title"][:240],
                    "text": _truncate_text(backend["text"]),
                    "fetched_at": round(time.time(), 3), "engine": backend["engine"]}
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,text/plain"})
    try:
        with _pinned_open(request, timeout) as response:
            final_url = response.geturl()
            if not _public_url(final_url):
                raise ResearchError("The result redirected outside the public web.")
            content_type = (response.headers.get_content_type() or "").lower()
            if content_type and not (content_type.startswith("text/") or "html" in content_type):
                raise ResearchError("The result is not an HTML/text page.")
            data = response.read(MAX_PAGE_BYTES)
    except ResearchError:
        raise
    except Exception as error:
        raise ResearchError(f"Page fetch failed: {error}") from None
    parser = _PageText()
    try:
        parser.feed(data.decode("utf-8", errors="replace"))
    except Exception:
        pass
    text = _truncate_text(parser.text())
    return {"url": final_url, "title": re.sub(r"\s+", " ", parser.title).strip()[:240],
            "text": text, "fetched_at": round(time.time(), 3), "engine": "builtin"}


# Grouping separators before the decimal part used to be ignored, so
# "1,234.56 USD" yielded 234.56. Accept space, comma and dot grouping and
# let _normalize_amount decide which separator is the decimal one.
PRICE_RE = re.compile(
    r"(?<![\w.])(\d{1,3}(?:[ \u00a0]\d{3})+(?:[.,]\d{2})?"
    r"|\d{1,3}(?:[.,]\d{3})+(?:[.,]\d{2})?"
    r"|\d+(?:[.,]\d{2})?)\s*(zł|pln|eur|€|usd|\$|gbp|£)\b", re.I)
CURRENCIES = {"zł": "PLN", "pln": "PLN", "eur": "EUR", "€": "EUR", "usd": "USD", "$": "USD",
              "gbp": "GBP", "£": "GBP"}


# A cut-off text must not read as a complete answer: say so, visibly.
_TRUNC_MARK = re.compile(r"\s*(?:…|\[[^\]]*$|\[truncated\])\s*$")


def _truncate_text(text: str, limit: int = MAX_PAGE_TEXT) -> str:
    text = str(text or "")
    if len(text) <= limit:
        return text
    cut = _TRUNC_MARK.sub("", text[:limit])  # drop a previous marker cut mid-word
    return cut.rstrip() + " … [truncated]"


def _normalize_amount(raw: str) -> str:
    """Drop grouped thousands and keep the decimal separator.

    Both `1,234.56` and `1.234,56` must become `1234.56`; a lone comma with
    two trailing digits stays a decimal (`4,12` -> `4.12`).
    """
    value = str(raw or "").replace(" ", "").replace("\u00a0", "")
    if "," in value and "." in value:
        decimal = "," if value.rfind(",") > value.rfind(".") else "."
        grouping = "." if decimal == "," else ","
        return value.replace(grouping, "").replace(decimal, ".")
    if "," in value:
        head, _, tail = value.rpartition(",")
        if len(tail) == 2:
            return head.replace(",", "") + "." + tail
        return value.replace(",", "")
    if "." in value:
        head, _, tail = value.rpartition(".")
        if len(tail) == 2 and "." not in head:
            return value
        return value.replace(".", "")
    return value


def extract_price(text: str) -> dict:
    match = PRICE_RE.search(str(text or ""))
    if not match:
        return {}
    amount = _normalize_amount(match.group(1))
    return {"price": amount, "currency": CURRENCIES.get(match.group(2).lower(), match.group(2).upper())}


def research(query: str, limit: int = 5, fetch_top: int = 2, timeout: float = 15) -> dict:
    """Search, read the first public pages, and return cited, dated sources.

    The cache key is a hash of the normalized query; cache entries expire after
    an hour. Page-reading failures do not destroy otherwise useful snippets.
    """
    query = str(query or "").strip()
    if not query:
        raise ResearchError("A research query is required.")
    # One question, any amount of extra blank: one cache entry (the id used to
    # hash the raw string, so "żelazko" and "żelazko  " missed each other).
    # limit/fetch_top are part of the payload, so they must be part of the key;
    # otherwise a small agent call poisoned the chat lane's five-source call.
    normalized = re.sub(r"\s+", " ", query.casefold()).strip()
    key = hashlib.sha256(
        f"{normalized}\x00{int(limit)}\x00{int(fetch_top)}".encode("utf-8")).hexdigest()[:32]
    cache = _read_cache()
    cached = cache.get(key)
    cached_ttl = float(cached.get("ttl") or CACHE_TTL) if isinstance(cached, dict) else CACHE_TTL
    if (isinstance(cached, dict) and cached.get("sources")
            and time.time() - float(cached.get("cached_at") or 0) < cached_ttl):
        return {"query": query, "sources": cached.get("sources", []), "cached": True,
                "checked_at": cached.get("checked_at")}
    deadline = time.time() + max(3.0, float(timeout))
    results = search(query, limit, timeout=min(15, max(1.0, deadline - time.time())))
    sources = []
    top_cap = max(0, min(int(fetch_top or 0), 5))
    to_fetch = []
    for index, row in enumerate(results):
        source = dict(row)
        source["id"] = f"W{index + 1}"
        source["fetched_at"] = round(time.time(), 3)
        source["price"] = source.get("price") or extract_price(source.get("snippet", ""))
        sources.append(source)
        if index < top_cap and _public_url(source["url"]):
            to_fetch.append(source)

    def _read_one(source):
        remaining = deadline - time.time()
        if remaining < 2.0:
            source["page_error"] = "page read skipped: research deadline"
            return
        try:
            page = fetch_page(source["url"], timeout=min(8.0, remaining))
            source["page_title"] = page["title"]
            source["page_text"] = _truncate_text(page["text"], 3000)
            source["fetched_at"] = page["fetched_at"]
            if not source["price"]:
                source["price"] = extract_price(page["text"][:12000])
        except ResearchError:
            source["page_error"] = "page could not be read"

    if len(to_fetch) == 1:
        _read_one(to_fetch[0])
    elif len(to_fetch) > 1:
        with ThreadPoolExecutor(max_workers=min(len(to_fetch), 6)) as pool:
            for future in [pool.submit(_read_one, item) for item in to_fetch]:
                try:
                    future.result()
                except Exception:
                    pass
    checked_at = round(time.time(), 3)
    with _CACHE_LOCK:
        # Re-read under the lock: the snapshot taken before the (slow) network
        # work used to be written back verbatim, silently dropping entries a
        # concurrent research() saved meanwhile.
        cache = _read_cache()
        # A transient page failure must not be frozen for an hour: cache only
        # a complete result for the full TTL, or for a short 300s window when
        # at least one top page was read cleanly alongside another page error.
        has_errors = any(source.get("page_error") for source in sources)
        has_read_page = any(source.get("page_text") for source in sources)
        entry_ttl = 900 if is_news_query(normalized) else CACHE_TTL
        if sources and not has_errors:
            cache[key] = {"cached_at": checked_at, "checked_at": checked_at,
                          "sources": sources, "ttl": entry_ttl}
        elif sources and has_read_page:
            cache[key] = {"cached_at": checked_at, "checked_at": checked_at,
                          "sources": sources, "ttl": min(300, entry_ttl)}
        else:
            cache.pop(key, None)
        # Evict expired entries, then keep the freshest rows instead of the
        # last-80-by-insertion-order (which could evict fresh, keep stale).
        fresh = {entry_key: row for entry_key, row in cache.items()
                 if isinstance(row, dict)
                 and checked_at - float(row.get("cached_at") or 0) < float(row.get("ttl") or CACHE_TTL)}
        ordered = sorted(fresh.items(),
                         key=lambda item: float(item[1].get("cached_at") or 0), reverse=True)
        _write_cache(dict(ordered[:CACHE_MAX]))
    return {"query": query, "sources": sources, "cached": False, "checked_at": checked_at}


def _clean_plan(questions, limit):
    out, seen = [], set()
    for question in questions or []:
        text = re.sub(r"\s+", " ", str(question or "")).strip()
        text = re.sub(r"^(?:[-•*]|\d+[.)])\s*", "", text).strip()
        if not text or len(text) > 200 or text.casefold() in seen:
            continue
        seen.add(text.casefold())
        out.append(text)
        if len(out) >= limit:
            break
    return out


def plan_questions(query, planner=None, limit=3):
    """Split a question into sub-questions; without a planner, keep the query."""
    if planner is None:
        return [query]
    try:
        proposed = planner(query, limit)
    except Exception:
        return [query]
    return _clean_plan(proposed, limit) or [query]


def deep_research(query, planner=None, limit=4, fetch_top=2, timeout=20, max_questions=3):
    """gpt-researcher's shape: plan sub-questions, search each, merge citations.

    Every source keeps the sub-question that found it, so the answer can say
    which part of the plan a citation serves. Failures of one sub-question do
    not destroy the others.
    """
    query = str(query or "").strip()
    if not query:
        raise ResearchError("A research query is required.")
    questions = plan_questions(query, planner, max_questions)
    merged, order = {}, []
    for question in questions:
        try:
            found = research(question, limit=limit, fetch_top=fetch_top, timeout=timeout)
        except ResearchError:
            continue
        for source in found.get("sources", []):
            url = source.get("url") or ""
            if not url or url in merged:
                continue
            row = dict(source)
            row["question"] = question
            merged[url] = row
            order.append(url)
    sources = [merged[url] for url in order[: max(1, limit) * max(1, max_questions)]]
    for index, source in enumerate(sources):
        source["id"] = f"W{index + 1}"
    return {"query": query, "plan": questions, "sources": sources,
            "checked_at": round(time.time(), 3), "deep": True}


class _BingResults(HTMLParser):
    """Small fallback parser for Bing's non-JavaScript result list."""
    def __init__(self):
        super().__init__()
        self.rows = []
        self._row = None
        self._in_h2 = False
        self._in_link = False
        self._in_snippet = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        classes = set((attrs.get("class") or "").split())
        if tag == "li" and "b_algo" in classes:
            self._row = {"title": "", "url": "", "snippet": "", "source": "bing"}
        elif self._row is not None and tag == "h2":
            self._in_h2 = True
        elif self._row is not None and self._in_h2 and tag == "a":
            self._in_link = True
            if attrs.get("href"):
                self._row["url"] = attrs["href"]
        elif self._row is not None and tag == "p":
            self._in_snippet = True

    def handle_data(self, data):
        if self._row is None:
            return
        if self._in_link and self._in_h2:
            self._row["title"] += data
        elif self._in_snippet:
            self._row["snippet"] += data

    def handle_endtag(self, tag):
        if tag == "a":
            self._in_link = False
        elif tag == "h2":
            self._in_h2 = False
        elif tag == "p":
            self._in_snippet = False
        elif tag == "li" and self._row is not None:
            if self._row["title"].strip() and self._row["url"].startswith(("http://", "https://")):
                self.rows.append(self._row)
            self._row = None

    def finish(self):
        if self._row and self._row["title"].strip() and self._row["url"].startswith(("http://", "https://")):
            self.rows.append(self._row)
            self._row = None
        return self.rows


def _search_terms(query: str) -> str:
    """Drop question framing before a shop/search fallback; keep product words."""
    text = str(query or "").strip()
    text = re.sub(r"^(?:ile\s+kosztuje|jaka\s+(?:jest\s+)?cena|jaki\s+(?:jest\s+)?koszt|"
                  r"gdzie\s+(?:mogę\s+)?kupić|gdzie\s+kupic|what\s+is\s+the\s+price\s+of|"
                  r"how\s+much\s+(?:does|do|is)\s+)\s*", "", text, flags=re.I)
    text = re.sub(r"\b(?:proszę|please)\b", "", text, flags=re.I).strip(" ?!.")
    return text or query


def _search_bing(query: str, limit: int, timeout: float) -> list[dict]:
    url = "https://www.bing.com/search?q=" + urllib.parse.quote_plus(_search_terms(query)) + "&setlang=pl"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html"})
    with _pinned_open(request, timeout) as response:
        body = response.read(2_000_000).decode("utf-8", errors="replace")
    parser = _BingResults()
    parser.feed(body)
    output, seen = [], set()
    for row in parser.finish():
        url = _canonical(row["url"])
        if not url or url in seen or "bing.com" in urllib.parse.urlsplit(url).hostname:
            continue
        seen.add(url)
        output.append({"title": re.sub(r"\s+", " ", row["title"]).strip()[:240],
                       "url": url, "snippet": re.sub(r"\s+", " ", row["snippet"]).strip()[:500],
                       "source": "bing"})
        if len(output) >= limit:
            break
    return output


def _search_ceneo(query: str, limit: int, timeout: float) -> list[dict]:
    """Ceneo's server-rendered price comparison list, used for price queries."""
    url = "https://www.ceneo.pl/;szukaj-" + urllib.parse.quote_plus(_search_terms(query))
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html"})
    with _pinned_open(request, timeout) as response:
        body = response.read(1_500_000).decode("utf-8", errors="replace")
    rows, seen = [], set()
    for raw in re.findall(r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>', body, re.S | re.I):
        try:
            payload = json.loads(raw)
        except ValueError:
            continue
        candidates = []
        if isinstance(payload, dict):
            if isinstance(payload.get("itemListElement"), list):
                candidates = payload["itemListElement"]
            elif payload.get("@type") == "Product":
                candidates = [{"item": payload}]
        for entry in candidates:
            product = entry.get("item") if isinstance(entry, dict) else None
            if not isinstance(product, dict):
                continue
            title = re.sub(r"\s+", " ", str(product.get("name") or "")).strip()
            raw_link = str(product.get("url") or "").strip()
            if raw_link.startswith("/"):
                raw_link = "https://www.ceneo.pl" + raw_link
            url = _canonical(raw_link)
            if not title or not url:
                continue
            offers = product.get("offers") or {}
            price = (offers.get("lowPrice") or offers.get("price")) if isinstance(offers, dict) else None
            snippet = f"Ceneo price from {price} PLN" if price else "Ceneo product listing"
            if url in seen:
                continue  # the same product can appear per offer variant
            seen.add(url)
            rows.append({"title": title[:240], "url": url, "snippet": snippet,
                         "source": "ceneo", "price": {"price": str(price), "currency": "PLN"} if price else {}})
            if len(rows) >= limit:
                return [row for row in rows if row["url"]]
    return [row for row in rows if row["url"]]
