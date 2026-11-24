#!/usr/bin/env python3
"""Fetch one public page from the isolated web-backend venv.

This file is executed by the interpreter in ~/.jarvis-tools/venvs/web, never by
the Jarvis venv, so crawl4ai and Scrapling dependencies cannot disturb the
server. Protocol: one JSON object on stdin, one JSON object on stdout.

Request:  {"mode": "probe" | "fetch", "url": str, "timeout": float,
           "engines": ["crawl4ai", "scrapling"]}
Response: {"ok": bool, "engine": str, "url": str, "title": str, "text": str,
           "status": int, "error": str}
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys

import net_guard

os.environ.setdefault("CRAWL4AI_NO_CLOUD_NOTICE", "1")
os.environ.setdefault("CRAWL4AI_VERBOSE", "false")

MAX_TEXT = 12000
MARKER = "@@JARVIS@@"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


def _public(url: str) -> bool:
    """SSRF guard: True only for a public HTTP(S) URL."""
    return net_guard.is_public_url(url)


def _clean(text: str) -> str:
    text = re.sub(r"\r\n?", "\n", str(text or ""))
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()[:MAX_TEXT]


def _chrome_path() -> str:
    """Prefer the Chrome for Testing binary Jarvis already trusts."""
    import glob
    from pathlib import Path
    for pattern in (
        str(Path.home() / ".cache/ms-playwright/chromium-*/chrome-linux*/chrome"),
        "/opt/google/chrome/chrome",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
    ):
        hits = sorted(glob.glob(pattern))
        if hits:
            return hits[-1]
    return ""


def _markdown(result) -> str:
    value = getattr(result, "markdown", "") or ""
    if isinstance(value, str):
        return value
    for name in ("fit_markdown", "raw_markdown", "markdown_with_citations"):
        text = getattr(value, name, "") or ""
        if text:
            return text
    return str(value or "")


async def _crawl4ai(url: str, timeout: float) -> dict:
    from crawl4ai import AsyncWebCrawler, BrowserConfig, CrawlerRunConfig

    browser = BrowserConfig(
        headless=True, verbose=False, text_mode=True,
        # QUIC/WebRTC ride UDP and can escape an HTTP-level guard.
        extra_args=["--disable-quic",
                    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"],
    )
    chrome = _chrome_path()
    if chrome:
        browser.executable_path = chrome
    run = CrawlerRunConfig(page_timeout=int(timeout * 1000))

    async def guard(route):
        """Abort private requests before Chromium connects, including subresources."""
        target = str(getattr(getattr(route, "request", None), "url", "") or "")
        if target.startswith(("http://", "https://")) and not net_guard.is_public_url(target):
            await route.abort()
        else:
            await route.continue_()

    peer = {"violation": ""}
    peer_checks = []

    async def install_guard(page, **_kwargs):
        await page.route("**/*", guard)

        def on_response(response):
            async def check():
                try:
                    address = await response.server_addr() or {}
                except Exception:
                    return
                ip = (str(address.get("ipAddress") or address.get("ip_address") or "")
                      if isinstance(address, dict) else "")
                # DNS rebinding defeats the pre-connect route check: inspect
                # the actual peer and discard the whole capture if it is local.
                if ip and not net_guard.is_public_ip(ip) and not peer["violation"]:
                    peer["violation"] = ip
            peer_checks.append(asyncio.create_task(check()))

        page.on("response", on_response)

    async with AsyncWebCrawler(config=browser) as crawler:
        try:
            # The hook fires when the page context is created, i.e. before the
            # goto and every subresource. Without it the only check was the
            # final URL, after a hostile redirect had already been fetched.
            crawler.crawler_strategy.set_hook("on_page_context_created", install_guard)
        except Exception as error:
            raise RuntimeError(f"crawl4ai could not install the public-route guard: {error}") from None
        result = await crawler.arun(url=url, config=run)
        if peer_checks:
            await asyncio.gather(*peer_checks, return_exceptions=True)
    if peer["violation"]:
        raise RuntimeError(f"crawl4ai connected to a private peer ({peer['violation']})")
    if not getattr(result, "success", False):
        raise RuntimeError(str(getattr(result, "error_message", "") or "crawl4ai failed"))
    metadata = getattr(result, "metadata", {}) or {}
    text = _clean(_markdown(result))
    if not text:
        raise RuntimeError("crawl4ai returned no text")
    # CrawlResult.url is the requested URL; redirected_url is the page the
    # browser actually rendered (including JS redirects). The parent validates
    # this value, so returning result.url would validate the wrong host.
    final_url = (getattr(result, "redirected_url", None)
                 or getattr(result, "url", None) or url)
    if not net_guard.is_public_url(final_url):
        raise RuntimeError("crawl4ai ended on a non-public URL")
    return {"engine": "crawl4ai", "url": final_url,
            "title": str(metadata.get("title") or "")[:240], "text": text,
            "status": int(getattr(result, "status_code", 200) or 200)}


def _scrapling(url: str, timeout: float) -> dict:
    from urllib.parse import urljoin

    from scrapling.fetchers import Fetcher

    # Follow redirects ourselves so every hop is validated *before* it is
    # fetched; letting curl_cffi follow them made the post-hoc final-URL check
    # the only guard, after the private request had already happened.
    current = url
    page = None
    for _ in range(6):
        page = Fetcher.get(current, timeout=int(max(3, timeout)), stealthy_headers=True,
                           follow_redirects=False)
        status = int(getattr(page, "status", 200) or 200)
        if status not in (301, 302, 303, 307, 308):
            break
        headers = getattr(page, "headers", {}) or {}
        location = headers.get("location") or headers.get("Location") or ""
        if not location:
            raise RuntimeError("scrapling returned a redirect without a location")
        current = urljoin(current, str(location))
        if not net_guard.is_public_url(current):
            raise RuntimeError("scrapling redirect target is not public")
    else:
        raise RuntimeError("scrapling exceeded the redirect limit")
    status = int(getattr(page, "status", 200) or 200)
    text = ""
    for name in ("get_all_text", "text"):
        value = getattr(page, name, None)
        try:
            text = value() if callable(value) else (value or "")
        except TypeError:
            text = ""
        if text:
            break
    if not text:
        body = getattr(page, "body", b"") or getattr(page, "html_content", "")
        if isinstance(body, bytes):
            body = body.decode("utf-8", "replace")
        text = re.sub(r"<script.*?</script>|<style.*?</style>", " ", str(body), flags=re.S | re.I)
        text = re.sub(r"<[^>]+>", " ", text)
    text = _clean(text)
    if status >= 400 or not text:
        raise RuntimeError(f"scrapling returned status {status} and no usable text")
    title = ""
    match = re.search(r"<title[^>]*>(.*?)</title>", str(getattr(page, "html_content", "") or ""), re.S | re.I)
    if match:
        title = re.sub(r"\s+", " ", match.group(1)).strip()[:240]
    final_url = getattr(page, "url", url) or url
    if not net_guard.is_public_url(final_url):
        raise RuntimeError("scrapling ended on a non-public URL")
    return {"engine": "scrapling", "url": final_url,
            "title": title, "text": text, "status": status}


def fetch(request: dict) -> dict:
    url = str(request.get("url") or "")
    if not _public(url):
        return {"ok": False, "error": "not a public http(s) url"}
    timeout = max(3.0, min(float(request.get("timeout") or 20), 45.0))
    errors = []
    for engine in request.get("engines") or ["crawl4ai"]:
        if engine == "scrapling":
            # Scrapling/curl_cffi resolves DNS itself, so the pre-flight check
            # can be defeated by rebinding and there is no peer-address hook to
            # verify afterwards. Keep it off the network path entirely.
            errors.append("scrapling: disabled (no pinned public-peer check)")
            continue
        try:
            if engine == "crawl4ai":
                found = asyncio.run(_crawl4ai(url, timeout))
            else:
                continue
            found["ok"] = True
            return found
        except Exception as error:  # keep the reason, try the next engine
            errors.append(f"{engine}: {type(error).__name__}: {str(error)[:160]}")
    return {"ok": False, "error": " | ".join(errors) or "no engines"}


def probe() -> dict:
    found = {}
    for module in ("crawl4ai", "scrapling"):
        try:
            __import__(module)
            found[module] = True
        except Exception:
            found[module] = False
    return {"ok": True, "engines": found, "chrome": _chrome_path()}


def main() -> int:
    try:
        request = json.loads(sys.stdin.read() or "{}")
    except Exception:
        # The wrapper reads MARKER-prefixed lines only: an error reply must
        # stay parseable like every other response.
        print(MARKER + json.dumps({"ok": False, "error": "bad request"}))
        return 0
    mode = request.get("mode") or "fetch"
    result = probe() if mode == "probe" else fetch(request)
    print(MARKER + json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
